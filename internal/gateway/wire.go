package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/0x1ee7/mcp-paddock/internal/mcpwire"
)

// knownMethods bounds the method label's cardinality. Method names come from
// the client, so anything unrecognised is reported as "_other".
var knownMethods = map[string]bool{
	"initialize": true, "ping": true, "server/discover": true,
	"tools/list": true, "tools/call": true,
	"resources/list": true, "resources/templates/list": true, "resources/read": true,
	"resources/subscribe": true, "resources/unsubscribe": true,
	"prompts/list": true, "prompts/get": true,
	"completion/complete": true, "logging/setLevel": true, "subscriptions/listen": true,
	"notifications/initialized": true, "notifications/cancelled": true,
	"notifications/progress": true, "notifications/roots/list_changed": true,
}

func methodLabel(m *mcpwire.Message) string {
	switch {
	case m.Method == "":
		return "_response" // the client answering a server-initiated request
	case knownMethods[m.Method]:
		return m.Method
	}
	return "_other"
}

// labelSet caps how many distinct tool names become metric labels. Tool names
// are client input too, and an agent probing random names must not be able
// to blow up the metrics backend. The audit log always has the real name.
type labelSet struct {
	mu   sync.Mutex
	seen map[string]bool
	max  int
}

var labelRE = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,64}$`)

func newLabelSet(max int) *labelSet { return &labelSet{seen: map[string]bool{}, max: max} }

func (l *labelSet) label(v string) string {
	if v == "" {
		return "none"
	}
	if !labelRE.MatchString(v) {
		return "_invalid"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen[v] {
		return v
	}
	if len(l.seen) >= l.max {
		return "_overflow"
	}
	l.seen[v] = true
	return v
}

// filterToolsList removes tools the agent may not call from a tools/list
// response, so the model never even sees them. It handles both response
// formats of the streamable HTTP transport: a single JSON body and SSE.
func filterToolsList(body []byte, contentType string, id json.RawMessage, keep func(string) bool) ([]byte, error) {
	if strings.HasPrefix(contentType, "text/event-stream") {
		return rewriteSSE(body, func(data []byte) ([]byte, error) {
			if matched, _ := mcpwire.ClassifyResponse(data, id); !matched {
				return data, nil
			}
			return filterToolsJSON(data, keep)
		})
	}
	return filterToolsJSON(body, keep)
}

func filterToolsJSON(msg []byte, keep func(string) bool) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(msg, &top); err != nil {
		return nil, err
	}
	rawResult, ok := top["result"]
	if !ok {
		return msg, nil // an error response has nothing to filter
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return nil, err
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil {
		return nil, fmt.Errorf("result.tools: %w", err)
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var tool struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &tool) == nil && keep(tool.Name) {
			kept = append(kept, t)
		}
	}
	var err error
	if result["tools"], err = json.Marshal(kept); err != nil {
		return nil, err
	}
	if top["result"], err = json.Marshal(result); err != nil {
		return nil, err
	}
	return json.Marshal(top)
}

// rewriteSSE applies fn to the data of every event in an SSE body and keeps
// the other fields (id, event, retry) as they were.
func rewriteSSE(body []byte, fn func([]byte) ([]byte, error)) ([]byte, error) {
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	var out bytes.Buffer
	for _, ev := range bytes.Split(body, []byte("\n\n")) {
		if len(bytes.TrimSpace(ev)) == 0 {
			continue
		}
		var data [][]byte
		var other [][]byte
		for _, line := range bytes.Split(ev, []byte("\n")) {
			if d, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				data = append(data, bytes.TrimPrefix(d, []byte(" ")))
			} else {
				other = append(other, line)
			}
		}
		for _, line := range other {
			out.Write(line)
			out.WriteByte('\n')
		}
		if data != nil {
			newData, err := fn(bytes.Join(data, []byte("\n")))
			if err != nil {
				return nil, err
			}
			for _, line := range bytes.Split(newData, []byte("\n")) {
				out.WriteString("data: ")
				out.Write(line)
				out.WriteByte('\n')
			}
		}
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// outcomeObserver watches a streamed response for the JSON-RPC response to
// one request id, without buffering the stream itself.
type outcomeObserver struct {
	id      json.RawMessage
	sse     bool
	buf     bytes.Buffer // current line (SSE) or whole body (JSON), capped
	data    bytes.Buffer // data lines of the current SSE event
	outcome mcpwire.Outcome
	done    bool
}

const observeCap = 1 << 20

func newOutcomeObserver(id json.RawMessage, sse bool) *outcomeObserver {
	return &outcomeObserver{id: id, sse: sse, outcome: mcpwire.OutcomeUnknown}
}

func (o *outcomeObserver) Write(p []byte) {
	if o.done {
		return
	}
	if !o.sse {
		if o.buf.Len()+len(p) <= observeCap {
			o.buf.Write(p)
		}
		return
	}
	for _, c := range p {
		if c != '\n' {
			if o.buf.Len() < observeCap {
				o.buf.WriteByte(c)
			}
			continue
		}
		line := bytes.TrimSuffix(o.buf.Bytes(), []byte("\r"))
		switch {
		case len(line) == 0: // end of event
			if o.data.Len() > 0 {
				if matched, oc := mcpwire.ClassifyResponse(o.data.Bytes(), o.id); matched {
					o.outcome, o.done = oc, true
				}
			}
			o.data.Reset()
		case bytes.HasPrefix(line, []byte("data:")):
			if o.data.Len() > 0 {
				o.data.WriteByte('\n')
			}
			o.data.Write(bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" ")))
		}
		o.buf.Reset()
		if o.done {
			return
		}
	}
}

func (o *outcomeObserver) Outcome() mcpwire.Outcome {
	if !o.sse && !o.done {
		if _, oc := mcpwire.ClassifyResponse(o.buf.Bytes(), o.id); oc != mcpwire.OutcomeUnknown {
			return oc
		}
	}
	return o.outcome
}
