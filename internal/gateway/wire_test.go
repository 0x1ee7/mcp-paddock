package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x1ee7/mcp-paddock/internal/mcpwire"
)

const toolsList = `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"get_a"},{"name":"delete_b"}],"nextCursor":"x"}}`

func keepGet(name string) bool { return strings.HasPrefix(name, "get_") }

func TestFilterToolsListJSON(t *testing.T) {
	out, err := filterToolsList([]byte(toolsList), "application/json", json.RawMessage("3"), keepGet)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "delete_b") || !strings.Contains(string(out), "get_a") ||
		!strings.Contains(string(out), `"nextCursor":"x"`) {
		t.Fatalf("got %s", out)
	}
}

func TestFilterToolsListSSE(t *testing.T) {
	sse := "event: message\r\nid: 1\r\ndata: " + toolsList + "\r\n\r\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"
	out, err := filterToolsList([]byte(sse), "text/event-stream", json.RawMessage("3"), keepGet)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "delete_b") || !strings.Contains(s, "get_a") {
		t.Fatalf("not filtered: %s", s)
	}
	if !strings.Contains(s, "id: 1\n") || !strings.Contains(s, "notifications/progress") {
		t.Fatalf("other fields or events lost: %s", s)
	}
}

func TestFilterFailsClosedOnGarbage(t *testing.T) {
	if _, err := filterToolsList([]byte(`{"result":{"tools":"nope"}}`), "application/json", json.RawMessage("1"), keepGet); err == nil {
		t.Fatal("malformed tools/list should be an error, not passed through")
	}
}

func TestOutcomeObserverAcrossChunks(t *testing.T) {
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"result\":{\"isError\":true,\"content\":[]}}\n\n"
	o := newOutcomeObserver(json.RawMessage(`"abc"`), true)
	for i := 0; i < len(stream); i += 7 { // feed in awkward chunk sizes
		end := min(i+7, len(stream))
		o.Write([]byte(stream[i:end]))
	}
	if o.Outcome() != mcpwire.OutcomeToolError {
		t.Fatalf("outcome = %s", o.Outcome())
	}
}

func TestLabelSetCapsCardinality(t *testing.T) {
	l := newLabelSet(2)
	if l.label("a") != "a" || l.label("b") != "b" || l.label("c") != "_overflow" || l.label("a") != "a" {
		t.Fatal("cap not applied")
	}
	if l.label("bad name with spaces") != "_invalid" {
		t.Fatal("invalid label passed through")
	}
}
