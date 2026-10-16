package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/0x1ee7/mcp-paddock/internal/mcpwire"
	"github.com/0x1ee7/mcp-paddock/internal/opstools"
	"github.com/0x1ee7/mcp-paddock/internal/policy"
	"github.com/0x1ee7/mcp-paddock/internal/ratelimit"
)

var spans = tracetest.NewSpanRecorder()

func TestMain(m *testing.M) {
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	os.Exit(m.Run())
}

const testPolicy = `
upstreams:
  ops: UPSTREAM
agents:
  - name: oncall
    token_sha256: ` + "HASH_ONCALL" + `
    allow: [ops/list_*, ops/get_*, ops/tail_logs, ops/restart_service]
    deny: [ops/delete_*]
    tool_rate_limits:
      ops/restart_service: {per_minute: 60, burst: 2}
  - name: readonly
    token_sha256: HASH_RO
    allow: [ops/list_*, ops/get_*]
  - name: off
    token_sha256: HASH_OFF
    disabled: true
    allow: [ops/*]
`

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// events returns the parsed audit log lines.
func (s *syncBuffer) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(s.b.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["event"] == "mcp_request" {
			out = append(out, m)
		}
	}
	return out
}

type env struct {
	gw       *httptest.Server
	logs     *syncBuffer
	mu       sync.Mutex
	upHeader []http.Header // headers of requests that reached the tool server
}

func (e *env) upstreamHeaders() []http.Header {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]http.Header(nil), e.upHeader...)
}

func setup(t *testing.T, jsonResponse bool) *env {
	t.Helper()
	e := &env{logs: &syncBuffer{}}
	tools := opstools.Handler(opstools.NewFleet(), jsonResponse)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.upHeader = append(e.upHeader, r.Header.Clone())
		e.mu.Unlock()
		tools.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)

	raw := strings.NewReplacer(
		"UPSTREAM", up.URL,
		"HASH_ONCALL", policy.HashToken("t-oncall"),
		"HASH_RO", policy.HashToken("t-ro"),
		"HASH_OFF", policy.HashToken("t-off"),
	).Replace(testPolicy)
	pol, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(Options{
		Policy:  policy.NewStore(pol),
		Limiter: ratelimit.New(),
		Logger:  slog.New(slog.NewJSONHandler(e.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.gw = httptest.NewServer(gw.Handler())
	t.Cleanup(e.gw.Close)
	return e
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, e *env, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             e.gw.URL + "/mcp/ops",
		HTTPClient:           &http.Client{Transport: bearer(token)},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// eventually retries cond for up to a second. The gateway records a request
// after the last byte of the response has been relayed, so with SSE the
// client can see the result a moment before the audit event exists.
func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func rpcCode(err error) int64 {
	var e *jsonrpc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func forBothTransports(t *testing.T, fn func(t *testing.T, e *env)) {
	for _, mode := range []struct {
		name string
		json bool
	}{{"json", true}, {"sse", false}} {
		t.Run(mode.name, func(t *testing.T) { fn(t, setup(t, mode.json)) })
	}
}

func TestToolsListIsFilteredPerAgent(t *testing.T) {
	forBothTransports(t, func(t *testing.T, e *env) {
		for token, want := range map[string]string{
			"t-oncall": "get_service_health,list_services,restart_service,tail_logs",
			"t-ro":     "get_service_health,list_services",
		} {
			res, err := connect(t, e, token).ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tool := range res.Tools {
				names = append(names, tool.Name)
			}
			sort.Strings(names)
			if got := strings.Join(names, ","); got != want {
				t.Errorf("%s sees %s, want %s", token, got, want)
			}
		}
	})
}

func TestAllowedCallCarriesIdentityNotCredential(t *testing.T) {
	forBothTransports(t, func(t *testing.T, e *env) {
		ctx, span := otel.Tracer("test").Start(context.Background(), "agent turn")
		res, err := connect(t, e, "t-oncall").CallTool(ctx, &mcp.CallToolParams{
			Name: "restart_service", Arguments: map[string]any{"service": "scan-ingest", "reason": "test"}})
		span.End()
		if err != nil || res.IsError {
			t.Fatalf("call failed: %v %+v", err, res)
		}
		out, _ := json.Marshal(res.StructuredContent)
		if !strings.Contains(string(out), `"performed_by":"oncall"`) {
			t.Errorf("tool did not see the gateway-asserted identity: %s", out)
		}
		for _, h := range e.upstreamHeaders() {
			if h.Get("Authorization") != "" {
				t.Fatal("agent credential was forwarded to the tool server")
			}
			if h.Get(AgentHeader) != "oncall" {
				t.Fatalf("missing %s header", AgentHeader)
			}
		}
		// The gateway span and the tool server span join the caller's trace.
		var gwSpan, toolSpan sdktrace.ReadOnlySpan
		eventually(t, func() bool {
			for _, s := range spans.Ended() {
				if s.SpanContext().TraceID() != span.SpanContext().TraceID() || s.Name() != "tools/call restart_service" {
					continue
				}
				switch s.InstrumentationScope().Name {
				case "github.com/0x1ee7/mcp-paddock/gateway":
					gwSpan = s
				case "github.com/0x1ee7/mcp-paddock/opstools":
					toolSpan = s
				}
			}
			return gwSpan != nil && toolSpan != nil
		})
		if gwSpan == nil || toolSpan == nil {
			t.Fatalf("missing spans in trace: gateway=%v tool=%v", gwSpan != nil, toolSpan != nil)
		}
		if toolSpan.Parent().SpanID() != gwSpan.SpanContext().SpanID() {
			t.Error("tool server span is not a child of the gateway span")
		}
		attrs := map[string]string{}
		for _, a := range gwSpan.Attributes() {
			attrs[string(a.Key)] = a.Value.Emit()
		}
		for k, v := range map[string]string{"gen_ai.tool.name": "restart_service", "gen_ai.agent.name": "oncall",
			"mcp.method.name": "tools/call", "paddock.decision": "allow", "paddock.outcome": "ok"} {
			if attrs[k] != v {
				t.Errorf("span attribute %s = %q, want %q", k, attrs[k], v)
			}
		}
	})
}

func TestDeniedCallNeverReachesTheToolServer(t *testing.T) {
	forBothTransports(t, func(t *testing.T, e *env) {
		s := connect(t, e, "t-oncall")
		before := len(e.upstreamHeaders())
		_, err := s.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "delete_service", Arguments: map[string]any{"service": "scan-ingest"}})
		if rpcCode(err) != mcpwire.CodeForbidden {
			t.Fatalf("want JSON-RPC %d, got %v", mcpwire.CodeForbidden, err)
		}
		if len(e.upstreamHeaders()) != before {
			t.Fatal("denied call was forwarded")
		}
		// Not listed in an allow pattern at all: default deny.
		_, err = connect(t, e, "t-ro").CallTool(context.Background(), &mcp.CallToolParams{
			Name: "tail_logs", Arguments: map[string]any{"service": "scan-ingest"}})
		if rpcCode(err) != mcpwire.CodeForbidden {
			t.Fatalf("want default deny, got %v", err)
		}
		var rules []string
		for _, ev := range e.logs.events() {
			if ev["decision"] == "deny" {
				rules = append(rules, ev["rule"].(string))
			}
		}
		if strings.Join(rules, ",") != "deny:ops/delete_*,default-deny" {
			t.Errorf("audit rules = %v", rules)
		}
	})
}

func TestRateLimitIsPerAgentAndTool(t *testing.T) {
	e := setup(t, true)
	s := connect(t, e, "t-oncall")
	restart := func() error {
		_, err := s.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "restart_service", Arguments: map[string]any{"service": "store-sync", "reason": "test"}})
		return err
	}
	for i := 0; i < 2; i++ {
		if err := restart(); err != nil {
			t.Fatalf("call %d within burst: %v", i, err)
		}
	}
	err := restart()
	if rpcCode(err) != mcpwire.CodeRateLimited {
		t.Fatalf("want JSON-RPC %d, got %v", mcpwire.CodeRateLimited, err)
	}
	var rpcErr *jsonrpc.Error
	errors.As(err, &rpcErr)
	if !strings.Contains(string(rpcErr.Data), "retry_after_ms") {
		t.Errorf("no retry hint in %s", rpcErr.Data)
	}
	// Another tool for the same agent is unaffected.
	if _, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_services"}); err != nil {
		t.Fatalf("other tool was limited: %v", err)
	}
}

func TestToolErrorsAreRecordedAsOutcomes(t *testing.T) {
	forBothTransports(t, func(t *testing.T, e *env) {
		res, err := connect(t, e, "t-oncall").CallTool(context.Background(), &mcp.CallToolParams{
			Name: "get_service_health", Arguments: map[string]any{"service": "no-such-service"}})
		if err != nil || !res.IsError {
			t.Fatalf("want a tool error result, got %v %+v", err, res)
		}
		var last map[string]any
		eventually(t, func() bool {
			evs := e.logs.events()
			last = evs[len(evs)-1]
			return last["method"] == "tools/call"
		})
		if last["decision"] != "allow" || last["outcome"] != "tool_error" || last["tool"] != "get_service_health" {
			t.Errorf("audit event = %v", last)
		}
	})
}

func post(t *testing.T, url, token string, hdr map[string]string, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRejections(t *testing.T) {
	e := setup(t, true)
	call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_service_health","arguments":{"service":"store-sync"}}}`
	cases := []struct {
		name, path, token string
		hdr               map[string]string
		body              string
		status            int
		contains          string
	}{
		{"no token", "/mcp/ops", "", nil, call, 401, "bearer token"},
		{"unknown token", "/mcp/ops", "nope", nil, call, 401, "bearer token"},
		{"disabled agent", "/mcp/ops", "t-off", nil, call, 403, "disabled"},
		{"unknown upstream", "/mcp/billing", "t-oncall", nil, call, 404, "unknown upstream"},
		{"batch", "/mcp/ops", "t-oncall", nil, "[" + call + "]", 400, "batches"},
		{"not json", "/mcp/ops", "t-oncall", nil, "hello", 400, "-32700"},
		{"method header mismatch", "/mcp/ops", "t-oncall",
			map[string]string{"Mcp-Method": "tools/list"}, call, 400, "-32020"},
		{"name header mismatch", "/mcp/ops", "t-oncall",
			map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "list_services"}, call, 400, "-32020"},
	}
	for _, c := range cases {
		status, body := post(t, e.gw.URL+c.path, c.token, c.hdr, c.body)
		if status != c.status || !strings.Contains(body, c.contains) {
			t.Errorf("%s: got %d %s, want %d containing %q", c.name, status, body, c.status, c.contains)
		}
	}
	if n := len(e.upstreamHeaders()); n != 0 {
		t.Errorf("%d rejected requests reached the tool server", n)
	}
	if n := len(e.logs.events()); n != len(cases) {
		t.Errorf("%d audit events for %d rejected requests", n, len(cases))
	}
}

func TestUpstreamDownIsA502(t *testing.T) {
	e := setup(t, true)
	pol, _ := policy.Parse([]byte(strings.NewReplacer("UPSTREAM", "http://127.0.0.1:1/mcp",
		"HASH_ONCALL", policy.HashToken("t-oncall"), "HASH_RO", policy.HashToken("t-ro"),
		"HASH_OFF", policy.HashToken("t-off")).Replace(testPolicy)))
	gw, _ := New(Options{Policy: policy.NewStore(pol), Limiter: ratelimit.New(),
		Logger: slog.New(slog.NewJSONHandler(e.logs, nil))})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()
	status, body := post(t, srv.URL+"/mcp/ops", "t-oncall", nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_services"}}`)
	if status != http.StatusBadGateway || !strings.Contains(body, `"id":1`) {
		t.Fatalf("got %d %s", status, body)
	}
	evs := e.logs.events()
	if evs[len(evs)-1]["outcome"] != "upstream_error" {
		t.Errorf("audit event = %v", evs[len(evs)-1])
	}
}
