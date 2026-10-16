// Package gateway is an MCP-aware reverse proxy that sits between AI agents
// and MCP tool servers. Every request is authenticated to an agent identity,
// every tool call is checked against that agent's policy and rate limit, and
// every decision is recorded as a trace span, a metric and an audit log line.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/0x1ee7/mcp-paddock/internal/mcpwire"
	"github.com/0x1ee7/mcp-paddock/internal/policy"
	"github.com/0x1ee7/mcp-paddock/internal/ratelimit"
)

// AgentHeader carries the authenticated agent name to tool servers. The
// agent's own credential is never forwarded, so a tool server cannot replay
// it elsewhere. Tool servers trust this header only because network policy
// makes the gateway the only client that can reach them.
const AgentHeader = "X-Paddock-Agent"

// Limiter is the rate-limit seam. The in-memory implementation suits a single
// replica; a Redis-backed one would satisfy the same interface.
type Limiter interface {
	Allow(key string, perMinute float64, burst int) ratelimit.Result
}

// Options configures a Gateway.
type Options struct {
	Policy       *policy.Store
	Limiter      Limiter
	Logger       *slog.Logger
	Client       *http.Client  // for upstream calls; defaults to a tuned client
	MaxBodyBytes int64         // inbound request body limit; default 1 MiB
	CallTimeout  time.Duration // upstream timeout for POSTs; default 60s
}

// Gateway serves the agent-facing MCP endpoints.
type Gateway struct {
	opts     Options
	tracer   trace.Tracer
	requests metric.Int64Counter
	duration metric.Float64Histogram
	tools    *labelSet
}

// New builds a gateway.
func New(o Options) (*Gateway, error) {
	if o.Policy == nil || o.Limiter == nil || o.Logger == nil {
		return nil, errors.New("gateway: Policy, Limiter and Logger are required")
	}
	if o.Client == nil {
		o.Client = &http.Client{Transport: &http.Transport{
			Proxy:                 nil, // tool servers are in-cluster; never route via env proxies
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 0, // tool calls may legitimately take a while; CallTimeout bounds POSTs
		}}
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 1 << 20
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = 60 * time.Second
	}
	meter := otel.Meter("github.com/0x1ee7/mcp-paddock/gateway")
	requests, err := meter.Int64Counter("paddock.gateway.requests",
		metric.WithUnit("{request}"),
		metric.WithDescription("MCP requests handled by the gateway, by agent, method, tool and decision."))
	if err != nil {
		return nil, err
	}
	duration, err := meter.Float64Histogram("paddock.gateway.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("End-to-end gateway latency, including the upstream tool call."),
		metric.WithExplicitBucketBoundaries(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30))
	if err != nil {
		return nil, err
	}
	return &Gateway{
		opts:     o,
		tracer:   otel.Tracer("github.com/0x1ee7/mcp-paddock/gateway"),
		requests: requests,
		duration: duration,
		tools:    newLabelSet(256),
	}, nil
}

// Handler returns the gateway's HTTP routes.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/{upstream}", g.serveMCP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","policy_version":%q}`+"\n", g.opts.Policy.Get().Version)
	})
	return mux
}

// event collects everything known about one request for the audit log,
// metrics and span.
type event struct {
	start         time.Time
	agent         string
	upstream      string
	method        string
	tool          string
	decision      string // allow | deny | rate_limited | unauthenticated | agent_disabled | bad_request | unknown_upstream
	rule          string
	outcome       string // ok | tool_error | rpc_error | upstream_error | unknown
	status        int
	argsHash      string
	sessionID     string
	policyVersion string
	retryAfter    time.Duration
	reason        string
}

func (g *Gateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	pol := g.opts.Policy.Get()
	ev := &event{
		start:         time.Now(),
		upstream:      r.PathValue("upstream"),
		method:        "http." + r.Method,
		sessionID:     r.Header.Get(mcpwire.HeaderSessionID),
		policyVersion: pol.Version,
	}
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	agent, ok := pol.Authenticate(bearerToken(r))
	if !ok {
		ev.decision, ev.status = "unauthenticated", http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-paddock"`)
		g.reject(ctx, w, ev, "missing or unknown bearer token")
		return
	}
	ev.agent = agent.Name
	if agent.Disabled {
		ev.decision, ev.rule, ev.status = "agent_disabled", "agent-disabled", http.StatusForbidden
		g.reject(ctx, w, ev, "agent is disabled")
		return
	}
	upstream, ok := pol.Upstream(ev.upstream)
	if !ok {
		ev.decision, ev.status = "unknown_upstream", http.StatusNotFound
		g.reject(ctx, w, ev, "unknown upstream")
		return
	}

	switch r.Method {
	case http.MethodPost:
		g.handlePost(ctx, w, r, pol, agent, upstream.String(), ev)
	case http.MethodGet, http.MethodDelete:
		// Standalone SSE stream and session termination: authenticated, then
		// passed through. They carry no tool calls of their own.
		ev.decision = "allow"
		ctx, span := g.startSpan(ctx, ev)
		defer g.finish(ctx, span, ev)
		g.forward(ctx, w, r, nil, upstream.String(), agent.Name, nil, ev)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		ev.decision, ev.status = "bad_request", http.StatusMethodNotAllowed
		g.reject(ctx, w, ev, "method not allowed")
	}
}

func (g *Gateway) handlePost(ctx context.Context, w http.ResponseWriter, r *http.Request,
	pol *policy.Policy, agent *policy.Agent, upstream string, ev *event) {

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.opts.MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		ev.decision, ev.status = "bad_request", http.StatusBadRequest
		if errors.As(err, &tooBig) {
			ev.status = http.StatusRequestEntityTooLarge
		}
		g.reject(ctx, w, ev, "could not read body: "+err.Error())
		return
	}
	msg, err := mcpwire.Parse(body)
	if err != nil {
		ev.decision, ev.status = "bad_request", http.StatusBadRequest
		code := mcpwire.CodeParseError
		if errors.Is(err, mcpwire.ErrBatch) {
			code = mcpwire.CodeInvalidRequest
		}
		g.rejectRPC(ctx, w, ev, nil, code, err.Error(), nil)
		return
	}
	ev.method = methodLabel(msg)
	ev.tool = msg.ToolName

	// The 2026-07-28 transport mirrors method and name into headers for
	// intermediaries. If they disagree with the body, something is trying to
	// make the gateway check one call while the server executes another.
	if h := r.Header.Get(mcpwire.HeaderMethod); h != "" && h != msg.Method {
		ev.decision, ev.status = "bad_request", http.StatusBadRequest
		g.rejectRPC(ctx, w, ev, msg.ID, mcpwire.CodeHeaderMismatch, "Mcp-Method header does not match body", nil)
		return
	}
	if h := r.Header.Get(mcpwire.HeaderName); h != "" && msg.Method == "tools/call" && h != msg.ToolName {
		ev.decision, ev.status = "bad_request", http.StatusBadRequest
		g.rejectRPC(ctx, w, ev, msg.ID, mcpwire.CodeHeaderMismatch, "Mcp-Name header does not match params.name", nil)
		return
	}

	// MCP clients may carry trace context in params._meta instead of headers.
	if !trace.SpanContextFromContext(ctx).IsValid() && msg.Meta["traceparent"] != "" {
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier{
			"traceparent": msg.Meta["traceparent"], "tracestate": msg.Meta["tracestate"]})
	}

	if msg.Method == "tools/call" {
		sum := sha256.Sum256(msg.Arguments)
		ev.argsHash = hex.EncodeToString(sum[:8])

		d := pol.Decide(agent, ev.upstream, msg.ToolName)
		ev.rule = d.Rule
		if !d.Allowed {
			ev.decision, ev.status = "deny", http.StatusOK
			g.rejectRPC(ctx, w, ev, msg.ID, mcpwire.CodeForbidden,
				fmt.Sprintf("gateway policy does not allow agent %q to call %q on %q", agent.Name, msg.ToolName, ev.upstream),
				map[string]any{"rule": d.Rule, "policy_version": pol.Version})
			return
		}
		lim := pol.RateLimitFor(agent, ev.upstream, msg.ToolName)
		res := g.opts.Limiter.Allow(agent.Name+"\x00"+ev.upstream+"/"+msg.ToolName, lim.PerMinute, lim.Burst)
		if !res.Allowed {
			ev.decision, ev.status, ev.retryAfter = "rate_limited", http.StatusOK, res.RetryAfter
			g.rejectRPC(ctx, w, ev, msg.ID, mcpwire.CodeRateLimited,
				fmt.Sprintf("rate limit for %q exceeded (%g/min, burst %d); retry after %s",
					msg.ToolName, lim.PerMinute, lim.Burst, res.RetryAfter),
				map[string]any{"retry_after_ms": res.RetryAfter.Milliseconds()})
			return
		}
	}

	ev.decision = "allow"
	ctx, span := g.startSpan(ctx, ev)
	defer g.finish(ctx, span, ev)

	var rewrite func([]byte, string) ([]byte, error)
	if msg.Method == "tools/list" {
		rewrite = func(b []byte, contentType string) ([]byte, error) {
			return filterToolsList(b, contentType, msg.ID, func(name string) bool {
				return pol.Decide(agent, ev.upstream, name).Allowed
			})
		}
	}
	var id json.RawMessage
	if msg.IsRequest() {
		id = msg.ID
	}
	g.forward(ctx, w, r, body, upstream, agent.Name, &forwardOpts{rewrite: rewrite, id: id}, ev)
}

type forwardOpts struct {
	// rewrite, when set, buffers the whole response and transforms it.
	rewrite func(body []byte, contentType string) ([]byte, error)
	// id is the JSON-RPC request id whose response decides ev.outcome.
	id json.RawMessage
}

var forwardRequestHeaders = []string{"Content-Type", "Accept", "Last-Event-ID",
	mcpwire.HeaderSessionID, mcpwire.HeaderProtocolVersion, mcpwire.HeaderMethod, mcpwire.HeaderName}

var forwardResponseHeaders = []string{"Content-Type", "Cache-Control",
	mcpwire.HeaderSessionID, mcpwire.HeaderProtocolVersion}

func (g *Gateway) forward(ctx context.Context, w http.ResponseWriter, r *http.Request,
	body []byte, upstream, agent string, fo *forwardOpts, ev *event) {

	if r.Method == http.MethodPost {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.opts.CallTimeout)
		defer cancel()
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, upstream, reqBody)
	if err != nil {
		g.upstreamFailed(w, ev, fo, err)
		return
	}
	for _, h := range forwardRequestHeaders {
		if v := r.Header.Values(h); len(v) > 0 {
			req.Header[h] = v
		}
	}
	for k, v := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), mcpwire.HeaderParamPrefix) {
			req.Header[k] = v
		}
	}
	req.Header.Set(AgentHeader, agent)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := g.opts.Client.Do(req)
	if err != nil {
		g.upstreamFailed(w, ev, fo, err)
		return
	}
	defer resp.Body.Close()
	ev.status = resp.StatusCode
	if resp.StatusCode >= 500 {
		ev.outcome = "upstream_error"
	}
	for _, h := range forwardResponseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			w.Header()[h] = v
		}
	}
	contentType := resp.Header.Get("Content-Type")

	if fo != nil && fo.rewrite != nil && resp.StatusCode == http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			g.upstreamFailed(w, ev, fo, err)
			return
		}
		if out, err := fo.rewrite(raw, contentType); err == nil {
			raw = out
		} else {
			// Fail closed: an unfilterable tool list could leak tools the
			// agent is not allowed to see.
			g.upstreamFailed(w, ev, fo, fmt.Errorf("filter tools/list: %w", err))
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(raw)
		if ev.outcome == "" {
			ev.outcome = "ok"
		}
		return
	}

	w.WriteHeader(resp.StatusCode)
	var obs *outcomeObserver
	if fo != nil && len(fo.id) > 0 {
		obs = newOutcomeObserver(fo.id, strings.HasPrefix(contentType, "text/event-stream"))
	}
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if obs != nil {
				obs.Write(buf[:n])
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				break // client went away
			}
			_ = rc.Flush() // keep SSE streams live
		}
		if err != nil {
			break
		}
	}
	if obs != nil && ev.outcome == "" {
		ev.outcome = string(obs.Outcome())
	}
}

func (g *Gateway) upstreamFailed(w http.ResponseWriter, ev *event, fo *forwardOpts, err error) {
	ev.outcome, ev.status, ev.reason = "upstream_error", http.StatusBadGateway, err.Error()
	var id json.RawMessage
	if fo != nil {
		id = fo.id
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write(mcpwire.ErrorResponse(id, mcpwire.CodeUpstream, "tool server unavailable", nil))
}

// reject answers a request that never reached policy evaluation.
func (g *Gateway) reject(ctx context.Context, w http.ResponseWriter, ev *event, reason string) {
	ev.reason = reason
	ctx, span := g.startSpan(ctx, ev)
	defer g.finish(ctx, span, ev)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ev.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

// rejectRPC answers with a JSON-RPC error, so MCP clients surface the reason
// to the model as a normal failed call instead of a transport failure.
func (g *Gateway) rejectRPC(ctx context.Context, w http.ResponseWriter, ev *event,
	id json.RawMessage, code int, msg string, data any) {
	ev.reason = msg
	ctx, span := g.startSpan(ctx, ev)
	defer g.finish(ctx, span, ev)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ev.status)
	_, _ = w.Write(mcpwire.ErrorResponse(id, code, msg, data))
}

func (g *Gateway) startSpan(ctx context.Context, ev *event) (context.Context, trace.Span) {
	name := ev.method
	if ev.tool != "" {
		name += " " + ev.tool
	}
	attrs := []attribute.KeyValue{
		attribute.String("mcp.method.name", ev.method),
		attribute.String("paddock.upstream", ev.upstream),
		attribute.String("paddock.policy.version", ev.policyVersion),
	}
	if ev.tool != "" {
		attrs = append(attrs,
			attribute.String("gen_ai.tool.name", ev.tool),
			attribute.String("gen_ai.operation.name", "execute_tool"))
	}
	if ev.agent != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.name", ev.agent))
	}
	if ev.sessionID != "" {
		attrs = append(attrs, attribute.String("mcp.session.id", ev.sessionID))
	}
	return g.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
}

func (g *Gateway) finish(ctx context.Context, span trace.Span, ev *event) {
	elapsed := time.Since(ev.start)
	span.SetAttributes(
		attribute.String("paddock.decision", ev.decision),
		attribute.Int("http.response.status_code", ev.status))
	if ev.rule != "" {
		span.SetAttributes(attribute.String("paddock.policy.rule", ev.rule))
	}
	if ev.outcome != "" {
		span.SetAttributes(attribute.String("paddock.outcome", ev.outcome))
	}
	if ev.argsHash != "" {
		span.SetAttributes(attribute.String("paddock.tool.arguments.sha256", ev.argsHash))
	}
	switch {
	case ev.decision != "allow":
		// A policy refusal is the gateway working, not failing, so the span is
		// not an error. It gets an event so it stands out in the trace view.
		span.AddEvent("request refused", trace.WithAttributes(attribute.String("reason", ev.reason)))
	case ev.outcome == "upstream_error" || ev.outcome == "rpc_error" || ev.outcome == "tool_error":
		span.SetAttributes(attribute.String("error.type", ev.outcome))
		span.SetStatus(codes.Error, ev.outcome)
	}
	span.End()

	outcome := ev.outcome
	if outcome == "" {
		outcome = "none"
	}
	tool := g.tools.label(ev.tool)
	mattrs := metric.WithAttributes(
		attribute.String("agent", orNone(ev.agent)),
		attribute.String("upstream", ev.upstream),
		attribute.String("mcp.method.name", ev.method),
		attribute.String("gen_ai.tool.name", tool),
		attribute.String("decision", ev.decision),
		attribute.String("outcome", outcome))
	g.requests.Add(ctx, 1, mattrs)
	g.duration.Record(ctx, elapsed.Seconds(), mattrs)

	level := slog.LevelInfo
	if ev.decision != "allow" || ev.outcome == "upstream_error" {
		level = slog.LevelWarn
	}
	sc := span.SpanContext()
	logAttrs := []slog.Attr{
		slog.String("event", "mcp_request"),
		slog.String("agent", orNone(ev.agent)),
		slog.String("upstream", ev.upstream),
		slog.String("method", ev.method),
		slog.String("decision", ev.decision),
		slog.String("outcome", outcome),
		slog.Int("status", ev.status),
		slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
		slog.String("policy_version", ev.policyVersion),
	}
	if sc.IsValid() {
		logAttrs = append(logAttrs, slog.String("trace_id", sc.TraceID().String()))
	}
	if ev.tool != "" {
		logAttrs = append(logAttrs, slog.String("tool", ev.tool), slog.String("args_sha256", ev.argsHash))
	}
	if ev.rule != "" {
		logAttrs = append(logAttrs, slog.String("rule", ev.rule))
	}
	if ev.retryAfter > 0 {
		logAttrs = append(logAttrs, slog.Int64("retry_after_ms", ev.retryAfter.Milliseconds()))
	}
	if ev.reason != "" {
		logAttrs = append(logAttrs, slog.String("reason", ev.reason))
	}
	if ev.sessionID != "" {
		logAttrs = append(logAttrs, slog.String("session_id", ev.sessionID))
	}
	g.opts.Logger.LogAttrs(ctx, level, "mcp request", logAttrs...)
}

func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
