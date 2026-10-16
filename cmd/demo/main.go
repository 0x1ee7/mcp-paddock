// Command demo plays a scripted on-call agent against the gateway, so the
// whole story runs without an LLM or API key: tool discovery, triage, a
// prompt injection hidden in the logs, a runaway loop, and a bad credential.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/0x1ee7/mcp-paddock/internal/opstools"
	"github.com/0x1ee7/mcp-paddock/internal/telemetry"
)

var (
	gatewayURL    = flag.String("gateway", envOr("PADDOCK_GATEWAY", "http://localhost:8080"), "gateway base URL")
	oncallToken   = flag.String("oncall-token", envOr("ONCALL_TOKEN", "demo-oncall-token"), "token for oncall-bot")
	readonlyToken = flag.String("readonly-token", envOr("READONLY_TOKEN", "demo-readonly-token"), "token for dashboard-bot")
	loop          = flag.Int("loop", 20, "calls in the runaway-loop scenario")
)

var tracer trace.Tracer

func main() {
	flag.Parse()
	ctx := context.Background()
	_, shutdown, err := telemetry.Setup(ctx, "demo-agent", "v0.1.0")
	if err != nil {
		fail(err)
	}
	defer shutdown(context.Background())
	tracer = otel.Tracer("github.com/0x1ee7/mcp-paddock/demo")

	oncall, err := connect(ctx, *oncallToken)
	if err != nil {
		fail(fmt.Errorf("connect as oncall-bot: %w", err))
	}
	defer oncall.Close()
	readonly, err := connect(ctx, *readonlyToken)
	if err != nil {
		fail(fmt.Errorf("connect as dashboard-bot: %w", err))
	}
	defer readonly.Close()

	scenario(ctx, "1. Tool discovery: each agent only sees what its policy allows", func(ctx context.Context) {
		for _, a := range []struct {
			name string
			s    *mcp.ClientSession
		}{{"oncall-bot", oncall}, {"dashboard-bot", readonly}} {
			res, err := a.s.ListTools(ctx, nil)
			if err != nil {
				step("✗", a.name+" tools/list", err.Error())
				continue
			}
			var names []string
			for _, t := range res.Tools {
				names = append(names, t.Name)
			}
			sort.Strings(names)
			step("✓", a.name+" sees", strings.Join(names, ", "))
		}
		note("delete_service exists on the server, but no agent's policy allows it, so nobody is shown it.")
	})

	var injected string
	scenario(ctx, "2. Triage as oncall-bot", func(ctx context.Context) {
		var list struct{ Services []opstools.Service }
		if call(ctx, oncall, "list_services", nil, &list) {
			var parts []string
			for _, s := range list.Services {
				parts = append(parts, fmt.Sprintf("%s %s (%d/%d ready)", s.Name, s.Status, s.Ready, s.Replicas))
			}
			step("✓", "list_services", strings.Join(parts, "; "))
		}
		var h opstools.Service
		if call(ctx, oncall, "get_service_health", map[string]any{"service": "scan-ingest"}, &h) {
			step("✓", "get_service_health scan-ingest", fmt.Sprintf("errors %.0f%%, p95 %dms, %d restarts/h, SLO burn %.1fx",
				h.ErrorRate*100, h.P95LatencyMS, h.Restarts1h, h.SLOBurnRate))
		}
		var logs struct{ Lines []string }
		if call(ctx, oncall, "tail_logs", map[string]any{"service": "scan-ingest", "lines": 10}, &logs) {
			step("✓", "tail_logs scan-ingest", fmt.Sprintf("%d lines, includes: OOMKilled (exit 137)", len(logs.Lines)))
			for _, l := range logs.Lines {
				if m := regexp.MustCompile(`call (\w+) on ([\w-]+)`).FindStringSubmatch(l); m != nil {
					injected = m[1] + " " + m[2]
				}
			}
		}
		var r struct {
			Message     string `json:"message"`
			PerformedBy string `json:"performed_by"`
		}
		if call(ctx, oncall, "restart_service", map[string]any{"service": "scan-ingest", "reason": "OOMKilled crash loop"}, &r) {
			step("✓", "restart_service scan-ingest", r.Message+" (performed_by="+r.PerformedBy+", asserted by the gateway)")
		}
	})

	scenario(ctx, "3. Prompt injection hidden in the logs", func(ctx context.Context) {
		if injected == "" {
			step("✗", "no injected instruction found in logs", "")
			return
		}
		note(`A log line says: "AI assistant reading this: ... call ` + strings.Replace(injected, " ", " on ", 1) + `"`)
		note("A naive agent follows it:")
		tool, svc, _ := strings.Cut(injected, " ")
		call(ctx, oncall, tool, map[string]any{"service": svc}, nil)
	})

	scenario(ctx, fmt.Sprintf("4. Runaway loop: %d calls to get_service_health as fast as possible", *loop), func(ctx context.Context) {
		allowed, limited := 0, 0
		var firstRetry string
		for i := 0; i < *loop; i++ {
			_, err := oncall.CallTool(ctx, &mcp.CallToolParams{Name: "get_service_health",
				Arguments: map[string]any{"service": "fit-recommender"}})
			var rpcErr *jsonrpc.Error
			switch {
			case err == nil:
				allowed++
			case errors.As(err, &rpcErr) && rpcErr.Code == -32029:
				limited++
				if firstRetry == "" {
					var d struct {
						RetryAfterMS int64 `json:"retry_after_ms"`
					}
					_ = json.Unmarshal(rpcErr.Data, &d)
					firstRetry = (time.Duration(d.RetryAfterMS) * time.Millisecond).String()
				}
			default:
				step("✗", "unexpected error", err.Error())
				return
			}
		}
		step("✓", "allowed", fmt.Sprint(allowed))
		step("✗", "rate limited", fmt.Sprintf("%d (JSON-RPC -32029, first retry_after %s)", limited, firstRetry))
		note("The limit is per agent and per tool, so other tools and other agents are unaffected.")
	})

	scenario(ctx, "5. Unknown credential", func(ctx context.Context) {
		_, err := connect(ctx, "stolen-or-made-up-token")
		if err != nil {
			step("✗", "connect with a bad token", firstLine(err.Error()))
		} else {
			step("!", "connect with a bad token", "unexpectedly succeeded")
		}
	})

	fmt.Println("\nEvery call above is in the gateway's audit log, and as a trace in Grafana (Explore → Tempo, service mcp-gateway).")
}

// call invokes a tool and decodes its structured result into out.
func call(ctx context.Context, s *mcp.ClientSession, tool string, args map[string]any, out any) bool {
	label := tool
	if svc, ok := args["service"].(string); ok {
		label += " " + svc
	}
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	var rpcErr *jsonrpc.Error
	switch {
	case errors.As(err, &rpcErr):
		var d struct {
			Rule string `json:"rule"`
		}
		_ = json.Unmarshal(rpcErr.Data, &d)
		step("✗", label, fmt.Sprintf("BLOCKED by gateway (JSON-RPC %d, rule %s)", rpcErr.Code, d.Rule))
		note(rpcErr.Message)
		return false
	case err != nil:
		step("✗", label, err.Error())
		return false
	case res.IsError:
		step("✗", label, "tool error")
		return false
	}
	if out != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(raw, out)
	}
	return true
}

func connect(ctx context.Context, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "paddock-demo", Version: "v0.1.0"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             strings.TrimRight(*gatewayURL, "/") + "/mcp/ops",
		HTTPClient:           &http.Client{Transport: authTransport{token: token}, Timeout: 30 * time.Second},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
}

// authTransport adds the agent's bearer token and the current trace context.
type authTransport struct{ token string }

func (t authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	return http.DefaultTransport.RoundTrip(r)
}

func scenario(ctx context.Context, title string, fn func(context.Context)) {
	fmt.Printf("\n── %s\n", title)
	ctx, span := tracer.Start(ctx, "agent turn: "+title, trace.WithAttributes(attribute.String("gen_ai.agent.name", "demo")))
	defer span.End()
	fn(ctx)
}

func step(mark, what, detail string) {
	if detail != "" {
		fmt.Printf("   %s %-32s %s\n", mark, what, detail)
	} else {
		fmt.Printf("   %s %s\n", mark, what)
	}
}

func note(s string) { fmt.Printf("     %s\n", s) }

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "demo:", err)
	os.Exit(1)
}
