package policy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var tokenA, tokenB = HashToken("token-a"), HashToken("token-b")

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(`
upstreams:
  ops: http://ops:8081/mcp
default_rate_limit: {per_minute: 60, burst: 5}
agents:
  - name: alpha
    token_sha256: ` + tokenA + `
    allow: ["ops/get_*", "ops/restart_service"]
    deny: ["ops/get_secrets"]
    tool_rate_limits:
      ops/restart_service: {per_minute: 1, burst: 1}
  - name: beta
    token_sha256: ` + tokenB + `
    disabled: true
    allow: ["ops/*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecide(t *testing.T) {
	p := testPolicy(t)
	alpha, _ := p.Authenticate("token-a")
	beta, _ := p.Authenticate("token-b")
	cases := []struct {
		agent   *Agent
		tool    string
		allowed bool
		rule    string
	}{
		{alpha, "get_service_health", true, "allow:ops/get_*"},
		{alpha, "restart_service", true, "allow:ops/restart_service"},
		{alpha, "get_secrets", false, "deny:ops/get_secrets"}, // deny beats allow
		{alpha, "delete_service", false, "default-deny"},
		{beta, "get_service_health", false, "agent-disabled"},
	}
	for _, c := range cases {
		d := p.Decide(c.agent, "ops", c.tool)
		if d.Allowed != c.allowed || d.Rule != c.rule {
			t.Errorf("%s/%s: got %+v, want allowed=%v rule=%s", c.agent.Name, c.tool, d, c.allowed, c.rule)
		}
	}
	// A pattern for one upstream never matches another.
	if d := p.Decide(alpha, "billing", "get_invoice"); d.Allowed {
		t.Errorf("cross-upstream match: %+v", d)
	}
}

func TestAuthenticate(t *testing.T) {
	p := testPolicy(t)
	if a, ok := p.Authenticate("token-a"); !ok || a.Name != "alpha" {
		t.Errorf("token-a: got %v %v", a, ok)
	}
	for _, tok := range []string{"", "token-c", "TOKEN-A", " token-a"} {
		if _, ok := p.Authenticate(tok); ok {
			t.Errorf("token %q authenticated", tok)
		}
	}
}

func TestRateLimitFor(t *testing.T) {
	p := testPolicy(t)
	alpha, _ := p.Authenticate("token-a")
	if l := p.RateLimitFor(alpha, "ops", "restart_service"); l.PerMinute != 1 {
		t.Errorf("tool override: %+v", l)
	}
	if l := p.RateLimitFor(alpha, "ops", "get_service_health"); l.PerMinute != 60 || l.Burst != 5 {
		t.Errorf("default: %+v", l)
	}
}

func TestParseRejectsBadPolicies(t *testing.T) {
	base := "upstreams:\n  ops: http://ops/mcp\nagents:\n"
	cases := map[string]string{
		"unknown field":      base + "  - name: a\n    token_sha256: " + tokenA + "\n    alow: [ops/x]\n",
		"short token hash":   base + "  - name: a\n    token_sha256: abc\n",
		"shared token":       base + "  - name: a\n    token_sha256: " + tokenA + "\n  - name: b\n    token_sha256: " + tokenA + "\n",
		"unknown upstream":   base + "  - name: a\n    token_sha256: " + tokenA + "\n    allow: [billing/x]\n",
		"pattern without /":  base + "  - name: a\n    token_sha256: " + tokenA + "\n    allow: [get_*]\n",
		"bad glob":           base + "  - name: a\n    token_sha256: " + tokenA + "\n    allow: [\"ops/[\"]\n",
		"bad agent name":     base + "  - name: Not_Valid\n    token_sha256: " + tokenA + "\n",
		"wildcard tool rate": base + "  - name: a\n    token_sha256: " + tokenA + "\n    tool_rate_limits: {ops/get_*: {per_minute: 1}}\n",
		"no upstreams":       "agents: []\n",
		"bad upstream url":   "upstreams:\n  ops: ftp://x\n",
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("OPS_URL", "http://from-env:9000/mcp")
	p, err := Parse([]byte("upstreams:\n  ops: ${OPS_URL:-http://default/mcp}\n  b: ${UNSET_VAR_X:-http://fallback/mcp}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := p.Upstream("ops"); u.Host != "from-env:9000" {
		t.Errorf("ops: %v", u)
	}
	if u, _ := p.Upstream("b"); u.Host != "fallback" {
		t.Errorf("b: %v", u)
	}
}

func TestWatchReloadsAndKeepsLastGoodPolicy(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	good := "upstreams:\n  ops: http://ops/mcp\nagents:\n  - name: a\n    token_sha256: " + tokenA + "\n    allow: [ops/x]\n"
	if err := os.WriteFile(file, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Watch(ctx, file, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))

	waitFor := func(cond func() bool) bool {
		for i := 0; i < 200; i++ {
			if cond() {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}
	// A valid edit is picked up: the kill switch takes effect without a restart.
	_ = os.WriteFile(file, []byte(strings.Replace(good, "name: a\n", "name: a\n    disabled: true\n", 1)), 0o600)
	if !waitFor(func() bool { a, _ := s.Get().Authenticate("token-a"); return a != nil && a.Disabled }) {
		t.Fatal("reload not applied")
	}
	// An invalid edit is ignored and the last good policy stays.
	version := s.Get().Version
	_ = os.WriteFile(file, []byte("upstreams: [broken"), 0o600)
	time.Sleep(100 * time.Millisecond)
	if s.Get().Version != version {
		t.Fatal("invalid policy replaced the active one")
	}
}
