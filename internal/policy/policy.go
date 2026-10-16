// Package policy loads the gateway's policy file and answers two questions:
// who is this agent, and may it call this tool.
//
// The policy is deny by default. An agent can only call tools matched by one
// of its allow patterns and not matched by any deny pattern. Patterns are
// matched against "<upstream>/<tool>" with path.Match semantics, so
// "ops/get_*" allows every tool on the ops upstream that starts with get_.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
)

// File is the on-disk policy format.
type File struct {
	// Upstreams maps a short name to an MCP tool server endpoint. Agents reach
	// an upstream at /mcp/<name> on the gateway and never see its real URL.
	Upstreams map[string]string `yaml:"upstreams"`
	// DefaultRateLimit applies to every agent and tool unless overridden.
	DefaultRateLimit RateLimit `yaml:"default_rate_limit"`
	Agents           []Agent   `yaml:"agents"`
}

// Agent is one agent identity and what it is allowed to do.
type Agent struct {
	Name string `yaml:"name"`
	// TokenSHA256 is the hex SHA-256 of the agent's bearer token. Plain
	// tokens never appear in the policy file. Generate with: gateway hash-token
	TokenSHA256 string `yaml:"token_sha256"`
	// Disabled is a kill switch. A disabled agent is rejected on every call,
	// and since the policy hot-reloads it takes effect without a restart.
	Disabled bool     `yaml:"disabled"`
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
	// RateLimit overrides the default for every tool this agent calls.
	RateLimit *RateLimit `yaml:"rate_limit"`
	// ToolRateLimits overrides the limit for specific "<upstream>/<tool>" keys.
	ToolRateLimits map[string]RateLimit `yaml:"tool_rate_limits"`
}

// RateLimit is a token bucket: PerMinute tokens refill per minute, up to Burst.
// PerMinute <= 0 means unlimited.
type RateLimit struct {
	PerMinute float64 `yaml:"per_minute"`
	Burst     int     `yaml:"burst"`
}

// Decision is the result of an authorization check.
type Decision struct {
	Allowed bool
	// Rule is the pattern that decided, or "default-deny".
	Rule string
}

// Policy is a validated, immutable policy ready for lookups.
type Policy struct {
	Version   string // short content hash, recorded on every audit event
	upstreams map[string]*url.URL
	byToken   map[string]*Agent
	defaults  RateLimit
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load reads and validates a policy file.
func Load(file string) (*Policy, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// envRE matches ${VAR} and ${VAR:-default}.
var envRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// expandEnv substitutes environment variables, so one policy file works in
// local runs, Compose and Kubernetes with different upstream addresses.
func expandEnv(raw []byte) []byte {
	return envRE.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := envRE.FindSubmatch(m)
		if v, ok := os.LookupEnv(string(sub[1])); ok && v != "" {
			return []byte(v)
		}
		return sub[2]
	})
}

// Parse validates raw YAML and builds a Policy.
func Parse(raw []byte) (*Policy, error) {
	raw = expandEnv(raw)
	var f File
	if err := yaml.UnmarshalWithOptions(raw, &f, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	p := &Policy{
		Version:   hex.EncodeToString(sum[:])[:12],
		upstreams: map[string]*url.URL{},
		byToken:   map[string]*Agent{},
		defaults:  f.DefaultRateLimit,
	}
	var errs []error
	if len(f.Upstreams) == 0 {
		errs = append(errs, errors.New("no upstreams defined"))
	}
	for name, raw := range f.Upstreams {
		u, err := url.Parse(raw)
		switch {
		case !nameRE.MatchString(name):
			errs = append(errs, fmt.Errorf("upstream %q: name must match %s", name, nameRE))
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			errs = append(errs, fmt.Errorf("upstream %q: invalid URL %q", name, raw))
		default:
			p.upstreams[name] = u
		}
	}
	seen := map[string]bool{}
	for i := range f.Agents {
		a := &f.Agents[i]
		if !nameRE.MatchString(a.Name) {
			errs = append(errs, fmt.Errorf("agent %q: name must match %s", a.Name, nameRE))
			continue
		}
		if seen[a.Name] {
			errs = append(errs, fmt.Errorf("agent %q: duplicate name", a.Name))
		}
		seen[a.Name] = true
		a.TokenSHA256 = strings.ToLower(a.TokenSHA256)
		if b, err := hex.DecodeString(a.TokenSHA256); err != nil || len(b) != sha256.Size {
			errs = append(errs, fmt.Errorf("agent %q: token_sha256 must be 64 hex characters", a.Name))
		} else if other, dup := p.byToken[a.TokenSHA256]; dup {
			errs = append(errs, fmt.Errorf("agents %q and %q share a token", other.Name, a.Name))
		} else {
			p.byToken[a.TokenSHA256] = a
		}
		for _, pat := range append(append([]string{}, a.Allow...), a.Deny...) {
			if err := p.checkPattern(pat); err != nil {
				errs = append(errs, fmt.Errorf("agent %q: %w", a.Name, err))
			}
		}
		for key := range a.ToolRateLimits {
			if err := p.checkPattern(key); err != nil || strings.ContainsAny(key, "*?[") {
				errs = append(errs, fmt.Errorf("agent %q: tool_rate_limits key %q must be an exact <upstream>/<tool>", a.Name, key))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Policy) checkPattern(pat string) error {
	up, _, ok := strings.Cut(pat, "/")
	if !ok {
		return fmt.Errorf("pattern %q must look like <upstream>/<tool>", pat)
	}
	if _, err := path.Match(pat, ""); err != nil {
		return fmt.Errorf("pattern %q: %w", pat, err)
	}
	if up != "*" && p.upstreams[up] == nil {
		return fmt.Errorf("pattern %q names unknown upstream %q", pat, up)
	}
	return nil
}

// HashToken returns the value to put in token_sha256 for a bearer token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticate maps a bearer token to an agent. Tokens are compared by hash,
// so lookup time does not depend on how much of a token matches.
func (p *Policy) Authenticate(token string) (*Agent, bool) {
	if token == "" {
		return nil, false
	}
	a, ok := p.byToken[HashToken(token)]
	return a, ok
}

// Upstream returns the endpoint for an upstream name.
func (p *Policy) Upstream(name string) (*url.URL, bool) {
	u, ok := p.upstreams[name]
	return u, ok
}

// Decide reports whether agent may call tool on upstream. Deny beats allow,
// and anything not explicitly allowed is denied.
func (p *Policy) Decide(a *Agent, upstream, tool string) Decision {
	key := upstream + "/" + tool
	if a.Disabled {
		return Decision{false, "agent-disabled"}
	}
	for _, pat := range a.Deny {
		if ok, _ := path.Match(pat, key); ok {
			return Decision{false, "deny:" + pat}
		}
	}
	for _, pat := range a.Allow {
		if ok, _ := path.Match(pat, key); ok {
			return Decision{true, "allow:" + pat}
		}
	}
	return Decision{false, "default-deny"}
}

// RateLimitFor returns the limit that applies to agent calling tool.
func (p *Policy) RateLimitFor(a *Agent, upstream, tool string) RateLimit {
	if l, ok := a.ToolRateLimits[upstream+"/"+tool]; ok {
		return l
	}
	if a.RateLimit != nil {
		return *a.RateLimit
	}
	return p.defaults
}
