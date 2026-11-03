// Package gateway is the read-only tool gateway: the only way an automated
// reasoner (an LLM, KAgent, a runbook) is allowed to read ACRA state. Every call
// is default-deny (the tool must exist and the caller must hold its role),
// argument-validated, rate limited, audited, and returned as redacted,
// size-capped text marked as untrusted. There is deliberately no write path:
// the Tool type has no way to express a mutation, and ACRA's investigation
// flow never executes remediation.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/redact"
)

// Tool is one read-only capability.
type Tool struct {
	Name        string
	Description string
	Role        string           // role required to call it
	Args        *contract.Schema // validated before Handler runs
	Handler     func(ctx context.Context, args json.RawMessage) (any, error)
}

// Result is what a caller receives. Content is untrusted text: it may contain
// instructions planted by whoever influenced the underlying data, so consumers
// must treat it as data.
type Result struct {
	Tool      string `json:"tool"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
	Untrusted bool   `json:"untrusted"`
}

// AuditRecord is written for every call, allowed or not. Arguments are stored
// as a hash, not verbatim, so audit data cannot become a second leak.
type AuditRecord struct {
	Time      time.Time     `json:"time"`
	Principal string        `json:"principal"`
	Tool      string        `json:"tool"`
	ArgsHash  string        `json:"argsHash"`
	Outcome   string        `json:"outcome"` // ok | denied | invalid | rate_limited | error | unknown_tool
	Duration  time.Duration `json:"duration"`
}

// Auditor receives audit records. Implementations must not block for long.
type Auditor interface{ Record(AuditRecord) }

// Config tunes limits.
type Config struct {
	MaxArgsBytes   int
	MaxResultBytes int
	CallsPerMinute int // per principal
	CallTimeout    time.Duration
}

// Gateway dispatches tool calls.
type Gateway struct {
	cfg   Config
	audit Auditor
	now   func() time.Time

	mu      sync.Mutex
	tools   map[string]Tool
	windows map[string]*window
}

type window struct {
	start time.Time
	n     int
}

// New returns a Gateway. audit may be nil.
func New(cfg Config, audit Auditor) *Gateway {
	if cfg.MaxArgsBytes <= 0 {
		cfg.MaxArgsBytes = 16 << 10
	}
	if cfg.MaxResultBytes <= 0 {
		cfg.MaxResultBytes = 32 << 10
	}
	if cfg.CallsPerMinute <= 0 {
		cfg.CallsPerMinute = 60
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 20 * time.Second
	}
	return &Gateway{cfg: cfg, audit: audit, now: time.Now, tools: map[string]Tool{}, windows: map[string]*window{}}
}

// Register adds a tool. A tool with no role or handler is refused (default deny).
func (g *Gateway) Register(t Tool) error {
	if t.Name == "" || t.Handler == nil || t.Role == "" {
		return errors.New("gateway: tool needs a name, role and handler")
	}
	if t.Args != nil {
		if err := t.Args.Validate(); err != nil {
			return fmt.Errorf("gateway: tool %s: %w", t.Name, err)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.tools[t.Name]; dup {
		return fmt.Errorf("gateway: tool %q already registered", t.Name)
	}
	g.tools[t.Name] = t
	return nil
}

// ToolInfo describes a tool a principal may call.
type ToolInfo struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema *contract.Schema `json:"inputSchema,omitempty"`
}

// List returns the tools the principal is allowed to call.
func (g *Gateway) List(p identity.Principal) []ToolInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []ToolInfo
	for _, t := range g.tools {
		if p.Has(t.Role) {
			out = append(out, ToolInfo{Name: t.Name, Description: t.Description, InputSchema: t.Args})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Errors returned by Call.
var (
	ErrUnknownTool = errors.New("gateway: unknown tool")
	ErrDenied      = errors.New("gateway: not permitted")
	ErrInvalidArgs = errors.New("gateway: invalid arguments")
	ErrRateLimited = errors.New("gateway: rate limit exceeded")
)

// Call runs one tool on behalf of p.
func (g *Gateway) Call(ctx context.Context, p identity.Principal, name string, args json.RawMessage) (Result, error) {
	start := g.now()
	h := sha256.Sum256(args)
	rec := AuditRecord{Time: start.UTC(), Principal: p.ID, Tool: name, ArgsHash: hex.EncodeToString(h[:6])}
	finish := func(outcome string) {
		rec.Outcome, rec.Duration = outcome, g.now().Sub(start)
		if g.audit != nil {
			g.audit.Record(rec)
		}
	}

	g.mu.Lock()
	t, ok := g.tools[name]
	g.mu.Unlock()
	if !ok {
		finish("unknown_tool")
		return Result{}, ErrUnknownTool
	}
	if !p.Has(t.Role) {
		finish("denied")
		return Result{}, ErrDenied
	}
	if !g.allow(p.ID, start) {
		finish("rate_limited")
		return Result{}, ErrRateLimited
	}
	if len(args) > g.cfg.MaxArgsBytes {
		finish("invalid")
		return Result{}, fmt.Errorf("%w: arguments too large", ErrInvalidArgs)
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	if t.Args != nil {
		if probs := t.Args.Check(args); len(probs) > 0 {
			finish("invalid")
			return Result{}, fmt.Errorf("%w: %s", ErrInvalidArgs, probs[0])
		}
	}

	cctx, cancel := context.WithTimeout(ctx, g.cfg.CallTimeout)
	defer cancel()
	val, err := safeHandle(cctx, t, args)
	if err != nil {
		finish("error")
		return Result{}, fmt.Errorf("gateway: tool %s failed: %s", name, redact.String(err.Error()))
	}
	raw, err := json.Marshal(val)
	if err != nil {
		finish("error")
		return Result{}, errors.New("gateway: result not serializable")
	}
	text := redact.String(string(raw))
	trunc := false
	if len(text) > g.cfg.MaxResultBytes {
		text, trunc = text[:g.cfg.MaxResultBytes], true
	}
	finish("ok")
	return Result{Tool: name, Content: text, Truncated: trunc, Untrusted: true}, nil
}

func safeHandle(ctx context.Context, t Tool, args json.RawMessage) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("tool panicked")
		}
	}()
	return t.Handler(ctx, args)
}

func (g *Gateway) allow(principal string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	w := g.windows[principal]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		g.windows[principal] = w
	}
	if w.n >= g.cfg.CallsPerMinute {
		return false
	}
	w.n++
	return true
}
