package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/identity"
)

type memAudit struct {
	mu  sync.Mutex
	rec []AuditRecord
}

func (m *memAudit) Record(r AuditRecord) { m.mu.Lock(); m.rec = append(m.rec, r); m.mu.Unlock() }
func (m *memAudit) last() AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rec[len(m.rec)-1]
}

var (
	reader = identity.Principal{ID: "viewer", Roles: []string{identity.RoleReader}}
	ingest = identity.Principal{ID: "ing", Roles: []string{identity.RoleIngest}}
)

func echoTool(h func(context.Context, json.RawMessage) (any, error)) Tool {
	no := false
	one := 1
	return Tool{
		Name: "echo", Description: "echo", Role: identity.RoleReader,
		Args: &contract.Schema{Type: "object", Required: []string{"id"}, AdditionalProperties: &no,
			Properties: map[string]*contract.Schema{"id": {Type: "string", MinLength: &one}}},
		Handler: h,
	}
}

func newGW(t *testing.T, cfg Config, h func(context.Context, json.RawMessage) (any, error)) (*Gateway, *memAudit) {
	t.Helper()
	a := &memAudit{}
	g := New(cfg, a)
	if err := g.Register(echoTool(h)); err != nil {
		t.Fatal(err)
	}
	return g, a
}

func ok(context.Context, json.RawMessage) (any, error) { return map[string]string{"v": "fine"}, nil }

func TestDefaultDeny(t *testing.T) {
	g, a := newGW(t, Config{}, ok)
	if _, err := g.Call(context.Background(), reader, "nope", nil); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("unknown tool: %v", err)
	}
	if _, err := g.Call(context.Background(), ingest, "echo", json.RawMessage(`{"id":"x"}`)); !errors.Is(err, ErrDenied) {
		t.Errorf("wrong role: %v", err)
	}
	if a.last().Outcome != "denied" {
		t.Errorf("denial must be audited, got %q", a.last().Outcome)
	}
	if err := g.Register(Tool{Name: "bad"}); err == nil {
		t.Error("tool without role/handler must be refused")
	}
	if got := g.List(ingest); len(got) != 0 {
		t.Errorf("principal must only see tools it may call: %v", got)
	}
}

func TestArgumentValidation(t *testing.T) {
	g, _ := newGW(t, Config{MaxArgsBytes: 64}, ok)
	for _, args := range []string{`{}`, `{"id":""}`, `{"id":"x","extra":1}`, `not json`} {
		if _, err := g.Call(context.Background(), reader, "echo", json.RawMessage(args)); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("args %s: want ErrInvalidArgs, got %v", args, err)
		}
	}
	big := json.RawMessage(`{"id":"` + strings.Repeat("a", 100) + `"}`)
	if _, err := g.Call(context.Background(), reader, "echo", big); !errors.Is(err, ErrInvalidArgs) {
		t.Errorf("oversized args: %v", err)
	}
	if _, err := g.Call(context.Background(), reader, "echo", json.RawMessage(`{"id":"x"}`)); err != nil {
		t.Errorf("valid call failed: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	g, a := newGW(t, Config{CallsPerMinute: 2}, ok)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	args := json.RawMessage(`{"id":"x"}`)
	for i := 0; i < 2; i++ {
		if _, err := g.Call(context.Background(), reader, "echo", args); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := g.Call(context.Background(), reader, "echo", args); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third call must be limited: %v", err)
	}
	if a.last().Outcome != "rate_limited" {
		t.Errorf("audit outcome %q", a.last().Outcome)
	}
	now = now.Add(61 * time.Second)
	if _, err := g.Call(context.Background(), reader, "echo", args); err != nil {
		t.Errorf("window must reset: %v", err)
	}
}

func TestResultRedactedTruncatedUntrusted(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	g, _ := newGW(t, Config{MaxResultBytes: 50}, func(context.Context, json.RawMessage) (any, error) {
		return map[string]string{"k": secret, "pad": strings.Repeat("z", 200)}, nil
	})
	res, err := g.Call(context.Background(), reader, "echo", json.RawMessage(`{"id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Content, secret) {
		t.Error("result must be redacted")
	}
	if !res.Truncated || len(res.Content) > 50 {
		t.Errorf("result must be truncated to the limit (len=%d truncated=%v)", len(res.Content), res.Truncated)
	}
	if !res.Untrusted {
		t.Error("tool output must be marked untrusted")
	}
}

func TestPanicAndErrorAreContained(t *testing.T) {
	g, a := newGW(t, Config{}, func(context.Context, json.RawMessage) (any, error) { panic("x") })
	if _, err := g.Call(context.Background(), reader, "echo", json.RawMessage(`{"id":"x"}`)); err == nil {
		t.Fatal("panic must surface as an error")
	}
	if a.last().Outcome != "error" {
		t.Errorf("outcome %q", a.last().Outcome)
	}
}

func TestAuditDoesNotStoreArguments(t *testing.T) {
	g, a := newGW(t, Config{}, ok)
	_, _ = g.Call(context.Background(), reader, "echo", json.RawMessage(`{"id":"super-secret-value"}`))
	r := a.last()
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "super-secret-value") || r.ArgsHash == "" {
		t.Errorf("audit must hold a hash, not arguments: %s", raw)
	}
}
