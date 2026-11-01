package evidence

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/deepnavakoti/acra/internal/model"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(t.TempDir(), "evidence.db"), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A signed chain round-trips and verifies, mirroring the t-3102 trace.
func TestStore_AppendVerify(t *testing.T) {
	s := newStore(t)
	steps := []model.Event{
		{TraceID: "t-3102", Kind: "dispatch", Actor: "decision-agent/dec-1f0", Detail: "task key minted"},
		{TraceID: "t-3102", Kind: "tool", Actor: "decision-agent/dec-1f0", Detail: "lookup-record ok"},
		{TraceID: "t-3102", Kind: "gate", Actor: "acra-gate", Detail: "claim c-9f2 roots=1 required=2 · hold"},
	}
	for _, ev := range steps {
		if _, err := s.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	tr, err := s.Trace("t-3102")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if len(tr.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(tr.Events))
	}
	if tr.Chain != "intact" {
		t.Fatalf("chain = %q, want intact", tr.Chain)
	}
	if tr.Events[0].Seq != 1 || tr.Events[2].Seq != 3 {
		t.Fatalf("bad seq assignment: %v", []int{tr.Events[0].Seq, tr.Events[2].Seq})
	}
	if ok, err := s.Verify("t-3102"); !ok || err != nil {
		t.Fatalf("verify = %v, %v; want true, nil", ok, err)
	}
}

// Tampering with a stored event breaks verification.
func TestStore_TamperDetected(t *testing.T) {
	s := newStore(t)
	for _, d := range []string{"a", "b", "c"} {
		if _, err := s.Append(model.Event{TraceID: "t-1", Kind: "model", Actor: "x", Detail: d}); err != nil {
			t.Fatal(err)
		}
	}
	tr, _ := s.Trace("t-1")
	tr.Events[1].Detail = "tampered" // flip a signed field
	if ok, _ := s.verify(tr.Events); ok {
		t.Fatal("verify passed on a tampered chain; want fail")
	}
}
