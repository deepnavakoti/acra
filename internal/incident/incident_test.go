package incident

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/deepnavakoti/acra/internal/contract"
)

var t0 = time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	s, err := Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func fail(trace string, at time.Time, rules ...string) contract.Evaluation {
	e := contract.Evaluation{AgentID: "a", TraceID: trace, Version: "1", Status: contract.StatusFail, EvaluatedAt: at}
	for _, r := range rules {
		e.Violations = append(e.Violations, contract.Violation{Rule: r, Status: "violated", Severity: "high", Message: "m " + r})
	}
	return e
}

func TestPassOpensNothing(t *testing.T) {
	s := open(t)
	inc, _, err := s.RecordEvaluation(contract.Evaluation{AgentID: "a", TraceID: "t", Status: contract.StatusPass, EvaluatedAt: t0})
	if err != nil || inc != nil {
		t.Fatalf("%v %v", inc, err)
	}
}

func TestDedup(t *testing.T) {
	s := open(t)
	a, created, _ := s.RecordEvaluation(fail("t1", t0, "output.schema"))
	b, created2, _ := s.RecordEvaluation(fail("t2", t0.Add(time.Minute), "output.schema"))
	if !created || created2 || a.ID != b.ID || b.Count != 2 || len(b.TraceIDs) != 2 {
		t.Fatalf("%+v %+v", a, b)
	}
	c, created3, _ := s.RecordEvaluation(fail("t3", t0, "limit.latency"))
	if !created3 || c.ID == a.ID {
		t.Fatal("different rules must be a different incident")
	}
}

func TestTraceIDsBounded(t *testing.T) {
	s := open(t)
	var last *Incident
	for i := 0; i < 40; i++ {
		last, _, _ = s.RecordEvaluation(fail(string(rune('a'+i%26))+string(rune('A'+i/26)), t0.Add(time.Duration(i)*time.Second), "r"))
	}
	if len(last.TraceIDs) > maxTraces || last.Count != 40 {
		t.Fatalf("%d traces, count %d", len(last.TraceIDs), last.Count)
	}
}

func TestResolveAndRegress(t *testing.T) {
	s := open(t)
	a, _, _ := s.RecordEvaluation(fail("t1", t0, "r"))
	if err := s.SetStatus(a.ID, StatusResolved); err != nil {
		t.Fatal(err)
	}
	b, created, _ := s.RecordEvaluation(fail("t2", t0.Add(time.Hour), "r"))
	if !created || b.ID == a.ID {
		t.Fatalf("a resolved incident must not absorb new failures silently: %+v", b)
	}
}

func TestUnknownOnlyFlagged(t *testing.T) {
	s := open(t)
	e := contract.Evaluation{AgentID: "a", TraceID: "t", Status: contract.StatusUnknown, EvaluatedAt: t0,
		Violations: []contract.Violation{{Rule: "run.complete", Status: "unknown", Severity: "medium", Message: "no response"}}}
	inc, _, _ := s.RecordEvaluation(e)
	if inc == nil || !inc.Unknown {
		t.Fatalf("%+v", inc)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "i.db")
	s, _ := Open(p)
	a, _, _ := s.RecordEvaluation(fail("t1", t0, "r"))
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Get(a.ID)
	if err != nil || got.Count != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	b, created, _ := s2.RecordEvaluation(fail("t2", t0, "r"))
	if created || b.ID != a.ID {
		t.Fatal("dedup index must survive restart")
	}
	if _, err := s2.Get("INC-99999"); err != ErrNotFound {
		t.Fatalf("%v", err)
	}
}

func TestListAndEvaluations(t *testing.T) {
	s := open(t)
	s.RecordEvaluation(fail("t1", t0, "x"))
	s.RecordEvaluation(fail("t2", t0.Add(time.Minute), "y"))
	l, _ := s.List(StatusOpen)
	if len(l) != 2 || !l[0].LastSeen.After(l[1].LastSeen) {
		t.Fatalf("%+v", l)
	}
	ev, _ := s.Evaluations("a", 1)
	if len(ev) != 1 || ev[0].TraceID != "t2" {
		t.Fatalf("%+v", ev)
	}
}

func TestInvalidStatus(t *testing.T) {
	s := open(t)
	a, _, _ := s.RecordEvaluation(fail("t1", t0, "r"))
	if err := s.SetStatus(a.ID, "weird"); err == nil {
		t.Fatal("invalid status accepted")
	}
}
