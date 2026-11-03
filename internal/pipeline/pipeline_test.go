package pipeline

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepnavakoti/acra/internal/agentrun"
	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/incident"
)

func newSvc(t *testing.T) (*Service, *incident.Store) {
	t.Helper()
	inc, err := incident.Open(filepath.Join(t.TempDir(), "inc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inc.Close() })
	reg := contract.NewRegistry()
	c := &contract.Contract{
		ID: "c1", AgentID: "planner", Version: "v1",
		OutputSchema: &contract.Schema{Type: "object", Required: []string{"answer"}},
	}
	if err := reg.Put(c); err != nil {
		t.Fatal(err)
	}
	return New(Config{}, reg, inc), inc
}

func run(trace string, output string) []agentrun.Event {
	t0 := time.Now().Add(-time.Minute)
	return []agentrun.Event{
		{TraceID: trace, SpanID: "a", AgentID: "planner", Kind: agentrun.KindRequest, Start: t0, End: t0.Add(time.Second)},
		{TraceID: trace, SpanID: "b", AgentID: "planner", Kind: agentrun.KindResponse, Start: t0.Add(time.Second), End: t0.Add(2 * time.Second),
			Output: json.RawMessage(output)},
	}
}

func TestViolationOpensIncident(t *testing.T) {
	s, inc := newSvc(t)
	acc, errs := s.Ingest(run("t1", `{"nope":1}`))
	if acc != 2 || len(errs) != 0 {
		t.Fatalf("accepted=%d errs=%v", acc, errs)
	}
	list, err := inc.List("")
	if err != nil || len(list) != 1 {
		t.Fatalf("want one incident, got %d (err=%v)", len(list), err)
	}
	if list[0].AgentID != "planner" || list[0].Status != incident.StatusOpen {
		t.Errorf("unexpected incident %+v", list[0])
	}
	if _, ok := s.Run("t1"); !ok {
		t.Error("completed run must be cached for investigation")
	}
}

func TestPassingRunOpensNothing(t *testing.T) {
	s, inc := newSvc(t)
	s.Ingest(run("t2", `{"answer":"ok"}`))
	if list, _ := inc.List(""); len(list) != 0 {
		t.Fatalf("a passing run must not open an incident: %+v", list)
	}
}

func TestSameFailureDeduplicates(t *testing.T) {
	s, inc := newSvc(t)
	s.Ingest(run("t3", `{"nope":1}`))
	s.Ingest(run("t4", `{"nope":2}`))
	list, _ := inc.List("")
	if len(list) != 1 || list[0].Count != 2 {
		t.Fatalf("repeat failures must fold into one incident with count 2: %+v", list)
	}
}

func TestNoContractIsCountedNotPassed(t *testing.T) {
	s, inc := newSvc(t)
	evs := run("t5", `{"nope":1}`)
	for i := range evs {
		evs[i].AgentID = "stranger"
	}
	s.Ingest(evs)
	if s.NoContract.Load() != 1 {
		t.Errorf("run without a contract must be counted, got %d", s.NoContract.Load())
	}
	if list, _ := inc.List(""); len(list) != 0 {
		t.Error("no contract means no claim, so no incident")
	}
}

func TestInvestigateWithoutEngine(t *testing.T) {
	s, _ := newSvc(t)
	if _, err := s.Investigate(t.Context(), "x"); err == nil {
		t.Fatal("investigating without an engine must fail loudly")
	}
}
