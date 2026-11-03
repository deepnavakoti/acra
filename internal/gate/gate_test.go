package gate_test

import (
	"testing"

	"github.com/deepnavakoti/acra/internal/detectors"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

type panicker struct{}

func (panicker) ID() string { return "test.panic" }
func (panicker) Check(gate.Write, gate.Policy, gate.Env) model.GateResult {
	panic("boom")
}

type admitter struct{}

func (admitter) ID() string { return "test.admit" }
func (admitter) Check(gate.Write, gate.Policy, gate.Env) model.GateResult {
	return model.GateResult{Verdict: model.Admit}
}

func TestEvaluate_NoDetectorsHolds(t *testing.T) {
	r := gate.Evaluate(gate.Write{}, gate.Policy{}, gate.Env{}, nil)
	if r.Verdict != model.Hold {
		t.Fatalf("empty detector set must HOLD, got %v", r.Verdict)
	}
}

func TestEvaluate_NilDetectorHolds(t *testing.T) {
	r := gate.Evaluate(gate.Write{}, gate.Policy{}, gate.Env{}, []gate.Detector{nil})
	if r.Verdict != model.Hold {
		t.Fatalf("nil detector must HOLD, got %v", r.Verdict)
	}
}

func TestEvaluate_PanicHolds(t *testing.T) {
	r := gate.Evaluate(gate.Write{}, gate.Policy{}, gate.Env{}, []gate.Detector{panicker{}, admitter{}})
	if r.Verdict != model.Hold {
		t.Fatalf("a panicking detector must HOLD, got %v", r.Verdict)
	}
}

func TestEvaluate_AdmitsWhenAllAdmit(t *testing.T) {
	r := gate.Evaluate(gate.Write{}, gate.Policy{}, gate.Env{}, []gate.Detector{admitter{}})
	if r.Verdict != model.Admit {
		t.Fatalf("expected ADMIT, got %v (%s)", r.Verdict, r.Reason)
	}
}

type fakeGraph struct{ n int }

func (f fakeGraph) Independence(string) int { return f.n }

// C2 must not admit a claim-bearing write when no lineage graph is supplied.
func TestC2_NilGraphWithClaimsHolds(t *testing.T) {
	w := gate.Write{Task: "t", Claims: []string{"c1"}}
	p := gate.Policy{MinIndependentRoots: 2}
	r := gate.Evaluate(w, p, gate.Env{}, []gate.Detector{detectors.C2{}})
	if r.Verdict != model.Hold {
		t.Fatalf("claims with unknown independence must HOLD, got %v", r.Verdict)
	}
	w.Graph = fakeGraph{n: 2}
	r = gate.Evaluate(w, p, gate.Env{}, []gate.Detector{detectors.C2{}})
	if r.Verdict != model.Admit {
		t.Fatalf("2 independent roots should ADMIT, got %v (%s)", r.Verdict, r.Reason)
	}
}
