package detectors

import (
	"testing"

	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

var approved = model.Tuple{Prompt: "p-30", Manifest: "1.8.3", Ruleset: "e8d3", Formula: "f-6"}

func policy() gate.Policy {
	return gate.Policy{ApprovedTuples: []model.Tuple{approved}, MinIndependentRoots: 2}
}

// c4: the approved tuple admits; a new combination (each part otherwise valid) holds.
func TestC4_Combinative(t *testing.T) {
	if r := (C4{}).Check(gate.Write{Tuple: approved}, policy(), gate.Env{}); r.Verdict != model.Admit {
		t.Fatalf("approved tuple: got %s, want ADMIT", r.Verdict)
	}
	drifted := approved
	drifted.Formula = "f-7" // f-7 may be valid elsewhere; (p-30,…,f-7) never approved
	r := (C4{}).Check(gate.Write{Tuple: drifted}, policy(), gate.Env{})
	if r.Verdict != model.Hold || r.Detector != "acra.c4" {
		t.Fatalf("combinative drift: got %s/%s, want HOLD/acra.c4", r.Verdict, r.Detector)
	}
}

// c2: one root cited three times -> independence 1 < required 2 -> HOLD.
func TestC2_Independence(t *testing.T) {
	g := evidence.NewGraph()
	g.AddNode(evidence.Node{ID: "doc-4411", Kind: evidence.Root, Provider: "doc-4411"})
	g.AddNode(evidence.Node{ID: "s-12", Kind: evidence.Derived})
	g.AddNode(evidence.Node{ID: "c-9f2", Kind: evidence.Derived})
	g.AddEdge("c-9f2", "s-12")
	g.AddEdge("s-12", "doc-4411")
	g.AddEdge("c-9f2", "doc-4411")

	w := gate.Write{Claims: []string{"c-9f2"}, Graph: g}
	if r := (C2{}).Check(w, policy(), gate.Env{}); r.Verdict != model.Hold || r.Detector != "acra.c2" {
		t.Fatalf("independence: got %s/%s, want HOLD/acra.c2", r.Verdict, r.Detector)
	}

	// add a second distinct root -> admit
	g.AddNode(evidence.Node{ID: "receipt-B", Kind: evidence.Root, Provider: "provider-B"})
	g.AddEdge("c-9f2", "receipt-B")
	if r := (C2{}).Check(w, policy(), gate.Env{}); r.Verdict != model.Admit {
		t.Fatalf("two roots: got %s, want ADMIT", r.Verdict)
	}
}

// c3: a stale epoch is fenced.
func TestC3_Epoch(t *testing.T) {
	env := gate.Env{CurrentEpoch: func(string) int { return 8 }}
	if r := (C3{}).Check(gate.Write{Task: "t", Epoch: 7}, policy(), env); r.Verdict != model.Hold {
		t.Fatalf("stale epoch: got %s, want HOLD", r.Verdict)
	}
	if r := (C3{}).Check(gate.Write{Task: "t", Epoch: 8}, policy(), env); r.Verdict != model.Admit {
		t.Fatalf("current epoch: got %s, want ADMIT", r.Verdict)
	}
}

// m3: status promotion without supporting authority holds; with it, admits; no
// authority reader at all -> unknown -> HOLD (invariant 7).
func TestM3_Authority(t *testing.T) {
	w := gate.Write{PromotesStatus: true, Subject: "r-18", NewStatus: "satisfied"}

	no := gate.Env{ReadAuthority: func(string) (string, bool) { return "submitted", true }}
	if r := (M3{}).Check(w, policy(), no); r.Verdict != model.Hold {
		t.Fatalf("authority mismatch: got %s, want HOLD", r.Verdict)
	}
	yes := gate.Env{ReadAuthority: func(string) (string, bool) { return "satisfied", true }}
	if r := (M3{}).Check(w, policy(), yes); r.Verdict != model.Admit {
		t.Fatalf("authority supports: got %s, want ADMIT", r.Verdict)
	}
	if r := (M3{}).Check(w, policy(), gate.Env{}); r.Verdict != model.Hold {
		t.Fatalf("no authority reader: got %s, want HOLD (unknown)", r.Verdict)
	}
}

// A fully clean write passes every detector.
func TestEvaluate_AllAdmit(t *testing.T) {
	g := evidence.NewGraph()
	g.AddNode(evidence.Node{ID: "a", Kind: evidence.Root, Provider: "a"})
	g.AddNode(evidence.Node{ID: "b", Kind: evidence.Root, Provider: "b"})
	g.AddNode(evidence.Node{ID: "c", Kind: evidence.Derived})
	g.AddEdge("c", "a")
	g.AddEdge("c", "b")

	w := gate.Write{Task: "t", Epoch: 8, Tuple: approved, Claims: []string{"c"}, Graph: g}
	env := gate.Env{CurrentEpoch: func(string) int { return 8 }}
	if r := gate.Evaluate(w, policy(), env, Default()); r.Verdict != model.Admit {
		t.Fatalf("clean write: got %s (%s), want ADMIT", r.Verdict, r.Reason)
	}
}
