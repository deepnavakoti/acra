// Package gate is ACRA's deterministic admission core: for each consequential
// write it runs the invariant checks (via detectors) and returns ADMIT or HOLD.
// The gate CHECKS; it never decides an outcome, signs, or edits a record
// (invariant 5 — docs/03-core-specs.md §0).
package gate

import "github.com/deepnavakoti/acra/internal/model"

// Independencer computes evidence independence for a claim. *evidence.Graph
// satisfies it — the gate depends on the behavior, not the package.
type Independencer interface {
	Independence(claim string) int
}

// Write is one consequential write presented to the gate.
type Write struct {
	Task           string        // task id (for epoch lookup)
	Epoch          int           // epoch this write was produced under
	Tuple          model.Tuple   // (prompt, manifest, ruleset, formula)
	Claims         []string      // claims that support this write
	Graph          Independencer // lineage graph for independence (may be nil)
	PromotesStatus bool          // does this write promote a record status?
	Subject        string        // the record subject (for authority check)
	NewStatus      string        // the status it would promote to
	Signals        Signals       // optional signals for the broader detector set
}

// Signals carry the extra, optional evidence the non-core detectors key off.
// A zero value means "that signal is not present".
type Signals struct {
	EffectState           string  // "UNKNOWN" → effect state cannot be proven (c1)
	TraceSpans            int     // spans actually present
	DurableEvents         int     // durable events expected; > TraceSpans ⇒ unprovable (c5)
	OscillationXcorr      float64 // cross-correlation of scale vs throttles (c6)
	SchemaChanged         bool    // a field was redefined across schema versions (m1)
	ClaimsExpected        int     // critical contract claims expected (m2)
	ClaimsPresent         int     // claims still present after compression/route switch (m2)
	SoleSupportStaleHours int     // sole analytical support, staleness in hours (m5)
	UncertainOps          int     // uncertain consequential ops after a restart (m6)
	DuplicateSameProvider bool    // two evidence paths, one provider, treated as independent (m4)
}

// Policy is the governing AgentPolicy, flattened to what the gate needs.
type Policy struct {
	ApprovedTuples      []model.Tuple
	Invariants          []string
	MinIndependentRoots int
	DriftMagnitude      int
}

// Env provides the live reads the gate needs. Injected so checks stay
// deterministic and testable. A nil hook means "that signal is unavailable".
type Env struct {
	CurrentEpoch  func(task string) int                         // current lease epoch
	ReadAuthority func(subject string) (status string, ok bool) // authoritative record, read at now
}

// Detector is one invariant check. First HOLD wins.
type Detector interface {
	ID() string
	Check(w Write, p Policy, env Env) model.GateResult
}

// Evaluate runs the detectors in order and returns the first HOLD, else ADMIT.
// Unknown is never admitted (invariant 7) — detectors return HOLD when they
// cannot prove safety.
func Evaluate(w Write, p Policy, env Env, dets []Detector) model.GateResult {
	for _, d := range dets {
		if r := d.Check(w, p, env); r.Verdict == model.Hold {
			return r
		}
	}
	return model.GateResult{Verdict: model.Admit}
}
