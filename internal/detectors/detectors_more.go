package detectors

import (
	"fmt"

	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

// The remaining detector classes (docs/03-core-specs.md §8). Each is a plug-in
// on the same gate; none change the gate loop. They key off gate.Write.Signals.

// All returns the full v0.1 detector set: the core 4 plus these 8.
func All() []gate.Detector {
	return []gate.Detector{
		C4{}, C3{}, M3{}, C2{}, // core
		C1{}, C5{}, C6{}, M1{}, M2{}, M4{}, M5{}, M6{},
	}
}

// C1 — effect state unknown (inv7). A consequential op whose effect cannot be
// proven (e.g. provider timeout) is held, never optimistically retried.
type C1 struct{}

func (C1) ID() string { return "acra.c1" }
func (C1) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.EffectState == "UNKNOWN" {
		return hold("acra.c1", "effect state unknown",
			"1 consequential op, state UNKNOWN", 0.98, "task held before retry; 0 duplicate effects")
	}
	return admit()
}

// C5 — unprovable trace (inv7). Durable events without matching spans mean the
// chain cannot be proven; the verdict is unknown → hold.
type C5 struct{}

func (C5) ID() string { return "acra.c5" }
func (C5) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.DurableEvents > 0 && w.Signals.TraceSpans < w.Signals.DurableEvents {
		return hold("acra.c5", "cannot prove",
			fmt.Sprintf("spans %d of %d durable events", w.Signals.TraceSpans, w.Signals.DurableEvents),
			0.93, "task held; trace re-checked")
	}
	return admit()
}

// C6 — control-loop oscillation. High cross-correlation of scaling vs throttles
// across cycles signals a runaway loop; bound and roll back.
type C6 struct{}

func (C6) ID() string { return "acra.c6" }
func (C6) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.OscillationXcorr >= 0.8 {
		return hold("acra.c6", "control-loop oscillation",
			fmt.Sprintf("xcorr %.2f over cycles", w.Signals.OscillationXcorr),
			0.90, "re-dispatches refused; retries capped")
	}
	return admit()
}

// M1 — schema/field redefinition. A field redefined across schema versions means
// the model read a different quantity; refuse until re-extracted.
type M1 struct{}

func (M1) ID() string { return "acra.m1" }
func (M1) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.SchemaChanged {
		return hold("acra.m1", "schema redefinition",
			"1 field redefined across schema versions", 0.97, "tasks re-extracted; effects refused")
	}
	return admit()
}

// M2 — context-compression claim loss. If compression/route-switch dropped
// contract claims, consequential steps are refused until recited.
type M2 struct{}

func (M2) ID() string { return "acra.m2" }
func (M2) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.ClaimsExpected > 0 && w.Signals.ClaimsPresent < w.Signals.ClaimsExpected {
		return hold("acra.m2", "context claim loss",
			fmt.Sprintf("critical claims %d of %d after switch", w.Signals.ClaimsPresent, w.Signals.ClaimsExpected),
			0.96, "task held; consequential steps refused")
	}
	return admit()
}

// M4 — duplicate-path corroboration. Two evidence paths from the SAME provider
// treated as independent collapse to one source (independence dedup).
type M4 struct{}

func (M4) ID() string { return "acra.m4" }
func (M4) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.DuplicateSameProvider {
		return hold("acra.m4", "duplicate-path corroboration",
			"2 paths, 1 provider — not independent", 0.97, "claim single-source; promotion refused")
	}
	return admit()
}

// M5 — stale analytical sole support. A claim resting solely on a stale
// analytical/warehouse view is refused in favour of the operational source.
type M5 struct{}

func (M5) ID() string { return "acra.m5" }
func (M5) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.SoleSupportStaleHours > 0 {
		return hold("acra.m5", "stale analytical source",
			fmt.Sprintf("sole support analytical, %d h stale", w.Signals.SoleSupportStaleHours),
			0.95, "task re-run against the operational source")
	}
	return admit()
}

// M6 — uncertain ops after restart (inv7). Recovery that enumerated uncertain
// consequential ops (rather than replaying a checkpoint) is held for reconcile.
type M6 struct{}

func (M6) ID() string { return "acra.m6" }
func (M6) Check(w gate.Write, _ gate.Policy, _ gate.Env) model.GateResult {
	if w.Signals.UncertainOps > 0 {
		return hold("acra.m6", "uncertain ops after restart",
			fmt.Sprintf("%d uncertain consequential ops", w.Signals.UncertainOps),
			0.98, "task held; ops reconciled read-only")
	}
	return admit()
}
