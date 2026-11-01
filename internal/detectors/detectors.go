// Package detectors holds ACRA's v1 detector plug-ins: c2 (independence),
// c3 (epoch fence), c4 (combinative tuple), m3 (authority). Each implements
// gate.Detector and maps to an algorithm in docs/03-core-specs.md.
// Adding a drift class = adding a detector here; the gate loop is unchanged.
package detectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

// Default returns the v1 detector set, ordered cheapest/hardest-fail first.
func Default() []gate.Detector {
	return []gate.Detector{C4{}, C3{}, M3{}, C2{}}
}

func admit() model.GateResult { return model.GateResult{Verdict: model.Admit} }

func hold(detector, reason, magnitude string, confidence float64, radius string) model.GateResult {
	return model.GateResult{
		Verdict: model.Hold, Detector: detector, Reason: reason,
		Magnitude: magnitude, Confidence: confidence, Radius: radius,
	}
}

// C4 — combinative drift (§1). Each element may be individually valid, yet the
// tuple as a whole was never approved → effects refused (drafts allowed).
type C4 struct{}

func (C4) ID() string { return "acra.c4" }
func (C4) Check(w gate.Write, p gate.Policy, _ gate.Env) model.GateResult {
	for _, t := range p.ApprovedTuples {
		if t == w.Tuple {
			return admit()
		}
	}
	return hold("acra.c4", "combinative — tuple never approved",
		"tuple "+tupleHash(w.Tuple)+" unapproved", 1.0, "effects refused; drafts allowed")
}

// C2 — evidence independence (§2). A claim whose distinct-root count is below
// the floor is held. Derived artifacts never count as roots.
type C2 struct{}

func (C2) ID() string { return "acra.c2" }
func (C2) Check(w gate.Write, p gate.Policy, _ gate.Env) model.GateResult {
	if w.Graph == nil || p.MinIndependentRoots <= 0 {
		return admit()
	}
	for _, c := range w.Claims {
		if n := w.Graph.Independence(c); n < p.MinIndependentRoots {
			return hold("acra.c2", "independence",
				fmt.Sprintf("independent sources %d vs required %d", n, p.MinIndependentRoots),
				0.99, "task held at the gate; 0 writes")
		}
	}
	return admit()
}

// C3 — epoch fence (§4). A write published under a superseded lease epoch is
// not trusted; its derived claims are superseded.
type C3 struct{}

func (C3) ID() string { return "acra.c3" }
func (C3) Check(w gate.Write, _ gate.Policy, env gate.Env) model.GateResult {
	if env.CurrentEpoch == nil {
		return admit()
	}
	if cur := env.CurrentEpoch(w.Task); w.Epoch < cur {
		return hold("acra.c3", "epoch fence",
			fmt.Sprintf("epoch %d vs current %d", w.Epoch, cur), 1.0,
			"downstream claims superseded; 0 writes")
	}
	return admit()
}

// M3 — authority read against now (§5). A status may be promoted only if the
// authoritative record, read at decision time, supports it. If authority can't
// be read, the result is unknown → HOLD (invariant 7).
type M3 struct{}

func (M3) ID() string { return "acra.m3" }
func (M3) Check(w gate.Write, _ gate.Policy, env gate.Env) model.GateResult {
	if !w.PromotesStatus {
		return admit()
	}
	if env.ReadAuthority == nil {
		return hold("acra.m3", "authority unknown",
			"status promotion with no authority read", 1.0, "task held; unknown stays unknown")
	}
	if status, ok := env.ReadAuthority(w.Subject); !ok || status != w.NewStatus {
		return hold("acra.m3", "authority",
			"status without authority or receipt", 1.0, "task reverted; 0 effects")
	}
	return admit()
}

func tupleHash(t model.Tuple) string {
	sum := sha256.Sum256([]byte(t.Prompt + "|" + t.Manifest + "|" + t.Ruleset + "|" + t.Formula))
	return hex.EncodeToString(sum[:])[:8]
}
