package detectors

import (
	"testing"

	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

func TestExtraDetectors(t *testing.T) {
	var p gate.Policy
	cases := []struct {
		name string
		d    gate.Detector
		w    gate.Write
	}{
		{"c1", C1{}, gate.Write{Signals: gate.Signals{EffectState: "UNKNOWN"}}},
		{"c5", C5{}, gate.Write{Signals: gate.Signals{DurableEvents: 7, TraceSpans: 5}}},
		{"c6", C6{}, gate.Write{Signals: gate.Signals{OscillationXcorr: 0.81}}},
		{"m1", M1{}, gate.Write{Signals: gate.Signals{SchemaChanged: true}}},
		{"m2", M2{}, gate.Write{Signals: gate.Signals{ClaimsExpected: 9, ClaimsPresent: 7}}},
		{"m4", M4{}, gate.Write{Signals: gate.Signals{DuplicateSameProvider: true}}},
		{"m5", M5{}, gate.Write{Signals: gate.Signals{SoleSupportStaleHours: 26}}},
		{"m6", M6{}, gate.Write{Signals: gate.Signals{UncertainOps: 2}}},
	}
	for _, c := range cases {
		if r := c.d.Check(c.w, p, gate.Env{}); r.Verdict != model.Hold {
			t.Errorf("%s: want HOLD, got %s", c.name, r.Verdict)
		}
		if r := c.d.Check(gate.Write{}, p, gate.Env{}); r.Verdict != model.Admit {
			t.Errorf("%s: clean write should ADMIT, got %s", c.name, r.Verdict)
		}
	}
}

func TestAll_HasTwelve(t *testing.T) {
	if n := len(All()); n != 12 {
		t.Fatalf("All() = %d detectors, want 12", n)
	}
}
