// Package workload is ACRA's synthetic agent workload. Generate() injects a
// drift of a chosen kind: it builds a consequential write that the REAL gate
// holds, writes a signed evidence trace, and returns the resulting ticket.
// Everything the demo shows is produced by the real gate + evidence code.
package workload

import (
	"fmt"
	"time"

	"github.com/deepnavakoti/acra/internal/detectors"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/model"
)

// Kinds are the drift classes inject-drift can trigger (one per detector).
var Kinds = []string{
	"combinative", "independence", "epoch", "authority", // core
	"effect-unknown", "unprovable", "oscillation", "schema",
	"context-loss", "duplicate-path", "stale-source", "uncertain-ops",
}

var approved = model.Tuple{Prompt: "p-30", Manifest: "1.8.3", Ruleset: "e8d3", Formula: "f-6"}

func demoPolicy() gate.Policy {
	return gate.Policy{ApprovedTuples: []model.Tuple{approved}, MinIndependentRoots: 2}
}

// Generate injects one drift. seq numbers the ticket (ACRA-32NN). The returned
// ticket is built from the gate's real verdict; the trace is really signed.
func Generate(kind string, store *evidence.Store, seq int) (model.Ticket, error) {
	traceID := fmt.Sprintf("t-32%02d", seq)
	now := time.Now().UTC()
	ts := now.Format("15:04:05")

	var w gate.Write
	var env gate.Env
	var events [][3]string // kind, actor, detail
	t := model.Ticket{
		ID:       fmt.Sprintf("ACRA-32%02d", seq),
		Agent:    "decision-agent",
		Sev:      model.SevCrit,
		Opened:   now.Format(time.RFC3339),
		State:    "hold",
		Bundle:   "sha256:9f1c…",
		ModelPin: "bedrock · pinned v1",
		Evidence: traceID,
		Attempt:  1,
		Step:     1,
	}

	switch kind {
	case "combinative":
		drifted := approved
		drifted.Formula = "f-7" // each element valid; (p-30,…,f-7) never approved
		w = gate.Write{Task: "4482", Epoch: 8, Tuple: drifted}
		t.Layer = model.LayerCompatibility
		t.Title = "decision-agent bundle runs tuple (prompt p-30, manifest 1.8.3, rules e8d3, formula f-7) not in the approved set; effects refused"
		t.Hyps = []model.Hypothesis{{Confidence: 0.94, Text: "Prompt registry advanced to p-30 after the golden run; formula f-7 from an earlier approval; the combination was never tested."}}
		t.Action = model.Action{Name: "rollback_bundle", Params: map[string]string{"agent": "decision-agent", "to": "last-approved"}, Radius: "new tasks only", Band: "pre-approved"}
		events = [][3]string{
			{"dispatch", "decision-agent/dec-7c9", "task key minted · budget 120k / 6 calls · epoch 8"},
			{"model", "decision-agent/dec-7c9", "200 · 13.9k settled · stop=end_turn"},
			{"gate", "acra-gate", "tuple 4b9e… not in approved set · effects refused"},
		}

	case "independence":
		g := evidence.NewGraph()
		g.AddNode(evidence.Node{ID: "doc-4411", Kind: evidence.Root, Provider: "doc-4411"})
		g.AddNode(evidence.Node{ID: "s-12", Kind: evidence.Derived}) // memory summary — not a root
		g.AddNode(evidence.Node{ID: "c-9f2", Kind: evidence.Derived})
		g.AddEdge("c-9f2", "s-12")
		g.AddEdge("s-12", "doc-4411")
		g.AddEdge("c-9f2", "doc-4411") // cited again, same root
		w = gate.Write{Task: "4478", Epoch: 8, Tuple: approved, Claims: []string{"c-9f2"}, Graph: g}
		t.Layer = model.LayerEvidence
		t.Title = "claim c-9f2 'verification confirmed' has one root source cited three times; one citation is the agent's own earlier summary retrieved from memory; independence = 1, required 2"
		t.Hyps = []model.Hypothesis{{Confidence: 0.90, Text: "Summary s-12 was indexed before the compaction; the agent retrieved it as an independent verification; all three hops valid on their own."}}
		t.Action = model.Action{Name: "hold_and_request_root", Params: map[string]string{"task": "4478", "claim": "c-9f2", "need": "second root source"}, Radius: "one task; no record changed", Band: "human"}
		events = [][3]string{
			{"dispatch", "decision-agent/dec-1f0", "task key minted · epoch 8"},
			{"tool", "decision-agent/dec-1f0", "lookup-record · manifest 1.8.3 ok"},
			{"agent", "decision-agent/dec-1f0", "compaction event · context 118k → 61k"},
			{"gate", "acra-gate", "claim c-9f2 roots=1 required=2 · hold"},
		}

	case "epoch":
		env = gate.Env{CurrentEpoch: func(string) int { return 8 }}
		w = gate.Write{Task: "3e44", Epoch: 7, Tuple: approved}
		t.Layer = model.LayerExecution
		t.Title = "worker published result for task 3e44 under epoch 7 after the lease moved to epoch 8; fenced at write"
		t.Hyps = []model.Hypothesis{{Confidence: 0.96, Text: "Lease transfer during rollout; the old worker resumed after a stall and published under epoch 7."}}
		t.Action = model.Action{Name: "fence_inbox_and_rerun", Params: map[string]string{"task": "3e44", "from_epoch": "8"}, Radius: "one task step", Band: "pre-approved"}
		events = [][3]string{
			{"agent", "analysis-agent/ana-2", "A2A message epoch 7 accepted after epoch 8 opened"},
			{"gate", "acra-gate", "epoch 7 vs current 8 · claims superseded · hold"},
		}

	case "authority":
		env = gate.Env{ReadAuthority: func(string) (string, bool) { return "submitted", true }}
		w = gate.Write{Task: "4a02", Epoch: 8, Tuple: approved, PromotesStatus: true, Subject: "r-18", NewStatus: "satisfied"}
		t.Layer = model.LayerContext
		t.Title = "requirement r-18 handed off as 'satisfied'; source is an AI recommendation; authoritative record still 'submitted'; promotion refused"
		t.Hyps = []model.Hypothesis{{Confidence: 0.95, Text: "Handoff summariser collapsed a 0.83 likelihood into 'satisfied'; the record never moved past 'submitted'."}}
		t.Action = model.Action{Name: "revert_status_and_type_handoff", Params: map[string]string{"task": "4a02", "to": "evaluated"}, Radius: "one task", Band: "pre-approved"}
		events = [][3]string{
			{"agent", "analysis-agent/ana-2", "status satisfied, set_by analysis-agent, no receipt"},
			{"gate", "acra-gate", "status without authority or receipt · hold"},
		}

	case "effect-unknown":
		w = gate.Write{Task: "9a40", Epoch: 8, Tuple: approved, Signals: gate.Signals{EffectState: "UNKNOWN"}}
		t.Layer = model.LayerEffect
		t.Title = "verification call timed out at the gateway and the Pod was terminated; provider completed; redelivery held, provider state unknown"
		t.Hyps = []model.Hypothesis{{Confidence: 0.90, Text: "Provider completed just past the gateway timeout; the Pod scaled in during the wait; redelivery would re-issue the intent."}}
		t.Action = model.Action{Name: "reconcile_intent", Params: map[string]string{"task": "9a40"}, Radius: "one task; read-only against provider", Band: "pre-approved"}
		events = [][3]string{{"agent", "verification-agent/ver-1", "timeout + pod terminated + redelivery"}, {"gate", "acra-gate", "effect.state=UNKNOWN · retry refused · hold"}}

	case "unprovable":
		w = gate.Write{Task: "6d18", Epoch: 8, Tuple: approved, Signals: gate.Signals{DurableEvents: 7, TraceSpans: 5}}
		t.Sev = model.SevWarn
		t.Layer = model.LayerEvidence
		t.Title = "trace shows 5 of 7 durable events; sampling under load dropped a hop; span parentage joined across the gap; held on cannot-prove"
		t.Hyps = []model.Hypothesis{{Confidence: 0.85, Text: "Head sampling under load dropped a hop; the client propagated a stale parent so the gap closed visually."}}
		t.Action = model.Action{Name: "tail_sample_consequential", Params: map[string]string{"rate": "1.0"}, Radius: "collector config only", Band: "pre-approved"}
		events = [][3]string{{"agent", "decision-agent/dec-1f0", "durable events 7, spans 5, unsupported edge"}, {"gate", "acra-gate", "verdict unknown · approve refused · hold"}}

	case "oscillation":
		w = gate.Write{Task: "loop", Epoch: 8, Tuple: approved, Signals: gate.Signals{OscillationXcorr: 0.81}}
		t.Layer = model.LayerExecution
		t.Title = "recovery loop: event-loop lag → throttle → scaler → gateway retries → provider 429 → re-dispatch; 3-cycle oscillation, bounded"
		t.Hyps = []model.Hypothesis{{Confidence: 0.88, Text: "Scaler step unbounded; retry and re-dispatch both reacted to the same throttles; the provider limit is per account, not per replica."}}
		t.Action = model.Action{Name: "bound_and_rollback", Params: map[string]string{"scaler_step": "2", "retries": "2"}, Radius: "one agent", Band: "human"}
		events = [][3]string{{"agent", "verification-agent/ver-1", "xcorr(scale,429)=0.81, cycle 3"}, {"gate", "acra-gate", "budgets exceeded · re-dispatch refused · hold"}}

	case "schema":
		w = gate.Write{Task: "3107", Epoch: 8, Tuple: approved, Signals: gate.Signals{SchemaChanged: true}}
		t.Sev = model.SevWarn
		t.Layer = model.LayerCompatibility
		t.Title = "extraction schema v2 redefined a field; the normaliser mapped it onto the v1 field; the model read a different quantity; held on schema mismatch"
		t.Hyps = []model.Hypothesis{{Confidence: 0.92, Text: "A cloud moved extraction to v2; the normaliser matches by name; the field's definition changed, not only its name."}}
		t.Action = model.Action{Name: "reextract_and_rescore", Params: map[string]string{"normaliser": "1.4.0"}, Radius: "affected tasks", Band: "pre-approved"}
		events = [][3]string{{"agent", "document-agent/doc-3", "schema v2 item under v1 normaliser · tuple miss"}, {"gate", "acra-gate", "field redefined · effects refused · hold"}}

	case "context-loss":
		w = gate.Write{Task: "2f61", Epoch: 8, Tuple: approved, Signals: gate.Signals{ClaimsExpected: 9, ClaimsPresent: 7}}
		t.Layer = model.LayerContext
		t.Title = "route switched on timeout; compressed context dropped 2 of 9 critical contract claims; recitation failed; held"
		t.Hyps = []model.Hypothesis{{Confidence: 0.90, Text: "Compression under the second model's window dropped two contract claims; the template placed the contract after the working context."}}
		t.Action = model.Action{Name: "reattach_contract_and_recite", Params: map[string]string{"task": "2f61"}, Radius: "one task", Band: "pre-approved"}
		events = [][3]string{{"agent", "decision-agent/dec-1f0", "route switch · recite 7/9"}, {"gate", "acra-gate", "critical claims missing · consequential steps refused · hold"}}

	case "duplicate-path":
		w = gate.Write{Task: "8d04", Epoch: 8, Tuple: approved, Signals: gate.Signals{DuplicateSameProvider: true}}
		t.Sev = model.SevWarn
		t.Layer = model.LayerEvidence
		t.Title = "verification reached the agent by two paths (direct + adapter) with different cache ages; treated as corroboration; collapsed to one source"
		t.Hyps = []model.Hypothesis{{Confidence: 0.88, Text: "The adapter answered from cache while the backend called the provider live; same provider id in both receipts; the model wrote 'two independent checks agree'."}}
		t.Action = model.Action{Name: "collapse_and_recheck", Params: map[string]string{"require": "distinct provider_id"}, Radius: "one task", Band: "pre-approved"}
		events = [][3]string{{"agent", "decision-agent/dec-1f0", "two rows, same provider_id, different cache age"}, {"gate", "acra-gate", "single-source · promotion refused · hold"}}

	case "stale-source":
		w = gate.Write{Task: "1c33", Epoch: 8, Tuple: approved, Signals: gate.Signals{SoleSupportStaleHours: 26}}
		t.Sev = model.SevWarn
		t.Layer = model.LayerEvidence
		t.Title = "summary rests solely on a warehouse view 26 h stale while the record and provider hold newer state; analytical sole support refused"
		t.Hyps = []model.Hypothesis{{Confidence: 0.90, Text: "The nightly warehouse load finished late; the summariser gave no priority to source role."}}
		t.Action = model.Action{Name: "rerun_with_operational_pin", Params: map[string]string{"pin": "record_system"}, Radius: "one task", Band: "pre-approved"}
		events = [][3]string{{"agent", "analysis-agent/ana-2", "sole support analytical, freshness 26 h"}, {"gate", "acra-gate", "approve refused · hold"}}

	case "uncertain-ops":
		w = gate.Write{Task: "5e09", Epoch: 8, Tuple: approved, Signals: gate.Signals{UncertainOps: 2}}
		t.Layer = model.LayerEffect
		t.Title = "worker restarted between provider accept and callback; recovery enumerated 2 uncertain operations from the graph instead of replaying the checkpoint; held"
		t.Hyps = []model.Hypothesis{{Confidence: 0.92, Text: "Restart between accept and callback; the checkpoint predates the accept; the callback hit a dead listener."}}
		t.Action = model.Action{Name: "reconcile_uncertain_ops", Params: map[string]string{"task": "5e09"}, Radius: "one task; read-only against providers", Band: "pre-approved"}
		events = [][3]string{{"agent", "verification-agent/ver-1", "restart with uncertain consequential ops"}, {"gate", "acra-gate", "replay refused · ops reconciled read-only · hold"}}

	default:
		return model.Ticket{}, fmt.Errorf("workload: unknown drift kind %q (want one of %v)", kind, Kinds)
	}

	// Run the REAL gate. If it admits, the injection is a bug — refuse to fake a ticket.
	res := gate.Evaluate(w, demoPolicy(), env, detectors.All())
	if res.Verdict != model.Hold {
		return model.Ticket{}, fmt.Errorf("workload: gate ADMITted a %q injection (expected HOLD) — logic bug", kind)
	}
	t.Detector = res.Detector
	t.Epoch = w.Epoch
	t.Magnitude = res.Magnitude
	t.Confidence = res.Confidence
	t.Radius = res.Radius

	// Write the signed evidence trace.
	for _, e := range events {
		if _, err := store.Append(model.Event{TraceID: traceID, Kind: e[0], Actor: e[1], Detail: e[2]}); err != nil {
			return model.Ticket{}, err
		}
	}

	t.History = [][3]string{
		{ts, "detect", events[len(events)-1][2]},
		{ts, "hold", "task parked; no write"},
	}
	return t, nil
}
