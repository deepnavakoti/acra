package rca

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepnavakoti/acra/internal/adapters"
	"github.com/deepnavakoti/acra/internal/agentrun"
	"github.com/deepnavakoti/acra/internal/contract"
)

var t0 = time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC)

type fixedAdapter struct {
	name string
	res  adapters.Result
	err  error
}

func (f fixedAdapter) Name() string { return f.name }
func (f fixedAdapter) Fetch(context.Context, adapters.Query) (adapters.Result, error) {
	return f.res, f.err
}

func run(events ...agentrun.Event) agentrun.Run {
	return agentrun.Run{TraceID: "t", AgentID: "a", Complete: true, Events: events}
}

func ev429() agentrun.Event {
	return agentrun.Event{Kind: agentrun.KindModel, SpanID: "m1", HTTPStatus: 429, Start: t0, End: t0.Add(time.Second)}
}

func TestInvestigate_RateLimitFromSpan(t *testing.T) {
	rep := (&Engine{}).Investigate(context.Background(), Input{IncidentID: "I", Run: run(ev429())})
	if rep.Hypotheses[0].Cause != RateLimit || rep.Hypotheses[0].Confidence < 0.8 || rep.State != "done" {
		t.Fatalf("%+v", rep)
	}
	if !contains(rep.Unknowns, "no evidence sources") {
		t.Fatalf("missing sources must be stated: %v", rep.Unknowns)
	}
}

func contains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestInvestigate_OOMFromPodState_BeatsLogText(t *testing.T) {
	ad := fixedAdapter{name: "k8s", res: adapters.Result{Source: "k8s", Signals: []adapters.Signal{
		{Source: "k8s", Kind: "state", Time: t0, Resource: "p1", Ref: "uid1", Attrs: map[string]string{"reason": "OOMKilled"}},
		{Source: "k8s", Kind: "log", Time: t0, Resource: "p1", Message: "out of memory"},
	}}}
	rep := (&Engine{}).Investigate(context.Background(), Input{Run: run(agentrun.Event{Kind: agentrun.KindRequest, Start: t0, End: t0}), Adapters: []adapters.Adapter{ad}})
	if rep.Hypotheses[0].Cause != ResourceExhaust || rep.Hypotheses[0].Confidence < 0.9 {
		t.Fatalf("%+v", rep.Hypotheses)
	}
}

func TestInvestigate_LogTextOnlyIsLowerConfidence(t *testing.T) {
	ad := fixedAdapter{name: "aws", res: adapters.Result{Source: "aws", Signals: []adapters.Signal{
		{Source: "aws", Time: t0, Ref: "e1", Message: "ThrottlingException: rate limit"},
	}}}
	rep := (&Engine{}).Investigate(context.Background(), Input{Run: run(agentrun.Event{Kind: agentrun.KindRequest, Start: t0, End: t0}), Adapters: []adapters.Adapter{ad}})
	if rep.Hypotheses[0].Cause != RateLimit || rep.Hypotheses[0].Confidence > 0.6 {
		t.Fatalf("%+v", rep.Hypotheses)
	}
}

func TestInvestigate_SourceFailureReportedNotHidden(t *testing.T) {
	bad := fixedAdapter{name: "gcp", err: errors.New("403 denied")}
	rep := (&Engine{}).Investigate(context.Background(), Input{Run: run(ev429()), Adapters: []adapters.Adapter{bad}})
	if len(rep.Unavailable) != 1 || !strings.HasPrefix(rep.Unavailable[0], "gcp:") {
		t.Fatalf("%+v", rep.Unavailable)
	}
	if !contains(rep.Unknowns, "unavailable") {
		t.Fatalf("%v", rep.Unknowns)
	}
}

func TestInvestigate_ContractRules(t *testing.T) {
	in := Input{Run: run(), Evaluation: contract.Evaluation{Violations: []contract.Violation{
		{Rule: "output.schema", Status: "violated"}, {Rule: "limit.totalTokens", Status: "violated"},
		{Rule: "tool.required", Status: "unknown"},
	}}}
	rep := (&Engine{}).Investigate(context.Background(), in)
	got := map[Cause]bool{}
	for _, h := range rep.Hypotheses {
		got[h.Cause] = true
	}
	for _, c := range []Cause{SchemaViolation, CostOverrun, MissingTelemetry} {
		if !got[c] {
			t.Errorf("missing %s", c)
		}
	}
	if rep.Hypotheses[0].Cause != SchemaViolation {
		t.Fatalf("highest confidence first, got %s", rep.Hypotheses[0].Cause)
	}
}

func TestInvestigate_NothingMatches_Unknown(t *testing.T) {
	rep := (&Engine{}).Investigate(context.Background(), Input{Run: run()})
	if rep.Hypotheses[0].Cause != UnknownCause || !contains(rep.Unknowns, "0.5") {
		t.Fatalf("%+v", rep)
	}
}

func TestInvestigate_StepBudget(t *testing.T) {
	rep := (&Engine{MaxSteps: 2}).Investigate(context.Background(), Input{Run: run(ev429())})
	if rep.State == "done" || !contains(rep.Unknowns, "budget") {
		t.Fatalf("%+v", rep)
	}
}

func TestInvestigate_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := (&Engine{}).Investigate(ctx, Input{Run: run(ev429())})
	if rep.State == "done" || !contains(rep.Unknowns, "cancelled") {
		t.Fatalf("%+v", rep)
	}
}

type narr struct {
	reply string
	seen  string
}

func (n *narr) Complete(_ context.Context, _, user string) (string, error) {
	n.seen = user
	return n.reply, nil
}

func TestNarrative_AcceptedWhenCitationsValid(t *testing.T) {
	n := &narr{reply: "Rate limiting [span:m1] is most likely [H1]."}
	rep := (&Engine{Narrator: n}).Investigate(context.Background(), Input{Run: run(ev429())})
	if rep.NarrativeBy != "llm" || rep.Narrative == "" {
		t.Fatalf("%+v", rep)
	}
	if !strings.Contains(n.seen, "<facts>") {
		t.Fatal("facts must be delimited")
	}
}

func TestNarrative_DiscardedOnInventedEvidence(t *testing.T) {
	rep := (&Engine{Narrator: &narr{reply: "Caused by [span:made-up]."}}).Investigate(context.Background(), Input{Run: run(ev429())})
	if rep.Narrative != "" || !contains(rep.Unknowns, "discarded") {
		t.Fatalf("%+v", rep)
	}
}

func TestNarrative_Redacted(t *testing.T) {
	rep := (&Engine{Narrator: &narr{reply: "see password=supersecret1 [H1]"}}).Investigate(context.Background(), Input{Run: run(ev429())})
	if strings.Contains(rep.Narrative, "supersecret1") {
		t.Fatal("narrative leaked a secret")
	}
}
