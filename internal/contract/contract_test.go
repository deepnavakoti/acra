package contract

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/deepnavakoti/acra/internal/agentrun"
	"github.com/deepnavakoti/acra/internal/llm"
)

var t0 = time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC)

func goodRun() agentrun.Run {
	return agentrun.Run{TraceID: "t", AgentID: "a", Complete: true, Events: []agentrun.Event{
		{Kind: agentrun.KindRequest, SpanID: "s0", Start: t0, End: t0},
		{Kind: agentrun.KindTool, Name: "lookup", SpanID: "s1", ParentSpanID: "s0", Attempt: 1, Start: t0, End: t0.Add(time.Second)},
		{Kind: agentrun.KindModel, SpanID: "s2", ParentSpanID: "s0", Usage: &agentrun.Usage{InputTokens: 100, OutputTokens: 50},
			ContextTokens: 1000, ContextLimit: 8000, Start: t0, End: t0.Add(2 * time.Second)},
		{Kind: agentrun.KindResponse, SpanID: "s3", ParentSpanID: "s0", Start: t0.Add(3 * time.Second), End: t0.Add(3 * time.Second),
			Output: json.RawMessage(`{"answer":"hello","confidence":0.9}`)},
	}}
}

func baseContract() *Contract {
	one := 1
	return &Contract{ID: "c", AgentID: "a", Version: "1",
		OutputSchema: &Schema{Type: "object", Required: []string{"answer"},
			Properties: map[string]*Schema{"answer": {Type: "string", MinLength: &one}, "confidence": {Type: "number"}}},
		Tools:  ToolRules{Allowed: []string{"lookup"}, Required: []string{"lookup"}, MaxCalls: 3},
		Limits: Limits{MaxLatencyMs: 5000, MaxTotalTokens: 1000, MaxContextUtil: 0.8}}
}

func eval(c *Contract, r agentrun.Run, j Judge) Evaluation {
	return Evaluate(context.Background(), c, r, j, t0)
}

func hasRule(e Evaluation, rule, status string) bool {
	for _, v := range e.Violations {
		if v.Rule == rule && v.Status == status {
			return true
		}
	}
	return false
}

func TestEvaluate_Pass(t *testing.T) {
	if e := eval(baseContract(), goodRun(), nil); e.Status != StatusPass {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestEvaluate_SchemaViolation(t *testing.T) {
	r := goodRun()
	r.Events[3].Output = json.RawMessage(`{"confidence":"high"}`)
	e := eval(baseContract(), r, nil)
	if e.Status != StatusFail || !hasRule(e, "output.schema", "violated") {
		t.Fatalf("%+v", e)
	}
}

func TestEvaluate_ForbiddenPattern_NotEchoed(t *testing.T) {
	c := baseContract()
	c.ForbiddenPatterns = []string{`AKIA[0-9A-Z]{16}`}
	r := goodRun()
	r.Events[3].Output = json.RawMessage(`{"answer":"key AKIAABCDEFGHIJKLMNOP"}`)
	e := eval(c, r, nil)
	if !hasRule(e, "output.forbidden[0]", "violated") {
		t.Fatalf("%+v", e)
	}
	for _, v := range e.Violations {
		if v.Message != "" && (len(v.Message) > 0 && containsStr(v.Message, "AKIAABCDEFGHIJKLMNOP")) {
			t.Fatal("matched secret echoed in violation")
		}
	}
}

func containsStr(s, sub string) bool { return len(sub) > 0 && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestEvaluate_Tools(t *testing.T) {
	c := baseContract()
	r := goodRun()
	r.Events[1].Name = "delete_all"
	e := eval(c, r, nil)
	if !hasRule(e, "tool.allowed", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestEvaluate_RequiredToolMissing_CompleteTrace_Violated(t *testing.T) {
	r := goodRun()
	r.Events = append(r.Events[:1], r.Events[2:]...) // drop tool call
	e := eval(baseContract(), r, nil)
	if !hasRule(e, "tool.required", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestEvaluate_RequiredToolMissing_IncompleteTrace_Unknown(t *testing.T) {
	r := goodRun()
	r.Events = append(r.Events[:1], r.Events[2:]...)
	r.Events[1].ParentSpanID = "never-arrived"
	e := eval(baseContract(), r, nil)
	if !hasRule(e, "tool.required", "unknown") || hasRule(e, "tool.required", "violated") {
		t.Fatalf("missing telemetry must be unknown, not an accusation: %+v", e.Violations)
	}
}

func TestEvaluate_Loop(t *testing.T) {
	c := baseContract()
	c.Tools.MaxCallsPerTool = 2
	r := goodRun()
	for i := 0; i < 3; i++ {
		r.Events = append(r.Events, agentrun.Event{Kind: agentrun.KindTool, Name: "lookup", SpanID: "x", ParentSpanID: "s0", Attempt: 1})
	}
	e := eval(c, r, nil)
	if !hasRule(e, "tool.maxCallsPerTool", "violated") || !hasRule(e, "tool.maxCalls", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestEvaluate_Retries(t *testing.T) {
	c := baseContract()
	c.Tools.MaxRetries = 2
	r := goodRun()
	r.Events[1].Attempt = 6
	if !hasRule(eval(c, r, nil), "tool.retries", "violated") {
		t.Fatal("retry storm not flagged")
	}
}

func TestEvaluate_Limits(t *testing.T) {
	c := baseContract()
	c.Limits = Limits{MaxLatencyMs: 100, MaxTotalTokens: 10, MaxContextUtil: 0.05}
	e := eval(c, goodRun(), nil)
	for _, rule := range []string{"limit.latency", "limit.totalTokens", "limit.contextUtilization"} {
		if !hasRule(e, rule, "violated") {
			t.Errorf("missing %s: %+v", rule, e.Violations)
		}
	}
}

func TestEvaluate_NoUsage_IsUnknownNotInferred(t *testing.T) {
	r := goodRun()
	r.Events[2].Usage = nil
	r.Events[2].HTTPStatus = 429
	e := eval(baseContract(), r, nil)
	if !hasRule(e, "limit.tokens", "unknown") {
		t.Fatalf("%+v", e.Violations)
	}
	if e.Status == StatusFail {
		t.Fatal("429 must not be treated as billed tokens")
	}
}

func TestEvaluate_IncompleteRun_Unknown(t *testing.T) {
	r := goodRun()
	r.Complete, r.Incomplete = false, true
	r.Events = r.Events[:3]
	e := eval(baseContract(), r, nil)
	if e.Status == StatusPass || !hasRule(e, "run.complete", "unknown") {
		t.Fatalf("%+v", e)
	}
}

func TestEvaluate_MissingOutput_Unknown(t *testing.T) {
	r := goodRun()
	r.Events[3].Output = nil
	if !hasRule(eval(baseContract(), r, nil), "output.captured", "unknown") {
		t.Fatal("uncaptured output must be unknown")
	}
}

type fakeLLM struct {
	reply string
	err   error
	seen  string
}

func (f *fakeLLM) Complete(_ context.Context, _, user string) (string, error) {
	f.seen = user
	return f.reply, f.err
}

var _ llm.Completer = (*fakeLLM)(nil)

func TestRubric_SkippedWithoutJudge(t *testing.T) {
	c := baseContract()
	c.Rubrics = []Rubric{{ID: "polite", Criterion: "polite", MinScore: 0.8}}
	e := eval(c, goodRun(), nil)
	if e.Status != StatusPass || len(e.Skipped) != 1 {
		t.Fatalf("%+v", e)
	}
}

func TestRubric_JudgeScores(t *testing.T) {
	c := baseContract()
	c.Rubrics = []Rubric{{ID: "polite", Criterion: "polite", MinScore: 0.8}}
	f := &fakeLLM{reply: "Sure.\n```json\n{\"score\":0.4,\"reason\":\"curt\"}\n```"}
	e := eval(c, goodRun(), LLMJudge{C: f})
	if !hasRule(e, "rubric.polite", "violated") || e.Scores["polite"] != 0.4 {
		t.Fatalf("%+v", e)
	}
	if !containsStr(f.seen, "<untrusted_output>") {
		t.Fatal("output not delimited as untrusted")
	}
}

func TestRubric_JudgeFailureIsUnknown(t *testing.T) {
	c := baseContract()
	c.Rubrics = []Rubric{{ID: "p", Criterion: "x", MinScore: 0.5}}
	for _, f := range []*fakeLLM{{err: errors.New("down")}, {reply: "no json"}, {reply: `{"score":7}`}, {reply: `{"reason":"x"}`}} {
		e := eval(c, goodRun(), LLMJudge{C: f})
		if e.Status != StatusUnknown {
			t.Fatalf("judge failure must be unknown, got %s (%+v)", e.Status, f)
		}
	}
}

func TestRubric_DeterministicFailureWinsOverGoodScore(t *testing.T) {
	c := baseContract()
	c.Rubrics = []Rubric{{ID: "p", Criterion: "x", MinScore: 0.5}}
	r := goodRun()
	r.Events[3].Output = json.RawMessage(`{}`)
	e := eval(c, r, LLMJudge{C: &fakeLLM{reply: `{"score":1}`}})
	if e.Status != StatusFail {
		t.Fatal("a perfect rubric score must not mask a schema failure")
	}
}

func TestParse_StrictAndValidated(t *testing.T) {
	if _, err := Parse([]byte(`{"id":"c","agentId":"a","version":"1","limits":{"maxLatency":5}}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Parse([]byte(`{"id":"c","agentId":"a","version":"1","forbiddenPatterns":["("]}`)); err == nil {
		t.Fatal("bad regex accepted")
	}
	if _, err := Parse([]byte(`{"id":"c","agentId":"a","version":"1","limits":{"maxContextUtilization":2}}`)); err == nil {
		t.Fatal("bad utilization accepted")
	}
	if _, err := Parse([]byte(`{"id":"c","agentId":"a","version":"1"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRegistry_VersionsImmutable(t *testing.T) {
	r := NewRegistry()
	c := baseContract()
	if err := r.Put(c); err != nil {
		t.Fatal(err)
	}
	if err := r.Put(c); err != nil {
		t.Fatal("identical re-put should be a no-op")
	}
	c2 := baseContract()
	c2.Limits.MaxLatencyMs = 1
	if err := r.Put(c2); err == nil {
		t.Fatal("mutating an existing version must be refused")
	}
	c3 := baseContract()
	c3.Version = "2"
	_ = r.Put(c3)
	if got, _ := r.Get("a", ""); got.Version != "2" {
		t.Fatal("latest version should be active")
	}
	if got, ok := r.Get("a", "1"); !ok || got.Version != "1" {
		t.Fatal("old version not retrievable")
	}
}

func TestSchemaCheck(t *testing.T) {
	two := 2
	f := false
	s := &Schema{Type: "object", AdditionalProperties: &f, Required: []string{"x"},
		Properties: map[string]*Schema{
			"x":   {Type: "string", Enum: []json.RawMessage{json.RawMessage(`"a"`), json.RawMessage(`"b"`)}},
			"n":   {Type: "integer"},
			"arr": {Type: "array", MaxItems: &two, Items: &Schema{Type: "string", Pattern: `^[a-z]+$`}},
		}}
	if p := s.Check(json.RawMessage(`{"x":"a","n":3,"arr":["ok"]}`)); len(p) != 0 {
		t.Fatalf("%v", p)
	}
	p := s.Check(json.RawMessage(`{"x":"c","n":1.5,"arr":["A","b","c"],"extra":1}`))
	if len(p) < 4 {
		t.Fatalf("expected >=4 problems, got %v", p)
	}
	if p := s.Check(json.RawMessage(`not json`)); len(p) != 1 {
		t.Fatal("invalid JSON must be one problem")
	}
}
