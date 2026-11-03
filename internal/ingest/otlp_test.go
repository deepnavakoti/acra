package ingest

import (
	"strings"
	"testing"

	"github.com/deepnavakoti/acra/internal/agentrun"
)

const sample = `{
 "resourceSpans":[{
  "resource":{"attributes":[
    {"key":"service.name","value":{"stringValue":"planner"}},
    {"key":"k8s.namespace.name","value":{"stringValue":"team-a"}},
    {"key":"acra.contract.version","value":{"stringValue":"v1"}}]},
  "scopeSpans":[{"spans":[
   {"traceId":"t1","spanId":"s1","name":"agent.request","startTimeUnixNano":"1700000000000000000","endTimeUnixNano":"1700000001000000000",
    "attributes":[{"key":"acra.kind","value":{"stringValue":"agent.request"}}]},
   {"traceId":"t1","spanId":"s2","parentSpanId":"s1","name":"chat","startTimeUnixNano":"1700000000100000000","endTimeUnixNano":"1700000000900000000",
    "attributes":[{"key":"gen_ai.request.model","value":{"stringValue":"m1"}},
                  {"key":"gen_ai.usage.input_tokens","value":{"intValue":"120"}},
                  {"key":"gen_ai.usage.output_tokens","value":{"intValue":"30"}},
                  {"key":"acra.context.tokens","value":{"intValue":"900"}},
                  {"key":"acra.context.limit","value":{"intValue":"1000"}}]},
   {"traceId":"t1","spanId":"s3","parentSpanId":"s1","name":"search","startTimeUnixNano":"1700000000200000000","endTimeUnixNano":"1700000000300000000",
    "attributes":[{"key":"gen_ai.tool.name","value":{"stringValue":"search"}},
                  {"key":"http.response.status_code","value":{"intValue":"429"}}],
    "status":{"code":2,"message":"rate limited"}},
   {"traceId":"t1","spanId":"s4","name":"agent.response","startTimeUnixNano":"1700000000900000000","endTimeUnixNano":"1700000001000000000",
    "attributes":[{"key":"acra.kind","value":{"stringValue":"agent.response"}},
                  {"key":"acra.output","value":{"stringValue":"{\"answer\":\"ok\"}"}}]},
   {"spanId":"bad","name":"no trace id"}
  ]}]
 }]}`

func TestFromOTLP(t *testing.T) {
	evs, problems, err := FromOTLP([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 4 {
		t.Fatalf("want 4 events, got %d", len(evs))
	}
	if len(problems) != 1 {
		t.Errorf("the span with no traceId must be reported and skipped, got %v", problems)
	}
	by := map[string]agentrun.Event{}
	for _, e := range evs {
		by[e.SpanID] = e
	}
	if by["s1"].Kind != agentrun.KindRequest || by["s1"].AgentID != "planner" || by["s1"].ContractVersion != "v1" {
		t.Errorf("request mapping wrong: %+v", by["s1"])
	}
	m := by["s2"]
	if m.Kind != agentrun.KindModel || m.Name != "m1" || m.Usage == nil || m.Usage.InputTokens != 120 || m.ContextTokens != 900 || m.ContextLimit != 1000 {
		t.Errorf("model mapping wrong: %+v", m)
	}
	tc := by["s3"]
	if tc.Kind != agentrun.KindTool || tc.Name != "search" || tc.HTTPStatus != 429 || tc.Status != "error" {
		t.Errorf("tool mapping wrong: %+v", tc)
	}
	if by["s4"].Kind != agentrun.KindResponse || !strings.Contains(string(by["s4"].Output), "answer") {
		t.Errorf("response mapping wrong: %+v", by["s4"])
	}
	if by["s1"].Attrs["k8s.namespace.name"] != "team-a" {
		t.Errorf("namespace must be carried for RCA: %+v", by["s1"].Attrs)
	}
}

func TestFromOTLPNeverInventsAResponse(t *testing.T) {
	body := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"a"}}]},
	 "scopeSpans":[{"spans":[{"traceId":"t","spanId":"s","name":"work"}]}]}]}`
	evs, _, err := FromOTLP([]byte(body))
	if err != nil || len(evs) != 1 {
		t.Fatalf("err=%v evs=%d", err, len(evs))
	}
	if evs[0].Kind == agentrun.KindResponse {
		t.Fatal("an unlabelled span must never be treated as a final response")
	}
}

func TestFromOTLPRejectsGarbageAndFloods(t *testing.T) {
	if _, _, err := FromOTLP([]byte("not json")); err == nil {
		t.Error("garbage must be rejected")
	}
	var b strings.Builder
	b.WriteString(`{"resourceSpans":[{"scopeSpans":[{"spans":[`)
	for i := 0; i < MaxOTLPSpans+5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"traceId":"t","spanId":"s","name":"x"}`)
	}
	b.WriteString(`]}]}]}`)
	if _, _, err := FromOTLP([]byte(b.String())); err == nil {
		t.Error("span flood must be rejected")
	}
}
