package agentrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var base = time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC)

func ev(kind Kind, span string, off int) Event {
	return Event{TraceID: "t1", AgentRunID: "r1", AgentID: "a1", TenantID: "ten", Kind: kind,
		SpanID: span, Start: base.Add(time.Duration(off) * time.Second), End: base.Add(time.Duration(off+1) * time.Second)}
}

func collect() (*Assembler, *[]Run) {
	var got []Run
	a := NewAssembler(AssemblerConfig{}, func(r Run) { got = append(got, r) })
	return a, &got
}

func TestAssembler_CompletesOnResponse_SortsOutOfOrder(t *testing.T) {
	a, got := collect()
	for _, e := range []Event{ev(KindTool, "s2", 5), ev(KindRequest, "s1", 1), ev(KindResponse, "s3", 9)} {
		if err := a.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if len(*got) != 1 {
		t.Fatalf("runs=%d", len(*got))
	}
	r := (*got)[0]
	if !r.Complete || r.Events[0].SpanID != "s1" || r.Events[2].SpanID != "s3" {
		t.Fatalf("order/complete wrong: %+v", r.Events)
	}
	if r.Latency() != 9*time.Second {
		t.Fatalf("latency %v", r.Latency())
	}
}

func TestAssembler_DedupAndLate(t *testing.T) {
	a, got := collect()
	_ = a.Add(ev(KindRequest, "s1", 1))
	_ = a.Add(ev(KindRequest, "s1", 1)) // duplicate
	_ = a.Add(ev(KindResponse, "s9", 3))
	_ = a.Add(ev(KindTool, "s5", 2)) // late
	if len(*got) != 1 || len((*got)[0].Events) != 2 {
		t.Fatalf("%+v", *got)
	}
	s := a.Stats()
	if s.Duplicates != 1 || s.DroppedLate != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestAssembler_TenantIsolation(t *testing.T) {
	a, got := collect()
	e1, e2 := ev(KindRequest, "s1", 1), ev(KindRequest, "s1", 1)
	e2.TenantID = "other"
	_ = a.Add(e1)
	_ = a.Add(e2)
	if a.Open() != 2 {
		t.Fatalf("tenants share a run: open=%d", a.Open())
	}
	_ = got
}

func TestAssembler_BackpressureAndSweep(t *testing.T) {
	var got []Run
	a := NewAssembler(AssemblerConfig{MaxOpenRuns: 1, IdleTimeout: time.Minute}, func(r Run) { got = append(got, r) })
	now := time.Now()
	a.now = func() time.Time { return now }
	_ = a.Add(ev(KindRequest, "s1", 1))
	e := ev(KindRequest, "s1", 1)
	e.AgentRunID = "r2"
	if err := a.Add(e); err != ErrBackpressure {
		t.Fatalf("want backpressure, got %v", err)
	}
	now = now.Add(2 * time.Minute)
	if n := a.Sweep(); n != 1 || !got[0].Incomplete || got[0].Complete {
		t.Fatalf("sweep n=%d runs=%+v", n, got)
	}
}

func TestEventValidate(t *testing.T) {
	cases := []Event{
		{AgentID: "a", Kind: KindTool},
		{TraceID: "t", Kind: KindTool},
		{TraceID: "t", AgentID: "a", Kind: "weird"},
		{TraceID: strings.Repeat("x", 600), AgentID: "a", Kind: KindTool},
	}
	for i, c := range cases {
		if c.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	big := Event{TraceID: "t", AgentID: "a", Kind: KindResponse, Output: json.RawMessage(`"` + strings.Repeat("x", MaxPayloadBytes+10) + `"`)}
	if err := big.Validate(); err != nil || big.Attrs["acra.truncated.output"] != "true" {
		t.Fatalf("oversized payload not bounded: %v %+v", err, big.Attrs)
	}
}

func TestTraceComplete(t *testing.T) {
	r := Run{Complete: true, Events: []Event{{SpanID: "a"}, {SpanID: "b", ParentSpanID: "a"}}}
	if !r.TraceComplete() {
		t.Fatal("complete trace misjudged")
	}
	r.Events = append(r.Events, Event{SpanID: "c", ParentSpanID: "missing"})
	if r.TraceComplete() {
		t.Fatal("orphan span must mark trace incomplete")
	}
}

func TestUsageSum(t *testing.T) {
	r := Run{Events: []Event{
		{Kind: KindModel, Usage: &Usage{InputTokens: 10, OutputTokens: 5}},
		{Kind: KindModel}, {Kind: KindModel, Usage: &Usage{InputTokens: 1}},
	}}
	if u := r.TotalUsage(); u.Total() != 16 {
		t.Fatalf("%+v", u)
	}
}
