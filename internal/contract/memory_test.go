package contract

import (
	"encoding/json"
	"testing"

	"github.com/deepnavakoti/acra/internal/agentrun"
)

func memContract() *Contract {
	c := baseContract()
	c.Tools.Allowed = []string{"lookup", "mem_write", "mem_read"}
	c.Memory = MemoryRules{
		WriteTools: []string{"mem_write"}, ReadTools: []string{"mem_read"},
		MaxWrites: 2, MaxReads: 2, MaxWriteBytes: 64,
		ForbiddenWritePatterns: []string{`AKIA[0-9A-Z]{16}`},
	}
	return c
}

func memEvent(name, input string) agentrun.Event {
	e := agentrun.Event{Kind: agentrun.KindTool, Name: name, SpanID: "m-" + name, ParentSpanID: "s0", Attempt: 1}
	if input != "" {
		e.Input = json.RawMessage(input)
	}
	return e
}

func TestMemory_CleanRunPasses(t *testing.T) {
	r := goodRun()
	r.Events = append(r.Events, memEvent("mem_write", `{"k":"pref","v":"dark mode"}`), memEvent("mem_read", ""))
	if e := eval(memContract(), r, nil); e.Status != StatusPass {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestMemory_Limits(t *testing.T) {
	r := goodRun()
	for i := 0; i < 3; i++ {
		r.Events = append(r.Events, memEvent("mem_write", `{"v":"x"}`), memEvent("mem_read", ""))
	}
	e := eval(memContract(), r, nil)
	if !hasRule(e, "memory.maxWrites", "violated") || !hasRule(e, "memory.maxReads", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestMemory_WriteSize(t *testing.T) {
	r := goodRun()
	big := `{"v":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}`
	r.Events = append(r.Events, memEvent("mem_write", big))
	if e := eval(memContract(), r, nil); !hasRule(e, "memory.writeBytes", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
}

func TestMemory_ForbiddenWrite_NotEchoed(t *testing.T) {
	r := goodRun()
	r.Events = append(r.Events, memEvent("mem_write", `{"v":"AKIAABCDEFGHIJKLMNOP"}`))
	e := eval(memContract(), r, nil)
	if e.Status != StatusFail || !hasRule(e, "memory.forbiddenWrite[0]", "violated") {
		t.Fatalf("%+v", e.Violations)
	}
	for _, v := range e.Violations {
		if containsStr(v.Message, "AKIAABCDEFGHIJKLMNOP") {
			t.Fatal("matched secret echoed in violation")
		}
	}
}

func TestMemory_UncapturedInput_IsUnknown(t *testing.T) {
	r := goodRun()
	r.Events = append(r.Events, memEvent("mem_write", ""))
	e := eval(memContract(), r, nil)
	if !hasRule(e, "memory.inputCaptured", "unknown") || e.Status != StatusUnknown {
		t.Fatalf("a write with no captured input must be unknown, not a pass: %+v", e.Violations)
	}
}

func TestMemory_UnlistedToolIsNotMemory(t *testing.T) {
	c := memContract()
	r := goodRun()
	r.Events = append(r.Events, memEvent("lookup", `{"v":"AKIAABCDEFGHIJKLMNOP"}`))
	if e := eval(c, r, nil); hasRule(e, "memory.forbiddenWrite[0]", "violated") {
		t.Fatalf("only listed write tools are memory writes: %+v", e.Violations)
	}
}

func TestMemory_ValidateRejectsSilentRules(t *testing.T) {
	cases := map[string]MemoryRules{
		"write rule without write tool": {MaxWrites: 1},
		"reads without read tool":       {MaxReads: 1},
		"negative":                      {WriteTools: []string{"w"}, MaxWrites: -1},
		"bad regex":                     {WriteTools: []string{"w"}, ForbiddenWritePatterns: []string{"("}},
		"both read and write":           {WriteTools: []string{"x"}, ReadTools: []string{"x"}},
		"empty name":                    {WriteTools: []string{""}},
	}
	for name, m := range cases {
		c := baseContract()
		c.Memory = m
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestMemory_ParseStrict(t *testing.T) {
	ok := `{"id":"c","agentId":"a","version":"1","memory":{"writeTools":["w"],"maxWrites":3}}`
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	typo := `{"id":"c","agentId":"a","version":"1","memory":{"writeTools":["w"],"maxWrite":3}}`
	if _, err := Parse([]byte(typo)); err == nil {
		t.Fatal("unknown memory field must be rejected")
	}
}
