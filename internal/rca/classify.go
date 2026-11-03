package rca

import (
	"fmt"
	"sort"
	"strings"

	"github.com/deepnavakoti/acra/internal/adapters"
	"github.com/deepnavakoti/acra/internal/agentrun"
)

func sigRef(s adapters.Signal) string {
	if s.Ref != "" {
		return s.Source + ":" + s.Ref
	}
	return fmt.Sprintf("%s:%s@%d", s.Source, s.Resource, s.Time.Unix())
}

func textHas(s string, subs ...string) bool {
	l := strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(l, x) {
			return true
		}
	}
	return false
}

func eventRef(e agentrun.Event) string {
	switch {
	case e.SpanID != "":
		return "span:" + e.SpanID
	case e.ToolCallID != "":
		return "tool:" + e.ToolCallID
	case e.ModelCallID != "":
		return "model:" + e.ModelCallID
	}
	return "event:" + string(e.Kind) + ":" + e.Name
}

func violated(in Input, prefixes ...string) []string {
	var refs []string
	for _, v := range in.Evaluation.Violations {
		if v.Status != "violated" {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(v.Rule, p) {
				refs = append(refs, "rule:"+v.Rule)
				refs = append(refs, v.EventRefs...)
				break
			}
		}
	}
	return refs
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func cap5(xs []string) []string {
	xs = uniq(xs)
	if len(xs) > 8 {
		xs = xs[:8]
	}
	return xs
}

// classify applies the rules. Direct evidence (a status code on a span, a
// contract rule that deterministically failed, a pod's recorded termination
// reason) scores high; a keyword in a log line scores lower, because text can be
// misleading.
func classify(in Input, sigs []adapters.Signal) []Hypothesis {
	var hs []Hypothesis
	add := func(c Cause, conf float64, ev []string, why string, actions ...string) {
		ev = cap5(ev)
		if len(ev) == 0 {
			return
		}
		hs = append(hs, Hypothesis{Cause: c, Confidence: conf, Evidence: ev, Reasoning: why, Actions: actions})
	}

	// Rate limiting.
	{
		var direct, text []string
		for _, e := range in.Run.Events {
			if e.HTTPStatus == 429 {
				direct = append(direct, eventRef(e))
			} else if textHas(e.Message, "rate limit", "too many requests", "quota exceeded") {
				text = append(text, eventRef(e))
			}
		}
		for _, s := range sigs {
			if textHas(s.Message, "429", "rate limit", "too many requests", "quota exceeded", "throttl") {
				text = append(text, sigRef(s))
			}
		}
		if len(direct) > 0 {
			add(RateLimit, 0.85, append(direct, text...), "a model/tool call returned HTTP 429",
				"add backoff with jitter", "request a higher quota", "reduce concurrency")
		} else {
			add(RateLimit, 0.55, text, "log text mentions throttling, but no span carries a 429",
				"confirm the status code in provider metrics")
		}
	}

	// Context overflow.
	{
		ev := violated(in, "limit.contextUtilization")
		conf := 0.85
		if len(ev) == 0 {
			conf = 0.6
			for _, s := range sigs {
				if textHas(s.Message, "context length", "context window", "maximum context", "token limit", "too many tokens") {
					ev = append(ev, sigRef(s))
				}
			}
			for _, e := range in.Run.Events {
				if textHas(e.Message, "context length", "context window", "maximum context", "token limit") {
					ev = append(ev, eventRef(e))
				}
			}
		}
		add(ContextOverflow, conf, ev, "the prompt approached or exceeded the model's context window",
			"summarize or truncate history", "retrieve fewer documents", "use a larger-context model")
	}

	// Loops and tool failures.
	add(ToolLoop, 0.85, violated(in, "tool.maxCalls", "tool.maxCallsPerTool", "tool.retries"),
		"the agent called tools more often than its contract allows",
		"add a loop guard or step limit", "inspect the tool result the agent keeps rejecting")
	{
		var ev []string
		for _, e := range in.Run.Of(agentrun.KindTool) {
			if e.IsError() {
				ev = append(ev, eventRef(e))
			}
		}
		add(ToolFailure, 0.7, ev, "one or more tool calls failed", "check the failing tool's availability and credentials")
	}

	// Timeouts.
	{
		ev := violated(in, "limit.latency", "tool.duration")
		conf := 0.7
		for _, s := range sigs {
			if textHas(s.Message, "deadline exceeded", "timed out", "timeout") {
				ev = append(ev, sigRef(s))
				conf = 0.75
			}
		}
		for _, e := range in.Run.Events {
			if textHas(e.Message, "deadline exceeded", "timed out", "timeout") {
				ev = append(ev, eventRef(e))
				conf = 0.75
			}
		}
		add(Timeout, conf, ev, "the run or a dependency exceeded its time budget", "raise or tune timeouts", "check the slow dependency")
	}

	// Platform: OOM and crash loops come from pod state (direct) or log text.
	{
		var direct, text []string
		var crash []string
		for _, s := range sigs {
			switch {
			case s.Attrs["reason"] == "OOMKilled" || s.Attrs["reason"] == "OOMKilling" || strings.Contains(s.Message, "exit=137"):
				direct = append(direct, sigRef(s))
			case textHas(s.Message, "out of memory", "oomkilled"):
				text = append(text, sigRef(s))
			}
			if s.Attrs["reason"] == "CrashLoopBackOff" {
				crash = append(crash, sigRef(s))
			}
		}
		if len(direct) > 0 {
			add(ResourceExhaust, 0.9, append(direct, text...), "a container was terminated for exceeding its memory limit",
				"raise the memory limit", "profile memory use of the agent")
		} else {
			add(ResourceExhaust, 0.55, text, "logs mention running out of memory, but no pod termination was observed")
		}
		add(CrashLoop, 0.85, crash, "a pod is restarting repeatedly (CrashLoopBackOff)", "read the previous container's logs", "check recent deploys")
	}

	// Deterministic contract failures.
	add(SchemaViolation, 0.95, violated(in, "output.schema"), "the final output does not match the contract schema",
		"check for a recent prompt or model change", "tighten structured-output settings")
	add(SafetyViolation, 0.95, violated(in, "output.forbidden"), "the final output matched a forbidden pattern",
		"treat as a possible data leak and review the response", "add an output filter")
	add(CostOverrun, 0.9, violated(in, "limit.totalTokens", "limit.inputTokens"), "token usage exceeded the contract budget",
		"shorten prompts", "cap retries")

	// Not enough telemetry to conclude.
	{
		var ev []string
		for _, v := range in.Evaluation.Violations {
			if v.Status == "unknown" {
				ev = append(ev, "rule:"+v.Rule)
			}
		}
		if len(ev) > 0 {
			add(MissingTelemetry, 0.6, ev, "ACRA lacked the data to decide some rules, so those findings are unproven",
				"verify the agent emits spans for tool calls and a final response")
		}
	}

	if len(hs) == 0 {
		hs = append(hs, Hypothesis{
			Cause: UnknownCause, Confidence: 0.2, Evidence: []string{"rule:none-matched"},
			Reasoning: "no rule matched the available evidence",
		})
	}
	return hs
}

func rank(hs []Hypothesis) {
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].Confidence != hs[j].Confidence {
			return hs[i].Confidence > hs[j].Confidence
		}
		return hs[i].Cause < hs[j].Cause
	})
}

func unknowns(in Input, rep Report) []string {
	var u []string
	if len(rep.Unavailable) > 0 {
		u = append(u, fmt.Sprintf("%d evidence source(s) were unavailable, so conclusions rest on the others", len(rep.Unavailable)))
	}
	if len(rep.Partial) > 0 {
		u = append(u, "some sources returned truncated results: "+strings.Join(rep.Partial, ", "))
	}
	if len(rep.Hypotheses) > 0 {
		if rep.Hypotheses[0].Confidence < 0.5 {
			u = append(u, "no hypothesis reaches 0.5 confidence")
		}
		if len(rep.Hypotheses) > 1 && rep.Hypotheses[0].Confidence-rep.Hypotheses[1].Confidence < 0.1 {
			u = append(u, "the top two hypotheses are close; the evidence does not separate them")
		}
	}
	if !in.Run.TraceComplete() {
		u = append(u, "the trace is incomplete, so absent spans do not prove absent actions")
	}
	return u
}
