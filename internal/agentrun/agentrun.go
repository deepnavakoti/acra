// Package agentrun is ACRA's normalized runtime-event model. Instrumented
// agents, gateways and OpenTelemetry spans are all converted to Event; events
// are correlated into a Run per agent execution. Everything downstream
// (contract evaluation, incidents, RCA) works on Runs, never on raw telemetry.
package agentrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Kind classifies a normalized event.
type Kind string

const (
	KindRequest  Kind = "agent.request"  // request entering an agent
	KindResponse Kind = "agent.response" // final response leaving an agent
	KindTool     Kind = "tool.call"      // a tool/MCP invocation
	KindModel    Kind = "model.call"     // an LLM call
	KindError    Kind = "error"          // an exception / failure
	KindInfra    Kind = "infra"          // k8s / platform signal tied to the run
	KindLog      Kind = "log"            // application log line tied to the run
)

// Limits that keep one hostile or buggy emitter from exhausting memory.
const (
	MaxPayloadBytes = 256 << 10
	MaxAttrs        = 64
	MaxFieldLen     = 512
)

// Usage is token usage as REPORTED BY THE PROVIDER. ACRA never estimates billed
// tokens from HTTP status codes: a 429 alone does not establish billing.
type Usage struct {
	InputTokens  int64 `json:"inputTokens"`
	OutputTokens int64 `json:"outputTokens"`
	CachedTokens int64 `json:"cachedTokens,omitempty"`
}

// Total returns input plus output tokens.
func (u Usage) Total() int64 { return u.InputTokens + u.OutputTokens }

// Event is one normalized execution event. The identifier set matches the
// source-of-truth document (section 5).
type Event struct {
	TraceID           string `json:"traceId"`
	SpanID            string `json:"spanId,omitempty"`
	ParentSpanID      string `json:"parentSpanId,omitempty"`
	AgentRunID        string `json:"agentRunId,omitempty"`
	AgentID           string `json:"agentId"`
	SessionID         string `json:"sessionId,omitempty"`
	ToolCallID        string `json:"toolCallId,omitempty"`
	ModelCallID       string `json:"modelCallId,omitempty"`
	RequestID         string `json:"requestId,omitempty"`
	ResponseID        string `json:"responseId,omitempty"`
	MessageID         string `json:"messageId,omitempty"`
	CorrelationID     string `json:"correlationId,omitempty"`
	TenantID          string `json:"tenantId,omitempty"`
	Environment       string `json:"environment,omitempty"`
	Service           string `json:"service,omitempty"`
	PodUID            string `json:"podUid,omitempty"`
	DeploymentVersion string `json:"deploymentVersion,omitempty"`
	ContractVersion   string `json:"contractVersion,omitempty"`

	Kind       Kind              `json:"kind"`
	Name       string            `json:"name,omitempty"` // tool / model / operation name
	Status     string            `json:"status,omitempty"`
	HTTPStatus int               `json:"httpStatus,omitempty"`
	Message    string            `json:"message,omitempty"`
	Start      time.Time         `json:"start,omitempty"`
	End        time.Time         `json:"end,omitempty"`
	Attempt    int               `json:"attempt,omitempty"` // 1 = first try
	Attrs      map[string]string `json:"attrs,omitempty"`

	Input  json.RawMessage `json:"input,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`

	Usage         *Usage `json:"usage,omitempty"`
	ContextTokens int64  `json:"contextTokens,omitempty"` // prompt size sent to the model
	ContextLimit  int64  `json:"contextLimit,omitempty"`  // model's effective window
}

// Duration is End-Start, or zero when either is missing or inverted (clock skew).
func (e Event) Duration() time.Duration {
	if e.Start.IsZero() || e.End.IsZero() || e.End.Before(e.Start) {
		return 0
	}
	return e.End.Sub(e.Start)
}

// IsError reports whether the event represents a failure.
func (e Event) IsError() bool {
	return e.Kind == KindError || e.Status == "error" || e.HTTPStatus >= 500 || e.HTTPStatus == 429
}

// Validate checks required identifiers and bounds. It also normalizes oversized
// payloads (replacing them with a marker) rather than storing them.
func (e *Event) Validate() error {
	if e.TraceID == "" {
		return errors.New("agentrun: event has no traceId")
	}
	if e.AgentID == "" {
		return errors.New("agentrun: event has no agentId")
	}
	switch e.Kind {
	case KindRequest, KindResponse, KindTool, KindModel, KindError, KindInfra, KindLog:
	default:
		return fmt.Errorf("agentrun: unknown event kind %q", e.Kind)
	}
	for _, f := range []*string{
		&e.TraceID, &e.SpanID, &e.ParentSpanID, &e.AgentRunID, &e.AgentID, &e.SessionID,
		&e.ToolCallID, &e.ModelCallID, &e.RequestID, &e.ResponseID, &e.MessageID,
		&e.CorrelationID, &e.TenantID, &e.Environment, &e.Service, &e.PodUID,
		&e.DeploymentVersion, &e.ContractVersion, &e.Name, &e.Status,
	} {
		if len(*f) > MaxFieldLen {
			return fmt.Errorf("agentrun: identifier longer than %d bytes", MaxFieldLen)
		}
	}
	if len(e.Message) > 4096 {
		e.Message = e.Message[:4096]
	}
	if len(e.Attrs) > MaxAttrs {
		return fmt.Errorf("agentrun: more than %d attributes", MaxAttrs)
	}
	e.Input = boundPayload(e, e.Input, "input")
	e.Output = boundPayload(e, e.Output, "output")
	return nil
}

func boundPayload(e *Event, p json.RawMessage, name string) json.RawMessage {
	if len(p) <= MaxPayloadBytes {
		return p
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	e.Attrs["acra.truncated."+name] = "true"
	return json.RawMessage(`{"_truncated":true}`)
}

// Run is every event of one agent execution, correlated.
type Run struct {
	TraceID         string
	AgentRunID      string
	AgentID         string
	TenantID        string
	ContractVersion string
	Events          []Event // sorted by Start (stable)
	Complete        bool    // a final response was observed
	Incomplete      bool    // finalized by idle timeout, not by a response
}

// Of returns the events of kind k.
func (r Run) Of(k Kind) []Event {
	var out []Event
	for _, e := range r.Events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// Start and End are the earliest start and latest end across events.
func (r Run) Start() time.Time {
	var t time.Time
	for _, e := range r.Events {
		if !e.Start.IsZero() && (t.IsZero() || e.Start.Before(t)) {
			t = e.Start
		}
	}
	return t
}

func (r Run) End() time.Time {
	var t time.Time
	for _, e := range r.Events {
		end := e.End
		if end.IsZero() {
			end = e.Start
		}
		if end.After(t) {
			t = end
		}
	}
	return t
}

// Latency is wall-clock from the first start to the last end (zero if unknown).
func (r Run) Latency() time.Duration {
	s, e := r.Start(), r.End()
	if s.IsZero() || e.IsZero() || e.Before(s) {
		return 0
	}
	return e.Sub(s)
}

// Response returns the last agent.response event, if any.
func (r Run) Response() (Event, bool) {
	rs := r.Of(KindResponse)
	if len(rs) == 0 {
		return Event{}, false
	}
	return rs[len(rs)-1], true
}

// Request returns the first agent.request event, if any.
func (r Run) Request() (Event, bool) {
	rs := r.Of(KindRequest)
	if len(rs) == 0 {
		return Event{}, false
	}
	return rs[0], true
}

// TotalUsage sums provider-reported usage over all model calls.
func (r Run) TotalUsage() Usage {
	var u Usage
	for _, e := range r.Of(KindModel) {
		if e.Usage != nil {
			u.InputTokens += e.Usage.InputTokens
			u.OutputTokens += e.Usage.OutputTokens
			u.CachedTokens += e.Usage.CachedTokens
		}
	}
	return u
}

// TraceComplete reports whether every non-empty parent span id refers to a span
// that is present in the run. When false, "no tool span" is NOT proof that a
// tool never ran (missing telemetry alone is not proof of hallucination).
func (r Run) TraceComplete() bool {
	have := map[string]bool{}
	for _, e := range r.Events {
		if e.SpanID != "" {
			have[e.SpanID] = true
		}
	}
	for _, e := range r.Events {
		if e.ParentSpanID != "" && !have[e.ParentSpanID] {
			return false
		}
	}
	return r.Complete
}

func sortEvents(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i].Start, evs[j].Start
		if a.IsZero() || b.IsZero() {
			return false
		}
		return a.Before(b)
	})
}
