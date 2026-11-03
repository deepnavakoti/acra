// Package ingest converts external telemetry formats into agentrun events.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/deepnavakoti/acra/internal/agentrun"
)

// OTLP/JSON trace export (the subset ACRA needs). Unknown fields are ignored:
// OTLP exporters add fields freely and rejecting them would drop real data.
type otlpRequest struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpKV `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpKV struct {
	Key   string `json:"key"`
	Value struct {
		String *string      `json:"stringValue"`
		Int    *json.Number `json:"intValue"`
		Double *float64     `json:"doubleValue"`
		Bool   *bool        `json:"boolValue"`
	} `json:"value"`
}

type otlpSpan struct {
	TraceID      string   `json:"traceId"`
	SpanID       string   `json:"spanId"`
	ParentSpanID string   `json:"parentSpanId"`
	Name         string   `json:"name"`
	Start        string   `json:"startTimeUnixNano"`
	End          string   `json:"endTimeUnixNano"`
	Attributes   []otlpKV `json:"attributes"`
	Status       struct {
		Code    json.Number `json:"code"`
		Message string      `json:"message"`
	} `json:"status"`
}

func (kv otlpKV) str() string {
	switch {
	case kv.Value.String != nil:
		return *kv.Value.String
	case kv.Value.Int != nil:
		return kv.Value.Int.String()
	case kv.Value.Double != nil:
		return strconv.FormatFloat(*kv.Value.Double, 'f', -1, 64)
	case kv.Value.Bool != nil:
		return strconv.FormatBool(*kv.Value.Bool)
	}
	return ""
}

// MaxOTLPSpans bounds one export request.
const MaxOTLPSpans = 5000

// FromOTLP converts an OTLP/JSON export into events. Spans are mapped as
// follows. The span's "acra.kind" attribute selects the event kind (use
// agent.request / agent.response on the agent's root spans); without it a span
// with gen_ai model attributes is a model.call, one with a tool name is a
// tool.call, and anything else becomes a log event. ACRA never guesses that a
// span is a final response: without agent.response a run can only be finalized
// by the idle timeout and is marked incomplete.
//
// Returned problems list spans that were skipped; conversion of the rest continues.
func FromOTLP(body []byte) ([]agentrun.Event, []string, error) {
	var req otlpRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil {
		return nil, nil, fmt.Errorf("ingest: invalid OTLP JSON: %w", err)
	}
	var evs []agentrun.Event
	var problems []string
	total := 0
	for _, rs := range req.ResourceSpans {
		res := map[string]string{}
		for _, kv := range rs.Resource.Attributes {
			res[kv.Key] = kv.str()
		}
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				total++
				if total > MaxOTLPSpans {
					return evs, problems, errors.New("ingest: too many spans in one request")
				}
				ev, err := convertSpan(sp, res)
				if err != nil {
					problems = append(problems, fmt.Sprintf("span %q: %v", sp.SpanID, err))
					continue
				}
				evs = append(evs, ev)
			}
		}
	}
	return evs, problems, nil
}

func convertSpan(sp otlpSpan, res map[string]string) (agentrun.Event, error) {
	attrs := map[string]string{}
	for _, kv := range sp.Attributes {
		attrs[kv.Key] = kv.str()
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := attrs[k]; v != "" {
				return v
			}
			if v := res[k]; v != "" {
				return v
			}
		}
		return ""
	}
	ev := agentrun.Event{
		TraceID: sp.TraceID, SpanID: sp.SpanID, ParentSpanID: sp.ParentSpanID,
		AgentID:           first("acra.agent.id", "gen_ai.agent.id", "service.name"),
		AgentRunID:        first("acra.agent.run.id"),
		SessionID:         first("session.id", "acra.session.id"),
		TenantID:          first("acra.tenant.id"),
		Environment:       first("deployment.environment", "deployment.environment.name"),
		Service:           first("service.name"),
		PodUID:            first("k8s.pod.uid"),
		DeploymentVersion: first("service.version"),
		ContractVersion:   first("acra.contract.version"),
		ToolCallID:        first("gen_ai.tool.call.id", "acra.tool.call.id"),
		Name:              sp.Name,
		Attempt:           atoi(first("acra.attempt")),
		HTTPStatus:        atoi(first("http.response.status_code", "http.status_code")),
	}
	if ns := first("k8s.namespace.name"); ns != "" {
		ev.Attrs = map[string]string{"k8s.namespace.name": ns}
	}
	if t, err := nano(sp.Start); err == nil {
		ev.Start = t
	}
	if t, err := nano(sp.End); err == nil {
		ev.End = t
	}

	switch k := first("acra.kind"); {
	case k != "":
		ev.Kind = agentrun.Kind(k)
	case first("gen_ai.request.model", "gen_ai.usage.input_tokens") != "":
		ev.Kind = agentrun.KindModel
	case first("gen_ai.tool.name", "tool.name") != "":
		ev.Kind = agentrun.KindTool
	default:
		ev.Kind = agentrun.KindLog
	}
	if n := first("gen_ai.tool.name", "tool.name"); n != "" && ev.Kind == agentrun.KindTool {
		ev.Name = n
	}
	if n := first("gen_ai.request.model"); n != "" && ev.Kind == agentrun.KindModel {
		ev.Name = n
	}

	if in, out := atoi64(first("gen_ai.usage.input_tokens")), atoi64(first("gen_ai.usage.output_tokens")); in > 0 || out > 0 {
		ev.Usage = &agentrun.Usage{InputTokens: in, OutputTokens: out}
	}
	ev.ContextTokens = atoi64(first("acra.context.tokens"))
	ev.ContextLimit = atoi64(first("acra.context.limit"))
	// Status: OTLP code 2 = ERROR. Never invent success from a missing status.
	switch sp.Status.Code.String() {
	case "2", "STATUS_CODE_ERROR":
		ev.Status, ev.Message = "error", sp.Status.Message
	case "1", "STATUS_CODE_OK":
		ev.Status = "ok"
	}
	if o := attrs["acra.output"]; o != "" {
		ev.Output = json.RawMessage(o)
		if !json.Valid(ev.Output) {
			b, _ := json.Marshal(o)
			ev.Output = b
		}
	}
	if i := attrs["acra.input"]; i != "" {
		ev.Input = json.RawMessage(i)
		if !json.Valid(ev.Input) {
			b, _ := json.Marshal(i)
			ev.Input = b
		}
	}
	return ev, ev.Validate()
}

func nano(s string) (time.Time, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, errors.New("bad timestamp")
	}
	return time.Unix(0, n).UTC(), nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
