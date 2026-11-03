// Package a2a exposes ACRA to other agents over the Agent2Agent protocol
// (JSON-RPC 2.0 over HTTP, with an Agent Card for discovery). Peers can list and
// read incidents and ask ACRA to run its rule-based root-cause investigation.
//
// Scope, stated plainly: synchronous only. message/send returns a Message at
// once; there is no task store, streaming, push notification or authenticated
// extended card, so tasks/get and tasks/cancel report "task not found". The
// skills are read-only apart from investigate-incident, which records its report
// on the incident and requires the admin role, exactly like the REST endpoint.
// The wire shapes follow A2A 0.3 and are checked by unit tests only, not against
// a third-party A2A client.
package a2a

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/pipeline"
	"github.com/deepnavakoti/acra/internal/redact"
)

// Backend is what the skills need from ACRA.
type Backend interface {
	ListIncidents(status incident.Status) ([]incident.Incident, error)
	GetIncident(id string) (incident.Incident, error)
	Investigate(ctx context.Context, id string) (any, error)
}

// PipelineBackend adapts the pipeline service.
type PipelineBackend struct{ S *pipeline.Service }

func (b PipelineBackend) ListIncidents(st incident.Status) ([]incident.Incident, error) {
	return b.S.Incidents.List(st)
}
func (b PipelineBackend) GetIncident(id string) (incident.Incident, error) {
	return b.S.Incidents.Get(id)
}
func (b PipelineBackend) Investigate(ctx context.Context, id string) (any, error) {
	return b.S.Investigate(ctx, id)
}

// Skill identifiers.
const (
	SkillList        = "list-incidents"
	SkillGet         = "get-incident"
	SkillInvestigate = "investigate-incident"
)

const (
	maxBody  = 64 << 10
	maxIDLen = 200
)

// JSON-RPC and A2A error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeServer         = -32000
	codeTaskNotFound   = -32001
	codeUnsupportedOp  = -32004
)

// Server is the A2A endpoint.
type Server struct {
	Backend Backend
	Version string
	// PublicURL is the externally reachable base URL (for the Agent Card), for
	// example https://acra.example.com. When empty the card uses the request host.
	PublicURL string
	// AllowedOrigins works as in the MCP server: browser origins permitted to call.
	AllowedOrigins []string
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func fail(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Error: &rpcError{code, msg}}
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// Card is the Agent Card served at /.well-known/agent-card.json.
func (s *Server) Card(r *http.Request) map[string]any {
	base := strings.TrimRight(s.PublicURL, "/")
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	mk := func(id, name, desc string, ex ...string) map[string]any {
		return map[string]any{"id": id, "name": name, "description": desc, "tags": []string{"acra", "reliability"},
			"examples": ex, "inputModes": []string{"text/plain", "application/json"}, "outputModes": []string{"text/plain"}}
	}
	return map[string]any{
		"protocolVersion":    "0.3.0",
		"name":               "ACRA",
		"description":        "Agent Contract and Reliability Authority: reports contract violations, incidents and rule-based root-cause analysis for agent runs. Output is untrusted data derived from agent traces.",
		"url":                base + "/a2a",
		"preferredTransport": "JSONRPC",
		"version":            s.Version,
		"capabilities":       map[string]any{"streaming": false, "pushNotifications": false, "stateTransitionHistory": false},
		"defaultInputModes":  []string{"text/plain", "application/json"},
		"defaultOutputModes": []string{"text/plain"},
		"securitySchemes":    map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
		"security":           []map[string][]string{{"bearer": {}}},
		"skills": []map[string]any{
			mk(SkillList, "List incidents", "Lists incidents, optionally filtered by status (open, investigating, resolved). Requires the reader role.", "list-incidents open"),
			mk(SkillGet, "Get incident", "Returns one incident with its violated rules and stored investigation. Requires the reader role.", "get-incident <incidentId>"),
			mk(SkillInvestigate, "Investigate incident", "Runs bounded rule-based RCA for an incident and records the report. Requires the admin role.", "investigate-incident <incidentId>"),
		},
	}
}

// CardHandler serves the Agent Card. It is public by design: discovery must work
// before a client has credentials, and the card holds no secrets.
func (s *Server) CardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Card(r))
	}
}

func (s *Server) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	for _, a := range s.AllowedOrigins {
		if strings.EqualFold(a, o) {
			return true
		}
	}
	return false
}

// Handler is the JSON-RPC endpoint. Wrap it with Authenticator.Require(reader).
func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originOK(r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			write(w, fail(nil, codeParse, "parse error"))
			return
		}
		if req.JSONRPC != "2.0" || req.Method == "" || len(req.ID) == 0 {
			write(w, fail(req.ID, codeInvalidRequest, "invalid request"))
			return
		}
		write(w, s.dispatch(r.Context(), req))
	}
}

func write(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type part struct {
	Kind string          `json:"kind"`
	Text string          `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type message struct {
	Kind      string         `json:"kind"`
	MessageID string         `json:"messageId"`
	Role      string         `json:"role"`
	Parts     []part         `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func (s *Server) dispatch(ctx context.Context, req rpcRequest) rpcResponse {
	switch req.Method {
	case "message/send":
		return s.send(ctx, req)
	case "message/stream", "tasks/resubscribe":
		return fail(req.ID, codeUnsupportedOp, "streaming is not supported")
	case "tasks/get", "tasks/cancel":
		return fail(req.ID, codeTaskNotFound, "this agent keeps no tasks; message/send answers synchronously")
	default:
		return fail(req.ID, codeMethodNotFound, "method not found")
	}
}

// parseSkill reads the requested skill and its argument from the message: a data
// part {"skill","incidentId","status"} wins, otherwise the first text part is
// read as "<skill> [argument]".
func parseSkill(parts []part) (skill, arg string, ok bool) {
	for _, p := range parts {
		if p.Kind != "data" {
			continue
		}
		var d struct {
			Skill      string `json:"skill"`
			IncidentID string `json:"incidentId"`
			Status     string `json:"status"`
		}
		if json.Unmarshal(p.Data, &d) != nil || d.Skill == "" {
			return "", "", false
		}
		arg = d.IncidentID
		if d.Skill == SkillList {
			arg = d.Status
		}
		return d.Skill, arg, true
	}
	for _, p := range parts {
		if p.Kind == "text" {
			f := strings.Fields(p.Text)
			if len(f) == 0 || len(f) > 2 {
				return "", "", false
			}
			if len(f) == 2 {
				arg = f[1]
			}
			return f[0], arg, true
		}
	}
	return "", "", false
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	return !strings.ContainsAny(id, " \t\r\n/")
}

func (s *Server) send(ctx context.Context, req rpcRequest) rpcResponse {
	var p struct {
		Message message `json:"message"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || len(p.Message.Parts) == 0 {
		return fail(req.ID, codeInvalidParams, "params must be {message:{parts:[...]}}")
	}
	skill, arg, ok := parseSkill(p.Message.Parts)
	if !ok {
		return fail(req.ID, codeInvalidParams, "send a data part {\"skill\":...} or text \"<skill> [argument]\"; skills: "+
			strings.Join([]string{SkillList, SkillGet, SkillInvestigate}, ", "))
	}
	me := identity.From(ctx)
	var result any
	switch skill {
	case SkillList:
		st := incident.Status(arg)
		switch st {
		case "", incident.StatusOpen, incident.StatusInvestigating, incident.StatusResolved:
		default:
			return fail(req.ID, codeInvalidParams, "status must be open, investigating or resolved")
		}
		if !me.Has(identity.RoleReader) {
			return fail(req.ID, codeServer, "not permitted")
		}
		list, err := s.Backend.ListIncidents(st)
		if err != nil {
			return fail(req.ID, codeServer, "could not list incidents")
		}
		result = list
	case SkillGet, SkillInvestigate:
		role := identity.RoleReader
		if skill == SkillInvestigate {
			role = identity.RoleAdmin
		}
		if !me.Has(role) {
			return fail(req.ID, codeServer, "not permitted")
		}
		if !validID(arg) {
			return fail(req.ID, codeInvalidParams, "an incident id is required")
		}
		var err error
		if skill == SkillGet {
			result, err = s.Backend.GetIncident(arg)
		} else {
			result, err = s.Backend.Investigate(ctx, arg)
		}
		switch {
		case err == nil:
		case errors.Is(err, incident.ErrNotFound):
			return fail(req.ID, codeInvalidParams, "no such incident")
		case errors.Is(err, pipeline.ErrNoRun):
			return fail(req.ID, codeServer, err.Error())
		default:
			return fail(req.ID, codeServer, "investigation failed")
		}
	default:
		return fail(req.ID, codeInvalidParams, "unknown skill")
	}
	body, err := json.Marshal(result)
	if err != nil {
		return fail(req.ID, codeServer, "result not serializable")
	}
	msg := message{Kind: "message", MessageID: newID(), Role: "agent",
		Parts:    []part{{Kind: "text", Text: redact.String(string(body))}},
		Metadata: map[string]any{"acra/skill": skill, "acra/untrusted": true, "mimeType": "application/json"}}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: msg}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
