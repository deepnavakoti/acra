package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/deepnavakoti/acra/internal/agentrun"
	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/gateway"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/ingest"
	"github.com/deepnavakoti/acra/internal/mcp"
	"github.com/deepnavakoti/acra/internal/pipeline"
)

// Request size limits. Every body is read through http.MaxBytesReader.
const (
	maxEventsBody   = 4 << 20
	maxOTLPBody     = 8 << 20
	maxContractBody = 256 << 10
	maxToolBody     = 32 << 10
	maxEventsBatch  = 1000
)

func (s *Server) reliabilityRoutes(mux *http.ServeMux) {
	if s.Pipeline != nil {
		a := s.Auth
		mux.HandleFunc("POST /v1/ingest/events", a.Require(identity.RoleIngest, s.ingestEvents))
		mux.HandleFunc("POST /v1/ingest/otlp", a.Require(identity.RoleIngest, s.ingestOTLP))
		mux.HandleFunc("POST /v1/traces", a.Require(identity.RoleIngest, s.ingestOTLP)) // OTLP/HTTP default path
		mux.HandleFunc("PUT /v1/contracts", a.Require(identity.RoleAdmin, s.putContract))
		mux.HandleFunc("GET /v1/contracts", a.Require(identity.RoleReader, s.listContracts))
		mux.HandleFunc("GET /v1/evaluations", a.Require(identity.RoleReader, s.listEvaluations))
		mux.HandleFunc("GET /v1/incidents", a.Require(identity.RoleReader, s.listIncidents))
		mux.HandleFunc("GET /v1/incidents/{id}", a.Require(identity.RoleReader, s.getIncident))
		mux.HandleFunc("GET /v1/incidents/{id}/evidence", a.Require(identity.RoleReader, s.incidentEvidence))
		mux.HandleFunc("POST /v1/incidents/{id}/investigate", a.Require(identity.RoleAdmin, s.investigate))
		mux.HandleFunc("POST /v1/incidents/{id}/resolve", a.Require(identity.RoleAdmin, s.resolve))
		mux.HandleFunc("GET /v1/pipeline/stats", a.Require(identity.RoleReader, s.pipelineStats))
	}
	if s.Gateway != nil {
		mux.HandleFunc("GET /v1/tools", s.Auth.Require(identity.RoleReader, s.listTools))
		mux.HandleFunc("POST /v1/tools/{name}/call", s.Auth.Require(identity.RoleReader, s.callTool))
	}
	if s.MCP != nil {
		mux.HandleFunc("POST /mcp", s.Auth.Require(identity.RoleReader, s.MCP.Handler()))
		mux.HandleFunc("GET /mcp", mcp.GetHandler)
	}
	if s.A2A != nil {
		card := s.A2A.CardHandler()
		mux.HandleFunc("GET /.well-known/agent-card.json", card)
		mux.HandleFunc("GET /.well-known/agent.json", card) // pre-0.3 clients
		mux.HandleFunc("POST /a2a", s.Auth.Require(identity.RoleReader, s.A2A.Handler()))
	}
}

// decode reads a size-limited JSON body. strict rejects unknown fields.
func decode(w http.ResponseWriter, r *http.Request, max int64, strict bool, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "unexpected data after JSON value")
		return false
	}
	return true
}

type ingestResult struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

func (s *Server) respondIngest(w http.ResponseWriter, total, accepted int, errs []error, pre []string) {
	res := ingestResult{Accepted: accepted, Rejected: total - accepted}
	res.Errors = append(res.Errors, pre...)
	backpressure := false
	for _, e := range errs {
		if errors.Is(e, agentrun.ErrBackpressure) {
			backpressure = true
		}
		res.Errors = append(res.Errors, e.Error())
	}
	if backpressure && accepted == 0 {
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": res})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": res})
}

func (s *Server) ingestEvents(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Events []agentrun.Event `json:"events"`
	}
	if !decode(w, r, maxEventsBody, true, &body) {
		return
	}
	if len(body.Events) == 0 || len(body.Events) > maxEventsBatch {
		writeError(w, http.StatusBadRequest, "events must contain 1.."+strconv.Itoa(maxEventsBatch)+" items")
		return
	}
	acc, errs := s.Pipeline.Ingest(body.Events)
	s.respondIngest(w, len(body.Events), acc, errs, nil)
}

func (s *Server) ingestOTLP(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "only OTLP/JSON (application/json) is supported")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOTLPBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	evs, problems, err := ingest.FromOTLP(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(problems) > 20 {
		problems = problems[:20]
	}
	acc, errs := s.Pipeline.Ingest(evs)
	s.respondIngest(w, len(evs)+len(problems), acc, errs, problems)
}

func (s *Server) putContract(w http.ResponseWriter, r *http.Request) {
	var c contract.Contract
	if !decode(w, r, maxContractBody, true, &c) {
		return
	}
	if err := s.Pipeline.Contracts.Put(&c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeEnvelope(w, map[string]string{"id": c.ID, "agentId": c.AgentID, "version": c.Version})
}

func (s *Server) listContracts(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agentId")
	out := []*contract.Contract{}
	for _, c := range s.Pipeline.Contracts.All() {
		if agent == "" || c.AgentID == agent {
			out = append(out, c)
		}
	}
	writeEnvelope(w, out)
}

func (s *Server) listEvaluations(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agentId")
	if agent == "" {
		writeError(w, http.StatusBadRequest, "agentId is required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	evs, err := s.Pipeline.Incidents.Evaluations(agent, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read evaluations")
		return
	}
	writeEnvelope(w, evs)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	st := incident.Status(r.URL.Query().Get("status"))
	switch st {
	case "", incident.StatusOpen, incident.StatusInvestigating, incident.StatusResolved:
	default:
		writeError(w, http.StatusBadRequest, "status must be open, investigating or resolved")
		return
	}
	list, err := s.Pipeline.Incidents.List(st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list incidents")
		return
	}
	writeEnvelope(w, list)
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	inc, err := s.Pipeline.Incidents.Get(r.PathValue("id"))
	if err != nil {
		incidentError(w, err)
		return
	}
	writeEnvelope(w, inc)
}

func (s *Server) incidentEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.Pipeline.Incidents.Get(id); err != nil {
		incidentError(w, err)
		return
	}
	tr, err := s.store.Trace(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no evidence recorded for this incident")
		return
	}
	writeEnvelope(w, traceShape(tr, id))
}

func (s *Server) investigate(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Pipeline.Investigate(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, pipeline.ErrNoRun):
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		incidentError(w, err)
	default:
		writeEnvelope(w, rep)
	}
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Pipeline.Incidents.SetStatus(id, incident.StatusResolved); err != nil {
		incidentError(w, err)
		return
	}
	writeEnvelope(w, map[string]string{"id": id, "status": string(incident.StatusResolved)})
}

func incidentError(w http.ResponseWriter, err error) {
	if errors.Is(err, incident.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such incident")
		return
	}
	writeError(w, http.StatusInternalServerError, "internal error")
}

type statsView struct {
	Assembler      agentrun.Stats `json:"assembler"`
	NoContractRuns uint64         `json:"runsWithoutContract"`
	EvalFailures   uint64         `json:"evaluationFailures"`
}

func (s *Server) pipelineStats(w http.ResponseWriter, _ *http.Request) {
	writeEnvelope(w, statsView{Assembler: s.Pipeline.Stats(), NoContractRuns: s.Pipeline.NoContract.Load(), EvalFailures: s.Pipeline.EvalFailures.Load()})
}

// --- read-only tool gateway ---

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	writeEnvelope(w, s.Gateway.List(identity.From(r.Context())))
}

func (s *Server) callTool(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	res, err := s.Gateway.Call(r.Context(), identity.From(r.Context()), r.PathValue("name"), json.RawMessage(raw))
	switch {
	case err == nil:
		writeEnvelope(w, res)
	case errors.Is(err, gateway.ErrUnknownTool):
		writeError(w, http.StatusNotFound, "no such tool")
	case errors.Is(err, gateway.ErrDenied):
		writeError(w, http.StatusForbidden, "not permitted")
	case errors.Is(err, gateway.ErrRateLimited):
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
	case errors.Is(err, gateway.ErrInvalidArgs):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}
