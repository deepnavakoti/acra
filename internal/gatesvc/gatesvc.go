// Package gatesvc is the HTTP front of the gate: POST /v1/gate/evaluate runs the
// real detector set and returns ADMIT or HOLD.
//
// Trust model: the caller supplies the WRITE (what it wants to do) but never the
// POLICY (what is approved) or the epoch fence; those are server-side. A caller
// therefore cannot approve its own tuple. The service fails closed: malformed
// input, an unloadable policy or an internal error all yield HOLD (HTTP 200
// with verdict HOLD for decisions; 4xx/5xx for requests that were not decisions
// and must not be treated as ADMIT by clients).
package gatesvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/model"
)

// PolicyFile is the on-disk policy (JSON).
type PolicyFile struct {
	ApprovedTuples      []model.Tuple `json:"approvedTuples"`
	Invariants          []string      `json:"invariants"`
	MinIndependentRoots int           `json:"minIndependentRoots"`
	DriftMagnitude      int           `json:"driftMagnitude"`
}

// LoadPolicy reads and validates a policy file. An empty approved set is refused:
// it would hold everything (safe) but is almost certainly a misconfiguration.
func LoadPolicy(path string) (gate.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return gate.Policy{}, err
	}
	var pf PolicyFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return gate.Policy{}, fmt.Errorf("gate policy: %w", err)
	}
	if len(pf.ApprovedTuples) == 0 {
		return gate.Policy{}, errors.New("gate policy: approvedTuples is empty")
	}
	if pf.MinIndependentRoots < 1 {
		pf.MinIndependentRoots = 2
	}
	return gate.Policy{ApprovedTuples: pf.ApprovedTuples, Invariants: pf.Invariants,
		MinIndependentRoots: pf.MinIndependentRoots, DriftMagnitude: pf.DriftMagnitude}, nil
}

// Service evaluates writes.
type Service struct {
	Policy    gate.Policy
	Detectors []gate.Detector
	Auth      *identity.Authenticator
	Evidence  *evidence.Store // optional: every decision is anchored
	Epochs    EpochStore      // epoch fence; defaults to in-memory
}

// New returns a Service with an in-memory epoch store.
func New(p gate.Policy, dets []gate.Detector, auth *identity.Authenticator, ev *evidence.Store) *Service {
	return &Service{Policy: p, Detectors: dets, Auth: auth, Evidence: ev, Epochs: NewMemoryEpochs()}
}

const epochTimeout = 2 * time.Second

// Routes registers handlers.
func (s *Service) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /v1/gate/evaluate", s.Auth.Require(identity.RoleIngest, s.evaluate))
	mux.HandleFunc("PUT /v1/gate/epochs/{task}", s.Auth.Require(identity.RoleAdmin, s.setEpoch))
	return mux
}

type lineage struct {
	Nodes []struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"` // root | derived
		Provider string `json:"provider,omitempty"`
	} `json:"nodes"`
	Edges []struct {
		Child  string `json:"child"`
		Parent string `json:"parent"`
	} `json:"edges"`
}

// Request is the body of POST /v1/gate/evaluate.
type Request struct {
	Task           string       `json:"task"`
	Epoch          int          `json:"epoch"`
	Tuple          model.Tuple  `json:"tuple"`
	Claims         []string     `json:"claims"`
	Lineage        *lineage     `json:"lineage,omitempty"`
	PromotesStatus bool         `json:"promotesStatus"`
	Subject        string       `json:"subject"`
	NewStatus      string       `json:"newStatus"`
	Signals        gate.Signals `json:"signals"`
}

const (
	maxBody  = 1 << 20
	maxNodes = 5000
)

func (s *Service) evaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var req Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	if req.Task == "" {
		writeErr(w, http.StatusBadRequest, "task is required")
		return
	}
	wr := gate.Write{Task: req.Task, Epoch: req.Epoch, Tuple: req.Tuple, Claims: req.Claims,
		PromotesStatus: req.PromotesStatus, Subject: req.Subject, NewStatus: req.NewStatus, Signals: req.Signals}
	if req.Lineage != nil {
		if len(req.Lineage.Nodes)+len(req.Lineage.Edges) > maxNodes {
			writeErr(w, http.StatusBadRequest, "lineage too large")
			return
		}
		g := evidence.NewGraph()
		for _, n := range req.Lineage.Nodes {
			kind := evidence.Derived
			switch n.Kind {
			case "root":
				kind = evidence.Root
			case "derived", "":
			default:
				writeErr(w, http.StatusBadRequest, "lineage node kind must be root or derived")
				return
			}
			g.AddNode(evidence.Node{ID: n.ID, Kind: kind, Provider: n.Provider})
		}
		for _, e := range req.Lineage.Edges {
			g.AddEdge(e.Child, e.Parent)
		}
		wr.Graph = g
	}

	env := gate.Env{CurrentEpoch: s.currentEpoch}
	res := gate.Evaluate(wr, s.Policy, env, s.Detectors)
	if s.Evidence != nil {
		_, _ = s.Evidence.Append(model.Event{TraceID: "gate-" + req.Task, Kind: "gate", Actor: identity.From(r.Context()).ID,
			Detail: fmt.Sprintf("verdict=%s detector=%s reason=%s", res.Verdict, res.Detector, res.Reason)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": res})
}

// currentEpoch fails closed: if the store cannot answer, the fence is set to the
// maximum so every write is held rather than admitted against an unknown epoch.
func (s *Service) currentEpoch(task string) int {
	ctx, cancel := context.WithTimeout(context.Background(), epochTimeout)
	defer cancel()
	n, err := s.Epochs.Get(ctx, task)
	if err != nil {
		log.Printf("gate: epoch store error, holding write: %v", err)
		return math.MaxInt
	}
	return n
}

func (s *Service) setEpoch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var b struct {
		Epoch int `json:"epoch"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || b.Epoch < 0 {
		writeErr(w, http.StatusBadRequest, "body must be {\"epoch\": <non-negative integer>}")
		return
	}
	task := r.PathValue("task")
	if err := checkTask(task); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), epochTimeout)
	defer cancel()
	cur, ok, err := s.Epochs.Advance(ctx, task, b.Epoch)
	if err != nil {
		log.Printf("gate: epoch store error: %v", err)
		writeErr(w, http.StatusServiceUnavailable, "epoch store unavailable; epoch not changed")
		return
	}
	if !ok { // a fence only moves forward
		writeErr(w, http.StatusConflict, fmt.Sprintf("epoch may not decrease (current %d)", cur))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"task": task, "epoch": b.Epoch}})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": http.StatusText(code), "message": msg}})
}
