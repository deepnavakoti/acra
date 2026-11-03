// Package pipeline wires the reliability path together:
//
//	events -> Assembler -> contract.Evaluate -> incident.Store -> (optional) RCA
//
// Every stage is bounded and degrades to "unknown" or "not evaluated" rather
// than to a false pass.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepnavakoti/acra/internal/adapters"
	"github.com/deepnavakoti/acra/internal/agentrun"
	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/model"
	"github.com/deepnavakoti/acra/internal/rca"
)

// Config configures a Service.
type Config struct {
	Assembler agentrun.AssemblerConfig
	// RecentRuns bounds the in-memory run cache used by investigations.
	RecentRuns int
	// AutoInvestigate starts an investigation when a new high/medium-severity
	// incident opens. At most MaxInvestigations run concurrently.
	AutoInvestigate    bool
	MaxInvestigations  int
	InvestigateTimeout time.Duration
	Window             time.Duration // RCA time window either side of a run
}

// Service is the reliability pipeline.
type Service struct {
	cfg       Config
	Contracts *contract.Registry
	Incidents *incident.Store
	Judge     contract.Judge
	Engine    *rca.Engine
	Adapters  []adapters.Adapter
	Evidence  *evidence.Store // optional: anchors incident events in the signed chain

	asm *agentrun.Assembler
	sem chan struct{}

	mu    sync.Mutex
	runs  map[string]agentrun.Run // by traceID
	order []string
	wg    sync.WaitGroup

	NoContract   atomic.Uint64 // runs finalized with no contract to evaluate against
	EvalFailures atomic.Uint64
}

// New builds a Service. Contracts and Incidents are required.
func New(cfg Config, c *contract.Registry, inc *incident.Store) *Service {
	if cfg.RecentRuns <= 0 {
		cfg.RecentRuns = 1000
	}
	if cfg.MaxInvestigations <= 0 {
		cfg.MaxInvestigations = 4
	}
	if cfg.InvestigateTimeout <= 0 {
		cfg.InvestigateTimeout = 45 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.Assembler.MaxOpenRuns == 0 {
		cfg.Assembler = agentrun.DefaultAssemblerConfig()
	}
	s := &Service{cfg: cfg, Contracts: c, Incidents: inc, runs: map[string]agentrun.Run{},
		sem: make(chan struct{}, cfg.MaxInvestigations)}
	s.asm = agentrun.NewAssembler(cfg.Assembler, s.onRun)
	return s
}

// Ingest adds events. It returns how many were accepted and the first error
// encountered per rejected event (bounded to 20 messages). Backpressure is
// reported as agentrun.ErrBackpressure inside errs so callers can answer 429.
func (s *Service) Ingest(evs []agentrun.Event) (accepted int, errs []error) {
	for _, e := range evs {
		if err := s.asm.Add(e); err != nil {
			if len(errs) < 20 {
				errs = append(errs, err)
			}
			continue
		}
		accepted++
	}
	return accepted, errs
}

// Start runs the idle sweeper until ctx is cancelled.
func (s *Service) Start(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 15 * time.Second
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.asm.Sweep()
			}
		}
	}()
}

// Wait blocks until background workers finish (used on shutdown and in tests).
func (s *Service) Wait() { s.wg.Wait() }

// Stats exposes assembler counters.
func (s *Service) Stats() agentrun.Stats { return s.asm.Stats() }

// Sweep finalizes idle runs now.
func (s *Service) Sweep() int { return s.asm.Sweep() }

func (s *Service) onRun(run agentrun.Run) {
	s.remember(run)
	c, ok := s.Contracts.Get(run.AgentID, run.ContractVersion)
	if !ok {
		// No contract: nothing is claimed about this run. It is counted so the
		// gap is visible, never recorded as a pass.
		s.NoContract.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ev := contract.Evaluate(ctx, c, run, s.Judge, time.Now())
	inc, created, err := s.Incidents.RecordEvaluation(ev)
	if err != nil {
		s.EvalFailures.Add(1)
		log.Printf("pipeline: record evaluation for trace %s: %v", run.TraceID, err)
		return
	}
	if inc == nil || !created {
		return
	}
	s.anchor(inc.ID, "incident.opened", fmt.Sprintf("agent=%s severity=%s rules=%v", inc.AgentID, inc.Severity, inc.Rules))
	if s.cfg.AutoInvestigate && s.Engine != nil && (inc.Severity == "high" || inc.Severity == "medium") {
		s.goInvestigate(inc.ID)
	}
}

func (s *Service) remember(run agentrun.Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[run.TraceID]; !ok {
		s.order = append(s.order, run.TraceID)
	}
	s.runs[run.TraceID] = run
	for len(s.order) > s.cfg.RecentRuns {
		delete(s.runs, s.order[0])
		s.order = s.order[1:]
	}
}

// Run returns a recently completed run.
func (s *Service) Run(traceID string) (agentrun.Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[traceID]
	return r, ok
}

func (s *Service) goInvestigate(id string) {
	select {
	case s.sem <- struct{}{}:
	default:
		return // saturated: the incident stays open and can be investigated on demand
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.InvestigateTimeout)
		defer cancel()
		if _, err := s.Investigate(ctx, id); err != nil {
			log.Printf("pipeline: investigate %s: %v", id, err)
		}
	}()
}

// ErrNoRun is returned when the run behind an incident is no longer cached.
var ErrNoRun = errors.New("pipeline: run no longer cached; cannot investigate")

// Investigate runs RCA for an incident using its most recent trace, stores the
// report on the incident and anchors a summary in the evidence chain.
func (s *Service) Investigate(ctx context.Context, id string) (rca.Report, error) {
	if s.Engine == nil {
		return rca.Report{}, errors.New("pipeline: no RCA engine configured")
	}
	inc, err := s.Incidents.Get(id)
	if err != nil {
		return rca.Report{}, err
	}
	if len(inc.TraceIDs) == 0 {
		return rca.Report{}, ErrNoRun
	}
	trace := inc.TraceIDs[len(inc.TraceIDs)-1]
	run, ok := s.Run(trace)
	if !ok {
		return rca.Report{}, ErrNoRun
	}
	evals, err := s.Incidents.Evaluations(inc.AgentID, 50)
	if err != nil {
		return rca.Report{}, err
	}
	var ev *contract.Evaluation
	for i := range evals {
		if evals[i].TraceID == trace {
			ev = &evals[i]
			break
		}
	}
	if ev == nil {
		return rca.Report{}, errors.New("pipeline: evaluation for incident trace not found")
	}
	if inc.Status == incident.StatusOpen {
		_ = s.Incidents.SetStatus(id, incident.StatusInvestigating)
	}
	rep := s.Engine.Investigate(ctx, rca.Input{
		IncidentID: id, Run: run, Evaluation: *ev, Adapters: s.Adapters, Window: s.cfg.Window,
		Service: serviceOf(run), Namespace: namespaceOf(run),
	})
	raw, err := json.Marshal(rep)
	if err != nil {
		return rep, err
	}
	if err := s.Incidents.SetInvestigation(id, raw); err != nil {
		return rep, err
	}
	top := "unknown"
	if len(rep.Hypotheses) > 0 {
		top = string(rep.Hypotheses[0].Cause)
	}
	s.anchor(id, "incident.investigated", fmt.Sprintf("state=%s top=%s unknowns=%d", rep.State, top, len(rep.Unknowns)))
	return rep, nil
}

func serviceOf(r agentrun.Run) string {
	for _, e := range r.Events {
		if e.Service != "" {
			return e.Service
		}
	}
	return ""
}

// namespaceOf returns the Kubernetes namespace the run reported (attribute
// k8s.namespace.name). Empty when the telemetry did not carry one, in which case
// the k8s adapter reports an error and the RCA records the source as unavailable.
func namespaceOf(r agentrun.Run) string {
	for _, e := range r.Events {
		if ns := e.Attrs["k8s.namespace.name"]; ns != "" {
			return ns
		}
	}
	return ""
}

func (s *Service) anchor(incidentID, kind, detail string) {
	if s.Evidence == nil {
		return
	}
	if _, err := s.Evidence.Append(model.Event{TraceID: incidentID, Kind: kind, Actor: "acra.pipeline", Detail: detail}); err != nil {
		log.Printf("pipeline: anchor %s: %v", incidentID, err)
	}
}
