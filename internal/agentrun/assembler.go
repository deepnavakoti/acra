package agentrun

import (
	"fmt"
	"sync"
	"time"
)

// AssemblerConfig bounds the assembler's memory and sets completion behavior.
type AssemblerConfig struct {
	IdleTimeout     time.Duration // finalize a run with no new events after this long
	MaxOpenRuns     int           // hard cap on concurrently open runs (backpressure)
	MaxEventsPerRun int           // events beyond this are dropped and counted
	TombstoneTTL    time.Duration // how long a completed run suppresses late duplicates
}

// DefaultAssemblerConfig returns conservative defaults.
func DefaultAssemblerConfig() AssemblerConfig {
	return AssemblerConfig{
		IdleTimeout: 2 * time.Minute, MaxOpenRuns: 10000,
		MaxEventsPerRun: 2000, TombstoneTTL: 10 * time.Minute,
	}
}

// Stats are monotonic counters for ingestion health (exposed for metrics).
type Stats struct {
	Accepted, Duplicates, DroppedFull, DroppedLate, DroppedOverflow, Completed, IdleFinalized uint64
}

type entry struct {
	run      Run
	seen     map[string]struct{}
	lastSeen time.Time
}

// Assembler correlates events into Runs. It is safe for concurrent use and is
// tolerant of the delivery problems real telemetry has: at-least-once delivery
// (duplicates are dropped), out-of-order arrival (events are sorted on
// completion) and clock skew (ordering falls back to arrival order).
// Runs are keyed by tenant first, so tenants can never share a Run.
type Assembler struct {
	cfg        AssemblerConfig
	onComplete func(Run)
	now        func() time.Time

	mu         sync.Mutex
	open       map[string]*entry
	tombstones map[string]time.Time
	stats      Stats
}

// NewAssembler builds an Assembler; onComplete is called (outside the lock)
// once per finished Run.
func NewAssembler(cfg AssemblerConfig, onComplete func(Run)) *Assembler {
	d := DefaultAssemblerConfig()
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = d.IdleTimeout
	}
	if cfg.MaxOpenRuns <= 0 {
		cfg.MaxOpenRuns = d.MaxOpenRuns
	}
	if cfg.MaxEventsPerRun <= 0 {
		cfg.MaxEventsPerRun = d.MaxEventsPerRun
	}
	if cfg.TombstoneTTL <= 0 {
		cfg.TombstoneTTL = d.TombstoneTTL
	}
	return &Assembler{
		cfg: cfg, onComplete: onComplete, now: time.Now,
		open: map[string]*entry{}, tombstones: map[string]time.Time{},
	}
}

// ErrBackpressure is returned when the assembler is full; callers should retry
// later (HTTP 429/503) rather than block the producing agent.
var ErrBackpressure = fmt.Errorf("agentrun: assembler at capacity")

func runKey(e Event) string {
	id := e.AgentRunID
	if id == "" {
		id = e.TraceID + "|" + e.AgentID
	}
	return e.TenantID + "|" + id
}

func eventKey(e Event) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d", e.TraceID, e.SpanID, e.Kind, e.Name, e.ToolCallID, e.ModelCallID, e.Attempt)
}

// Add validates and records one event. A final agent.response completes the run.
func (a *Assembler) Add(ev Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	key := runKey(ev)

	a.mu.Lock()
	if t, ok := a.tombstones[key]; ok && a.now().Sub(t) < a.cfg.TombstoneTTL {
		a.stats.DroppedLate++
		a.mu.Unlock()
		return nil // late event for a finished run: dropped, not an error
	}
	en, ok := a.open[key]
	if !ok {
		if len(a.open) >= a.cfg.MaxOpenRuns {
			a.stats.DroppedFull++
			a.mu.Unlock()
			return ErrBackpressure
		}
		en = &entry{
			run: Run{
				TraceID: ev.TraceID, AgentRunID: ev.AgentRunID, AgentID: ev.AgentID,
				TenantID: ev.TenantID, ContractVersion: ev.ContractVersion,
			},
			seen: map[string]struct{}{},
		}
		a.open[key] = en
	}
	// Spans without an id can legitimately repeat, so they are never deduped.
	if ev.SpanID != "" {
		k := eventKey(ev)
		if _, dup := en.seen[k]; dup {
			a.stats.Duplicates++
			a.mu.Unlock()
			return nil
		}
		en.seen[k] = struct{}{}
	}
	if len(en.run.Events) >= a.cfg.MaxEventsPerRun {
		a.stats.DroppedOverflow++
		a.mu.Unlock()
		return nil
	}
	if en.run.ContractVersion == "" {
		en.run.ContractVersion = ev.ContractVersion
	}
	en.run.Events = append(en.run.Events, ev)
	en.lastSeen = a.now()
	a.stats.Accepted++

	var done *Run
	if ev.Kind == KindResponse {
		r := en.run
		r.Complete = true
		done = &r
		delete(a.open, key)
		a.tombstones[key] = a.now()
		a.stats.Completed++
	}
	a.mu.Unlock()

	if done != nil {
		a.finish(*done)
	}
	return nil
}

// Sweep finalizes idle runs and expires old tombstones. Call it periodically.
// Idle runs are delivered with Incomplete=true: ACRA never pretends a run that
// never produced a response was complete.
func (a *Assembler) Sweep() int {
	now := a.now()
	var idle []Run
	a.mu.Lock()
	for k, en := range a.open {
		if now.Sub(en.lastSeen) >= a.cfg.IdleTimeout {
			r := en.run
			r.Incomplete = true
			idle = append(idle, r)
			delete(a.open, k)
			a.tombstones[k] = now
			a.stats.IdleFinalized++
		}
	}
	for k, t := range a.tombstones {
		if now.Sub(t) >= a.cfg.TombstoneTTL {
			delete(a.tombstones, k)
		}
	}
	a.mu.Unlock()
	for _, r := range idle {
		a.finish(r)
	}
	return len(idle)
}

// Stats returns a snapshot of the counters.
func (a *Assembler) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}

// Open returns the number of runs currently being assembled.
func (a *Assembler) Open() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.open)
}

func (a *Assembler) finish(r Run) {
	sortEvents(r.Events)
	if a.onComplete != nil {
		a.onComplete(r)
	}
}
