// Package api is ACRA's read API (/v1) plus the local demo endpoints. It holds
// the live tickets, embeds the evidence store, and serves the console. Response
// shapes match the console's DATA (docs/04-api-and-schemas.md §1).
package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/model"
	"github.com/deepnavakoti/acra/internal/telemetry"
	"github.com/deepnavakoti/acra/internal/workload"
)

// Server holds live state. Starts empty (everything green) until a drift is
// injected — the demo arc.
type Server struct {
	mu          sync.Mutex
	store       *evidence.Store
	tickets     []model.Ticket
	seq         int
	consolePath string
}

func New(store *evidence.Store, consolePath string) *Server {
	return &Server{store: store, consolePath: consolePath, tickets: []model.Ticket{}}
}

// Routes registers all handlers.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /v1/snapshot", s.snapshot)
	mux.HandleFunc("GET /v1/tickets", s.listTickets)
	mux.HandleFunc("GET /v1/tickets/{id}", s.getTicket)
	mux.HandleFunc("GET /v1/evidence/{id}", s.getEvidence)
	mux.HandleFunc("POST /v1/demo/inject", s.inject)
	mux.HandleFunc("GET /", s.console)
	return mux
}

func (s *Server) console(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, s.consolePath)
}

// snapshot: the whole live view the console merges over its built-in seed —
// just the parts the gate owns (tickets + evidence). Other screens keep the seed.
func (s *Server) snapshot(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeEnvelope(w, map[string]any{
		"tickets":  s.tickets,
		"evidence": s.evidenceShape(),
	})
}

func (s *Server) listTickets(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeEnvelope(w, s.tickets)
}

func (s *Server) getTicket(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tickets {
		if t.ID == id {
			writeEnvelope(w, t)
			return
		}
	}
	writeError(w, http.StatusNotFound, "no such ticket")
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	tr, err := s.store.Trace(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeEnvelope(w, traceShape(tr, ""))
}

// inject runs a real drift through the real gate and records the ticket.
func (s *Server) inject(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()

	tk, err := workload.Generate(kind, s.store, seq)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.tickets = append([]model.Ticket{tk}, s.tickets...) // newest first
	s.mu.Unlock()
	telemetry.RecordGate(r.Context(), tk) // emit the proof span
	writeEnvelope(w, tk)
}

// evidenceShape maps each live ticket's trace into the console's evidence shape.
func (s *Server) evidenceShape() map[string]any {
	out := map[string]any{}
	for _, t := range s.tickets {
		if t.Evidence == "" {
			continue
		}
		tr, err := s.store.Trace(t.Evidence)
		if err != nil {
			continue
		}
		out[t.Evidence] = traceShape(tr, t.ID)
	}
	return out
}

func traceShape(tr model.Trace, task string) map[string]any {
	entries := make([][]string, 0, len(tr.Events))
	caller := ""
	for i, ev := range tr.Events {
		if i == 0 {
			caller = ev.Actor
		}
		entries = append(entries, []string{ev.TS.Format("15:04:05"), ev.Kind, ev.Detail})
	}
	return map[string]any{
		"task": task, "caller": caller, "bundle": "sha256:9f1c…",
		"chain": tr.Chain, "entries": entries,
	}
}

func writeEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"asOf": time.Now().UTC().Format(time.RFC3339),
		"data": data,
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": http.StatusText(code), "message": msg},
	})
}
