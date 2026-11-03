// Package incident turns failed contract evaluations into deduplicated,
// durable incidents. Repeated failures of the same kind for the same agent fold
// into one incident (with a counter) instead of paging a human per occurrence.
package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deepnavakoti/acra/internal/contract"
)

// Status is the incident lifecycle.
type Status string

const (
	StatusOpen          Status = "open"
	StatusInvestigating Status = "investigating"
	StatusResolved      Status = "resolved"
)

const maxTraces = 25

// Incident is one deduplicated problem with one agent.
type Incident struct {
	ID              string          `json:"id"`
	AgentID         string          `json:"agentId"`
	TenantID        string          `json:"tenantId,omitempty"`
	Fingerprint     string          `json:"fingerprint"`
	Rules           []string        `json:"rules"`
	Severity        string          `json:"severity"`
	Status          Status          `json:"status"`
	Summary         string          `json:"summary"`
	ContractVersion string          `json:"contractVersion"`
	FirstSeen       time.Time       `json:"firstSeen"`
	LastSeen        time.Time       `json:"lastSeen"`
	Count           int             `json:"count"`
	TraceIDs        []string        `json:"traceIds"`
	Unknown         bool            `json:"unknown,omitempty"` // opened only on undecidable results
	Investigation   json.RawMessage `json:"investigation,omitempty"`
}

var sevRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// Fingerprint identifies "the same problem": agent + the set of violated rules.
// Rule indexes (e.g. forbidden[2]) are kept; trace ids and values never enter it.
func Fingerprint(agentID string, e contract.Evaluation) (string, []string) {
	seen := map[string]bool{}
	var rules []string
	for _, v := range e.Violations {
		if !seen[v.Rule] {
			seen[v.Rule] = true
			rules = append(rules, v.Rule)
		}
	}
	sort.Strings(rules)
	h := sha256.Sum256([]byte(agentID + "|" + strings.Join(rules, ",")))
	return hex.EncodeToString(h[:8]), rules
}

// Store persists incidents and evaluations in bbolt, with an in-memory index.
type Store struct {
	db  *bolt.DB
	mu  sync.Mutex
	now func() time.Time
	seq uint64
}

var (
	bIncidents = []byte("incidents")
	bFPIndex   = []byte("fp-index") // tenant|fingerprint -> incident id (only for non-resolved)
	bEvals     = []byte("evaluations")
)

// Open opens (or creates) the incident database.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bIncidents, bFPIndex, bEvals} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		s.seq = tx.Bucket(bIncidents).Sequence()
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// RecordEvaluation stores the evaluation and, when it did not pass, opens or
// updates the matching incident. It returns the incident (nil on pass) and
// whether it was newly created.
func (s *Store) RecordEvaluation(e contract.Evaluation) (*Incident, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out *Incident
	created := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bEvals).Put([]byte(e.AgentID+"|"+e.EvaluatedAt.UTC().Format(time.RFC3339Nano)+"|"+e.TraceID), raw); err != nil {
			return err
		}
		if e.Status == contract.StatusPass {
			return nil
		}
		fp, rules := Fingerprint(e.AgentID, e)
		idxKey := []byte(fp)
		var inc Incident
		if id := tx.Bucket(bFPIndex).Get(idxKey); id != nil {
			if v := tx.Bucket(bIncidents).Get(id); v != nil {
				if err := json.Unmarshal(v, &inc); err != nil {
					return err
				}
			}
		}
		if inc.ID == "" {
			n, err := tx.Bucket(bIncidents).NextSequence()
			if err != nil {
				return err
			}
			inc = Incident{
				ID: fmt.Sprintf("INC-%05d", n), AgentID: e.AgentID, Fingerprint: fp, Rules: rules,
				Status: StatusOpen, FirstSeen: e.EvaluatedAt, ContractVersion: e.Version,
			}
			created = true
		}
		inc.LastSeen = e.EvaluatedAt
		inc.Count++
		inc.Severity, inc.Summary, inc.Unknown = summarize(e, inc.Severity)
		if inc.Status == StatusResolved { // regression: reopen
			inc.Status = StatusOpen
		}
		if !contains(inc.TraceIDs, e.TraceID) {
			inc.TraceIDs = append(inc.TraceIDs, e.TraceID)
			if len(inc.TraceIDs) > maxTraces {
				inc.TraceIDs = inc.TraceIDs[len(inc.TraceIDs)-maxTraces:]
			}
		}
		buf, err := json.Marshal(inc)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bIncidents).Put([]byte(inc.ID), buf); err != nil {
			return err
		}
		out = &inc
		return tx.Bucket(bFPIndex).Put(idxKey, []byte(inc.ID))
	})
	return out, created, err
}

func summarize(e contract.Evaluation, prev string) (sev, summary string, unknownOnly bool) {
	sev = prev
	unknownOnly = true
	var first string
	for _, v := range e.Violations {
		if v.Status == "violated" {
			unknownOnly = false
		}
		if first == "" || (v.Status == "violated" && !strings.HasPrefix(first, "violated:")) {
			first = v.Status + ":" + v.Message
		}
		if sevRank[v.Severity] > sevRank[sev] {
			sev = v.Severity
		}
	}
	if sev == "" {
		sev = "low"
	}
	if i := strings.IndexByte(first, ':'); i >= 0 {
		first = first[i+1:]
	}
	return sev, fmt.Sprintf("%d rule(s) %s: %s", len(e.Violations), map[bool]string{true: "undecidable", false: "violated"}[unknownOnly], first), unknownOnly
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Get returns one incident.
func (s *Store) Get(id string) (Incident, error) {
	var inc Incident
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bIncidents).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &inc)
	})
	return inc, err
}

// ErrNotFound is returned for unknown incident ids.
var ErrNotFound = errors.New("incident: not found")

// List returns incidents, newest activity first. A non-empty status filters.
func (s *Store) List(status Status) ([]Incident, error) {
	var out []Incident
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bIncidents).ForEach(func(_, v []byte) error {
			var inc Incident
			if err := json.Unmarshal(v, &inc); err != nil {
				return err
			}
			if status == "" || inc.Status == status {
				out = append(out, inc)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, err
}

// SetInvestigation stores an investigation report and moves the incident to
// Investigating.
func (s *Store) SetInvestigation(id string, report json.RawMessage) error {
	return s.update(id, func(i *Incident) error {
		i.Investigation = report
		if i.Status == StatusOpen {
			i.Status = StatusInvestigating
		}
		return nil
	})
}

// SetStatus changes lifecycle state.
func (s *Store) SetStatus(id string, st Status) error {
	switch st {
	case StatusOpen, StatusInvestigating, StatusResolved:
	default:
		return fmt.Errorf("incident: invalid status %q", st)
	}
	return s.update(id, func(i *Incident) error { i.Status = st; return nil })
}

func (s *Store) update(id string, fn func(*Incident) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bIncidents).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		var inc Incident
		if err := json.Unmarshal(v, &inc); err != nil {
			return err
		}
		if err := fn(&inc); err != nil {
			return err
		}
		buf, err := json.Marshal(inc)
		if err != nil {
			return err
		}
		if inc.Status == StatusResolved {
			_ = tx.Bucket(bFPIndex).Delete([]byte(inc.Fingerprint))
		} else {
			_ = tx.Bucket(bFPIndex).Put([]byte(inc.Fingerprint), []byte(inc.ID))
		}
		return tx.Bucket(bIncidents).Put([]byte(id), buf)
	})
}

// Evaluations returns recent evaluations for an agent (newest first), up to limit.
func (s *Store) Evaluations(agentID string, limit int) ([]contract.Evaluation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []contract.Evaluation
	prefix := []byte(agentID + "|")
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bEvals).Cursor()
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var e contract.Evaluation
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].EvaluatedAt.After(out[j].EvaluatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, err
}
