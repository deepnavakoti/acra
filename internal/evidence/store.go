// Package evidence is ACRA's append-only, signed evidence chain plus the
// lineage graph used to compute independence (docs/03-core-specs.md §2,
// docs/04-api-and-schemas.md §3).
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deepnavakoti/acra/internal/model"
)

// Store is an append-only evidence chain backed by bbolt. Each trace is its own
// bucket; events within a trace chain by PrevHash and are individually signed.
type Store struct {
	db   *bolt.DB
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// metaBucket holds one anchor per trace: the last sequence number and head
// hash. verify() alone cannot see deleted tail events (every remaining link and
// signature is still valid), so Trace() cross-checks the chain against this
// anchor and reports "broken" on any mismatch or missing anchor (fail closed).
var metaBucket = []byte("\x00acra-anchor")

type anchor struct {
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}

// signedPayload is the exact set of fields a signature covers. Field order is
// fixed (struct order) so the JSON encoding is deterministic.
type signedPayload struct {
	Seq      int       `json:"seq"`
	TS       time.Time `json:"ts"`
	Kind     string    `json:"kind"`
	Actor    string    `json:"actor"`
	Detail   string    `json:"detail"`
	PrevHash string    `json:"prevHash"`
}

// Open opens (or creates) a store at path, signing with priv.
func Open(path string, priv ed25519.PrivateKey) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	return &Store{db: db, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Close closes the underlying db.
func (s *Store) Close() error { return s.db.Close() }

// Append adds an event to its trace. It assigns Seq, sets TS if zero, links
// PrevHash to the previous event in the trace, and signs. The stored event is
// returned.
func (s *Store) Append(ev model.Event) (model.Event, error) {
	if ev.TraceID == "" {
		return ev, fmt.Errorf("evidence: event has no traceId")
	}
	if ev.TraceID == string(metaBucket) {
		return ev, fmt.Errorf("evidence: reserved traceId")
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(ev.TraceID))
		if err != nil {
			return err
		}
		// previous event (highest seq), for the chain link
		prevHash := ""
		nextSeq := 1
		if k, v := b.Cursor().Last(); k != nil {
			var prev model.Event
			if err := json.Unmarshal(v, &prev); err != nil {
				return err
			}
			prevHash = eventHash(prev)
			nextSeq = prev.Seq + 1
		}
		ev.Seq = nextSeq
		ev.PrevHash = prevHash
		sig := ed25519.Sign(s.priv, payloadBytes(ev))
		ev.Sig = "ed25519:" + hex.EncodeToString(sig)
		buf, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if err := b.Put(seqKey(ev.Seq), buf); err != nil {
			return err
		}
		mb, err := tx.CreateBucketIfNotExists(metaBucket)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(anchor{Seq: ev.Seq, Head: eventHash(ev)})
		if err != nil {
			return err
		}
		return mb.Put([]byte(ev.TraceID), raw)
	})
	return ev, err
}

// Trace returns one trace: its events in order plus whether the chain verifies.
func (s *Store) Trace(traceID string) (model.Trace, error) {
	tr, _, err := s.load(traceID)
	return tr, err
}

// load reads a trace and its anchor verdict. The returned error is the reason
// the chain is not intact (nil when intact); the second return value of the
// outer signature is the lookup error.
func (s *Store) load(traceID string) (model.Trace, error, error) {
	tr := model.Trace{TraceID: traceID, Chain: "broken"}
	if traceID == "" || traceID == string(metaBucket) {
		return tr, nil, fmt.Errorf("evidence: invalid traceId")
	}
	var anc *anchor
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(traceID))
		if b == nil {
			return fmt.Errorf("evidence: no trace %q", traceID)
		}
		if mb := tx.Bucket(metaBucket); mb != nil {
			if raw := mb.Get([]byte(traceID)); raw != nil {
				var a anchor
				if json.Unmarshal(raw, &a) == nil {
					anc = &a
				}
			}
		}
		return b.ForEach(func(_, v []byte) error {
			var ev model.Event
			if err := json.Unmarshal(v, &ev); err != nil {
				return err
			}
			tr.Events = append(tr.Events, ev)
			return nil
		})
	})
	if err != nil {
		return tr, nil, err
	}
	if anc != nil {
		tr.Bundle = "sha256:" + anc.Head
	}
	broken := s.verifyAnchored(tr.Events, anc)
	if broken == nil {
		tr.Chain = "intact"
	}
	return tr, broken, nil
}

// Verify re-checks every signature, every chain link, and the anchored head and
// length for a trace (so deleted tail events are detected too).
func (s *Store) Verify(traceID string) (bool, error) {
	tr, broken, err := s.load(traceID)
	if err != nil {
		return false, err
	}
	return tr.Chain == "intact", broken
}

func (s *Store) verifyAnchored(events []model.Event, anc *anchor) error {
	if ok, err := s.verify(events); !ok {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("evidence: empty trace")
	}
	if anc == nil {
		return fmt.Errorf("evidence: missing anchor (possible truncation)")
	}
	if anc.Seq != len(events) {
		return fmt.Errorf("evidence: anchor expects %d events, found %d (truncated)", anc.Seq, len(events))
	}
	if anc.Head != eventHash(events[len(events)-1]) {
		return fmt.Errorf("evidence: head hash does not match anchor")
	}
	return nil
}

func (s *Store) verify(events []model.Event) (bool, error) {
	prevHash := ""
	for i, ev := range events {
		if ev.Seq != i+1 {
			return false, fmt.Errorf("evidence: seq gap at %d", i)
		}
		if ev.PrevHash != prevHash {
			return false, fmt.Errorf("evidence: broken link at seq %d", ev.Seq)
		}
		sigHex, ok := cutPrefix(ev.Sig, "ed25519:")
		if !ok {
			return false, fmt.Errorf("evidence: bad sig format at seq %d", ev.Seq)
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return false, err
		}
		if !ed25519.Verify(s.pub, payloadBytes(ev), sig) {
			return false, fmt.Errorf("evidence: bad signature at seq %d", ev.Seq)
		}
		prevHash = eventHash(ev)
	}
	return true, nil
}

// --- helpers ---

func payloadBytes(ev model.Event) []byte {
	p := signedPayload{Seq: ev.Seq, TS: ev.TS, Kind: ev.Kind, Actor: ev.Actor, Detail: ev.Detail, PrevHash: ev.PrevHash}
	b, _ := json.Marshal(p)
	return b
}

// eventHash chains events: it covers the signed payload plus the signature.
func eventHash(ev model.Event) string {
	h := sha256.New()
	h.Write(payloadBytes(ev))
	h.Write([]byte(ev.Sig))
	return hex.EncodeToString(h.Sum(nil))
}

func seqKey(seq int) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, uint64(seq))
	return k
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}
