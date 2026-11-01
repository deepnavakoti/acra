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
		return b.Put(seqKey(ev.Seq), buf)
	})
	return ev, err
}

// Trace returns one trace: its events in order plus whether the chain verifies.
func (s *Store) Trace(traceID string) (model.Trace, error) {
	tr := model.Trace{TraceID: traceID, Chain: "broken"}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(traceID))
		if b == nil {
			return fmt.Errorf("evidence: no trace %q", traceID)
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
		return tr, err
	}
	if ok, _ := s.verify(tr.Events); ok {
		tr.Chain = "intact"
	}
	return tr, nil
}

// Verify re-checks every signature and every chain link for a trace.
func (s *Store) Verify(traceID string) (bool, error) {
	tr, err := s.Trace(traceID)
	if err != nil {
		return false, err
	}
	return s.verify(tr.Events)
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
