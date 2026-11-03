package gateway

import (
	"fmt"
	"sync"

	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/model"
)

// EvidenceAuditor writes gateway audit records into the signed, hash-chained
// evidence store (trace "gateway-audit"), so the audit trail is tamper-evident
// like everything else ACRA proves. It also keeps a bounded in-memory tail.
type EvidenceAuditor struct {
	Store *evidence.Store

	mu   sync.Mutex
	tail []AuditRecord
}

// AuditTrace is the evidence trace id used for gateway audit.
const AuditTrace = "gateway-audit"

// Record implements Auditor. A failure to persist never blocks the call; it is
// kept in the in-memory tail so it is not silently lost.
func (a *EvidenceAuditor) Record(r AuditRecord) {
	a.mu.Lock()
	a.tail = append(a.tail, r)
	if len(a.tail) > 200 {
		a.tail = a.tail[len(a.tail)-200:]
	}
	a.mu.Unlock()
	if a.Store == nil {
		return
	}
	_, _ = a.Store.Append(model.Event{
		TraceID: AuditTrace, Kind: "gateway.call", Actor: r.Principal,
		Detail: fmt.Sprintf("tool=%s outcome=%s args=%s dur=%s", r.Tool, r.Outcome, r.ArgsHash, r.Duration),
	})
}

// Tail returns the most recent audit records.
func (a *EvidenceAuditor) Tail() []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditRecord(nil), a.tail...)
}
