// Package model holds ACRA's shared domain types — the frozen contract that
// every component builds against (see docs/04-api-and-schemas.md).
// These are plain Go types with no Kubernetes dependency on purpose: the gate,
// evidence store, api server and workload all speak them.
package model

import "time"

// Tuple is a running bundle: the four things that together must be approved
// before an agent's write may produce an effect. Combinative drift = a Tuple
// whose every element is individually valid but whose combination was never
// approved (see docs/03-core-specs.md §1).
type Tuple struct {
	Prompt   string `json:"prompt"`
	Manifest string `json:"manifest"` // tool manifest version
	Ruleset  string `json:"ruleset"`
	Formula  string `json:"formula"`
}

// Severity of a ticket/finding.
type Severity string

const (
	SevCrit Severity = "crit"
	SevWarn Severity = "warn"
)

// Layer is the domain a drift belongs to.
type Layer string

const (
	LayerExecution     Layer = "Execution"
	LayerContext       Layer = "Context"
	LayerAuthority     Layer = "Authority"
	LayerEvidence      Layer = "Evidence"
	LayerEffect        Layer = "Effect"
	LayerCompatibility Layer = "Compatibility"
)

// Verdict is the only thing the gate returns. The gate checks; it never decides
// an outcome, signs, or edits a record (invariant 5).
type Verdict string

const (
	Admit Verdict = "ADMIT"
	Hold  Verdict = "HOLD"
)

// GateResult is the gate's answer for one consequential write.
type GateResult struct {
	Verdict    Verdict `json:"verdict"`
	Reason     string  `json:"reason,omitempty"`     // invariant/detector that held it
	Detector   string  `json:"detector,omitempty"`   // e.g. "acra.c2"
	Magnitude  string  `json:"magnitude,omitempty"`  // one of the three numbers
	Confidence float64 `json:"confidence,omitempty"` // z-score mapped to 0..1
	Radius     string  `json:"radius,omitempty"`     // blast radius
}

// Event is one durable, signed entry in the evidence chain (append-only).
// Events chain by PrevHash; Sig signs {Seq,TS,Kind,Actor,Detail,PrevHash}.
type Event struct {
	TraceID  string    `json:"traceId"`
	Seq      int       `json:"seq"`
	TS       time.Time `json:"ts"`
	Kind     string    `json:"kind"` // dispatch|kong|model|tool|kernel|agent|gate|ticket
	Actor    string    `json:"actor"`
	Detail   string    `json:"detail"`
	PrevHash string    `json:"prevHash"`
	Sig      string    `json:"sig"`
}

// Trace is the full evidence for one task — what GET /v1/evidence/{id} returns.
type Trace struct {
	TraceID string  `json:"traceId"`
	Task    string  `json:"task"`
	Caller  string  `json:"caller"`
	Bundle  string  `json:"bundle"`
	Chain   string  `json:"chain"` // "intact" | "broken"
	Events  []Event `json:"entries"`
}

// Lineage supports the independence computation (docs/03 §2).
// Independence = count of DISTINCT roots, never the cite count. A derived
// artifact (summary, memory-index hit, an agent's own prior output) is never a
// root, however many times it is cited.
type Lineage struct {
	Claim        string   `json:"claim"`
	Edges        []string `json:"edges"`        // "source→source"
	Roots        []string `json:"roots"`        // distinct origin docs / provider receipts
	CitedCount   int      `json:"citedCount"`   // NOT independence
	Independence int      `json:"independence"` // = len(distinct Roots)
}

// Hypothesis is a cause proposed by the read-only LLM investigator. It can
// never change budgets, policies, routes or records.
type Hypothesis struct {
	Confidence float64 `json:"c"`
	Text       string  `json:"t"`
}

// Action is a proposed remediation. Band "pre-approved" may be rule-signed;
// "human" requires a human signature.
type Action struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
	Radius string            `json:"radius"`
	Band   string            `json:"band"` // "pre-approved" | "human"
}

// Ticket is a drift walking detect→hold→investigate→authorise→remediate→verify.
// Owned by the controller, served read-only via /v1.
type Ticket struct {
	ID         string       `json:"id"`
	Agent      string       `json:"agent"` // the agent this drift belongs to (ties to AgentPolicy)
	Layer      Layer        `json:"layer"`
	Sev        Severity     `json:"sev"`
	Title      string       `json:"title"` // the finding, human-readable
	Opened     string       `json:"opened"`
	State      string       `json:"state"`
	Detector   string       `json:"detector"`
	Magnitude  string       `json:"magnitude"`
	Confidence float64      `json:"confidence"`
	Radius     string       `json:"radius"`
	Bundle     string       `json:"bundle"`
	ModelPin   string       `json:"modelPin"`
	Hyps       []Hypothesis `json:"hyps"`
	Action     Action       `json:"action"`
	History    [][3]string  `json:"history"` // [ts, stage, detail]
	Evidence   string       `json:"evidence"`
	// Operational correlation ids (omitted when unknown; never fabricated).
	Epoch   int    `json:"epoch,omitempty"`
	Attempt int    `json:"attempt,omitempty"`
	Step    int    `json:"step,omitempty"`
	SpanID  string `json:"spanId,omitempty"`
}

// Baseline is a signed snapshot of "what we agreed", per layer. It changes only
// by a 2-approver PR against the baseline object — never by the controller.
type Baseline struct {
	Layer     Layer       `json:"layer"`
	Version   string      `json:"version"`
	Signed    string      `json:"signed"`
	Approvers string      `json:"approvers"`
	Fields    [][4]string `json:"fields"` // [name, baselineValue, liveValue, status]
}
