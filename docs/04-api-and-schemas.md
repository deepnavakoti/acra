# ACRA — API & Schemas (the contracts)

The seams every component builds against. Three contracts: the **`/v1` read API** (console ↔ API server), the **`AgentPolicy` CRD** (controller ↔ cluster), and the **evidence/trace schema** (gate → evidence store → API).

All examples use generic/synthetic names (`agents-eval`, `decision-agent`, …). No real system names, ever.

---

## 1 · The `/v1` read API (console ↔ API server)

Read-only JSON. One endpoint per console screen. The response shapes are **already defined** by the existing console's `DATA` object — the API server serves exactly those shapes so the console wires in with no rewrite.

| Method · Path | Serves | Response shape (source of truth) |
|---|---|---|
| `GET /v1/overview` | drift index by domain, contract freshness, KPIs, "needs attention" | `DATA.overview` + derived KPIs |
| `GET /v1/tickets` | all tickets (list) | `DATA.tickets[]` |
| `GET /v1/tickets/{id}` | one ticket (detail: stages, hyps, action, history) | one `DATA.tickets[]` entry |
| `GET /v1/fleet` | tasks in flight, bands, re-issues | `DATA.fleet` |
| `GET /v1/endpoints` | model routes, lifecycle, quota, TTFT/429 | `DATA.endpoints[]` |
| `GET /v1/evaluation?agent=` | nightly band, attribution, judge, golden set | `DATA.evaluation` |
| `GET /v1/baselines` | signed baselines, live-vs-signed diffs | `DATA.baselines[]` |
| `GET /v1/evidence/{traceId}` | one trace: hops, kernel events, chain state | `DATA.evidence[traceId]` |
| `GET /v1/policy` | Kyverno policy status + the approve queue | `DATA.policy` |

Write actions (sign/approve, request-verify, export) in v1 are `POST /v1/tickets/{id}:{action}` → returns updated ticket. These are the only writes the console triggers; all go through the gate's approval path.

**Envelope:** every response carries `{ "asOf": <RFC3339>, "data": <shape> }`. Errors: `{ "error": { "code", "message" } }`.

## 2 · The `AgentPolicy` CRD (controller ↔ cluster)

`apiVersion: acra.dev/v1alpha1` · `kind: AgentPolicy` · namespaced.

```yaml
spec:
  agent: decision-agent                 # which agent this governs
  approvedTuples:                        # the only (prompt,tool,manifest,formula) combos allowed to produce effects
    - prompt: p-30
      manifest: "1.8.3"
      ruleset: e8d3
      formula: f-6
  baseline:                              # signed snapshot of "what we agreed", per layer
    ref: a-0210                          # points at a signed baseline object
  invariants: [derived-not-independent, no-status-by-summary, epoch-is-a-fence,
               authority-read-against-now, gate-checks-not-decides,
               only-approved-tuples-run, unknown-stays-unknown]
  thresholds:
    driftMagnitude: 2                    # open a ticket above this
    minIndependentRoots: 2               # evidence independence floor
status:
  phase: Watching | Drifting | HeldForApproval | Remediating | Verifying
  openTickets: [ACRA-3102]
  lastCleanRun: "2026-10-18T13:40:00Z"
  conditions: [...]                      # standard k8s conditions
```

The controller reconciles `spec` against observed behavior and writes `status`. A baseline changes **only** by a 2-approver PR against the baseline object — never by the controller.

## 3 · Evidence / trace schema (gate → store → API)

Append-only. Each durable event is signed; events chain by `prevHash`.

```jsonc
// durable event
{
  "traceId": "t-3102",
  "seq": 7,
  "ts": "2026-10-19T11:51:59Z",
  "kind": "gate" | "dispatch" | "model" | "tool" | "kernel" | "agent" | "ticket",
  "actor": "decision-agent/dec-1f0",
  "detail": "claim c-9f2 roots=1 required=2 · hold",
  "prevHash": "sha256:…",               // chain link
  "sig": "ed25519:…"                     // signs {seq,ts,kind,actor,detail,prevHash}
}
```

Lineage (for independence): claims reference **sources**, sources have **roots**.

```jsonc
// claim lineage
{
  "claim": "c-9f2",
  "edges": ["doc-4411→e-7", "e-7→s-12", "s-12→a-3", "a-3→c-9f2"],
  "roots": ["doc-4411"],                 // distinct origin documents/providers
  "citedCount": 3,                        // how many times cited (NOT independence)
  "independence": 1                       // = count(distinct roots) ← the number that matters
}
```

A **trace** = `{ traceId, task, caller, bundle, chain: "intact"|"broken", events[] }` → this is what `GET /v1/evidence/{traceId}` returns.

## 4 · OTel proof attributes (two distinct ID sets)

Every span carries both sets. **Operational correlation IDs** and **ACRA proof attributes are different things** — never collapse them.

| Set | Attributes |
|---|---|
| **Operational correlation** | `task.id`, `attempt`, `step`, `epoch`, `trace.id`, `caller.spiffe` |
| **ACRA proof** | `acra.model.version`, `acra.prompt.hash`, `acra.context.sources`, `acra.response.fingerprint` |

GenAI semantic conventions are **emerging/experimental** — ACRA namespaces its own attrs under `acra.*` and writes durable events beside OTel (sampling is unreliable under load).

## 5 · Ticket schema (controller-owned, served read-only)

```jsonc
{
  "id": "ACRA-3102",
  "layer": "Evidence",                   // Execution|Context|Authority|Evidence|Effect|Compatibility
  "sev": "crit" | "warn",
  "state": "detect|hold|investigate|authorise|remediate|verify|closed",
  "detector": "acra.c2_c2",
  "magnitude": "independent sources 1 vs required 2 (cited 3)",
  "confidence": 0.99,                     // z-score vs baseline variance
  "radius": "task t-8c21 held; 0 writes; 14 re-scored, 2 held",
  "hyps": [{ "c": 0.9, "t": "…" }],       // LLM investigator, read-only
  "action": { "name", "params", "radius", "band": "pre-approved|human" },
  "history": [["11:51:59","detect","…"], …], // append-only
  "evidence": "t-3102"                     // link to the trace
}
```

`magnitude`, `confidence`, `radius` = the **three numbers on every ticket** (deterministic rules compute them; the LLM reads them, never changes them).

---

These three contracts are frozen seams. Components build against them independently.
Next: **03 Core specs** (the algorithms behind `independence`, `drift`, the invariants, epochs) · **05 Repo layout + build/run** · **06 Build plan**.
