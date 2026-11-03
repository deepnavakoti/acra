# ACRA — Where it sits in the ecosystem

The honest question anyone from the Kubernetes world asks first: **"Isn't this just Kyverno + OpenTelemetry?"**

No — and the reason is the point of ACRA. Each tool below secures *a layer*. None of them, alone, can tell you whether **correct components composed into an authorized outcome**. That composition layer is what ACRA reads.

## Tool landscape

| Component | Useful for | Not sufficient alone | ACRA's use |
|---|---|---|---|
| **Kagent + MCP** | investigation agents, K8s/observability tooling, agent delegation | not an authoritative ownership/approval oracle | investigator skills, evidence-query tools, safe runbooks |
| **OpenTelemetry + collector** | correlated traces, logs, metrics, spans | *a successful trace does not prove a provider commit or a valid approval* | correlate task/record/operation IDs; detect gaps |
| **OPA / Rego** | deterministic policy evaluation & decision APIs | needs *trusted business facts* and placement at the action boundary | task/evidence/approval contract predicates |
| **Kyverno / Gatekeeper** | K8s admission & policy enforcement | *cannot by itself decide business truth* | pod admission, RBAC, signed workload policies |
| **Temporal / Argo** | durable orchestration, retries, histories | doesn't ensure provider-side idempotency or business evidence | workflow ledger, checkpoints, replay control |
| **SPIFFE / SPIRE** | workload identity, mTLS trust | identity is not per-task authorization | bind identity to signed task intent |
| **AI gateway (e.g. Kong)** | model routing, gateway controls | route success is not business approval | capture actual model/route; block unapproved fallback |
| **Redis / vector stores** | caching, search, memory retrieval | TTL & semantic similarity don't prove freshness, ACL, or business truth | source-revision & revocation contracts |
| **SaaS systems of record / e-sign** | business records, external receipts | cross-system revisions and timing diverge | authoritative evidence reconciliation |

## The one-line positioning

> Every tool above answers *"did this component behave?"* ACRA answers *"did the composition stay authorized — and can you prove it?"*

A green admission check is not business truth. A successful trace is not an authoritative receipt. A valid identity is not a current authorization. ACRA layers **on top of** this ecosystem — it reuses Kyverno for admission, OTel for correlation, SPIFFE for identity — and adds the deterministic gate + signed evidence that read the whole chain.

## Design rationale (why this shape)

The architecture was a deliberate choice, not the maximal one:

- **Don't build a controller per check.** A detector is a small plug-in on one deterministic gate — not a Kubernetes controller each. (That's why 12 detectors live in one `gate`, not 12 operators.)
- **Reuse read-only investigation.** Diagnosis uses existing observability + investigation agents; the model *proposes*, it never holds authority.
- **Enforcement is policy-as-code + durable gates.** Admission and workflow gates fail closed on missing evidence or unknown effects; human approvals are revision-scoped.
- **The operator is optional.** A CRD/operator earns its place only where a *declarative policy lifecycle* needs it — which is exactly the narrow job ACRA's operator does (watch `AgentPolicy`, report drift), not per-check logic.

This keeps ACRA small enough to run on a `kind` cluster and understandable enough to audit.

See also: [architecture](02-architecture.md) · [drift taxonomy](07-drift-taxonomy.md).
