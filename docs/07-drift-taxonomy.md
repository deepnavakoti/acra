# ACRA — Drift Taxonomy

ACRA's detectors aren't ad hoc. They come from a taxonomy of **72 drift checks across 12 domains**, plus compound scenarios where domains combine. v0.1 implements the **12 checks that carry the combinative-drift story**; the rest are plug-ins on the same gate (`internal/detectors`).

> All examples are generic/synthetic. The taxonomy is a set of *hypotheses* about where agent systems drift — not a list of observed production incidents.

---

## The 12 domains (D01–D72)

Each domain shares a root cause, a detection approach, and a class of control. Six checks each.

### 01 — Agent cognition, goals, reasoning, evaluation
*Root:* the agent optimizes a proxy goal or grades against an outdated rubric instead of the authorized obligation. *Detect:* compare the authoritative source event / record revision / task contract. *Control:* independent obligation oracle; immutable task contract; evaluator manifest.
`D01` goal substitution · `D02` plan-prerequisite omission · `D03` reasoning-to-fact promotion · `D04` self-critique circular confirmation · `D05` premature completion/stopping · `D06` evaluator/grader drift

### 02 — Prompts, context, model routing, truncation
*Root:* prompts, summaries, model configs and token limits evolve independently; a required condition disappears or changes meaning. *Control:* context anchors; model/prompt version pinning; mandatory-claim validation.
`D07` system-prompt version mismatch · `D08` context truncation drops a blocking claim · `D09` compaction promotes an unresolved status · `D10` model-fallback semantic incompatibility · `D11` structured-output / tool meaning skew · `D12` token-budget-driven evidence omission

### 03 — RAG, retrieval, data, memory
*Root:* indexes, chunks, derived summaries and ACLs update at different times; retrieved relevance is mistaken for source authority. *Control:* source-event lineage; ACL checks; revocation gate; evidence freshness.
`D13` index-freshness divergence · `D14` source-version ancestry mismatch · `D15` circular derived-evidence corroboration · `D16` retrieval-permission drift · `D17` chunk-boundary condition loss · `D18` memory revocation / erasure drift

### 04 — Caching, token, cost, latency
*Root:* cache entries, TTLs and budget-driven fallbacks omit the current tenant / revision / policy / task version. *Control:* scope cache keys; epoch checks; reject incomplete budget fallbacks.
`D19` KV/prefix cache compatibility · `D20` semantic response-cache scope · `D21` stale cache state / TTL race · `D22` token-budget enforcement · `D23` cost-driven route degradation · `D24` latency-budget expiry

### 05 — Tool (MCP) permissions and side effects
*Root:* tool descriptions and schema checks don't prove authorization; untrusted outputs, retries and remote commits cross execution boundaries. *Control:* destination authorization; semantic contracts; stable operation IDs and receipts.
`D25` tool schema semantic change · `D26` tool-output prompt injection · `D27` task-scoped capability expansion · `D28` partial external side effect · `D29` tool error-to-success laundering · `D30` tool-registry cache-scope change

### 06 — Agent-to-agent delegation and task propagation
*Root:* delegation chains and message streams don't preserve current identity, ordering or authority. *Control:* delegation intersection; task/epoch binding; dependency receipts.
`D31` delegation-scope narrowing · `D32` task-ID / epoch mismatch · `D33` task-history evidence loss · `D34` message-dependency reordering · `D35` transitive authority amplification · `D36` result-provenance ambiguity

### 07 — AI gateway (e.g. Kong), DNS, TLS, network
*Root:* routing, DNS, TLS, retries and caches can select a different model or fallback while business-state checks stay unchanged. *Control:* route/evaluation manifest; gateway egress enforcement; fallback hold.
`D37` gateway model-route skew · `D38` DNS fallback selection · `D39` TLS/mTLS route-identity drift · `D40` retry amplification · `D41` gateway cache-key incompatibility · `D42` uncontrolled model-egress bypass

### 08 — Kubernetes scheduling, CNI, kubelet, controllers
*Root:* admission, scheduling, networking, OOM and autoscaling change runtime ownership or context; recovery is mistaken for business recovery. *Control:* execution fencing; checkpoint versioning; durable work ownership.
`D43` admission mutation / policy skew · `D44` scheduling placement / affinity · `D45` CNI/eBPF path divergence · `D46` CoreDNS partial outage · `D47` kubelet OOM / restart context loss · `D48` HPA/KEDA controller feedback

### 09 — CPU/GPU/MIG and inference runtime
*Root:* resource pressure, precision changes, batching and concurrency change latency or provenance without changing business validation. *Control:* inference receipts; model qualification; request-ID matching; backpressure.
`D49` MIG resource-assignment drift · `D50` GPU driver/kernel mismatch · `D51` quantization/precision decision skew · `D52` inference batching/ordering · `D53` KV-cache isolation and reuse · `D54` CPU/GIL/thread-pool starvation

### 10 — SPIFFE/SPIRE, cryptographic identity, signed intent
*Root:* a valid workload identity or signature authenticates an actor, not a *current task-scoped permission* or an approved business effect. *Control:* trust verification plus signed task intent and effect-scoped policy.
`D55` SPIFFE rotation / identity change · `D56` task-bound capability expiration · `D57` signed-intent replay · `D58` image/artifact supply-chain provenance · `D59` A2A delegated authorization · `D60` MCP audience / gateway effect scope

### 11 — Business integrity, approvals, compliance
*Root:* business rules, required-condition states, approvals and evaluation rules have distinct authoritative revisions and conditions. *Control:* authoritative backend state; human approval revision; deterministic effect gates.
`D61` business-rule version skew · `D62` status promotion without authority · `D63` ownership-verification mismatch · `D64` sensitive-data boundary leakage · `D65` human-approval scope and revocation · `D66` fairness/evaluation policy drift

### 12 — Orchestration, recovery, causal evidence
*Root:* replay, queue redelivery, partial provider commits and incomplete ledgers create incompatible execution histories. *Control:* durable ledger; provider reconciliation; replay fencing; recovery permissions.
`D67` durable task-ledger consistency · `D68` checkpoint semantic reconstruction · `D69` idempotent external effect · `D70` recovery replay and fencing · `D71` signed causal-evidence completeness · `D72` manager/controller authorization drift

---

## What v0.1 implements — detectors ↔ taxonomy

| Detector | Catches | Taxonomy |
|---|---|---|
| `c4` combinative tuple | a tuple nobody approved | compound (C-series) · D10/D61 |
| `c2` independence | derived evidence posing as independent | **D15** |
| `c3` epoch fence | stale-epoch work trusted | **D32** |
| `m3` authority | status promoted without the authoritative record | **D62** |
| `c1` effect unknown | unprovable effect optimistically admitted | D69 · C08 |
| `c5` unprovable trace | durable events without spans | D71 · C10 |
| `c6` oscillation | runaway recovery/scale loop | D40 · C12 |
| `m1` schema redefinition | a field redefined across versions | **D25** |
| `m2` context claim loss | compression/route-switch drops a claim | **D08** |
| `m4` duplicate-path | same provider, two paths, counted twice | D16 · C05 |
| `m5` stale source | sole support is a stale analytical view | **D13** |
| `m6` uncertain ops | recovery enumerates uncertain ops | D70 |

The 12 span 8 of the 12 domains. Adding a detector = one plug-in (see [CONTRIBUTING](../CONTRIBUTING.md)).

## Compound scenarios — where combinative drift lives

Single-domain checks miss the real failure: correct components from different domains composing into an unauthorized outcome. A few (generic) examples:

- **Recursive tool-output poisoning** — a synthetic tool instruction re-enters via RAG and A2A, and untrusted derived content becomes "independent authority." *(ACRA: provenance DAG; derived ≠ independent.)*
- **Gateway-timeout-becomes-success** — a 504 + a model fallback + a stale epoch, and a transport error is read as a completed business effect. *(ACRA: typed statuses; current epoch; fallback hold.)*
- **Trace-based false certification** — a successful sampled span while the provider status is unresolved, and a *diagnostic trace is treated as an authoritative receipt.* *(ACRA: durable signed ledger; trace correlation only.)*
- **Reviewer artifact masquerade** — a reviewer sees an agent's own summary labeled as independent evidence. *(ACRA: provenance DAG; reviewer-source independence.)*

## Evidence levels (how to read any claim here)

`E1` spec · `E2` vendor/project docs · `E3` local synthetic test · `E4` staging with real integrations · `E5` production-validated.
**ACRA v0.1 is E3** — synthetic, on a local cluster. Nothing here is claimed as production-validated.
