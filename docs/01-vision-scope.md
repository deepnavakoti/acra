# ACRA — Vision & Scope

**ACRA — Agentic Control & Runtime Assurance.**
A Kubernetes-native control plane that produces *proof* that AI agents stayed inside their authorized behavior — for teams in regulated environments.

---

## The problem

Regulators (and auditors, and your own risk team) ask one question: **"Can you prove this system did what you said it would?"**

For normal software, CI/CD *is* the proof — same code, same build, same behavior. AI agents break that:

- Same image, same manifest, same cluster → **different answer each run.**
- GitOps shows **zero changes** while the agent's behavior has drifted.
- There is **no settled prescriptive rule** for AI agents yet — so the proof has to come from *your own controls*, continuously, not a quarterly export.

## The insight: combinative drift

Single-layer checks miss the real failure. Every component can be green — the model passed eval, the policy passed admission, each call returned 200 — and the **composition** is still an outcome nobody authorized.

> *Every call returned 200. Every agent passed its own check. The approval at the end was one nobody authorized.*

**Combinative drift** = correct components composing into an unauthorized result. ACRA is the layer that reads the *composition*, not just the parts.

## What ACRA does

A deterministic control plane beside the agents. Agents **propose**; ACRA's gate **admits or holds** every consequential write, and emits signed, queryable evidence for each decision.

Four Kubernetes-native patterns:
1. **Behavioral-baseline gate** — Kyverno admission enforces the signed baseline / approved set; the gate computes drift and holds what's outside it.
2. **Continuous proof via OpenTelemetry** — every span carries operational IDs *and* ACRA's custom proof attributes. Proof is generated on every call, not exported quarterly.
3. **CRD controller → re-approval** — a Kubernetes operator watches behavior, detects drift, and drives a re-approval workflow.
4. **Automated evidence** — cluster telemetry becomes auditor-queryable dashboards instead of hand-filled spreadsheets.

## Who uses it / what they get

- **Who:** a platform/ML-platform team running AI agents on Kubernetes under compliance pressure (finance, health, gov-adjacent).
- **Install:** `kind` cluster → `make deploy` → agents + ACRA + console running on synthetic traffic.
- **Value in v1:** watch a combinative drift get *caught and held* that every single-layer tool misses — with a signed evidence chain you could hand an auditor.

## v1 scope (what's in)

- `AgentPolicy` **CRD + controller** (reconcile loop: detect drift → open ticket → drive re-approval).
- The **gate**: Kyverno `ValidatingPolicy` for the approved set + ACRA gate service computing drift & **evidence independence**.
- **Evidence store** + the core algorithms (combinative drift, roots-vs-citations independence, the invariants, epoch fencing).
- **OTel proof attributes** (collector config + custom attributes on spans).
- **Console** (read-only) wired to the `/v1` API.
- **Synthetic agent workload** generator so it's runnable + demoable on `kind`.

## Out of scope for v1 (roadmap)

- Bring-your-own-agents integration (real agent frameworks / MCP adapters).
- Production hardening, HA, multi-tenant, RBAC depth.
- Real model-provider gateways (Kong, SPIRE/SPIFFE) — referenced in design, stubbed in v1.
- Hardened Go operator (Saideep's authentic layer, post-v1).

## Honest framing (non-negotiable)

ACRA v1 is a **reference implementation on synthetic traces** — not a production deployment, not tied to any employer's system. All sample data is generic/synthetic. The README says this plainly.

## Facts to keep accurate (from the talk's currency review)

- Kyverno: use CEL policy types (`ValidatingPolicy` / `GeneratingPolicy`, API group `policies.kyverno.io`). Legacy `ClusterPolicy` removed in 1.20.
- OTel GenAI semantic conventions are **emerging/experimental**, not stable. Keep two ID sets distinct: operational correlation IDs vs ACRA's custom proof attributes.
- `kagent` is CNCF Sandbox / alpha.
- Regulators: stay generic — no rule numbers.

---

**License:** Apache-2.0 · **Target:** installable alpha (v0.1) for the Nov 9 talk · **Repo:** `acra` (local first → Saideep's GitHub)
