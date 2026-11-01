# ACRA — Architecture

How the pieces fit. v1 targets a single `kind` cluster, no external deps, no GPU.

---

## The shape in one picture

```
                            ┌─────────────────────────────┐
                            │         Console (UI)         │  read-only
                            │   overview · tickets · ...    │
                            └──────────────┬──────────────┘
                                           │ GET /v1/*
                            ┌──────────────▼──────────────┐
                            │        API Server (/v1)       │
                            └───┬───────────────┬──────────┘
                                │               │
          reads evidence/tickets│               │reads CRD state
                                │               │
     ┌──────────────────────────▼───┐   ┌──────▼────────────────────────┐
     │   Evidence Store + Graph      │   │  AgentPolicy Controller (op)   │
     │  append-only · signed chain   │   │  watch → detect → ticket →     │
     │  roots/citations/independence │   │  drive re-approval → verify    │
     └───────────▲──────────────────┘   └──────┬────────────────────────┘
                 │ durable events               │ reconciles
      spans+attrs│                              │ AgentPolicy CRD
     ┌───────────┴──────────────┐   ┌──────────▼────────────────────────┐
     │   OTel Collector          │   │          ACRA Gate                 │
     │   proof attributes        │◄──┤  admit / HOLD consequential writes │
     └───────────────────────────┘   │  Kyverno approved-set + drift/     │
                                      │  independence logic                │
                                      └──────────▲────────────────────────┘
                                                 │ proposes action
                                      ┌──────────┴────────────────────────┐
                                      │   Synthetic Agent Workload         │
                                      │   tasks · traces · injectable drift│
                                      └────────────────────────────────────┘
```

## Components

| # | Component | Responsibility | K8s form (v1) |
|---|-----------|----------------|---------------|
| 1 | **ACRA Gate** | Intercept every *consequential* write. Check it's an approved tuple; compute drift & evidence independence; **admit or HOLD**. The gate *checks*, it doesn't decide outcomes. | Kyverno `ValidatingPolicy` (approved set) + a gate `Deployment` for the drift/independence logic |
| 2 | **AgentPolicy Controller** | Reconcile loop: watch agent behavior + the `AgentPolicy` CRD, detect drift, open a ticket, drive re-approval, run verification. | `controller-runtime` operator `Deployment` + the `AgentPolicy` CRD |
| 3 | **Evidence Store + Graph** | Append-only, signed chain of durable events. Builds the lineage graph; computes **roots-vs-citations independence**. Serves evidence queries. | `Deployment` + embedded store (BoltDB/SQLite in v1) |
| 4 | **OTel Pipeline** | Every span carries operational IDs + ACRA proof attributes. Feeds durable events into the evidence store (sampling is unreliable, so ACRA writes durable events beside OTel). | OTel Collector `Deployment` + SDK attrs in the workload |
| 5 | **API Server (`/v1`)** | Read API the console consumes: overview, tickets, fleet, endpoints, evaluation, baselines, evidence, policy. | `Deployment`, `Service` |
| 6 | **Console** | Read-only dashboard (existing HTML/JS), wired to `/v1`. | static, served by API server |
| 7 | **Synthetic Workload** | Fake agents producing tasks/traces, with **injectable drifts** so you can break it on purpose and watch ACRA catch it. | `Job`/`Deployment` + a CLI to inject a drift |

## The decision flow (one consequential write)

1. A (synthetic) agent **proposes** a consequential action.
2. **Gate** intercepts → is this an *approved tuple* (prompt + tool + manifest + formula)? Kyverno enforces the approved set.
3. Gate computes **drift** (distance from signed baseline) and **evidence independence** (root sources, not citations).
4. **Admit** if inside baseline + independence satisfied; else **HOLD** (task parked, no write).
5. Gate emits an **OTel span** (operational IDs + proof attrs) and a **durable evidence event**.
6. **Controller** sees the drift → opens a ticket on the `AgentPolicy` status → drives the pipeline: `detect → hold → investigate → authorise → remediate → verify`.
7. An **LLM investigator** proposes causes/actions (read-only); a human signs; deterministic code applies. **The agent never holds the keys.**
8. **Verify**: the detector that opened the ticket re-runs. Nothing closes without a passing re-run.
9. **Console** reads the whole chain via `/v1`.

## Key architecture decisions

- **Deterministic gate, LLM only advises.** The model proposes and investigates; it never admits, holds, or changes records. Admission is deterministic code.
- **Append-only, signed evidence** (ed25519). A signature covers the exact bytes; a swapped change fails verification at apply.
- **Independence = count roots, not citations.** One source cited three times is one source. This is what catches recursive-evidence collapse.
- **Epochs are fences.** Work published under a stale epoch is superseded, not trusted.
- **Durable events beside OTel.** Sampling drops spans under load; consequential events are written durably regardless.
- **Storage is simple + swappable in v1.** Embedded store now; pluggable backend later.
- **Everything runs on `kind`, offline.** No GPU, no real model provider — the synthetic workload stands in. Real gateways (Kong, SPIRE/SPIFFE) are design-referenced, stubbed in v1.

## Build boundaries (for the agent-driven build)

Each component is an independently buildable unit with a contract (defined in docs 03–04):
`gate/` · `controller/` + `api/` (CRD) · `evidence/` · `otel/` · `apiserver/` · `console/` · `workload/`.
Shared: the `/v1` API schema and the evidence/trace schema — those are the seams every component builds against.

---

Next docs: **03 Core specs** (the algorithms) · **04 API & schemas** (the contracts) · **05 Repo layout + build/run** · **06 Build plan**.
