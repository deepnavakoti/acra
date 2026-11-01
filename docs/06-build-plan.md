# ACRA — Build Plan (to v0.1)

How the agent-driven build runs against the frozen contracts (docs 03–04). Milestones are sequenced so the **foundation lands first**, then components parallelize.

---

## Milestones

### M0 · Scaffold (done at kickoff)
Repo skeleton, `go.mod`, `.gitignore`, Makefile, README, LICENSE, kind config, `api/v1alpha1` + `internal/model` anchor types compiling, console copied in. **Exit:** `make build` compiles an empty skeleton; CRD types generate.

### M1 · Foundation — model, contracts, evidence (blocks everything)
- `internal/model/` — all shared types (Tuple, Baseline, Ticket, Trace, Event, lineage) exactly per doc 04.
- `api/v1alpha1/` — `AgentPolicy` CRD types + generated manifests.
- `internal/evidence/` — BoltDB store: append, ed25519 sign, `prevHash` chain, `verify`; lineage graph + `independence()` (doc 03 §2).
- **Exit:** evidence store round-trips a signed chain; `independence()` passes unit tests incl. the recursive-collapse case (1 root cited 3× → 1).

### M2 · Gate + algorithms *(parallel after M1)*
- `internal/gate/` — the top-level `gate()` + invariant checks.
- `internal/detectors/` — **c2** (independence), **c3** (epoch), **c4** (combinative tuple), **m3** (authority).
- `cmd/gate/` — validating webhook wiring.
- `config/kyverno/` — `ValidatingPolicy` for the approved set.
- **Exit:** given a synthetic write, gate returns ADMIT/HOLD correctly for all 4 detectors; unit tests cover each HOLD path.

### M3 · Controller *(parallel after M1)*
- `cmd/controller/` + reconcile loop: watch `AgentPolicy` + gate events → open ticket → drive `detect→…→verify` → write `status`.
- **Exit:** a HOLD from the gate produces a ticket on the CRD status; a signed approval advances it; verify re-runs the detector and closes.

### M4 · Telemetry + workload *(parallel after M1)*
- `internal/telemetry/` — span attrs (operational IDs + `acra.*` proof attrs), durable-event emit.
- `config/otel/` — collector config.
- `cmd/workload/` — synthetic agents producing tasks/traces + `inject-drift` (combinative, epoch, independence, authority).
- **Exit:** `inject-drift combinative` produces a write the gate HOLDs end-to-end, with spans + durable events landing.

### M5 · API server + console *(after M1–M4)*
- `internal/api/` + `cmd/apiserver/` — all `/v1` endpoints over evidence + controller state (doc 04 §1), embedded evidence store, serves `console/`.
- `console/index.html` — swap the static `DATA`/`fetchFromACRA()` for real `GET /v1/*` calls.
- **Exit:** console renders live from the cluster; the 8 screens match their `/v1` endpoints.

### M6 · Integration + demo + docs *(after M5)*
- `config/deploy/` + `config/kind/` — full `make kind-up … deploy seed demo console` path.
- README quickstart verified on a clean machine; honest framing + roadmap.
- **Exit (= v0.1):** clean `kind` → one command → green console → `make demo` → combinative drift HELD, evidence chain shows `roots=1 < 2`. Shareable repo link.

## Parallelization

```
M0 ─► M1 ─┬─► M2 (gate)        ─┐
          ├─► M3 (controller)   ├─► M5 (api+console) ─► M6 (integrate+demo)
          └─► M4 (telem+workload)┘
```
After M1, **M2/M3/M4 run as 3 parallel agents** against the frozen contracts. M5 integrates, M6 ships.

## Agent assignment (when we build)

One focused agent per component, each handed: its directory, the contracts it builds against (docs 03–04), and its milestone exit test. Agents never edit `internal/model/`, `api/`, or `api/v1alpha1/` — those are frozen; a contract change is a human decision.

## Definition of done (v0.1)

- [ ] `make`-driven quickstart works on a clean machine.
- [ ] 4 detectors (c2/c3/c4/m3) each catch their drift with a test.
- [ ] Evidence chain verifies; `independence` correct on the collapse case.
- [ ] Console renders live from `/v1`.
- [ ] README: honest "synthetic reference impl" framing + roadmap + Apache-2.0.
- [ ] No real system names anywhere (grep clean).
