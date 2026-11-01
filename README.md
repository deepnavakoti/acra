<div align="center">

# ACRA — Agentic Control & Runtime Assurance

**Proof that your AI agents stayed inside the lines — on Kubernetes, continuously.**

![status](https://img.shields.io/badge/status-alpha-orange)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8)
![Kubernetes](https://img.shields.io/badge/Kubernetes-native-326CE5)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

</div>

> *Every call returned 200. Every agent passed its own check. The approval at the end was one nobody authorized.*

That's **combinative drift** — correct components composing into an outcome no one approved. Single-layer checks miss it. ACRA is the layer that reads the *composition*, holds it at the gate, and hands you a signed evidence chain an auditor can actually read.

![ACRA catching combinative drift live](docs/img/acra-demo.gif)

*Everything green → inject a drift → the gate HOLDs it, a ticket opens, and the evidence shows `independence = 1, required 2`. Nothing faked — that's the real gate running.*

---

## Why this exists

Regulators ask one question: **"Can you prove this did what you said?"** For normal software, CI/CD is the proof. AI agents break it — same image, same manifest, *different answer*; GitOps shows zero changes while behavior drifts. And there's no settled rule for AI agents yet, so the proof has to come from **your own controls, continuously.**

ACRA is a deterministic control plane beside your agents. Agents **propose**; the gate **admits or holds** every consequential write; every decision emits a **signed, queryable proof**.

## See it in 60 seconds

**No cluster — just Go:**
```bash
make run                       # console at http://localhost:8080
make inject KIND=combinative   # watch the gate HOLD it
```

**On Kubernetes (kind):**
```bash
make up                        # cluster + image + CRD + operator + OTel + deploy
open http://localhost:8080
make inject KIND=independence  # or: epoch · authority · schema · … (12 kinds)
kubectl get agentpolicy        # the operator reports drift on the cluster itself
```

<div align="center">
<img src="docs/img/console-overview.jpg" width="49%" alt="Overview — three drifts held at the gate">
<img src="docs/img/console-ticket.jpg" width="49%" alt="A ticket — the detect→verify pipeline and the proof">
</div>

## How it works — 4 Kubernetes-native patterns

1. **Behavioral-baseline gate** — Kyverno admission enforces the approved set; the gate computes drift & evidence independence and holds what's outside it.
2. **Continuous proof via OpenTelemetry** — every gate decision emits a span with operational IDs + `acra.*` proof attributes.
3. **CRD controller → re-approval** — a `controller-runtime` operator watches `AgentPolicy` and reports/drives drift.
4. **Automated evidence** — cluster telemetry becomes an auditor-queryable, signed chain, not a spreadsheet.

## "Isn't this just Kyverno + OpenTelemetry?"

Fair question — and the answer is the whole point. Each of those secures *a layer*: Kyverno admits pods, OTel correlates traces, OPA evaluates policy, SPIFFE proves identity. **None of them, alone, can tell you whether correct components composed into an *authorized* outcome.** A green admission check is not business truth; a successful trace is not an authoritative receipt. ACRA layers *on top of* them — reusing Kyverno, OTel and SPIFFE — and adds the gate + signed evidence that read the whole chain. → [How ACRA relates to the ecosystem](docs/08-landscape.md)

## What's inside (v0.1)

- **Gate + 12 detectors** — combinative drift, evidence independence (roots, not citations), epoch fencing, authority-at-now, and 8 more — all unit-tested.
- **Signed evidence chain** — append-only, ed25519, tamper-evident.
- **Operator** — `kubectl get agentpolicy` shows live `Phase` / open tickets.
- **OpenTelemetry** → collector. **Kyverno** admission policy. **Live console.**
- **Grounded in a taxonomy** — the 12 detectors are a principled subset of **72 drift checks across 12 domains**, not an ad hoc list ([drift taxonomy](docs/07-drift-taxonomy.md)).

## The design, written down

Most OSS has no design docs. ACRA is spec-first — the thinking is in [`docs/`](docs/): [vision](docs/01-vision-scope.md) · [architecture](docs/02-architecture.md) · [the algorithms](docs/03-core-specs.md) · [API & schemas](docs/04-api-and-schemas.md) · [layout & run](docs/05-repo-layout-and-run.md) · [build plan](docs/06-build-plan.md) · [drift taxonomy](docs/07-drift-taxonomy.md) · [ecosystem & landscape](docs/08-landscape.md).

> ⚠️ ACRA v0.1 is an **alpha / reference implementation on synthetic traces** — not a production deployment, not tied to any organization's systems.

## Why I built it

> I've spent 12 years running banking infrastructure on Kubernetes. When teams started putting AI agents into regulated workflows, I kept hitting the same wall: every component was green, every check passed, and the *combination* still did something no one signed off on — and I couldn't *prove* what happened after the fact. ACRA is the control plane I wished I'd had: it reads the composition, holds what drifted, and leaves a signed trail. Built it as a reference so others don't have to start from zero.

## Roadmap

Bring-your-own-agents (real frameworks / MCP adapters) · model-provider gateways (Kong, SPIRE/SPIFFE) · `controller-gen` codegen · HA / multi-tenant.

Issues and ideas welcome — see [CONTRIBUTING](CONTRIBUTING.md).

## License

Apache-2.0.
