# ACRA — Repo Layout & Build/Run

> **v0.2 update.** The reliability pipeline, cloud adapters and Helm chart were added after this document was first written. The layout below is still correct for the drift-control core. What changed:
>
> - New packages under `internal/`: `agentrun` (events → runs), `contract` (agent contracts and evaluation), `incident`, `rca`, `adapters` (+ `kubeclient`; Azure, AWS, GCP, Kubernetes, KAgent), `ingest` (OTLP/JSON), `pipeline`, `gateway` (read-only tool gateway), `gatesvc` (HTTP gate), `identity` (roles), `redact`, `llm`.
> - `acra-gate` is now a standalone HTTP service (`POST /v1/gate/evaluate`), not a webhook.
> - `deploy/helm/acra/` is the production install. `config/deploy/*.yaml` remain the minimal kind demo.
> - Operations guide: [09-cluster-and-cloud-operations.md](09-cluster-and-cloud-operations.md).
>
> Extra make targets: `helm-lint`, `helm-template`, `helm-package`, `helm-install`, `helm-uninstall`.
> Build and test with Go 1.26+: `go build ./... && go vet ./... && go test ./...`.

Go, Kubebuilder-influenced. v1 collapses the 7 logical components into **4 processes + 2 off-the-shelf** so it runs clean on one `kind` cluster.

---

## Processes in v1

| Process | Is | Notes |
|---|---|---|
| `acra-controller` | the operator | watches `AgentPolicy` + behavior → tickets/status |
| `acra-gate` | admission + gate logic | validating webhook; runs the algorithms (docs 03) |
| `acra-apiserver` | `/v1` API **+ embedded evidence store** + serves console | evidence store folded in here for v1 (fewer moving parts) |
| `acra-workload` | synthetic agents + `inject-drift` CLI | makes it runnable/demoable offline |
| Kyverno | off-the-shelf | enforces the approved-set `ValidatingPolicy` |
| OTel Collector | off-the-shelf image + our config | receives spans with `acra.*` proof attrs |

## Directory layout

```
acra/
  README.md  LICENSE  Makefile  go.mod  .gitignore
  docs/                      # specs 01–06 (frozen contracts)
  api/v1alpha1/              # AgentPolicy CRD Go types (+ generated deepcopy)
  cmd/
    controller/main.go
    gate/main.go
    apiserver/main.go
    workload/main.go         # also hosts `inject-drift`
  internal/
    model/                   # shared domain types: Tuple, Baseline, Ticket, Trace, Event
    gate/                    # the algorithms: tuple-check, independence, drift, epoch, authority
    detectors/               # c2, c3, c4, m3 (plug-ins on the gate)
    evidence/                # BoltDB store, append+sign(ed25519)+chain, lineage graph
    api/                     # /v1 handlers + response envelope
    telemetry/               # otel attr helpers (operational IDs + acra.* proof attrs)
  config/
    crd/                     # generated CRD manifests
    kyverno/                 # ValidatingPolicy (approved set)
    otel/                    # collector config
    deploy/                  # k8s manifests for the 4 acra processes
    samples/                 # sample AgentPolicy + seed baselines (synthetic)
    kind/kind.yaml           # cluster config
  console/index.html         # the existing console, wired to /v1
  hack/                      # seed.sh, inject-drift wrappers
```

The seams in `internal/model/` + `api/` + `api/v1alpha1/` are the frozen contracts (docs 03–04). Components only touch each other through these.

## Make targets

```
make kind-up        # create the kind cluster
make install        # install Kyverno + OTel collector + the AgentPolicy CRD
make build          # go build all cmds
make docker-build   # build the 4 acra images, load into kind
make deploy         # apply config/deploy (the 4 acra processes) + kyverno policy
make seed           # apply sample AgentPolicy + signed baselines, start the workload
make demo           # inject a combinative drift and watch the gate HOLD it
make console        # port-forward apiserver, open the dashboard
make test           # unit tests (gate algorithms have the heaviest coverage)
make kind-down      # tear down
```

## The 90-second quickstart (README promise)

```
make kind-up install build docker-build deploy seed console
# open the console → everything green
make demo
# a new tuple runs: each component valid, the composition never approved
# → gate HOLDs, a ticket opens, the evidence chain shows roots=1 < required=2
```

No GPU, no cloud account, no real model provider — the synthetic workload stands in. Runs fully offline once images are built.

## Dependencies

Go 1.22+ · Docker · `kind` · `kubectl` · `make`. Everything else is pulled by `make install`.
