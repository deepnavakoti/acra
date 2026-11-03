# Contributing to ACRA

Thanks for looking — ACRA is early and contributions are genuinely welcome.

## Get it running

```bash
make run     # local, just Go 1.26+
# or
make up      # on a kind cluster (needs Docker + kind)
make test    # unit tests
```

Start with the design docs in [`docs/`](docs/) — the contracts (API, schemas, algorithms) are frozen there, and every component builds against them.

## Good first contributions

- **Add a detector.** Each drift class is a small plug-in in [`internal/detectors`](internal/detectors) implementing `gate.Detector` — see `detectors_more.go` for the pattern. Add the detector, a unit test, and an inject kind in `internal/workload`. No changes to the gate loop needed.
- **A new `inject-drift` scenario** that tells a sharper story in the console.
- **Docs**: clarify an algorithm in `docs/03-core-specs.md`, or improve the quickstart.
- **The operator**: richer `AgentPolicy` status, ticket lifecycle transitions, `controller-gen` codegen.

## Ground rules

- **Keep it use-agnostic.** No real company names, real system names, or real person names anywhere — examples are synthetic (see the existing `agents-eval`, `decision-agent`). Reviewers enforce this.
- **Tests with logic.** The gate and evidence code carry the heaviest coverage; keep it that way.
- `go fmt` + `go vet` clean. Small, focused PRs.

## Reporting

Open an issue with what you expected, what happened, and how to reproduce. For anything that looks security-sensitive, describe the class of problem rather than a working exploit.
