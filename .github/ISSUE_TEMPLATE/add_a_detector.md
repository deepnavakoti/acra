---
name: Add a detector (good first issue)
about: Propose or add a new drift detector
labels: [enhancement, good first issue]
---

**The drift class**
What composition goes wrong, and why single-layer checks miss it.

**How the gate should catch it**
The deterministic rule (inputs → HOLD/ADMIT). See `docs/03-core-specs.md`.

**Checklist for the PR**
- [ ] Detector in `internal/detectors` implementing `gate.Detector`
- [ ] Unit test (HOLD path + clean ADMIT)
- [ ] An `inject-drift` kind in `internal/workload`
- [ ] Synthetic example only — no real names
