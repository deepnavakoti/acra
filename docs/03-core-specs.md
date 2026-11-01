# ACRA — Core Specs (the algorithms)

The IP. Every rule here is deterministic and implementable. The LLM never runs these — it only *reads* their outputs and proposes causes. If an agent builds these, it builds ACRA; if it hand-waves them, it builds a JSON server.

Notation: a *consequential write* `W` is an action that would change an external record or produce an effect. The gate evaluates `W` before it lands.

---

## 0 · The gate decision (top level)

```
gate(W, policy, evidence, cluster):
    for inv in policy.invariants:            # order matters: cheapest/hardest-fail first
        verdict = check(inv, W, policy, evidence, cluster)
        if verdict == HOLD:
            return HOLD(reason=inv, magnitude, confidence, radius)
    return ADMIT
```

- **ADMIT** → the write proceeds; a durable event + span are emitted.
- **HOLD** → the task is parked, no write happens, a ticket opens. **Unknown is never admitted** (invariant 7).
- The gate **checks**; it does not choose the outcome (invariant 5). Humans sign; deterministic code applies.

---

## 1 · Approved-tuple check → combinative drift (invariant 6)

The core insight. Each component can be individually valid while the **combination** was never approved.

A running bundle is a tuple `T = (prompt, tool_manifest, ruleset, formula)`.

```
check_approved_tuple(W, policy):
    T = tuple_of(W)                          # e.g. (p-31, 1.8.3, e8d3, f-7)
    if T in policy.approvedTuples:
        return ADMIT
    # every element may exist in SOME approved tuple, yet T as a whole is new:
    return HOLD("acra.c4 combinative — tuple never approved",
                magnitude = "tuple " + hash(T) + " unapproved")
```

**Why it matters:** `prompt p-31` is approved, `formula f-7` is approved, but `(p-31, …, f-7)` together was never run through the golden set. Each green, the composition unapproved. Drafts allowed; **effects refused** until the tuple passes nightly and is registered.

## 2 · Evidence independence → roots, not citations (invariant 1: derived ≠ independent)

Catches recursive-evidence collapse: an agent's own summary returning as "independent" corroboration.

Given a claim `c` and the lineage graph (edges `source → source`, terminating at root documents/providers):

```
independence(c, graph):
    roots = { r for r in reachable_sources(c, graph) if is_root(r) }
    #   is_root(r): r is an origin document or an external provider receipt,
    #   NOT a summary/derivation/memory-index entry (those are DERIVED).
    return len(distinct(roots))              # count DISTINCT roots

check_independence(W, policy):
    for c in claims_supporting(W):
        if independence(c) < policy.thresholds.minIndependentRoots:   # default 2
            return HOLD("acra.c2 independence",
                        magnitude = f"independent {independence(c)} vs required {policy...}")
    return ADMIT
```

**Key rule:** a derived artifact (summary `s-12`, a memory-index hit, an agent's own prior output) is **never** a root, no matter how many times it's cited. One root cited three times → `independence = 1`. Deduplicate by **provider/source identity**, not by request — two calls to the same provider (even via different paths/caches) are **one** root.

## 3 · Drift magnitude → distance from the signed baseline

`drift` is always measured against *what we agreed* (the signed baseline), never against yesterday.

```
magnitude(W, baseline):
    # per observed field vs its signed baseline value
    return sum over fields: distance(observed_field, baseline_field)
    # distance: exact-match fields → 0/1; numeric fields → normalized |Δ| in band-units
```

A ticket opens when `magnitude > policy.thresholds.driftMagnitude`. Magnitude is one of the three numbers on every ticket.

## 4 · Epoch fencing (invariant 3: epoch is a fence)

Work published under a superseded lease epoch is not trusted.

```
check_epoch(W, cluster):
    if W.epoch < cluster.current_epoch(W.task):
        # the lease moved on; this write is stale
        supersede(claims_derived_from(W))
        return HOLD("acra.c3 epoch fence", magnitude=f"epoch {W.epoch} vs {current}")
    return ADMIT
```

Fence at **write and at receipt** — a peer accepting a stale-epoch message (A2A) is also fenced.

## 5 · Authority read against now (invariant 4)

A status may only be promoted if the **authoritative record, read at decision time**, supports it — not a cached or summarized value.

```
check_authority(W):
    if W.promotes_status:
        truth = read_authoritative_record(W.subject, at=now())   # live read
        if not truth.supports(W.new_status):
            return HOLD("acra.m3 authority", magnitude="status without authority/receipt")
    return ADMIT
```

## 6 · The remaining invariants (rules)

- **Invariant 2 — no status by summary.** A consequential status change cannot be justified by a summary/derivation; it needs a root receipt. (Special case of §2 applied to status writes.)
- **Invariant 5 — gate checks, not decides.** The gate returns ADMIT/HOLD only. It never picks a remediation, signs, or edits a record. (Architectural, enforced by having no write path from the gate to records.)
- **Invariant 7 — unknown stays unknown.** If the effect state cannot be proven (e.g. provider timeout, missing span), the result is `UNKNOWN` and treated as HOLD. Never optimistically admitted, never auto-retried.

## 7 · The three numbers (every ticket)

Deterministic rules compute them; the LLM reads them.

| Number | Definition |
|---|---|
| **Magnitude** | how far from baseline — §3. |
| **Confidence** | `z = |observed − baseline_mean| / baseline_stddev`; map to a 0–1 confidence that it's not noise. |
| **Blast radius** | from version stamps on outputs: count of tasks/records touched by this tuple/epoch/claim since it drifted. |

## 8 · Detector map (reference)

The console's `detector` ids are named classes of the above:
`acra.c1`=effect-state-unknown (§6 inv7) · `acra.c2`=independence (§2) · `acra.c3`=epoch (§4) · `acra.c4`=combinative tuple (§1) · `acra.c5`=unprovable trace/sampling (§6 inv7) · `acra.c6`=control-loop oscillation (cross-correlation of scale vs 429s) · `acra.m1`=schema/field redefinition · `acra.m2`=context-compression claim loss · `acra.m3`=authority (§5) · `acra.m4`=duplicate-path corroboration (§2 dedup) · `acra.m5`=stale analytical source · `acra.m6`=recovery enumerated uncertain ops (§6 inv7).

v1 must implement at least: **c2, c3, c4, m3** (the four that carry the combinative-drift story). The rest are detector plug-ins on the same gate.

---

These algorithms are the contract for the `gate/` and `evidence/` components. Next: **05 Repo layout + build/run** · **06 Build plan**.
