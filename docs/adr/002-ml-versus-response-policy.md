# ADR 002: What ML may and may not cause in the response path

- Status: accepted, implemented 2026-10-30
- Date: 2026-10-22
- Plan: [ml-scoring-stage.md](../plans/ml-scoring-stage.md)

## Context

The engine never acts: alerts carry recommendations. The manager translates each recommendation through `response_engine.translate_recommendation`, which fails closed on unknown strings and on missing `start_time_ticks` (`recommendation.py:16-64`). It then classifies the result into a tier (`policy.py:29-45`):

| Tier | Actions | What the manager does |
|---|---|---|
| AUTO_SAFE | `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS` | authorizes and enqueues them automatically (manager `detection/response.py:147`) |
| ANALYST_APPROVAL | everything else | waits for an analyst |

Three paths in the existing code already produce destructive recommendations:
- **Rule defaults by level:** level 12–13 maps to TERMINATE (`active_response.py:64`); level ≥ 14 maps to ISOLATE (`:86`).
- **Incident alerts:** they recommend terminating the root process (`incident.py:466-486`).

A classifier has a nonzero false-positive rate. Any way for ML alone to reach those paths turns that rate directly into kill or isolate requests.

## Decision

| What ML may do | Allowed? | How it is enforced |
|---|---|---|
| Recommend `TERMINATE_PROCESS` or `ISOLATE_HOST` on its own | **No** | ML alerts are built directly, never through `resolve_action`'s level defaults. A replay test asserts it. |
| Raise a level-capped alert | Yes | Level 7 (`ML-PROC-001`) or 9 (`ML-PROC-002`). Both are below the anchor level of 10 (`tagging.py:35`) and the default-TERMINATE level of 12. |
| Carry an ATT&CK tactic | **No** | With no tactic, an ML alert can never anchor an incident or count toward `min_tactics` (`incident.py:209-217`). |
| Change a rule hit's level | **No** | Rule alerts get an `ml` annotation only. Re-levelling would re-enter the level→action defaults. |
| Add to host risk | Yes, bounded | 15 or 25 points, once per rule per host per half-life (`risk_scorer.py:47-53, 87-107`). That is at most 40 per hour, below the 75 breach, and a breach only recommends COLLECT. |
| Raise an incident's score | Yes, bounded | One itemised factor (0.08), inside the 0.25 context cap (`incident.py:82-88`). It can lift the band, which re-emits the incident's own analyst-approved recommendation. That incident exists only because a rule anchored it, which is the corroboration. |
| Recommend `COLLECT_PROCESS_INFO` on its own | Later, behind a flag that is off by default | Only for the high band, and only when the registry incarnation carries observed ticks. Ticks are never derived. |

## Alternatives

**A. ML recommends nothing at all, ever.**
- Safest.
- Gives up cheap evidence collection on high-confidence hits.
- This is the starting state: the flag is off until false positives are measured.

**B. COLLECT at every alert threshold.**
- Simple.
- Every false positive becomes an auto-dispatched command to an endpoint.
- Rejected until measured.

**C. ML re-levels rule hits.**
- Rejected. A level-11 hit raised to 12 would mint a TERMINATE recommendation from ML alone.

**D. Give ML alerts a tactic such as Execution.**
- Rejected for v1. It would let ML plus a single rule anchor satisfy `min_tactics=2` and open incidents, which makes ML a co-author of the incident's TERMINATE recommendation.

**E. Fill the old `_EDGE_PRIOR` with ML posteriors.**
- Rejected. It confuses P(malicious | start) with the benign frequency of an edge kind, and counts the same evidence twice.

## False-positive cost

H = number of hosts; FP_h = validation false positives per host-hour at a given threshold. Values are placeholders until the model card exists.

| Cost | Formula |
|---|---|
| ML alerts per day | 24 · H · FP_h(alert) |
| Auto-COLLECT commands per day (once the flag is on) | 24 · H · FP_h(high) · P(ticks present) |
| Extra analyst-approval incident revisions | measured as Δ revisions in the replay harness |

**Gate:** the flag may be enabled only with FP_h(high) under budget (audit target: under 1 per host-hour), with a 95% CI reported.

## Consequences

**Amendment to `CLAUDE.md`.** "Evidence, not verdicts" stays for behavioral detectors. ML is a separate kind with the bounded permissions above. Widening any row of the decision table needs a new ADR, matching the workspace rule on auto-enqueue in manager ADR 004.

## Amendment 2026-10-30 (implementation)

As decided: annotation in `shadow` (the default), plus `ML-PROC-001` (level 7) / `ML-PROC-002` (level 9) findings in `active`, with `detection_source: "ml"`, no tactic and `active_response: null`. Soft stages (`ML-`, `BHV-` prefixes, `provenance/tagging.is_soft`) can join an incident but never root it: an ML hit on an earlier benign process must not re-root an incident a rule anchored. `ML-PROC-002` adds the itemised `ml_high_confidence_process` factor (+0.08) inside the existing context cap. The manager should list `"ml"` in its record-only sources as defence in depth.
