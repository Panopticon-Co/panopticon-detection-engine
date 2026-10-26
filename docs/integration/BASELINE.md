# Engine baseline for the contract-coverage work (W0)

Recorded 2026-10-26 on branch `engine/contract-coverage`, cut from `origin/main` @ `696dfb0`.
Python 3.12.12 (`../.venv`). Plan: contract-first consumer, coverage model and an
ML pipeline ready for richer future telemetry.

| Check | Command | Result |
| --- | --- | --- |
| Unit, corpus and ML tests | `pytest -q` | 494 passed, 2 skipped, 33.5 s. The sibling `../panopticon-agent` checkout is on `feat/ml-telemetry-foundation` (schema 0.5), so the OTRF 0.5 schema checks pass here. Against an agent checkout on `origin/main` (schema 0.4) four of them fail (`docs/capstone/E2E_VALIDATION.md`). |
| Rule sourcing gate | `python scripts/check_rule_sourcing.py` | OK, 69 rules |
| Track A replay | `python scripts/eval_demo_suite.py` | 7 scenarios; 4/4 attack chains detected with the correct incident; 0 benign alerts; replay idempotent |
| Track A replay, ETW twins | `python scripts/eval_demo_suite.py --etw-twins` | same summary; 96 benign events |
| Behaviour oracle | `python scripts/engine_oracle.py --check docs/integration/baseline_oracle.json` | identical on a second run (deterministic) |

## The behaviour oracle

`scripts/engine_oracle.py` replays the 7 corpus scenarios and 3 bundled samples
through the fully wired engine with the training replay's `CheckpointTap`, and
hashes the alerts, the graph edges, every checkpoint feature record and its
context vector (`CONTEXT_VERSION` 1), plus `FIELD_REGISTRY` and the feature-name
layouts. `baseline_oracle.json` is the reference. Any change described as "no
behaviour change" (the family-descriptor refactor, the declarative
behaviour-feature table) must reproduce it exactly. A change that alters
behaviour on purpose regenerates it in the same commit and says why.

The hashes are regression evidence over synthetic fixtures. They are not
detection results.

## ML reference points (unchanged, from `docs/ml/EVAL_REPORT.md`)

- v7 process-start model: worst-environment 1.156 FP per host-hour at alert, macro recall 0.0986 (−0.197 vs rules).
- ctx1 context model: C1–C5 fail; the pre-registered kill rule applies (Addendum 5).
- Rules on the full replay: macro recall 0.2748; 0.47–90.5 FP per host-hour by environment.
