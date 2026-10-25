# Capstone delivery plan (2026-10-25 → ~2026-11-01)

Decision record, contracts and evidence: the shared research report, plus
`docs/integration/CONTRACT.md`, `docs/ml/EVAL_REPORT.md` and
`docs/capstone/track_a_replay*.json`.

## Decision summary

- **Detection strategy:** layered hybrid. Rules and stateful rules raise
  detections, the provenance graph correlates them into incidents, and a policy
  gate stages responses. ML stays an offline research track (v1–v7 and ctx1 hit
  their pre-registered kill rules). Rarity is optional, evidence-only and off
  by default.
- **Fallback:** if incident correlation misbehaves live, demo atomic rule
  alerts with per-alert analyst approval (same response path).
- **Feature freeze:** end of day 4 (2026-10-29). After that point: no new
  rules, no new model work, no new dependency, no schema change. Only bug fixes
  found by rehearsal.
- **Rules frozen for live Track A:** tag the engine commit before the VM
  recording. A miss is reported as a miss.

## Priorities

| P | Task | Repo / files | Acceptance test | Est. | Fallback |
| --- | --- | --- | --- | --- | --- |
| P0 | Engine alert contract (`detection_source`, stage `alert_id`) | engine `alerting/alert.py`, `detection_run.py`, `provenance/incident.py` | `tests/test_alert_contract.py` | done | — |
| P0 | ETW + Sysmon duplicate start merge; ticks pass-through | engine `provenance/identity.py`, `detection_run.py`, `evaluator/stateful.py` | `tests/test_duplicate_process_start.py`, `tests/test_demo_suite.py` | done | — |
| P0 | Manager: engine pin bump, incidents tables, upsert + links, response dedup and behavioural guard, query API, status | manager `migrations.py`, `detection/store.py`, `detection/response.py`, `routers/` | manager `tests/test_capstone_e2e.py`: ingest → incident → API → approve → command → result; re-ingest makes no duplicates | 1–2 d | serve incident data from `alerts.alert_json` only |
| P0 | Console: manager-backed alerts, incidents view, approvals, audit, status | console `app.py`, `static/` | console unit and node tests; screenshots against a fake manager | 1–2 d | file-mode alerts plus existing response panel |
| P0 | End-to-end rehearsal on the Windows VM: agent → manager → console → approve → agent executes | all | runbook in manager `docs/DEMO.md`, executed start to finish | 0.5 d | replay through `tools/fake_agent.py --rebase-time` |
| P1 | Live Track A: Atomic Red Team suite (report table) + 2 h benign session | VM; `scripts/eval_demo_suite.py` style scoring from manager rows | per-test detected, alerts, latency, response class | 0.5 d | report the replay results only, stated as such |
| P1 | Report: final numbers, screenshots, qualified claims | shared doc | every number traceable to a file in a repo | 0.5 d | — |
| P2 | Storyline risk index (L3), per-site burn-in, agent schema 0.5, graph persistence | engine and agent | not before the capstone | — | future work |

## Day by day

| Day | Date | Work |
| --- | --- | --- |
| 0 | Sun 25 Oct | Evidence review and decisions; report drafted; engine contract and identity fixes; Track A replay; manager and console integration started |
| 1 | Mon 26 Oct | **Submit the report.** Merge manager and console branches after review; full local e2e |
| 2 | Tue 27 Oct | Windows VM: agent → manager over TLS; live replay of the corpus via `fake_agent`; fix integration defects |
| 3 | Wed 28 Oct | Live Atomic Red Team suite plus a benign session; score; fix only pipeline bugs (no rule changes) |
| 4 | Thu 29 Oct | **Feature freeze.** Screenshots, demo runbook, docs |
| 5 | Fri 30 Oct | Two full rehearsals, timed; record a backup video |
| 6–7 | Sat–Sun | Buffer, final report numbers, submission |

## First three tasks (started 25 Oct)

1. **Engine contract.** Inspect `alerting/alert.py`, `detection_run.py` and
   `provenance/incident.py`. Acceptance: every alert has a `detection_source`,
   every incident stage names its member `alert_id`, and replay is idempotent.
   Done in `f03fd9a`.
2. **Manager persistence and API.** Inspect `manager/migrations.py`,
   `detection/store.py`, `detection/response.py` and `routers/alerts.py`.
   Acceptance: the e2e test above passes, and a second ingest of the same batch
   adds zero rows.
3. **Console views.** Inspect `app.py` and `static/app.js`. Acceptance: the
   incidents list and detail render from manager data, approve/reject is
   available only on PENDING actions, and no text claims an action that did not
   succeed.
