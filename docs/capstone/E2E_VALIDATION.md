# Integrated pipeline validation (2026-10-25)

What was run, on which commits, and what was observed. Everything here was
executed in a Linux container. No Windows host and no real agent binary were
involved: the agent side was played by `tools/fake_agent.py` (ingest) and curl
(command poll, accept and result). Live Windows validation is the next step
(`docs/capstone/PLAN.md`, day 2–3).

## Commits

| Repository | Branch | Commit |
| --- | --- | --- |
| panopticon-detection-engine | claude/blissful-lamport-qk32ab | `39a3f4e` (engine code under test) |
| panopticon-manager | claude/blissful-lamport-qk32ab | `e32810b` (pins eyedetect `39a3f4e`, response_engine `cc61fcc`) |
| panopticon-console | claude/blissful-lamport-qk32ab | `00d8e1a` |
| panopticon-response-engine | claude/blissful-lamport-qk32ab | `2aa4848` (README only; manager pins `cc61fcc`) |

## Automated suites

| Suite | Command | Result |
| --- | --- | --- |
| Engine | `pytest -q` | 466 passed, 9 skipped, 4 failed. The 4 are `test_dataset_otrf.py` schema checks of 0.5 fixtures against the agent's published 0.4 schema; they fail only when a sibling `panopticon-agent` checkout exists, and the mismatch predates this work. |
| Engine rule gate | `python scripts/check_rule_sourcing.py` | all 69 rules read producible telemetry |
| Engine Track A replay | `python scripts/eval_demo_suite.py [--etw-twins]` | see `track_a_replay*.md`; exit 0 in both modes |
| Manager | `pytest tests/` + `ruff check .` | 200 passed; ruff clean |
| Console | `python -m unittest discover -s tests`, `node tests/*.cjs` | 61 OK; 5 node suites PASS |
| Response engine | `pytest` (contracts submodule initialised) | 73 passed |

## Live run: manager + console + simulated agent

1. Fresh SQLite database; `uvicorn manager.app:app`; then
   `tools/demo_seed.py` enrolled one analyst and three agents (ECDSA proof of
   possession). It replayed three corpus scenarios with timestamps rebased to
   now and with ETW twin reports, as the live agent sends them.
2. Manager `/api/v1/status`:
   - 179 events done, 0 failed;
   - 18 alerts;
   - 2 open incidents;
   - response actions: 5 PENDING, 2 AUTHORIZED (auto-safe network collection), 7 REJECTED (duplicates of open actions).
3. Incidents:
   - `WS-ALICE`: rooted at `winword.exe`, revision 2, Execution, Command and Control and Persistence.
   - `WS-CAROL`: rooted at `invoice_2026.exe`, Execution and Credential Access, provenance origin `chrome.exe`.
   - The benign host `WS-ERIN` has no alert and no incident.
4. Console against the real Manager (Chromium via Playwright):
   - the overview tiles, alert feed (18 rows, source badges), incident list and incident detail rendered;
   - the incident detail showed the stage timeline, lineage, causal path, score breakdown, member alerts, responses and audit;
   - no browser console or CSP errors.
5. The analyst approved the `KILL_PROCESS` for `rundll32.exe` pid 5600 in the console, typing the required confirmation. The agent (curl) polled and received:
   - `KILL_PROCESS {pid 5600, start_time_ticks 134373930753100000}`, the token from the process's ETW creation report;
   - then accepted it and reported `succeeded`.
6. The console showed "Agent reported SUCCEEDED for KILL_PROCESS (pid 5600)" with the audit trail `created (analyst) → dispatched → accepted → result_received (agent)`. The analyst resolved the incident with a note, which was audited as `status_changed` by `analyst:demo-analyst`.

## Defects found by running the components together

All are fixed, each with a regression test:

| Defect | Where | Effect before the fix |
| --- | --- | --- |
| A second report of one process creation replaced the first | engine `provenance/identity.py` | the process lost `start_time_ticks`; every kill recommendation failed closed on live telemetry |
| A rule recommendation built from a Sysmon start lacked ticks the process had | engine `detection_run.py` | same |
| A sequence rule completed twice from one creation reported twice | engine `evaluator/stateful.py` | duplicate stateful alerts |
| A merged re-report drew the creation edges again | engine `provenance/builder.py` | every causal path listed each step twice |
| Same-millisecond events were claimed in event-id order | manager `detection/worker.py` | the Sysmon report could be processed before ETW, again losing ticks |
| Console requested 500 alerts; Manager caps at 200 | console `static/app.js`, `app.py` | the alert feed returned 422 against the real Manager |
| The demo seed passed a token starting with `-` as a flag | manager `tools/demo_seed.py` | the demo seed aborted at random |

## Not validated here

- The real Windows agent binary, Sysmon and ETW on a live host.
- TLS between the agent and the manager. Earlier phases verified it (manager `docs/DEMO.md`); it was not re-run here.
- Atomic Red Team executions.
- Ingest-to-alert latency under load.
