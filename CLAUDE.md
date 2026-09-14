# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This is **panopticon-detection-engine**, internally named **"eyedetect"** — the detection/correlation/alerting engine for the Panopticon&Co EDR platform (a separate polyrepo project; see `../CLAUDE.md` if present for cross-repo context). It's a pure Python CLI/library that ingests process-telemetry events, evaluates them against YAML detection rules, correlates them, and produces alerts. It consumes events from the separate `panopticon-agent` ("Officer") repo via the **Panopticon Schema 0.2** contract; it does not depend on that repo's source and should not gain such a dependency.

The README has already been corrected to state this precisely, but keep a critical eye on any future edits to it: per actual code (see Remediation section below) this is a research/capstone-grade CLI prototype: no web API, no database, no message queue, and remediation is currently simulated bookkeeping, not live system action.

## Setup / Build

```bash
pip install -r requirements.txt
```

Dependencies are minimal and deliberate: `pyyaml` (rule loading), `pydantic` (rule schema validation), `pytest` (tests). No web framework, DB driver, or ML library — do not add one without a phase-appropriate reason (see the workspace-root `../CLAUDE.md` roadmap; a backend/API is a later phase, not this one).

On Windows, if `python` resolves to the Microsoft Store alias, use `py -m pip install -r requirements.txt` instead.

## Test

```bash
pytest -v tests/
```

12 test files under `tests/` (e.g. `test_engine.py`, `test_correlation.py`, `test_full_mitre_suite.py`, `test_remediation_engine.py`, `test_officer_integration.py`). CI (`.github/workflows/ci.yml`) runs this matrix across Python 3.10/3.11/3.12 on `ubuntu-latest`, followed by a smoke-test invocation of `src/main.py` against `samples/master_full_spectrum_simulation.ndjson`. No linting or rule-schema validation step exists in CI currently.

## Run

```bash
# Batch mode against a sample/telemetry file
python src/main.py --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson

# Live: consume a Schema 0.2 NDJSON stream (e.g. captured from officer-agent.exe)
python src/main.py --rules rules --officer-ndjson samples/officer_live_sample.ndjson

# Live: spawn the compiled Windows agent directly and stream its stdout
python src/main.py --rules rules --officer --officer-bin path/to/officer-agent.exe

# MITRE coverage report
python src/main.py --mitre-matrix --audit-taxonomy
```

There is no server mode — this is a CLI batch/streaming tool with no listening port, no HTTP API, and no database *server* (V2's spool is a local SQLite file).

```bash
# V2 continuous streaming: bounded queue -> SQLite spool -> incremental alerts,
# with delivery retry, restart recovery, health/metrics, clean shutdown.
python src/main.py --rules rules --officer --officer-bin path/to/officer-agent.exe \
  --reliable --spool-db spool/panopticon-v2.db --output-file alerts.ndjson \
  --duration 30 --health-file health.json --metrics-file metrics.prom
```

## Architecture

Pipeline (`src/main.py` wires this together): load YAML rules from `rules/` -> build `RuleEvaluator` / `ThresholdEngine` / `CorrelationEngine` / cloud & identity engines -> stream events via `LiveTelemetryStream` -> evaluate each event against atomic rules, the cloud engine, identity/UEBA logic, a ransomware canary, a C2 beacon detector, a port scanner, and threshold rules -> emit `Alert` objects -> optionally hand off to `EndpointRemediationEngine` -> print/save.

- `src/ingestion/` — `officer_adapter.py` (`OfficerIngestionAdapter`, `SCHEMA_VERSION = "0.2"`) normalizes the Officer agent's JSON (`event`/`process`/`parent`/`user`/`host`/`source`/`agent` blocks) into this engine's internal event dict. `live_stream.py` (`LiveTelemetryStream`) supports either reading an NDJSON file line-by-line (auto-detecting the Officer schema) or spawning `officer-agent.exe` as a subprocess and reading its stdout pipe. Full field-level contract: `docs/OFFICER_INTEGRATION.md`.
- `src/evaluator/`, `src/rules/` — rule loading (`pyyaml`) and pydantic-based schema validation (`src/rules/schema.py`).
- `src/correlation/` — process tree building, multi-hop correlation graph, risk scoring.
- `src/alerting/` — `Alert` model and formatters. `Alert.from_detection_result` derives a **deterministic** `alert_id` (hash of `rule_id | event_id | host_id | timestamp | evidence-keys`) so replays / V2 restart-recovery don't emit duplicates.
- `src/reliability/` — **V2** opt-in streaming pipeline (see `docs/V2_RELIABILITY.md`): `queue.py` (bounded ingestion queue), `spool.py` (`AlertSpool`, SQLite WAL, delivery lifecycle + migration), `retry.py` (bounded backoff), `alert_sink.py` (`IncrementalAlertWriter`, append-safe + torn-tail repair + dedup), `health.py`, `metrics.py`, `pipeline.py` (`StreamingPipeline`). Reached with `--reliable`; `src/pipeline_core.py::DetectionRun` holds the per-event detection logic shared by the legacy loop and the pipeline. Does **not** change Schema 0.2 or the `alerts.ndjson` boundary.
- `src/remediation/` — see below; also `src/network/`, `src/cloud/`, `src/identity/`, `src/threat_intel/`, `src/mitre/` for domain-specific detection logic.
- `rules/` — 92 YAML rule files (verified count via `find rules -name "*.yaml" | wc -l`; matches README's current count), organized by category (`process/`, `identity/`, `persistence/`, `privilege_escalation/`, `network/`, `malware/`, `credential_access/`, `web_api/`, `cloud/`, `lateral_movement/`, `defense_evasion/`, `exfiltration/`, `collection/`, `file/`, `initial_access/`). Custom Sigma/Wazuh-inspired format, **not** Sigma-format: `id`, `level` (0-16), `logic: {all/any/none}` conditions, `active_response`, `mitre: {tactic, technique}`, `compliance` tags.
- `samples/` — NDJSON attack simulations per domain, plus `officer_live_sample.ndjson` (real Schema 0.2 shape) and a MITRE Navigator layer JSON.
- `scripts/demo_edr_pipeline.py` — terminal visualizer demo, the only script in the repo.

## Remediation — important gap to know about

`src/remediation/engine.py` (`EndpointRemediationEngine`) defines real-looking actions (`KILL_PROCESS_TREE`, `QUARANTINE_FILE`, `REVERT_PERSISTENCE`, `ISOLATE_HOST`, `LOCK_USER_ACCOUNT`, `REVOKE_CLOUD_ACCESS_KEY`, etc.), but every action currently just appends a `RemediationAction` dataclass and marks it `SUCCESS` (or `SIMULATED` when `dry_run=True`) — **there is no real `subprocess`/`os.kill`/`winreg`/socket call anywhere**, regardless of the `dry_run` flag. `main.py` constructs the engine with `dry_run=False`, and the `--auto-remediate` CLI flag is `action="store_true", default=True"` with no `--no-auto-remediate` counterpart, so it currently can't be disabled from the command line — worth fixing, but low-risk today since no real action fires yet.

Per the workspace-level policy (`../CLAUDE.md`), remediation must stay dry-run/non-destructive during the current MVP phase — do not wire any of these actions up to real system calls (process kill, filesystem quarantine, host isolation, account lockout) until a later roadmap phase explicitly calls for it.

## Changing the event schema

`officer_adapter.py`'s Schema 0.2 handling is a cross-repo API boundary with `panopticon-agent`'s `schema/event.schema.json`. Before changing how events are parsed here, check the producer schema and this repo's `test_officer_integration.py`, and coordinate the change with the agent repo rather than patching around a mismatch locally.
