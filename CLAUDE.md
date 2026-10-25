# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**panopticon-detection-engine** — the detection, correlation and alerting engine
for the Panopticon&Co EDR platform. A pure-Python library plus CLI that ingests
endpoint telemetry, evaluates it against YAML rules, reconstructs multi-stage
attacks from a provenance graph, and emits alerts carrying *recommendations*.

**It never executes a response.** The closed seven-action command set, its
approval tiers and its dispatch live in `panopticon-response-engine` and
`panopticon-manager`. An alert's `active_response` is a recommendation those
repos translate, tier and stage for analyst authorization. Nothing here may call
`subprocess`, `os.kill`, `winreg` or a socket to act on a host.

Consumed by `panopticon-manager`, which vendors this repo as a git submodule at
`vendor/eyedetect` and calls `panopticon_detection.factory.build_detection_run`.

## Setup / test / run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/check_rule_sourcing.py     # CI gate, see "Rules" below
```

```bash
# Batch replay
panopticon-detect --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson

# Agent-shaped telemetry (exercises the provenance graph)
panopticon-detect --rules rules --officer-ndjson samples/officer_live_sample.ndjson --graph-stats

# Spawn the compiled Windows agent and stream its stdout
panopticon-detect --rules rules --officer --officer-bin path/to/officer-agent.exe

# Continuous pipeline: bounded queue -> SQLite spool -> incremental alerts
panopticon-detect --rules rules --officer-ndjson samples/officer_live_sample.ndjson \
  --reliable --spool-db spool/panopticon.db --output-file alerts.ndjson
```

Dependencies are deliberately minimal: `pyyaml`, `pydantic`. No web framework,
DB driver or ML library — adding one needs a stated reason.

There is no server mode, no HTTP API and no database server. The reliability
spool is a local SQLite file.

## Architecture

`factory.build_detection_run()` is the only supported way to construct a wired
run. `DetectionRun.process_event` handles one event, in this order:

1. **`provenance/builder.py`** turns the event into one graph edge and updates
   the process registry (inferring an unseen actor via `observe_context`). This
   runs *before* evaluation so ancestry and image-writer fields resolve.
2. **`evaluator/engine.py`** (single-event rules), **`evaluator/stateful.py`**
   (sequence / threshold / value_count) and **`behavioral/beacon.py`** detect.
   All read fields through `evaluator/matcher.extract_field`, which serves
   derived fields from **`enrichment.py`** (cached per event).
3. Repeats of a rule on the same process within the dedup TTL are suppressed.
4. Every detection is tagged onto the event's edge, then handed to
   **`provenance/incident.py`**, which attaches it to an open incident or opens
   one, emitting an incident alert only on open or material change.

### Behavioral detectors

`build_detection_run(..., behavioral_detectors=[...])` adds optional detectors
(none by default, so the manager is unaffected). Each takes
`(event, FeatureExtractor)` and returns `BehavioralSignal`s
(`behavioral/signal.py`). `DetectionRun` converts each one with `to_alert()` and
sends it down the ordinary dedup → emit → `tag_from_alert` → `on_tag` path.
Keep these properties:

- **One feature extractor.** `features.FeatureExtractor` serves live scoring,
  `--export-features` and `--learn-baseline`. Never compute features a second
  way for training.
- **Evidence, not verdicts.** A signal has no ATT&CK tactic, so it can join an
  incident but never open one. It carries no `active_response`, and it is
  excluded from the host risk meter. Do not give it a tactic, a response, or a
  weight in `_score`.
- **Frozen baseline.** `RarityDetector` never updates its `RarityBaseline`.
  Learning is offline (`--learn-baseline`), which keeps replay deterministic.
- Say "previously unseen behavior", never "zero-day detection".
- Details and limitations: `docs/behavioral-intelligence.md`.

### The provenance layer

- **`provenance/identity.py` (L1)** — the linchpin. The agent derives
  `process.entity_id` with a *different formula* for process-create than for
  network/file/registry/image-load (see the agent's `core/entity_id.hpp`), so
  entity_id can never join a process to its own later activity. This module
  joins on `(host_id, pid, timestamp)` instead, via interval stabbing over
  per-PID incarnations. **Never reintroduce an entity_id-keyed index.**
- **`provenance/graph.py` (L2)** — typed temporal graph. `backward()` follows
  *information flow* in reverse (child→parent, process→image file→its writer)
  and never steps forward in time; `forward_processes()` is its complement.
  Both stop at boundary processes (`provenance/boundary.py`). **Never make a
  walk undirected or let it expand through a boundary hub** — that merged every
  program under `explorer.exe` into one "attack" and rooted it at explorer.
  Sockets are leaves: shared destinations are correlation, not causation.
- **`provenance/incident.py` (L4)** — a tag's scope is its backward walk plus
  everything downstream of its tree's entry point; scopes that touch an open
  incident join it. Stages are recomputed from the graph, so replay rebuilds
  identical incidents. The incident alert keeps `rule_id: PROV-CAMPAIGN` (a
  stored contract with the manager) with `incident_id` stable and `alert_id`
  carrying the revision. The score is itemised in `score_breakdown`; keep it
  explainable rather than adding opaque weights.

### Rules

- Types: `single` (default), `sequence`, `threshold`, `value_count`
  (`rules/schema.py`). Stateful rules key `by` an entity kind (`process`,
  `parent`, `process_tree`, `host`, `user`) or a dotted event field.
- Named lists live in `rules/lists/<name>.yaml` and are referenced as `$name`.
- Unknown keys are rejected; `level` is required.

### Known limitations, stated deliberately

- The agent schema admits only `event.type: "start"` for the process family, so
  no `process_terminate` arrives. Incarnations are closed *implicitly* when a
  later one appears on the same `(host, pid)`. `observe_stop` is implemented and
  waiting for the agent-side schema change.
- A parent whose creation was never observed is *inferred* from the child's
  parent reference and flagged `inferred=True`. An agent starting on a running
  machine never sees existing processes being created.
- The graph is in-memory and does not survive a restart. SQLite persistence is
  the next step.
- `--story` and the default console view both render from the alert itself.
  They replaced hand-maintained rule-id tables that claimed the engine had
  terminated processes, quarantined files and "neutralized" threats. Keep them
  derived; do not reintroduce per-rule narrative text or any wording that says
  the engine acted.
- Every stateful component takes event time only (`identity.event_epoch`), never
  wall-clock time, and exposes `prune(before)`; `DetectionContext.prune` must
  reach all of them. A new stateful detector without `prune` is a memory leak in
  the manager's long-running worker. `before` and all parsed timestamps are
  naive UTC.

## Rule sourcing gate

`rules/` holds 64 rules, all reading telemetry a Panopticon agent emits.

`scripts/check_rule_sourcing.py` fails CI if a rule reads an `event_type` the
normalizer cannot produce, or a condition / `by` / counted / evidence field that
neither `ingestion/telemetry.FIELD_REGISTRY` (derived by running the normalizer)
nor `enrichment.DERIVED_FIELDS` provides for that event type. There is no
exemption directory: a rule that can never fire is not coverage, it is a claim.
New derived fields must declare the event types they apply to.

Replay scenarios in `tests/corpus/` are the evidence the engine works end to
end; add one (agent-schema NDJSON + `expected.json`) for any new correlation
behaviour, including a benign or must-not-merge case.

Rule format is Sigma/Wazuh-*inspired*, not Sigma: `id`, `level` (0-16),
`logic: {all/any/none}`, `active_response`, `mitre: {tactic, technique}`.

## Cross-repo boundaries

- **Event schema** — `ingestion/officer_adapter.py` and `ingestion/telemetry.py`
  consume `panopticon-agent/schema/event.schema.json`. Changing parsing here
  means coordinating with the agent repo, not patching around a mismatch.
- **Response recommendations** — the vocabulary this engine may emit is
  `TERMINATE_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`,
  `QUARANTINE_FILE`, `ISOLATE_HOST`. Anything else produces no command:
  `response_engine.translate_recommendation` fails closed by design. Never
  invent a sixth string or substitute a larger-blast-radius action for one that
  cannot be translated.
- **`start_time_ticks`** is an opaque, OS-native, pass-through-only token. It
  guards against PID reuse in `KILL_PROCESS`. Never derive, default or
  normalise it — a missing value must fail closed.
- **Manager entry point** — `factory.build_detection_run`. Changing its
  signature breaks `panopticon-manager` on the next submodule bump.
