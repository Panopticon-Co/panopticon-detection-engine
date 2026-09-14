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
   the process registry. This runs *before* evaluation so ancestry conditions on
   the event's own process resolve.
2. **`evaluator/`** matches atomic rules.
3. **`provenance/tagging.py`** writes each match onto the edge the event created
   — a detection becomes part of the graph, not a parallel stream.
4. **`provenance/campaign.py`** anchors a backward traversal when a match lands
   on a terminal tactic; that is how multi-stage campaigns are found.
5. Behavioral detectors (`behavioral/`) and threshold rules run independently.

### The provenance layer

- **`provenance/identity.py` (L1)** — the linchpin. The agent derives
  `process.entity_id` with a *different formula* for process-create than for
  network/file/registry/image-load (see the agent's `core/entity_id.hpp`), so
  entity_id can never join a process to its own later activity. This module
  joins on `(host_id, pid, timestamp)` instead, via interval stabbing over
  per-PID incarnations. **Never reintroduce an entity_id-keyed index.**
- **`provenance/graph.py` (L2)** — typed temporal graph. `backward()` walks
  undirected adjacency but only ever steps to edges at or before the time
  reached so far. That causality constraint is what makes the walk root-cause
  analysis rather than an arbitrary flood.
- **`provenance/campaign.py` (L4)** — scoring combines tactic breadth, path
  rareness and severity. `_EDGE_PRIOR` is an explicit **placeholder** for a
  learned baseline; the weights need real telemetry to tune. Do not present
  them as settled.

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
- `--story` renders from the alert itself. It replaced a hand-maintained rule-id
  table that claimed the engine had terminated processes and quarantined files.
  Keep it derived; do not reintroduce per-rule narrative text.

## Rules

`rules/` holds 54 rules, all targeting telemetry a Panopticon agent emits.

`scripts/check_rule_sourcing.py` fails CI if any rule declares an `event_type`
the normalizer cannot produce. There is no exemption directory: a rule that can
never fire is not coverage, it is a claim. The gate exists because 38 such rules
shipped unnoticed; they were deleted rather than parked.

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
