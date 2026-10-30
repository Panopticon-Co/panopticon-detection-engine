# ADR 001: Where the ML scoring stage runs

- Status: accepted, implemented 2026-10-30
- Date: 2026-10-22
- Plan: [ml-scoring-stage.md](../plans/ml-scoring-stage.md)

## Context

We plan to add a supervised process-start classifier: a LightGBM model, scored in pure Python. It is meant to become the engine's main triage input for living-off-the-land abuse.

The engine already has two candidate hooks:
- the `behavioral_detectors` loop (`detection_run.py:118-121`);
- the manager, after the engine emits an alert.

The behavioral loop has a fixed contract: evidence only. It sets kind `"behavioral"`, which is excluded from host risk (`detection_run.py:133`). Its signals carry no tactic, response or `_score` weight (`CLAUDE.md`, "Behavioral detectors").

A supervised classifier needs a narrower but non-zero role in risk and incident scoring, so it does not fit that contract.

## Decision

Add a dedicated `MLStage` to `DetectionRun`, constructed by `factory.build_detection_run` through new keyword-only arguments (`ml_model_path`, `ml_mode`). When those are not given, the factory falls back to the `PANOPTICON_MODEL_PATH` and `PANOPTICON_ML_MODE` environment variables.

**When it runs.** In `process_event`, right after `graph_builder.apply` (`detection_run.py:105`), and only for a `process_create` that produced an edge.

**What it produces.**
- An optional ML alert of kind `"ml"`, which goes through the existing dedup → emit → tag → `on_tag` path (`:127-163`).
- An `ml` annotation on rule alerts from the same event.

**How it computes the score.**
- **Featurizer:** event-local, stdlib-only, and stateless. Training imports the same module.
- **Scorer:** stateless.
- **Pruning:** `MLStage.prune` returns 0 but is still reached by `DetectionContext.prune`.

**Defaults.** With no model configured, the run behaves exactly as it does today.

## Alternatives considered

1. **Reuse `behavioral_detectors`.** Rejected: it would either break that contract or leave ML unable to inform risk and incidents.
2. **Score in the manager.** Rejected:
   - The manager is a read-only consumer of the engine (manager ADR 001).
   - CLI replays and corpus tests would no longer exercise the model.
   - Scores could not reach graph tags or incidents.
3. **Score per incident instead of per event.** Deferred. The model is trained on process starts, so incident-level scoring would need different labels.
4. **Score before `graph_builder.apply`.** Rejected: there would be no incarnation (`node_id`, observed ticks) and no edge to tag.

## Consequences

**Positive.**
- One code path serves the CLI, replays and the manager.
- Byte-identical behaviour with no model configured.
- No change to the manager's call.

**Negative.**
- `DetectionRun` gains a fourth detection kind.
- `CLAUDE.md`'s "one feature extractor" rule must be amended to "one featurizer per model, shared by training and serving".

**Follow-up.** `CLAUDE.md` and the engine README are updated in slice S2, not now.

## Amendment 2026-10-30 (implementation)

Implemented as `panopticon_detection/ml/stage.py`, called from `DetectionRun.process_event` right after `graph_builder.apply`. `score()` never raises: a malformed event or a scorer fault is counted in `ml_errors`. Scoring latency is reported as `ml_latency_mean_ms` / `ml_latency_max_ms` (about 0.15 ms per start for v7_v5). No timeout: a pure-Python tree walk is bounded by trees x depth.

**Train/serve skew, disclosed:** training applies a text scrub (`tools/train/pdtrain/experiment.py`, Atomic Red Team paths, `t1xxx` ids, lab domains) that serving does not. Scores on lab machines running Atomics are biased; do not quote them as performance.
