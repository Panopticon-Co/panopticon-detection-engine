# ADR 003: ML artifact contract and fail-open loading

- Status: accepted, implemented 2026-10-30
- Date: 2026-10-22
- Plan: [ml-scoring-stage.md](../plans/ml-scoring-stage.md)

## Context

The engine's runtime dependencies are `pyyaml` and `pydantic` only (`pyproject.toml:12`). So the model must be scored in pure Python from an exported file.

The manager runs the engine in one long-lived worker thread. That worker builds the run *outside* its `try`, so any exception at construction time kills detection silently.

The manager has no rule control plane: rules are a local directory (manager `config.py:16,39`).

## Decision

**Bundle.** A directory, kept outside the engine repo, containing:

| File | Contents |
|---|---|
| `manifest.json` | format version, the sha256 of each file, training-data hashes, git SHA, metrics |
| `model.json` | LightGBM `dump_model()["tree_info"]` plus feature names |
| `features.json` | feature spec and featurizer version |
| `calibration.json` | Platt `a` and `b` |
| `thresholds.json` | `alert` and `high` |
| `MODEL_CARD.md` | — |
| `golden.json` | feature vectors with `predict(raw_score=True)` outputs and probabilities |

**Validation** (`ml/artifact.py`; the same code runs as the CI gate `scripts/check_ml_artifact.py`):
- every file hash matches the manifest;
- the format version is known;
- `featurizer_version` equals the engine's;
- feature names and order match the featurizer's output;
- the objective is binary;
- splits use `"<="` only, with `missing_type` of `None` or `NaN`. `Zero` is rejected because it treats 0.0 as missing;
- no categorical splits in v1;
- every number is finite;
- `0 < alert ≤ high < 1`;
- size ≤ 25 MB.

Trees are compiled to flat arrays when loaded.

**Selection.**
- `build_detection_run(..., ml_model_path=None, ml_mode=None)`.
- When these are None, it reads `PANOPTICON_MODEL_PATH` and `PANOPTICON_ML_MODE`.
- With a model path and no mode, the mode defaults to `shadow`.
- Optional pin: `PANOPTICON_MODEL_SHA256` must equal the manifest hash.

**Failure handling.**
- If any validation or I/O error occurs, ML is disabled and the run continues rules-only. This is logged once at ERROR, with the reason, and exposed in `DetectionContext.stats()` as `ml_state`. `build_detection_run` never raises because of the model.
- Scoring errors on individual events are caught, counted and logged at a limited rate.

## Alternatives

**Embed the model with `m2cgen`-generated Python.**
- Avoids a JSON interpreter.
- But it makes model updates code changes, and makes them harder to review.
- Rejected.

**ONNX or LightGBM at runtime.**
- Adds a native dependency to the engine.
- Rejected under the dependency budget.

**Fail closed (refuse to start) on a bad model.**
- Safer for model integrity.
- But it trades rules-based detection for a missing optional signal.
- Rejected. Fail-open is acceptable because ML is additive and its absence is reported loudly.

## Consequences

**Upstream requirements.**
- The training tool must emit `golden.json`.
- The training tool must run the validator before publishing a model.

**Version coupling.** A featurizer change means a featurizer version bump, which deliberately invalidates existing bundles.

**Distribution.**
- Today: a local path, mirroring how rules are handled.
- Signed upload through the manager is future work, and out of capstone scope.

## Amendment 2026-10-30 (implementation)

Implemented as `panopticon_detection/ml/artifact.py` and `factory.build_ml_stage`. The served bundle is `data/models/v7_v5` (featurizer 5, 228 trees, golden max error 4e-15), shipped out of band because `data/` is git-ignored. Selection and limitations: `docs/ml/MODEL_CARD_v7_v5.md`.
