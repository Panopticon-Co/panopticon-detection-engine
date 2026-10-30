# Plan: an ML scoring stage for process starts

Status: **draft for review**. Date: 2026-10-22.
Decisions: [ADR 001](../adr/001-ml-scoring-stage-placement.md) (placement),
[ADR 002](../adr/002-ml-versus-response-policy.md) (ML versus response) and
[ADR 003](../adr/003-ml-artifact-format-and-fail-open-loading.md) (artifact and loading).

**Labels:** **(V)** means verified by running it; **(R)** means read in source, with a `file:line` citation; **ASSUMED** means not checked. Paths without a repo prefix are in this repo.

## What this is, and what it isn't

**What it is.** A supervised LightGBM classifier, in the style of Elastic's ProblemChild, that scores each Windows `process_create` as malicious or benign. It uses only fields the Officer agent emits. In other words, it is a **per-event triage signal for living-off-the-land abuse**.

**What it isn't.** It is not a file or malware classifier: the agent sends metadata, not file contents.

**What does not change.** The engine still only recommends. Alerts carry recommendations from the existing vocabulary; the response engine and the manager tier them and stage them for analyst authorization. An unknown string fails closed.

**The artifact interface is a proposal.** It is described in §C, and no model exists yet.

## Baseline (V, 2026-10-22)

| Repo @ commit | Suite | Result | Time |
|---|---|---|---|
| engine `phase-2/behavioral-rarity-baseline` @ d744c2a | `pytest -q` | 366 passed, 2 skipped | 20.9 s |
| engine | `scripts/check_rule_sourcing.py` | OK, 69 rules | 0.45 s |
| manager `feat/ml-telemetry-ingest` @ 73417c1 | `pytest tests/` | 162 passed | 10.7 s |
| response_engine (vendored) @ cc61fcc | `pytest` | 57 passed, 16 failed (\*) | — |
| console `main` @ 296e1ad | `pytest` | 31 passed | 31.8 s |

(\*) Every one of the 16 failures is a `FileNotFoundError` for `tests/vendor/panopticon-contracts`, a nested submodule that isn't checked out. They are environmental, not code failures.

Python 3.12.12. The agent is Windows-only and was not built.

**Corrections to the brief:**
- **Python floor.** It is 3.10 (`pyproject.toml:10`); `README.md:46` already says so.
- **`_EDGE_PRIOR` is gone from this tree.** `provenance/campaign.py` was removed in e1649fa and replaced by `provenance/incident.py`. The prior survives only in the manager's vendored pin db4981a (`campaign.py:51-54`, used at `:284`).
- **`subprocess` is not a violation.** `ingestion/live_stream.py:6,24` uses it only to *spawn the agent binary* for input. Nothing imports `socket` or `winreg`, or calls `os.kill` (V, grep), so the rule at `CLAUDE.md:16` holds.

## A. Insertion point and data flow

**Where.** In `DetectionRun.process_event`, right after `graph_builder.apply` (`detection_run.py:105`), when `event_type == "process_create"` and an edge exists. That edge is the FORKED edge whose actor is the child. Three reasons for this spot:

1. **The incarnation is registered by then,** with its `node_id` and its observed `start_time_ticks`.
2. **An ML alert can join `detections`** and take the existing path unchanged: dedup → emit → `edge.tags` → `incidents.on_tag` (`:127-163`).
3. **Rule alerts from the same event can be annotated with `ml` before they are emitted.**

**Why not reuse the behavioral slot.** It hard-codes kind `"behavioral"` (`:118-121`), and that kind is excluded from risk (`:133`). That evidence-only contract stays for rarity. ML gets its own kind, `"ml"`.

**Featurizer.** It lives in `panopticon_detection/ml/featurizer.py`.
- **Stdlib only**, and **event-local**: its input is the normalized event from `ingestion/telemetry.normalize`.
- **Stateless:** it never reads the graph.
- **Shared reuse:** it may call pure helpers (`enrichment.classify_path`, `CommandDeobfuscator`, `ShannonEntropyCalculator`). Golden vectors catch any drift in them.
- **One copy:** the training tool imports this module, never a copy of it. This amends the "one FeatureExtractor" rule to "one featurizer per model, shared by training and serving".

**Graph attachment.** The ML alert passes through `tag_from_alert` (`provenance/tagging.py:95-112`), producing a tag with:
- `rule_id`: `ML-PROC-001` (alert band) or `ML-PROC-002` (high band);
- `tactic=""`;
- `level`: 7 or 9;
- `confidence`: the calibrated probability.

The tag is appended to the FORKED edge (`detection_run.py:158`). The existing incident code then treats it like this:
- **Never an anchor**, because it has no tactic (`tagging.py:68-70`). So ML can never open an incident.
- **Not counted** toward tactics (`incident.py:216,320`) or toward incident confidence (`:451-453`).
- **Never the highest stage level.** An incident only opens on an anchor at level ≥ 10 (`tagging.py:35`), which is above ML's 9. So the severity term (`incident.py:354-355`) is unchanged.

**Interaction with incident scoring.** One new itemised context factor in `_CONTEXT` (`incident.py:82-87`): `ml_high_confidence_process`, worth 0.08. It applies when an in-scope stage is `ML-PROC-002`.
- **Bounded:** it stays inside the existing `_CONTEXT_CAP` of 0.25 (`:88`) and shows in `score_breakdown`.
- **Can change the band** (`:90`). A band change is material, so it creates a new revision (`:326-338`).
- **Can re-surface a destructive recommendation, but not create one.** The revised incident alert carries the existing TERMINATE recommendation for the root process, which needs analyst approval (`:458`, `:466-486`). That is ML's *only* route to a destructive recommendation, and it requires an incident some rule already anchored.

**Rule hits are annotated, never re-levelled.** A rule's level drives three things:
- anchoring (`tagging.py:68`);
- the default TERMINATE/ISOLATE mapping (`alerting/active_response.py:64,86`);
- risk points (`provenance/risk_scorer.py:47-53`).

So if ML raised a level-11 rule hit to 12, ML alone would mint a kill recommendation.

**Risk meter.**
- **Feeding it:** `"ml"` alerts join `evidential` (`detection_run.py:126-151`), at 15 points for level 7 and 25 for level 9.
- **Rate limit:** each rule counts once per host per half-life (`risk_scorer.py:87-107`). ML alone therefore tops out at 40 points per hour, below the 75-point breach (`factory.py:106`).
- **Consequence of a breach:** it recommends only `COLLECT_NETWORK_CONNECTIONS` (`risk_scorer.py:187`).

**State.**
- The featurizer and scorer are stateless and use event time only.
- `MLStage.prune(before)` returns 0, but it is still wired into `DetectionContext.prune` (`factory.py:55-61`) and `stats` (`:69-75`), so a later stateful slice inherits the invariant.
- A count-min sketch (§F, S5) would be learned offline and frozen, like `RarityBaseline`.

**`_EDGE_PRIOR` should not hold ML posteriors.**
- **Different quantity.** The old prior was P(edge kind) under *benign* activity, used as surprisal. A classifier posterior is P(malicious | process start): a different base rate, and it exists only for process-start edges.
- **Double counting.** The same evidence would count twice, once as a stage and once as a prior.
- **The right learned replacement** is a benign frequency baseline (the S5 sketch, or the rarity counts).
- **What would justify it:**
  - a benign corpus of stated host-hours;
  - better incident ranking (AUC) on held-out scenarios, with leave-one-scenario-out confidence intervals;
  - zero new merges on `tests/corpus/sibling_noise_no_merge`.

## B. Alert and schema changes

**A new optional field, `Alert.ml: Optional[Dict] = None`** (`alerting/alert.py:35-56`).
- `to_dict` (`:98-99`, currently plain `asdict`) **omits it when it is None**, so rules-only output stays byte-identical.
- **Why not put it in `evidence`:** `_stable_alert_id` hashes the evidence key names (`alert.py:30`). Adding `ml` there would change rule alert ids between runs with and without ML, and break the manager's `INSERT OR IGNORE` dedup.

The `ml` block:

```json
{"model_id": "...", "model_version": "...", "artifact_sha256": "...",
 "featurizer_version": 1, "mode": "shadow|active",
 "raw_score": 2.31, "probability": 0.91,
 "threshold": {"name": "high", "value": 0.9},
 "top_features": [{"name": "...", "value": 1.0, "contribution": 0.42}]}
```

`top_features` is optional and approximate (path attribution).

**ML-only alerts:**
- **Id:** `"ML-" + sha1(model_version|host|event_id|timestamp|node_id)[:10]`. It is deterministic, and a new model yields new ids.
- **Severity:** level 7 (`medium`) or 9 (`high`).
- **ATT&CK:** `mitre_*` is None.
- **Tags:** `["ml", "process"]`.
- **Evidence display keys:** `process.name`, `process.parent.name`, `ml.probability`, `ml.model_version`, `ml.threshold`.

**Compatibility:**
- **Manager:** it stores the whole alert JSON (manager `detection/store.py:38`) and returns it (`routers/alerts.py:36`), so no migration is needed.
- **Console:** it passes fields through (console `app.py:68-93`) and renders every evidence entry (`static/app.js:126`). ML alerts are therefore visible with no console change, and `DISPLAY_FIELDS` (`app.py:55-65`) stays as it is.
- **Later console work:** showing `ml` on rule alerts is a small console PR.

## C. Artifact loading and distribution

**The bundle** (outside this repo):
- `manifest.json`: hashes, git SHA, data hashes;
- `model.json`: the LightGBM `dump_model()["tree_info"]` plus feature names;
- `features.json`: the spec and the featurizer version;
- `calibration.json`: Platt `a` and `b`;
- `thresholds.json`: `alert` and `high`;
- `MODEL_CARD.md`;
- **`golden.json` (new):** feature vectors with the output of `predict(raw_score=True)` and the probabilities.

**Loader** (`ml/artifact.py`). It returns a validated bundle, or raises `ArtifactError`. It checks:
- each file's sha256 against the manifest;
- that the format version is known;
- that `featurizer_version` matches the engine's;
- that feature names and order equal the featurizer's output;
- that the objective is binary;
- that every split is `"<="`, with `missing_type` of `None` or `NaN`. `Zero` is rejected because it silently sends 0.0 down `default_left`.
- that there are no categorical splits (v1);
- that every number is finite;
- that `0 < alert ≤ high < 1`;
- a size cap of 25 MB.

The trees are compiled to flat arrays at load time.

**Factory.** `build_detection_run` gains keyword-only `ml_model_path=None` and `ml_mode=None` (`factory.py:78-85`).
- **Defaults:** when these are None, it reads `PANOPTICON_MODEL_PATH` and `PANOPTICON_ML_MODE`. A model path with no mode means `shadow`; no path means today's behaviour.
- **Manager:** its call (manager `detection/factory.py:77`) is unchanged.
- **Optional pin:** `PANOPTICON_MODEL_SHA256` must match the manifest.

**Fail-open, loudly.** A load error is logged once (`ML stage DISABLED: <reason>; rules-only`), and `stats()["ml_state"]` is set to `"disabled"`.
- **It never raises.** The manager worker builds the run outside its `try`, so a raise would kill the worker silently.
- **Per-event errors** are counted (`ml_errors`) and logged at a limited rate.

**Distribution.** The manager has no rule control plane today: rules are a local directory (manager `config.py:16,39`). Models will work the same way. A later version, *out of capstone scope*, could add:
- an analyst-authenticated upload of a content-addressed bundle;
- validation with the same loader;
- a hot swap between worker batches;
- the active hash reported back.

## D. Parity and testing

- **Golden vectors.**
  - `tests/ml/golden_featurizer.json` maps events to feature vectors.
  - The bundle's `golden.json` must reproduce raw scores to within 1e-9.
  - CI uses a small hand-written fixture bundle (`tests/fixtures/ml/`, 2–3 trees, including a NaN `default_left` case), so **LightGBM is never needed in CI**. A real bundle is tested whenever `PANOPTICON_MODEL_PATH` is set.
- **Determinism.** The corpus is featurized and scored in subprocesses with `PYTHONHASHSEED` set to 0, 1 and random; the outputs must be byte-identical. An AST check bans `hash(` and iteration over sets in `ml/`.
- **No NaNs.** Every feature and every output passes `math.isfinite`. A missing value becomes a sentinel plus an indicator feature.
- **Budget** (ASSUMED limits; the audit target is p99 < 50 ms per event for the whole pipeline):
  - 10,000 scorings of a synthetic 300-tree, depth-7 model at p99 ≤ 1 ms each;
  - peak memory at load ≤ 50 MB;
  - marked slow.
- **Replay harness** (`scripts/ml_replay_compare.py`). It runs rules-only against rules+ML over `samples/*.ndjson` and `tests/corpus/*/events.ndjson`. Asserted invariants:
  - rule, stateful, beacon and risk alerts are identical in id, level and `active_response`;
  - incident ids and roots are identical;
  - ML alerts carry `COLLECT_PROCESS_INFO` or nothing.

  It also reports band and revision differences.
- **New CI gates**, alongside `check_rule_sourcing.py`:
  - `scripts/check_ml_artifact.py <dir>`, the same validator the runtime uses;
  - `scripts/check_runtime_deps.py`, which checks that dependencies are exactly {pyyaml, pydantic} (`pyproject.toml:12`). It also scans imports with AST and allows only `sys.stdlib_module_names`, `yaml`, `pydantic` and the package itself.

## E. Agent schema asks (recommendation: defer)

**The two collectors carry different halves of a process start** (R):
- **ETW starts** have pid, parent pid, image and CreateTime, which becomes `start_time_ticks` (agent `src/collectors/etw_process_collector.cpp:270-293`).
- **Sysmon EID1** has ParentImage, Image, CommandLine, User and Hashes (`sysmon_process_decoder.cpp:274-278`), but **no ticks** (`:255-261`).
- **Both run by default:** `--source all` (agent `src/main.cpp:671-675`).

So the model's inputs and the token response actions need arrive on *different* events.

**Do the two copies merge?** ASSUMED until a VM capture checks it. The incarnation key includes the start timestamp (`provenance/identity.py:105`), and `_insert` closes the previous incarnation on the same PID (`:463-481`), so merging depends on the two timestamps matching exactly.

**v1 rule:**
- Score only starts that carry a command line.
- Read ticks from the registry incarnation, passed through exactly as `incident.py:474-481` already does. If there are none, ML makes no recommendation; ticks are never derived (`identity.py:484-493`).
- Train only on fields present on the scored source.

**The asks:**
- **`parent.executable`** is cheap. It is already decoded (`sysmon_process_decoder.cpp:274`) and used only to derive `parent_name` (`main.cpp:617-618`). The schema's `process.parent` has `additionalProperties: false` with `{entity_id, pid, name}`, so this is an additive 0.6 field.
- **`integrity_level` and `original_file_name`** should be in Sysmon EID1 (ASSUMED: Sysmon isn't installed on the dev Mac). Confirm on the VM with `sysmon64 -s` (look for IntegrityLevel, OriginalFileName, ParentCommandLine). Neither is decoded today, and ETW never has them, so they must always be nullable.

**Coordination order:**
1. Agent: schema, decoder, normalizer and serializer, tests.
2. Manager: wire mirror and `_SUPPORTED_SCHEMA_VERSIONS` (`routers/ingest.py:27`, which still rejects 0.5; that is gap F1).
3. Engine: `telemetry.normalize`, `FIELD_REGISTRY`, the rule gate.
4. Featurizer v2, then retrain.

When a field is absent, its indicator is set to 0.

**Cost estimate (ASSUMED):** about 1–2 days on the agent and half a day on manager plus engine, plus a new model version.

## F. Slices (one PR each)

| Slice | Scope | Accept when | Roll back by |
|---|---|---|---|
| **S1** smallest end-to-end | featurizer, loader, scorer; `MLStage` in active mode emitting **ML alerts only**: fixed level 7, no recommendation, no incident factor; `Alert.ml`; factory keyword + env; CLI `--ml-model`; fixture bundle; golden/determinism/NaN tests; both gates | suites green; rule gate OK; replay invariants hold; a corpus replay yields `ML-PROC-001`; the console shows `ml.*` evidence | unset `PANOPTICON_MODEL_PATH` (off by default), or revert |
| **S1.5** real model | the user's bundle passes `check_ml_artifact` and golden parity; replay metrics recorded | parity ≤ 1e-9; within the latency budget | remove the bundle (fails open) |
| **S2** policy | alert/high bands; `shadow` mode (annotate, no ML alerts); `"ml"` in the risk meter; incident factor; `COLLECT_PROCESS_INFO` for the high band **behind a flag, off by default**; `CLAUDE.md` amendment | replay invariants hold; the factor is visible in `score_breakdown`; no ML TERMINATE/ISOLATE anywhere | mode `shadow`; flag off |
| **S3** manager | rebase onto manager `origin/main`; bump the `vendor/eyedetect` pin; env var in `docs/DEMO.md`; console renders `ml` | 162+ manager tests pass; `tools/fake_agent.py` end-to-end shows an ML alert in `/api/v1/alerts` and the console | revert the pin |
| **S4** agent asks | schema 0.6 across agent, manager and engine | every suite passes, plus the Windows smoke test | stay on 0.5; features go null |
| **S5** rarity sketch | frozen count-min over parent→child pairs, used as a feature and an incident factor | memory bound tested; deterministic | drop the feature (featurizer version bump) |

S1, S1.5 and S2 together form a demoable stopping point.

## G. Risks, kill criteria, cut list

**Risks:**
1. The split between the two process-start sources (§E).
2. Distribution shift: OTRF and lab data are Sysmon-only.
3. Label circularity: labels must come from harness manifests, never from rule alerts.
4. Pure-Python tree parity; the golden test is the gate.
5. The volume of automatic `COLLECT` commands.
6. The manager pin bump pulls in e1649fa (incidents replace campaigns; `PROV-CAMPAIGN` is kept).
7. A worker death if the loader ever raises.

**Kill criteria.** If any of these hits, ship rules-only and report the result honestly:
- parity worse than 1e-6 and not fixed within a day;
- validation false positives above budget at the chosen threshold (audit target: under 1 per host-hour). Then keep shadow mode only;
- leave-one-family-out recall no better than the rules + heuristic baseline within its confidence interval. Report that as a negative result;
- p99 above 5 ms per event.

**False-positive cost.** Placeholders, to be filled from the model card. H = hosts; FP_h = validation false positives per host-hour.

| Cost | Formula | Value |
|---|---|---|
| ML alerts per day | 24 · H · FP_h(alert) | `{TBD}` |
| automatic `COLLECT_PROCESS_INFO` commands per day | 24 · H · FP_h(high) · P(ticks present) | `{TBD}` |
| extra analyst-approval incident revisions | Δ revisions in the replay | `{TBD}` |
| precision at high; leave-one-family-out recall at high | ± 95% CI | `{TBD}` |

**Cut first → last:**
1. S5 sketch
2. S4 agent asks
3. `top_features`
4. console `ml` block
5. incident factor
6. COLLECT recommendation

**Never cut:** loader validation, fail-open, golden/determinism tests, replay invariants.

## Decisions needed (with recommendations)

1. **Escalating rule hits:** annotate only *(recommended)*, rather than re-levelling.
2. **What ML alone may recommend:** nothing until false positives are measured; then `COLLECT_PROCESS_INFO` for the high band only, with observed ticks *(recommended, safest)*.
3. **ATT&CK tactic on ML alerts:** none *(recommended)*.
4. **Incident factor:** 0.08 inside the 0.25 cap *(recommended)*.
5. **Which starts to score:** only those with a command line *(recommended)*.
6. **Featurizer input:** the normalized event *(recommended)*; lineage features later.
7. **Default mode when a bundle is present:** `shadow` *(recommended)*.
8. **Bundle contents:** add `golden.json` to the interface *(recommended)*.
9. **Agent schema asks:** defer until after the capstone *(recommended)*.
10. **Manager branch:** rebase onto `origin/main` before S3; decide who owns the F1 fix.
11. **Capstone final review date:** [FILL IN].
