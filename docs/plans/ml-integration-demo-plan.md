# Plan: integrate the best defensible ML model, and a reliable live demo

Status: **plan only, not implemented**. Written 2026-10-30 from three parallel read-only
investigations: model evidence, engine/manager/console integration, and demo scenarios.
Every claim cites a file. "n/m" means not measured.


> **Update 2026-10-30, Phase 2 done.** LOEO was re-run for the shipped v7_v5 model (identical `model.json`).
>
> | Measure | Value |
> |---|---|
> | Macro recall | 0.0838 |
> | Difference vs rules | −0.211 |
> | Worst held-out FP/h | 0.1156 (BOTSv1, 1 event) |
> | Criteria | S1/S3/S5 pass; S2/S4 fail |
>
> Where §C says the shipped rebuild is unevaluated, use `docs/ml/MODEL_CARD.md` and `docs/ml/results/v7_v5.json` instead.

Windows-only checks are in `docs/capstone/WINDOWS_HANDOFF.md`.

---

## A. Executive recommendation

1. **Model.** Integrate **v7_v5**, the v7 recipe rebuilt under featurizer v5. It is the only
   artifact the current engine can load.
   - Its recipe has the only defensible held-out result: leave-one-environment-out (LOEO),
     worst environment 1.156 FP/host-hour.
   - Every input it reads is produced by Officer's process-create telemetry.
   - It is weak. Macro recall is 0.0986, 20 points below rules, and it failed its own
     pre-registered criteria S1, S2 and S4.
   - So it is integrated as a **triage aid**, never a verdict, and never a response trigger.
   - ctx1 is excluded: its kill rule fired and it cannot be served.
2. **Architecture.** Keep the design already implemented, uncommitted, on `ml/scoring-stage`.
   - A fail-open `MLStage` runs after the provenance graph update.
   - It **annotates** rule alerts (`Alert.ml`) and, in `active` mode, emits separately
     labelled `ML-PROC-001/002` findings (level 7/9, `detection_source: "ml"`). These carry no
     tactic and no response, and cannot open an incident.
   - Rules never depend on it. This needs hardening, a rebase onto the manager's pinned
     engine (`9697e6b`), and small manager and console changes before ML is visible in the
     dashboard.
3. **Demo.** It rests on deterministic detections, not on ML.
   - **Live on Windows:** `whoami /priv`, `schtasks`, `cmdkey`, `certutil` and a Run key. The
     first four are already proven over HTTP by the manager test `test_live_demo_path.py`.
   - **Mac replay as fallback:** corpus scenarios through `fake_agent.py`, for incidents,
     ransomware and LSASS.
   - **ML demo, a separate segment:** the real artifact loads; a positive and a benign
     fixture are scored, with outputs measured, not chosen; a corrupted artifact still lets
     every rule alert fire.
4. **One small extra evaluation is warranted.** Re-run LOEO for the v7_v5 recipe (about 2–5
   min, local data present) so the slide quotes numbers for the model actually shipped. No
   other training.

---

## B. Current-state evidence

| Area | State | Evidence |
|---|---|---|
| ML stage (engine) | Implemented, uncommitted. 36 targeted tests pass; real-bundle tests skip in CI because `data/` is git-ignored | `panopticon_detection/ml/{artifact,stage}.py`, `detection_run.py`, `factory.py`, `tests/test_ml_stage.py`, `tests/ml/test_ml_artifact.py` |
| Scoring latency | About 155 µs per `score()` with v7_v5 (228 trees), pure Python | integration review probe |
| Full suite / oracle after the incident-root change | **Not yet re-run** | — |
| Manager engine pin | `9697e6b` = engine `origin/main` `696dfb0` + 2 commits from `origin/windows-canonical-endpoint-ingest`. Those commits touch `alert.py`, `detection_run.py` and `cli.py`, so a rebase is needed | `panopticon-manager/vendor/eyedetect` |
| Manager factory | Passes only `rules_dir`, `emit`, `retention`. ML would be enabled by env vars with no code change | `manager/detection/factory.py:110-114` |
| Manager storage | Stores the full `to_dict()` plus `detection_source`, with no CHECK constraint, so `"ml"` persists | `manager/detection/store.py:53-79` |
| Manager alerts API | `source` filter is a `Literal` without `"ml"`, so `?source=ml` returns 422 | `manager/routers/alerts.py:67` |
| Manager response policy | An ML alert has `active_response=None`, so it returns early. `"ml"` is not in `_RECORD_ONLY_SOURCES` (defence in depth missing) | `manager/detection/response.py:116,211-213` |
| Manager health | Never calls `context.stats()`, so ML state is invisible | `manager/routers/health.py:44-80`, `worker.py:98-106` |
| Console | Shows any `rule_id`. Source `"ml"` renders as "unknown". `a.ml` is never read, so shadow-mode annotations are invisible | `panopticon-console/static/app.js:94,103,131-134,599`, `app.py:83` |
| Live agent wire | Demo build sends canonical endpoint records 1.0 to `/api/v2/endpoint/records` | `panopticon-agent` `src/pipeline/endpoint_record.cpp:49-53`, `manager/routers/endpoint.py:35` |
| Legacy ingest | Rejects 0.5, which affects only replay of `fileless_powershell_lsass_dump` | `manager/routers/ingest.py:27,103` |
| Canonical mapping | process / network / file / registry / image_load / dns / process_access / remote_thread map. `script_block`, auth (4625) and FIM become `endpoint_<kind>_<category>`, which no rule reads | `vendor/eyedetect/.../ingestion/endpoint_adapter.py:17-20,166-167` |
| Default response | A level ≥ 12 alert with a pid gets `TERMINATE_PROCESS` even without a YAML response. The manager stages it for an analyst | `alerting/active_response.py:64` |
| Twin reports | ETW and Sysmon report each start, so one trigger may produce two rule alerts | manager `docs/demo/MAC_STATUS.md` |

---

## C. Model evaluation (v1 to v7, v7_v5, ctx1)

All models are LightGBM 4.7.0, served by the stdlib tree scorer.

| | v1 | v2 | v3 | v4 | v5 | v6 | **v7** | **v7_v5** | ctx1 |
|---|---|---|---|---|---|---|---|---|---|
| Unit | start | start | start | start | start | start | start | start | process-in-context |
| Features | 6,693 hashed | 6,693 | 6,693 | 6,693 | 6,693 | 6,693 (f3) | 540 closed (f4) | 540 (f5) | 632 (ctx v1) |
| Benign data | 152 lab rows | lab | + agent VM half | + OpTC | + OpTC, bare names removed | + 125 OpTC hosts | 6 environments | same, 37 rows relabelled | 8,774 replayed |
| Method | pooled out-of-fold, E3–E5 | E6 | E6 | E7 | E2–E7 | E2–E7 | **LOEO** | **not run** | LOEO (replay) |
| Worst held-out FP/h | 3.02 | 163 | 0 (recall 0.08) | 27.0 | 1.86 | 8.85 | **1.156** | n/m | 6.25 |
| Recall | 0.59–0.62 | 0.59 | 0.08 | n/m | 0.44–0.57 | 0.78–0.82 | **macro 0.0986** | n/m | macro 0.0041 |
| Precision | 0.986 (E3) | n/m | n/m | n/m | 0.98 | 0.94 | n/m | n/m | n/m |
| Difference vs rules | +0.296* | — | −0.21* | — | +0.274* | +0.484* | **−0.197** | n/m | −0.271 |
| F1, FPR, confusion matrix | n/m | n/m | n/m | n/m | n/m | n/m | n/m (per-fold FP and recall counts only) | n/m | n/m |
| Loads in engine | no | no | no | no | no | no | no (featurizer 4) | **yes** (golden error 4e-15) | no |

\* Pooled false-positive budget. **Not comparable** to v7 or ctx1. Pooling hid 6–31 FP/h on
unseen environments (`docs/ml/EVAL_REPORT.md:455-467`). Under LOEO, the v6 recipe gives
22.5–31 FP/h.

Sources: `docs/ml/EVAL_REPORT.md` (109–488), `docs/ml/results/v7.json`
(`recipes.v7_lgb_no_stats`), `docs/ml/results/context_ctx1.json`, and each bundle's
`manifest.json` / `features.json`.

**Selection: v7_v5**, for a limited, explicitly scoped contribution. The reasons, against the
brief's criteria:

1. **Officer compatibility.** It reads only `process.executable`, `process.command_line`,
   `process.name` and `parent.name` (`ml/featurizer.py:297-300`). All four are in
   `FIELD_REGISTRY["process_create"]`.
2. **Held-out evaluation.** It is the only recipe that kept every unseen environment at or
   below 1.16 FP/h.
3. **False positives.** It is the best of the measured recipes. Its alert threshold (3.4809)
   is set by the worst environment (minimax).
4. **Value beyond rules.** Weak (−0.197 macro recall), so it is used as a triage annotation
   and low-severity finding, not a detector of record.
5. **Reproducibility.** The rebuild is bit-identical (S6), and the bundle carries hashes and
   golden vectors.
6. **Explainability.** One score, two bands, and a model version plus sha on every output.

**Minimal additional evaluation (Phase 2):** re-run LOEO on the v7_v5 recipe. Until it runs,
the slide must say "v7 recipe LOEO numbers; the shipped rebuild has 228 vs 170 trees and a
threshold set by a different environment, and has not been re-evaluated".

**Limitations to disclose.**
1. Failed its pre-registered S1, S2 and S4. The documented verdict was "do not integrate as
   a detector".
2. About 10% macro recall under LOEO, 20 points below rules. Not "zero-day detection".
3. The shipped rebuild is not evaluated until the Phase 2 run.
4. The probability field is at training prevalence. Show the raw score and band, not a %.
5. It scores only Sysmon process starts carrying a command line. ETW twins are skipped.
6. Three environments have under 10 host-hours, so their FP/h is noisy.
7. No human label audit. 27 identical inputs carry both labels.
8. Residual environment fingerprint (benign-environment AUC 0.84).
9. The sealed test recording was never collected.
10. Training applies a text scrub (Atomic Red Team paths, `t1xxx` IDs, lab domains) that
    serving does not (`tools/train/pdtrain/experiment.py:189-212`). Lab-VM scores on Atomics
    are biased.
11. Mostly Windows 7–2019-era training data; the agent targets 10/11.

---

## D. ML integration architecture

### Data flow

```
Officer -> canonical record 1.0 -> manager /api/v2/endpoint/records -> worker
  -> EndpointIngestionAdapter -> DetectionRun.process_event
       1. graph_builder.apply                    (unchanged)
       2. ml_result = MLStage.score(event)        (process_create with command_line only; fail-open)
       3. rules / stateful / behavioral detect    (unchanged, never read ML)
       4. rule alerts get alert.ml = annotation   (score, band, thresholds, model version, sha)
       5. mode=active and band set -> ML-PROC-001 (alert band, level 7) / ML-PROC-002 (high band, level 9)
            detection_source "ml", tags [ml, process], no tactic, no active_response
       6. dedup (rule_id, host, actor, 600 s) -> tag -> IncidentTracker
            ML can JOIN an incident (+0.08 context factor, inside the 0.25 cap); it never opens one or roots it
  -> alerts table + alerts.ndjson -> console
```

### Alert semantics

| Kind | How to recognise it | Can open an incident | Response |
|---|---|---|---|
| Deterministic | `detection_source` rule/stateful, `DET-*` | yes (terminal tactic, level ≥ 10) | rule or level default, analyst-gated in the manager |
| ML finding | `detection_source: "ml"`, `ML-PROC-00x`, `ml{}` block, "triage aid, not a verdict" | no | none, ever |
| Correlated | rule alert carrying `ml{}`, or a `PROV-CAMPAIGN` whose stages include an ML stage | — | unchanged by ML |

Low-confidence results are kept on the annotation (`band: null`, "below threshold"). An
unavailable ML (disabled, not scoreable, errored) adds **no** `ml` key, so it is never
presented as a negative. The reason is visible in stats.

### Failure behaviour

| Case | Behaviour | Status |
|---|---|---|
| Artifact absent | Rules-only, no `ml_*` stats | done |
| Load failure, hash, featurizer or feature-order mismatch | `ml_state: disabled` plus `ml_error`, logged; rules run | done, tested |
| Missing command line | counted `ml_skipped_no_command_line` | done |
| **Malformed event** (`process` not a dict) | currently raises before the `try` | **GAP: fix in Phase 1** |
| Inference exception | counted `ml_errors`, logged on the 1st and every 1000th | done, **untested** |
| Timeout | No timeout. Not needed: bounded trees × depth, about 155 µs | **add latency sum/max metric** |
| Below threshold | annotation `band: null` | done |
| Same event as a rule | both alerts kept (different `rule_id`); ETW+Sysmon twins collapse by dedup | **add test** |

### Interface changes (all additive)

- **Engine:**
  - `build_detection_run(..., ml_model_path=None, ml_mode=None)`;
  - env vars `PANOPTICON_MODEL_PATH`, `PANOPTICON_ML_MODE`, `PANOPTICON_MODEL_SHA256`;
  - `Alert.ml` (omitted when None);
  - `detection_source: "ml"`;
  - CLI `--ml-model`, `--ml-mode`;
  - `DetectionContext.stats()` gains the `ml_*` keys.
- **Manager:** none required to run ML. The changes needed to **show** it are in Phase 3.

### Files expected to change

- **Engine:**
  - `ml/stage.py` (guard, latency);
  - `factory.py` (stale docstring at :46);
  - tests;
  - `docs/adr/001-003`, `CLAUDE.md` (ML stage paragraph), `docs/integration/CONTRACT.md`
    (`ml`, `"ml"` source);
  - a model card at `docs/ml/MODEL_CARD.md`.
- **Manager:**
  - `vendor/eyedetect` (pin);
  - `manager/routers/alerts.py:67`;
  - `manager/detection/response.py:116`;
  - `manager/detection/worker.py` (`describe`);
  - `manager/routers/health.py`;
  - tests;
  - `tools/demo_up.sh` (env passthrough).
- **Console:**
  - `app.py:83`;
  - `static/app.js:94,103,131-134,599`;
  - `static/index.html:230`;
  - tests.
- **Agent, contracts:** none.

---

## E. Demonstration scenarios (ranked)

The path to the dashboard is the same for all of them: worker → alerts table +
`alerts.ndjson` (`worker.py:294`) → console (`demo_up.sh:142,171,223`). Independent check:
`GET /api/v1/alerts?rule_id=…` or `grep <rule_id> $STATE_DIR/alerts.ndjson`.

| # | Scenario | Benign action | Telemetry | Rule (level, response) | Proven how | Cleanup | Gap | Rank |
|---|---|---|---|---|---|---|---|---|
| 0 | Benign control | `notepad`, bare `whoami` | Sysmon 1 | none expected | live-path test | close | — | must |
| 1 | Recon | `whoami /priv` | Sysmon 1 | DET-PROC-008 (10, none) | manager `test_live_demo_path.py` + corpus | none | — | 1 |
| 2 | Scheduled-task persistence | `schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f` | Sysmon 1 | DET-PERS-002 (10) | live-path test | `schtasks /delete /tn PanopticonDemo /f` | — | 2 |
| 3 | Credential enumeration + approval queue | `cmdkey /list` | Sysmon 1 (+ ETW ticks) | DET-CRED-003 (12, TERMINATE staged PENDING) | live-path test | none | kill fails closed without `start_time_ticks` | 3 |
| 4 | LOLBin download | `certutil -urlcache -split -f http://127.0.0.1:8080/demo.txt %TEMP%\ct.txt` | Sysmon 1 | DET-PROC-003 (12) | live-path test | `del %TEMP%\ct.txt` | Defender may block the download; the alert still fires | 4 |
| 5 | Run-key persistence | `reg add HKCU\...\CurrentVersion\Run /v PanopticonDemo /d notepad.exe /f` | Sysmon 13 | DET-PERS-001 (12) | corpus + synthetic; **not live** | `reg delete … /v PanopticonDemo /f` | confirm EID 13 reaches the manager | 5 |
| 6 | Discovery burst | `whoami; ipconfig /all; net user; systeminfo` (one shell) | Sysmon 1 | DET-DISC-001 (10, value_count by parent) | corpus + synthetic; **not on canonical path** | none | canonical parent reference | 6 |
| 7 | Encoded PowerShell | `powershell -NoProfile -EncodedCommand <b64 Write-Output>` | Sysmon 1 | DET-PROC-011 (11) | synthetic | none | entropy > 4.5: test the exact string; AMSI | 7 |
| R | Replay (Mac fallback) | `fake_agent.py --rebase-time --etw-twins`, default scenarios + `internal_reconnaissance`, `ransomware_precursors_and_encryption` | corpus 0.3 | PROV-CAMPAIGN incidents, DET-RANS-*, beacon, KILL approval | `docs/DEMO.md`, Track A 4/4 | restart with fresh state dir | `fileless_powershell_lsass_dump` is rejected (0.5) | fallback |

**Not demoable live** (show by replay or state it as a gap):
- failed logons (4625 has no rule);
- FIM / monitored directory (non-family records);
- ransomware rename (no Sysmon rename);
- script block (not mapped);
- LSASS access (no harmless trigger);
- beaconing (loopback excluded).

**ML in scenarios.**
- v7_v5 scores every Sysmon start. On the corpus (measured): `fileless_powershell_lsass_dump`
  powershell 3.97 and rundll32 3.70, and `office_macro_to_c2_and_persistence` svchelper 4.07,
  give ML-PROC-001. Benign stays at or below 2.56. `internal_reconnaissance` 3.41 is just
  under the threshold.
- Scores for the live triggers 1–7 are **unknown**. Phase 4 measures them on the Mac with
  synthetic records; the Windows handoff measures them live.
- The demo must not promise that ML fires on any particular trigger.

---

## F. Implementation sequence

The freeze (2026-10-29) has passed. Every phase below needs the owner's explicit go-ahead.
Manager and console edits are cross-repo and need separate authorization.

### Phase 0: regression gates on the current uncommitted work (Mac, engine; about 10 min)

- **Run:** `pytest -q`; `scripts/engine_oracle.py --check docs/integration/baseline_oracle.json`
  (rules-only must be identical); `scripts/check_rule_sourcing.py`; `scripts/check_runtime_deps.py`;
  `scripts/eval_demo_suite.py`.
- **Done when:** all green, and the oracle is identical.

### Phase 1: harden and commit the engine ML stage (Mac, engine; about 0.5 day)

1. Move the whole of `MLStage.score` into the `try`, plus `perf_counter` latency sum/max in
   `stats()`.
2. **Tests:**
   - a malformed event and an injected scorer exception leave rule alerts intact;
   - ML + rule on the same event;
   - twin dedup of ML alerts;
   - `to_dict()` / NDJSON round-trip with `ml` and `"ml"`.
3. **Docs:**
   - fix the stale `factory.py:46` docstring;
   - update ADR 001–003 (status, the scrub skew, shadow vs active);
   - `CLAUDE.md` ML paragraph;
   - `CONTRACT.md` additive fields;
   - model card.
4. Commit on `ml/scoring-stage`.
5. Create `ml/scoring-stage-canonical` from `9697e6b` and cherry-pick the commit, resolving
   conflicts in `alert.py`, `detection_run.py` and `cli.py`. Note that `_emit` rewrites
   `alert_id` to `ALT-…` for canonical records; `rule_id` keeps `ML-PROC-*`.
6. Add an engine test feeding canonical record 1.0 process records through the
   `EndpointIngestionAdapter` with ML active.

- **Done when:** Phase 0 gates are green on both branches, and the canonical-record ML test
  passes.

### Phase 2: honest numbers for the shipped model (Mac, background; about 5 min plus write-up; parallel with Phase 1)

- **Command:** `cd tools/train && ../../../.venv/bin/python -m pdtrain v7 --version v7_v5_loeo`.
  It writes `data/experiment/results_v7_v5_loeo.json` and a separate bundle; it does not
  overwrite `v7_v5`.
- **Check** that the produced `model.json` sha equals v7_v5's. If it differs, report the
  results as describing a sibling build.
- **Write** the model card with this table and §C's limitations.
- **Done when:** the model card cites a results file for the shipped recipe.

### Phase 3: make ML visible in manager and dashboard (Mac; cross-repo, needs authorization; about 0.5 day; parallel with Phase 2)

- **Manager:**
  - bump `vendor/eyedetect` to the Phase 1 canonical commit;
  - add `"ml"` to the `alerts.py:67` Literal and to `_RECORD_ONLY_SOURCES`;
  - `worker.describe()` carries the `ml_*` stats, exposed on `/metrics`;
  - `demo_up.sh` passes `PANOPTICON_MODEL_PATH` / `PANOPTICON_ML_MODE` /
    `PANOPTICON_MODEL_SHA256`;
  - tests: store persists `ml`, response stays NONE for `"ml"`, `?source=ml` returns 200.
- **Console:**
  - "ML" source badge and filter;
  - render `a.ml` (score, band, model version, sha, the "triage aid, not a verdict" text);
  - for `ML-*`, label confidence as a fixed prior;
  - tests.
- **Done when:** `test_live_demo_path.py` and `test_capstone_e2e.py` pass with ML on and off,
  and a replay shows an `ML-PROC-001` row and an annotated rule alert in the console.

### Phase 4: ML demo segment and fixtures (Mac; about 2 h; after Phase 1)

1. `scripts/ml_demo.py` (from the scratchpad prototype):
   - loads the real bundle and prints the version and sha;
   - scores the positive fixture (corpus `fileless_powershell_lsass_dump` powershell start)
     and the benign fixture (`benign_workstation` max);
   - prints the measured scores and bands;
   - repeats with a corrupted copy of the bundle and shows `ml_state: disabled` with the same
     rule alerts.
2. Record the outputs in `docs/capstone/ML_DEMO_EXPECTED.md`, generated by running the
   script, never hand-written.
3. Score the live triggers 1–7 as synthetic canonical records. Record which cross the
   threshold; this is a prediction for the Windows run only.

- **Done when:** the script is deterministic and two runs are identical.

### Phase 5: Windows rehearsal (Windows agent, `docs/capstone/WINDOWS_HANDOFF.md`)

- **Prerequisites:** Phases 1 and 3 merged into the demo branches, and the bundle copied to
  the manager host.
- **Done when:** the handoff report shows the benign control silent, at least two scenarios
  verified through the API and console, and the ML score observed live (or reported as
  absent with its reason).

### Phase 6: runbook and slides (Mac; about 2 h)

- `docs/capstone/DEMO_RUNBOOK.md`: live order 0 → 1 → 2 → 3 → 4 (→ 5, 6, 7 if verified); the
  ML segment; the replay fallback; cleanup; the twin-alert caveat.
- ML slide: §C table plus limitations.

**Parallelism.**
- Phase 2 runs in the background during Phase 1.
- Phase 3's console part is independent of the manager pin and can start alongside Phase 1.
- Subagents: one for the console UI and tests; one reviewer (`python-reviewer`) after
  Phases 1 and 3.

---

## G. Final acceptance checklist

**Mandatory**
- [ ] v7_v5 selected; model card cites a reproducible results file (or states "recipe-level
  numbers" explicitly).
- [ ] Engine loads the bundle; `stats()` shows `ml_state` active, `ml_scored` > 0.
- [ ] Missing, corrupt and hash-mismatched bundles leave rules-only output identical to the
  oracle.
- [ ] Phase 0 gates green; no regression in deterministic tests.
- [ ] At least two live scenarios verified by API **and** console on Windows (or on the Mac
  replay if Windows fails), benign control silent.
- [ ] At least one alert visible in the dashboard end to end.
- [ ] ML demo: real inference on a positive and a benign fixture, outputs measured and
  recorded, plus the failure demo.
- [ ] Every alert shows `detection_source`, evidence and (when scored) `ml`; no ML alert
  carries a response.

**Optional**
- [ ] ML visible live on Windows.
- [ ] Run-key, discovery burst and encoded PowerShell live.
- [ ] Latency metric on `/metrics`.

---

## H. Risks and fallback

| Risk | Fallback |
|---|---|
| Agent build not ready, or Windows VM unavailable | Mac replay (`demo_seed.py` + `fake_agent.py`) with the same console |
| Manager VM disk full (`/srv/panopticon-data` at 100%) | `--state-dir` on another volume |
| Sysmon EID 13 missing | drop scenario 5; replay shows DET-PERS-001 |
| Twin alerts on stage | say it before the audience sees it (known ETW+Sysmon double report) |
| Defender/AMSI blocks certutil or encoded PowerShell | the alert fires on the process start anyway; else skip it |
| Pin bump breaks the manager | keep the old pin; demo ML through the engine CLI (`panopticon-detect --ml-model … --ml-mode active`) on the corpus |
| ML bundle not on the manager host / sha mismatch | ML disables itself, the rules demo is unaffected; show ML via the CLI segment |
| ML fires on a benign live process | it is level 7, no response, labelled triage; this is a disclosed limitation, not hidden |
| ML does not fire on any live trigger | expected possibility; the ML segment uses the measured corpus fixtures |
| Replay of `fileless_powershell_lsass_dump` rejected (0.5) | use the engine CLI for that scenario |
