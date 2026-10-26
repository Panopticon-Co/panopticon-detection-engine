# Model card: `panopticon-process-start-lgbm` v1

Structure follows Mitchell et al., *Model Cards for Model Reporting*.

> **Status: NOT approved for integration (run v7). The global process-start classifier line
> ends here (pre-registered decision rule).**
> - Evaluated leave-one-environment-out over six environments, the v7 bundle keeps every unseen
>   environment at or below 1.16 false positives per host-hour, but detects 10% of attack rows,
>   20 pp fewer than the engine's rules.
> - v6's recipe, measured the same way, raises 6–31 false positives per host-hour in four of
>   six unseen environments.
> - See [EVAL_REPORT.md](EVAL_REPORT.md) (Verdict v7, Addendum 4). Bundle: `data/models/v7/`,
>   manifest in [`results/bundle_manifest_v7.json`](results/bundle_manifest_v7.json).

## v7 bundle (current)

- **Recipe `v7_lgb_no_stats`:** LightGBM, `num_leaves` 15, `max_depth` 4, `min_data_in_leaf`
  50, learning rate 0.05, 170 trees, monotone (+1) on the 43 indicators and the obfuscation,
  masquerade and double-extension flags; shape statistics dropped.
- **Featurizer v4** (`panopticon_detection.ml.featurizer`, stdlib-only, 540 features): roles
  and identity for 137 named Windows binaries (everything else `other`), role pairs, documented
  command-line indicators, path class and masquerade flags. No user or integrity features.
- **Training data:** all six environments (Splunk attack_data, OTRF, BOTSv1, the agent VM,
  OpTC, ATLASv2), 2,971 units after caps; environments weighted equally; parent-less copies at
  30%.
- **Thresholds:** `alert` and `high` are the strictest of the per-environment thresholds that
  keep each training environment within 1 and 0.1 false positives per observed host-hour.
- **Served by** `panopticon_detection.ml.scorer.load_model` (tree or linear), golden error 0.0;
  a rebuild is bit-identical.
- **Out of scope, unchanged:** not a malware classifier, not "zero-day detection", no
  autonomous response, Sysmon-sourced starts only.

## v1 bundle (historical)

## Model details

- **Type:** gradient-boosted decision trees (LightGBM 4.7.0), binary objective, in the
  style of Elastic's ProblemChild.
- **Variants:**
  - **A:** no integrity level; deployable with today's agent.
  - **B:** adds Sysmon integrity level; would need an agent schema change.
- **Hyperparameters:** chosen by grouped out-of-fold PR-AUC over a 4-point grid.
  `num_leaves` 15, `min_data_in_leaf` 20, learning rate 0.05, feature/bagging fraction 0.8,
  L2 1.0, 107 trees (A) and 86 trees (B), `deterministic`, single thread, seed 20261023.
- **Calibration:** Platt scaling on out-of-fold raw scores.
- **Thresholds:**
  - `alert`: ≤ 1 false positive per observed host-hour;
  - `high`: ≤ 0.1;

  both fitted on the training pool, out of fold.
- **Artefacts** (`data/models/v1/variant_{A,B}/`): `model.json` (LightGBM `dump_model`),
  `features.json`, `calibration.json`, `thresholds.json`, `golden.json`, and
  `manifest.json` (pins and labels hashes, engine commit `d03c4c1`, library versions,
  file SHA-256s). A copy of the manifest is in
  [`results/bundle_manifest.json`](results/bundle_manifest.json).
- **Serving path** (when approved): `panopticon_detection.ml.scorer.TreeModel` evaluates
  `model.json` in pure Python with no ML dependency. Its parity with LightGBM is tested
  (max error 0.0 on the golden vectors).
- **Featurizer:** `panopticon_detection.ml.featurizer`, version 2, stdlib-only, 6,693
  features. It's the same module for training and serving.

## Intended use

- **For:** triage of Windows *process-start* events (Sysmon-sourced) for living-off-the-land
  and post-exploitation behaviour. It's one signal among the engine's rules and correlation.
- **Not for:**
  - classifying files or malware (the agent sends metadata only);
  - "zero-day detection";
  - autonomous response;
  - ETW-sourced process starts (they have no command line or user);
  - any decision without an analyst.

  Per [ADR 002](../adr/002-ml-versus-response-policy.md) (draft), ML output may never
  recommend TERMINATE_PROCESS or ISOLATE_HOST on its own.

## Inputs

Only what the agent emits on a process start:
- process name, executable path and command line, all normalised;
- parent process name;
- user reduced to system / service / user / unknown;
- integrity level (Variant B only).

**Not used:** host, user identity, PIDs, timestamps, hashes. Harness and lab tokens are
scrubbed before featurizing.

## Training data

See [DATASHEET.md](DATASHEET.md).
- **Pool:** 4,666 de-duplicated rows (4,514 malicious, 152 benign).
- **Sources:** Splunk attack_data, OTRF compound and BOTSv1 servers.
- **Labels:** from provenance and dataset documentation, never from the engine's rules.

## Evaluation

Full tables with 95% CIs are in [EVAL_REPORT.md](EVAL_REPORT.md). Variant A, at the alert
threshold:

| Test | Result |
|---|---|
| Unseen techniques (grouped out-of-fold) | recall 0.59 [0.47, 0.71] at 0.86 FP/h; logistic regression 0.91, rules 0.29 |
| Another lab (OTRF) | recall 0.62 [0.52, 0.75], precision 0.99 |
| Held-out real desktop (4.3 h) | **3.0 FP/h** [1.6, 5.2]; recall on the Cerber infection 0.56 |
| Synthetic OOD (WinLOLBIN-GT) | near chance (ROC-AUC 0.54) |
| Calibration (out of fold) | ECE 0.005, valid only at the training prevalence (97% malicious) |

## Limitations and risks

1. **Too little benign data.** There are 152 distinct benign training rows, and only one
   real desktop for testing. Ordinary desktop software (Office, OneDrive, .NET compilation,
   vendor helpers) produces false positives.
2. **Lab artefacts.**
   - Run 1 learned the recording lab's Splunk forwarder as "benign". This was fixed by
     scrubbing and exclusion, but other lab artefacts may remain undetected.
   - Label noise is ~2–3% overall but clearly higher in OTRF.
3. **Generalisation gap.** Recall drops from 0.83 (random split) to 0.59 (unseen
   techniques). 26 of 94 technique groups are not detected at all at the alert threshold,
   including T1059, T1021 and T1053.
4. **Evasion.** Caret insertion (−11 pp) and `%SystemRoot%` spellings (−10 pp) lower
   recall.
5. **Integrity level adds nothing measurable** on this data (Variant B).
6. **Post-hoc fixes.** Run 2 was produced after run-1 numbers were seen (see the report), so
   it is not a pristine held-out estimate.

## Ethical and operational considerations

- **False positives cost analyst time and, if wired to collection actions, endpoint
  commands.** That is why the gate demands ≤ 1 per host-hour before any alerting.
- **Never describe this model as detecting "zero-days".** The measured claim is recall on
  held-out techniques and sources at a stated false-positive budget.
- **Licences:** WinLOLBIN-GT requires attribution (CC BY 4.0), and it was used only for
  evaluation.

## How to reproduce

```bash
pip install -e ".[dev,train]"         # libomp is needed on macOS (brew install libomp)
cd tools/train
python -m pdtrain fetch               # pinned downloads (~4.2 GB)
python -m pdtrain normalize
python -m pdtrain label
python -m pdtrain experiment          # ~2 min; writes data/experiment/results.json and data/models/v1/
```

A rebuild at commit `d03c4c1` gives bit-identical `model.json` files (A `e4114218…`,
B `0c0528c8…`).
