# Process-start classifier: dataset mixture, training and evaluation plan

## Context

We want a ProblemChild-style LightGBM classifier that scores Windows process starts as malicious or benign, trained **only on public data**.

- **Inputs:** only fields the Officer agent emits today, **plus integrity level**.
- **Integration:** wiring into the engine/manager is out of scope here. This plan ends with a model bundle, its documentation, and an evidence-based **integrate / don't-integrate verdict**.
- **Honesty contract:**
  - Labels never come from rule alerts.
  - Every number comes with a 95% CI.
  - Negative results are reported as such.
  - Never "zero-day". The claim is "recall on held-out techniques/sources at a stated FP budget".

### Facts this plan rests on

**Agent side.**
- **What a process start carries today:** `process.name`, `process.executable`, `process.command_line`, `parent.name`, `parent.pid`, and `user.name` / `user.domain` (`event.schema.json`; the agent's `main.cpp:337-352,617-620` split `DOMAIN\user`).
- **No SID on process starts** (the Sysmon path fills only name and domain). `sha256` is only present when Sysmon hashes are configured.
- **Only Sysmon EID1 carries a command line and the user.** ETW starts don't (`etw_process_collector.cpp:270-293`).
- **The model therefore scores the Sysmon copy of each start**, which is also where integrity level would come from.
- **The agent does not emit integrity level yet** (grep found nothing). A model that uses it can only be served after a small agent change (schema 0.6), which is out of scope.
- So we train **two variants**, and the evaluation decides whether integrity level is worth that agent change:

  | Variant | Features | Deployable |
  |---|---|---|
  | **A** | no integrity level | today |
  | **B** | A + integrity level | after the agent change |

**Datasets** (V = web page/sample read this session; nothing downloaded yet):

| Source | Licence | Format | Role |
|---|---|---|---|
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0 (V) | Sysmon XML (EID1 includes IntegrityLevel), per ATT&CK technique folder, Git LFS, >9 GB total, pulled selectively | main **malicious** source; its non-attack background processes are **benign, same-lab** |
| [Splunk BOTSv1](https://github.com/splunk/botsv1) | CC0 (V) | Sysmon sourcetype as per-sourcetype JSON/CSV (no Splunk needed); "attack-only" needles version is 135 MB, Splunk-indexed | main **benign** source: a realistic enterprise "haystack". ProblemChild used it. |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT | flattened Sysmon JSON. **Adapter already exists:** `panopticon_detection/datasets/otrf.py`, `panopticon-dataset` CLI, `docs/datasets.md` | second **malicious** source (Empire, Covenant, Mimikatz… different operators) plus same-lab benign background. Held out for leave-source-out. |
| [DARPA OpTC](https://github.com/FiveDirections/OpTC-data) | public domain | eCAR JSON (~1 TB); has image path, parent image path, command line, user, SID; **no integrity level**. Community labels: [optc-labels](https://github.com/AT03380/optc-labels), 748 malicious process creates | **optional**, Variant A only: large FP-rate test set plus an out-of-distribution (OOD) attack test |
| [WinLOLBIN-GT](https://zenodo.org/records/20533434) | CC BY 4.0 | CSV with `integrity_level`, per-row label. **Generated/templated** (documentation placeholders like `ExampleTask`, `$path`; synthetic `raw_event`) | **OOD stress test only, never trained on** |

**Excluded:**
- ATLASv2 and the 2026 multi-source Sysmon dataset: no public download found.
- EVTX-ATTACK-SAMPLES: licence not verified.

## 1. Where the work lives

- **Featurizer:** `panopticon_detection/ml/featurizer.py` in the engine. Stdlib-only, **not wired into the pipeline** (integration comes later). Training imports this module directly, so the featurizer used in training and the one used live are the same code.
- **Training tool:** `tools/train/` in the engine repo, with an optional extra `train = [lightgbm, scikit-learn, numpy]`.
  - Stated reason: training only.
  - `panopticon_detection/` never imports it, so runtime dependencies stay `pyyaml` + `pydantic`.
  - Adding this extra needs your approval (dependency budget).
- **Data:** everything downloaded or generated goes under `data/` (git-ignored, as `docs/datasets.md` already does).
- **Committed alongside:**
  - manifests, label rules, the model card, the datasheet, the evaluation report;
  - small fixtures under `tests/ml/`.
- **Pipeline** (each step is a CLI subcommand that writes a hash-stamped output):

  ```
  fetch → normalize → label → featurize → split → train → evaluate → export → report
  ```

## 2. Data acquisition and normalisation

1. **Fetch.** Reuse `panopticon-dataset fetch`, which already refuses a SHA-256 mismatch against a pin (`docs/datasets.md:54`).
   - Add pins for the selected Splunk attack_data technique folders and the BOTSv1 Sysmon JSON file.
   - **Each download is confirmed with you first** (file, source, size).
2. **Normalize to canonical agent events.**
   - New `datasets/sysmon_xml.py` reads Sysmon EID1 XML (Splunk attack_data and BOTSv1 `_raw`), reusing the EID1 field mapping and the `UtcTime` handling already in `otrf.py`.
   - Integrity level isn't in schema 0.5, and canonical events are schema-validated. So it is carried in a **side table keyed by `event_id`**, not injected into the event. It moves into the event once the agent's 0.6 schema lands.
3. **Optional: `datasets/ecar.py` for OpTC.** Process create only, a few hosts × days. Only if time allows.

## 3. Labelling (from provenance, never from rules)

- **Attack recordings (Splunk, OTRF).**
  1. Find the attack root from the dataset metadata: the Atomic test executor, the named payload, or the C2 launcher command.
  2. **Every process descending from that root is malicious**, found via the engine's own process tree: `ProcessRegistry`, `tree_root` in `enrichment.py`.
  3. Everything else on the host is **benign (same lab)**.
  4. Rows that can't be decided go to `unlabeled` and are excluded. They are never guessed.
- **BOTSv1.**
  - Benign = all Sysmon EID1 rows, **excluding** the documented attack host/time windows. Those come from the attack-only needles set: export its record ids once, using free Splunk, or use the published scenario timeline.
  - If a needle can be matched by record id, it becomes an extra malicious example.
- **Label audit.**
  - Manually review 200 random rows per class per source, stratified.
  - Record the disagreement rate.
  - If it's above 5%, fix the rule and relabel.
- **`labels_manifest.json`.** Per file: label rule, root process, counts per class and unlabeled, audit result.

## 4. Features (only emitted fields + integrity)

**Kept**, with ProblemChild-style normalisation (lowercase; usernames, GUIDs, hex and long digit runs replaced; system directories → `win_system_dir`):

- **Name:** normalised name; `ends_with_exe`.
- **Path:** normalised executable path; `path_class` via `enrichment.classify_path`; path depth.
- **Parent:** normalised parent name; a parent→child pair token.
- **Command line:**
  - length, token count, entropy (`ShannonEntropyCalculator`);
  - obfuscation flags (`CommandDeobfuscator`);
  - presence of a URL, IP, base64-like blob, or encoded/hidden/bypass flags;
  - character bigrams of the normalised command line, name and path.
- **User category:** `system`, `service`, `user` or `unknown`, from `user.name`/`user.domain`. **Never the user or host name itself.**
- **Integrity level (Variant B only):** Low / Medium / High / System / missing.

**Hashing.** Bigrams are hashed into a fixed 2¹² buckets with `hashlib.blake2b`, never `hash()`. That keeps features deterministic across `PYTHONHASHSEED`.

**Excluded** (memorisation or leakage): pid/ppid, host, timestamps, `entity_id`, `sha256`, raw usernames, parent path (not emitted).

**Harness-artifact scrub.** Before featurizing, strip tokens such as `AtomicRedTeam`, `atomics\T…`, `PathToAtomicsFolder`, `Invoke-AtomicTest` and `ExternalPayloads`, plus the lab's host and domain names. A **leakage probe** (§6) verifies it worked.

**Versioning.** `FEATURIZER_VERSION = 1`. Golden vectors (event → feature vector) are committed in `tests/ml/`.

## 5. Splits

- **Deduplicate** on (normalised name, normalised parent, normalised command line) before any split.
- **Grouping:**
  - malicious group = (source, ATT&CK technique);
  - benign group = (source, host).
  - No group straddles train and test.
- **Held out from the start, never touched until the final run:**
  - all of OTRF (leave-source-out);
  - one or more BOTSv1 hosts (FP test);
  - WinLOLBIN-GT;
  - OpTC.
- **On the remaining training pool:**
  - 5-fold `GroupKFold` for tuning;
  - a separate group-held-out calibration/threshold set (about 15%).

## 6. Training and evaluation

**Training.**
- LightGBM binary objective, with `deterministic=True`, `num_threads=1`, a fixed seed, `zero_as_missing=False`.
- A small grid: `num_leaves` {15, 31}, `learning_rate` 0.05, `min_data_in_leaf` {20, 50}, `feature_fraction` 0.8, early stopping, `scale_pos_weight` = benign/malicious ratio.
- Platt calibration is fitted on the calibration set.
- Thresholds are chosen on the calibration benign hosts:
  - `alert` at ≤ 1 FP per host-hour;
  - `high` at ≤ 0.1 FP per host-hour.

**Baselines** (same data, same splits):
1. **Rules-only.** Replay the canonical events through `build_detection_run`, and count a process as detected if any non-incident rule fires on its `process_create`. This is for evaluation only; it is never used as a label.
2. **Logistic regression** on the same features.
3. **LOLBin heuristic:** the `rules/lists` LOLBin names plus suspicious-flag tokens.
4. **Rarity baseline:** the existing `RarityDetector` (`behavioral/rarity.py`), learned on the training benign data.

**Evaluation protocols** (each reports Variant A and Variant B):

| ID | Protocol | Answers |
|---|---|---|
| E1 | random group split | optimistic ceiling. Reported, not trusted. |
| E2 | **leave-one-technique-out** (or leave-one-tactic-family-out if counts are small) | the primary "unseen behaviour" claim |
| E3 | leave-source-out: train Splunk → test OTRF, and the reverse | generalisation across tools and operators |
| E4 | held-out BOTSv1 hosts (+ OpTC benign, Variant A) | FP per host-hour on realistic benign data |
| E5 | WinLOLBIN-GT, OpTC red team | OOD stress, reported separately |

**Metrics.**
- PR-AUC (primary); ROC-AUC.
- Recall at 1 and at 0.1 FP per host-hour; precision at each threshold.
- Brier score / ECE and a reliability diagram.
- A per-technique recall table.
- **95% CIs** from a group bootstrap over techniques/hosts. **Paired bootstrap** against each baseline.

**Ablations.** Variant A vs B (does integrity help, or is it a source artefact?); no command-line bigrams; names only.

**Robustness.** A seeded mutation set over test positives, reporting the recall drop for each:
- caret insertion;
- case changes;
- environment-variable expansion;
- argument reordering;
- whitespace padding;
- a renamed binary copied to a temp path.

**Leakage probes.**
1. Train a classifier to predict the *source dataset* from features. If it is easy *and* sources correlate with labels, report it as a risk.
2. Inspect the top-30 feature importances for harness or lab tokens.
3. Check for duplicate rows across train and test.

**Error analysis.** Manually categorise the top 25 false positives and top 25 false negatives.

**Power, stated honestly.** Report the number of techniques and benign host-hours actually obtained. For example, with *k* held-out techniques all detected, the 95% lower bound on recall is 0.025^(1/k).

## 7. Integration decision gate (thresholds fixed now, before any test result)

**Integrate (in shadow mode first) only if all of these hold.**

| Gate | Condition |
|---|---|
| G1 | On E2, the model's recall at 1 FP per host-hour beats **rules-only** and **logistic regression** (paired bootstrap 95% CI of the difference > 0), and PR-AUC beats logistic regression |
| G2 | On E4, FP ≤ 1 per host-hour at `alert` and ≤ 0.1 at `high`, measured on held-out hosts |
| G3 | E3 recall within 15 percentage points of E2, i.e. no collapse across sources |
| G4 | The leakage probes are clean: no harness or lab tokens in the top-30 features, and no train/test duplicates |
| G5 | Calibrated ECE ≤ 0.1 |
| G6 | Reproducible: a rebuild from the manifests gives a bit-identical `model.json`; golden vectors pass |

**What failing the gates means.**
- If G1–G3 fail: **do not integrate.** Publish the evaluation as a negative result; at most, run it as a shadow research signal.
- If Variant B does not beat A by a CI-supported margin: the agent's integrity-level change is not justified *for the model*. It may still be justified for rules.

## 8. Deliverables and documentation checks

All under `docs/ml/` (committed) and `data/models/<version>/` (bundle).

- **`MODEL_CARD.md`** (Mitchell et al.):
  - intended use (process-start triage) and out-of-scope uses (not a malware/file classifier, not "zero-day");
  - training data, features, metrics with CIs for each protocol, thresholds and their FP cost;
  - known failure modes from the error analysis, ethical and operational caveats;
  - versions and hashes.
- **`DATASHEET.md`** (Gebru et al.), per source:
  - licence and attribution (CC BY for WinLOLBIN-GT; Apache-2.0, CC0, MIT, public domain for the rest);
  - URL and pin SHA-256, collection process, labelling rule and audit result;
  - class counts, known biases (lab vs enterprise, single red team, synthetic data);
  - personal-data notes (BOTSv1 usernames and hosts are fictional, and are normalised anyway).
- **`EVAL_REPORT.md`:** every table and figure from §6 and the §7 gate verdict with evidence.
- **Bundle:**
  - `manifest.json` (dataset pins, label manifest hash, featurizer version, engine and training git SHAs, LightGBM version, seeds, metrics);
  - `model.json`, `features.json`, `calibration.json`, `thresholds.json`, `golden.json`.
  - This matches the artifact interface in `docs/plans/ml-scoring-stage.md` §C.
- **Checklist enforced before the gate is evaluated:**
  - every dataset has a licence entry and pin;
  - every metric has a CI;
  - every exclusion is justified;
  - the report states what was *not* measured.

## 9. Schedule (estimate; today is Thu 2026-10-22)

| Day | Work |
|---|---|
| Thu–Fri | pins and downloads (with your approval); `sysmon_xml.py`; labelling plus audit; featurizer plus golden vectors |
| Sat | baselines; training; E1 and E2 |
| Sun | E3–E5, ablations, robustness, leakage probes; gate verdict; model card, datasheet, report |
| Stretch | OpTC adapter |

If time runs short, cut in this order:
1. OpTC;
2. robustness mutations;
3. the rarity baseline;
4. Variant B (leaving the integrity question for later).

**Never cut:** labelling audit, group splits, E2, E4, CIs, documentation.

## Verification

- `pytest -q` in the engine still passes (366/2 + new featurizer, label and adapter tests). `check_rule_sourcing.py` still OK. The new featurizer has no non-stdlib imports.
- Running `tools/train` end to end twice from the manifests produces identical `model.json` SHA-256 and identical metrics.
- Golden vectors pass under `PYTHONHASHSEED` = 0, 1 and random.
- The documentation checklist (§8) passes; `EVAL_REPORT.md` contains the gate table with a verdict.

---

## Deviations from this plan (recorded 2026-10-23, after execution)

Every change made after a result was seen is listed here and in
`EVAL_REPORT.md`; both runs' raw results are under `results/`.

| # | Planned | What happened | Why |
|---|---|---|---|
| D1 | BOTSv1 as the main realistic benign source | It holds only 767 process starts (3 hosts, 2 days, both days contain attacks) | measured on download |
| D2 | OpTC optional | Promoted to required for Variant A's false-positive test (user decision); two 25-host ranges from 19 Sep 2019 approved | D1 |
| D3 | OpTC downloaded | Initially **not used**: Google Drive answers "Quota exceeded" to anonymous full downloads (range requests work; splitting a download to get round the quota was not done). The eCAR reader (`pdtrain/optc.py`) is built and tested and waits for a manual download | access control |
| D4 | Leave-one-technique-out | 5-fold group cross-validation in which each technique (group) is unseen when scored; per-technique recall reported | 94-138 groups; one model per technique was not needed to get unseen-technique scores |
| D5 | Label audit: 200 rows per class per source | 100 rows reviewed by the assistant per iteration (3 iterations, labeller v1 -> v3); a 1,191-row sample is exported to `data/labelled/audit_sample.csv` for a human reviewer | time; stated as not done |
| D6 | Harness-token scrub before featurizing (§4) | Omitted in run 1 by mistake; the run-1 leakage probe found `splunkuniversalforwarder` as the top feature. Scrub implemented for run 2 | implementation gap |
| D7 | — | Lab infrastructure rows (Splunk forwarder & helpers) excluded from training in run 2 (still counted in false-positive streams) | run-1 leakage probe (G4) |
| D8 | — | Threshold search fixed for tied scores (baseline thresholds exceeded their budget in run 1) | bug |
| D9 | Rarity baseline | Cut (first item on the cut list after OpTC) | time |
| D10 | WinLOLBIN-GT OOD test | Only the 4 x 500-row samples were used, not the 15 GB release | approved scope |
| D11 | — | 466 OTRF process starts (31 NXLog-collected recordings) carry no ProcessId and are rejected by the existing adapter | data defect, documented |
| D12 | — | OpTC rows naming the image without a path (28%) excluded from training and E7 (run v5) | v4 leakage probe: `path_class=unknown` among the top features |
| D13 | Untouched test sets | E4, E6 and E7 were each evaluated in several runs (v2–v5); they are no longer pristine. A fresh test needs new data | iteration |
| D14 | — | The project owner's agent recording (4.5 h) added: the first half trains, the second half is test E6 | new data |
| D3 (update) | — | The project owner downloaded the two OpTC files; they are pinned and used from v4 | quota lifted manually |
