# Evaluation report: process-start classifier

Date: 2026-10-23. **Current configuration: run v7** (leave-one-environment-out protocol,
featurizer v4, labeller v4, LightGBM 4.7.0, selected recipe `v7_lgb_no_stats`), raw numbers in
[`results/v7.json`](results/v7.json), the v6 recipe under the same protocol in
[`results/v7_loeo_baseline_v6_recipe.json`](results/v7_loeo_baseline_v6_recipe.json). Earlier runs
are kept for transparency, told in order below: run 1/2 (lab data only), v2/v3 (agent-recorded
benign), v4/v5 (OpTC), v6 (more OpTC). Plan: [`training-plan.md`](training-plan.md) (deviations
at its end). Model: [`MODEL_CARD.md`](MODEL_CARD.md). Data: [`DATASHEET.md`](DATASHEET.md).

## Verdict (v7): do not integrate; the global process-start classifier stops here

Under the pre-registered decision rule, if v7 fails the false-positive criterion even with the
redesigned features, iterating this classifier on these data ends. It did:

- **Honest measurement changed the picture of v6.** Holding each environment out entirely, v6's
  recipe raises **6–31 false positives per host-hour** in four of six unseen environments
  (your VM 31, OTRF 22.5, OpTC 18, BOTSv1 6.1). OpTC's 0.65/h in v5/v6 held only because
  its own hosts were in training.
- **When every environment must stay within budget, the model detects almost nothing.** The
  best v7 candidate keeps all unseen environments at or below 1.16 FP/h, but finds 10% of
  attack rows (macro over environments), **20 pp fewer than the engine's rules** (CI
  [−25, −12]).
- **Why:** each small real environment contains a few benign starts that look exactly like
  tradecraft (BOTSv1's authorised Nessus scan running `netsh advfirewall show` and
  `schtasks /query`, your VM's PowerShell compiling with `csc`, OTRF lab administration), and
  process-start fields cannot tell them apart from attacks. In the low-false-positive region
  the ranking is near chance in two of four unseen environments (partial AUC 0.52 BOTSv1,
  0.56 OTRF; 0.69 ATLASv2, 0.83 Attack Range; 0.5 = chance).
- **ATLASv2 in training** removed every false positive on your VM (7.1 → 0 FP/h), but added
  some on BOTSv1 (0.12 → 1.16) and did not change recall (+1.4 pp, CI [−0.6, +3.9]).

**What remains true:** the model ranks attacks above most benign activity (ROC-AUC 0.72–0.86
in unseen environments), training is reproducible bit for bit, and the rules raise far more
false positives than any v7 candidate in five of six environments (6.8–79 per host-hour; 0.58
on ATLASv2). **Next steps are different
projects, not v8:** per-site burn-in thresholds or baselines, provenance context (lineage,
image writers), or using the score only as evidence inside rule-opened incidents.

## Verdict (v5, historical): do not integrate yet

Realistic benign data changed the picture. The final model was trained on lab attacks plus:
- DARPA OpTC benign activity from 25 hosts;
- the first half of your own Officer-agent recording.

**Where it now meets the budget:**
- **≤ 1 false positive per host-hour on two of three held-out benign streams:**
  - 25 unseen OpTC hosts: **0.65/h** [0.50, 0.83] over 100 h;
  - the second half of your agent recording: **0.93/h** [0.11, 3.36] over 2.1 h.
- **At the `high` threshold, both streams give 0 false positives.**
- **Detection:** it catches **57%** [43, 69] of techniques it never saw in training. That's
  +27 pp over the engine's rules (CI [+10, +44]).
- **The rules, for comparison:** 80 false positives per host-hour on the same OpTC hosts,
  and 7 per host-hour on your VM.

**Three pre-registered conditions still fail:**
1. **G1.** It does not significantly beat logistic regression (+3 pp, CI [−7, +13]). The
   LOLBin keyword heuristic catches more unseen techniques at the same budget (−13 pp,
   CI [−25, −3]).
2. **G2.** On the held-out BOTSv1 desktop it raises **1.86/h** [0.80, 3.67] at `alert` and
   0.70/h at `high`, against budgets of 1 and 0.1.
3. **G4 (in spirit).** The training source is still predictable from the features (AUC
   0.83–0.86), and environment fingerprints rank among the top features:
   - OpTC's emulated users drive everything through `python.exe → cmd.exe`;
   - your VM runs `git … --ignore-submodules`.

   "python → cmd is benign" is not a lesson to deploy.

**Robustness:** caret insertion cuts recall from 0.44 to 0.13 on another lab's attacks.

**Variant B (integrity level) looks much better: 86% on unseen techniques. It is not
trustworthy.** OpTC and your recording carry no integrity level, and they are almost all of
the benign data. So "integrity missing" means "benign", which is exactly the missingness
leak the plan warned about. On BOTSv1, which does have integrity level, Variant B raises
9 false positives per hour. To judge integrity level fairly, it has to be recorded on the
benign side too: the agent schema change, then new recordings.

**What would change the verdict:**
- benign recordings from more machines and users, taken with the agent;
- a fresh, untouched test set. **The held-out sets above have been looked at across several
  runs**, so they are no longer pristine;
- removing environment fingerprints. Options include per-environment baselines, or dropping
  parent→child pair features that encode a lab's automation;
- deobfuscating carets before featurizing.

**Recommended use now:** a shadow-mode research signal at the `high` threshold, if anything.
No alerts, and no response actions.

## What was evaluated

| Set | Content | Rows (deduplicated) |
|---|---|---|
| **pool** (train, out-of-fold scoring) | Splunk attack_data, OTRF compound, BOTSv1 servers; malicious groups = ATT&CK technique (capped at 300), benign groups = host; lab infrastructure excluded | 4,666 (4,514 malicious / 152 benign), 133 groups, 202 observed host-hours |
| **E3** leave-source-out | OTRF atomic: another lab, other operators | 296 (113 / 183) |
| **E4** held-out host | BOTSv1 `we8105desk`, raw event stream incl. the Cerber infection | 588 raw events (27 malicious), 4.3 observed host-hours |
| **E5** out-of-distribution | WinLOLBIN-GT samples (synthetic) | 1,000 (500 / 500) |

**Calibration and thresholds** (Platt; ≤ 1 and ≤ 0.1 false positives per observed
host-hour) were fitted on pool out-of-fold scores only, then frozen for E3–E5.
- *Observed host-hours* is the sum of gaps between consecutive events per host, each capped
  at one hour.
- Confidence intervals come from a 1,000-sample bootstrap over groups.
- Comparisons between models are paired bootstraps.

## Gates (fixed in code before any test result)

| Gate | Result | Evidence |
|---|---|---|
| **G1**: beat rules-only and LR at the alert budget; PR-AUC ≥ LR | **FAIL** | vs rules +0.296 [+0.179, +0.426] ✔; vs LR **−0.319 [−0.443, −0.200]** ✘; PR-AUC vs LR −0.0024 [−0.0086, −0.00001] ✘ |
| **G2**: E4 FP ≤ 1/h at alert, ≤ 0.1/h at high | **FAIL** | alert 3.02/h [1.61, 5.17] (13 events), high 2.09/h [0.96, 3.97] (9 events) |
| **G3**: E3 recall within 15 pp of E2 | PASS | E3 0.619 vs E2 0.588 |
| **G4**: no harness tokens in the top 30; no train/test duplicates | PASS *(after D6/D7)* | 0 harness tokens (A and B); 0 shared keys; source-predictability AUC 0.52/0.51/0.57 |
| **G5**: ECE ≤ 0.10 | PASS *(caveat)* | out-of-fold ECE 0.005, Brier 0.013; calibrated at the pool's 97% malicious prevalence, so the probabilities do **not** carry over to deployment prevalence |
| **G6**: bit-identical rebuild; golden vectors | PASS | `model.json` A `e4114218…`, B `0c0528c8…` identical across three rebuilds; pure-Python scorer max error 0.0 |

## Results

### E2: unseen techniques (pool, out-of-fold)

| Model | PR-AUC | ROC-AUC | Recall @ ≤1 FP/h | Recall @ ≤0.1 FP/h | FP/h achieved (alert) |
|---|---|---|---|---|---|
| LightGBM A | 0.995 [0.981, 1.000] | 0.916 [0.786, 0.994] | 0.588 [0.466, 0.714] | 0.511 [0.393, 0.638] | 0.86 |
| LightGBM B (+integrity) | 0.995 | 0.915 | 0.544 [0.431, 0.664] | 0.451 | 0.86 |
| Logistic regression | 0.997 | 0.940 | **0.908** [0.861, 0.945] | 0.738 | 0.87 |
| LOLBin heuristic | 0.987 | 0.794 | 0.700 [0.598, 0.774] | 0.231 | 0.36 |
| Rules only (process starts) | 0.975 | 0.624 | 0.292 [0.232, 0.362] | 0.292 | 0.04 |
| *E1 ceiling: random split, LightGBM A* | 0.999 | 0.986 | 0.832 | 0.732 | — |

**Why PR-AUC is saturated:** with 97% malicious prevalence in the pool, PR-AUC is near 1 for
everything. Use recall at the budget and ROC-AUC.

**The generalisation gap is large.** E1 (random split) recall at alert is 0.83; E2 (unseen
techniques) is 0.59.

**Per technique, LightGBM A at the alert threshold:**
- 26 of 94 groups have zero recall, including T1059 (300 rows), T1021 and T1053;
- 39 groups reach recall ≥ 0.8.

### E3: another lab (OTRF atomic)

| Model | PR-AUC | ROC-AUC | Recall @ alert | Precision @ alert |
|---|---|---|---|---|
| LightGBM A | 0.939 [0.852, 0.993] | 0.954 [0.917, 0.980] | 0.619 [0.517, 0.746] | 0.986 |
| LightGBM B | 0.945 | 0.956 | 0.345 | 1.000 |
| Logistic regression | 0.920 | 0.934 | 0.752 [0.650, 0.875] | 0.904 |
| LOLBin heuristic | 0.571 | 0.661 | 0.363 | 0.820 |
| Rules only | 0.443 | 0.580 | 0.195 | 0.759 |

**Error analysis.** Of the 43 malicious rows the model misses, about 17 of the 25
lowest-scoring are Windows housekeeping that the background-subtraction labeller wrongly
called malicious: Update Orchestrator, SmartScreen, Office Click-to-Run, SCOM monitoring,
`wlrmdr`, `upfc` and similar.
- **Consequence:** E3 recall is *understated*, and label noise in OTRF is far above the
  2–3% that the overall audit (dominated by attack_data) measured.
- **The genuine misses:**
  - a Covenant implant (`wmiprvse → GruntHTTP2.exe`);
  - webshell commands (`w3wp → cmd /c whoami`);
  - `wmiprvse → net user /add backdoor`.

### E4: held-out real desktop (raw stream, 4.3 host-hours)

| Model | Threshold | FP events | FP / host-hour [95% Poisson CI] | Recall on malicious events |
|---|---|---|---|---|
| LightGBM A | alert | 13 | 3.02 [1.61, 5.17] | 0.56 |
| LightGBM A | high | 9 | 2.09 [0.96, 3.97] | 0.56 |
| LightGBM B | alert | 10 | 2.33 [1.12, 4.28] | 0.52 |
| LightGBM B | high | 3 | 0.70 [0.14, 2.04] | 0.11 |
| Logistic regression | alert | 61 | 14.18 [10.85, 18.22] | 0.85 |
| LOLBin heuristic | alert | 67 | 15.58 [12.07, 19.79] | 0.59 |
| Rules (any rule fired) | — | 51 | 11.86 [8.83, 15.59] | 0.33 |

**The highest-scoring benign events:**
- .NET compilation (`csc → cvtres` under the troubleshooting host);
- OneDrive;
- the user opening a Word document;
- Intel graphics helpers;
- `rundll32 shell32.dll,OpenAs_RunDLL`.

These are the ordinary desktop programs the training data barely contains. **Logistic
regression's lab advantage reverses here:** it raises nearly five times LightGBM's false
positives.

### E5: synthetic out-of-distribution (WinLOLBIN-GT samples)

All learned models are near chance (ROC-AUC: LightGBM A 0.54 [0.49, 0.61], logistic
regression 0.55). The keyword heuristic does best (0.67). The generated, templated rows do
not resemble the lab recordings, so treat this as a distribution-shift check, not a
performance estimate.

### Robustness (E3 malicious rows, LightGBM A, alert threshold; baseline recall 0.619)

| Mutation | Recall |
|---|---|
| caret insertion (`p^o^w^e^r`) | 0.513 (−0.106) |
| `C:\Windows` → `%SystemRoot%` | 0.522 (−0.097) |
| random letter case | 0.619 (±0) |
| doubled whitespace | 0.628 |
| last two arguments swapped | 0.637 |
| binary renamed and moved to a temp path | 0.673 (score rises) |

**Caret insertion and environment-variable spelling are real evasion costs.** The
deobfuscator's flags are not enough to undo them.

### Ablations (out-of-fold PR-AUC; saturated, so differences are small)

| Feature set | PR-AUC |
|---|---|
| full A | 0.9946 |
| full B | 0.9950 |
| without command-line n-grams | 0.9940 |
| names only (process, parent, pair) | 0.9944 |

Most of the separability comes from process and parent names. Command-line tokens add
little on this data.

## Post-hoc changes and their effect (transparency)

Run 1 implemented the plan except for the harness scrub (deviation D6). Its leakage probe
flagged the top feature as the path token `splunkuniversalforwarder`: the benign training
data was dominated by the recording lab's Splunk forwarder.

**What changed in run 2:**
- the harness scrub (D6);
- lab infrastructure excluded from training (D7);
- the threshold tie bug fixed (D8).

**How the main numbers moved:**

| | Run 1 | Run 2 |
|---|---|---|
| E2 recall @ alert, A | 0.255 | 0.588 |
| E3 recall @ alert, A | 0.009 | 0.619 |
| E4 FP/h @ alert, A | 0.70 (recall 0.00) | 3.02 (recall 0.56) |
| Top feature | `splunkuniversalforwarder` | parent-name bigram (no harness token) |

These changes were driven by a pre-registered probe (G4), not by the test results. But they
were made after test numbers existed, so run 2 is not a pristine held-out estimate.
**OpTC, once available, is the next untouched test.**

## Not measured

- **False positives on OpTC** (D3) or on any benign data with more than one real user. The
  E4 rate rests on 4.3 hours of one desktop.
- **A full human label audit** (D5). 100 rows per iteration were reviewed by the assistant;
  a 1,191-row sample awaits a human.
- **The rarity baseline** (D9).
- **Latency and memory budgets of the pure-Python scorer** (an integration-stage test).
- **Performance on the agent's ETW-sourced process starts.** They lack command lines and
  users, so this model applies only to Sysmon-sourced starts.
- **Whether OTRF label noise biases E3** beyond the qualitative count above.

## Addendum (2026-10-23): benign data recorded with the Officer agent

**What the data is.** The user recorded 4.5 hours of ordinary use of their own Windows VM
(arm64, build 26100) with the Officer collection kit. The kit ran version 1.0.0; the package
was produced by 1.0.1. After handling the kit's known issues, 2,485 Sysmon process starts
remain (884 distinct):
- 215 self-tagged records dropped;
- 112 untagged children of the kit dropped;
- 2,479 ETW duplicates removed.

The recording carries no integrity level, so it serves Variant A only. Details are in
`DATASHEET.md`; counts are in `results/officer_vm_manifest.json`.

**The new test (E6).** The recording becomes test **E6**: false positives per host-hour on
the agent's own event stream. Gate G2 was extended to cover E6 with the same budget,
**before these runs**. Two runs:
- **v2:** the lab-trained model; E6 is the whole recording.
- **v3:** the first half of the recording (by time) in training, with at most 50 rows per
  image; E6 is the second half, 2.15 h.

| | v2 (lab-trained) | v3 (+ agent benign in training) |
|---|---|---|
| E6 FP/h, LightGBM A, alert / high | **163 / 77** | 0 / 0 |
| E6 FP/h, logistic regression, alert | 234 | 0.5 |
| E6 FP/h, heuristic / rules | 68 / 9.8 | 52 / 7.0 |
| E2 recall @ ≤1 FP/h, LightGBM A (rules) | 0.59 (0.29) | **0.08** (0.29) |
| E3 recall @ alert, LightGBM A | 0.62 | 0.00 |
| E4 recall on the Cerber infection, A | 0.56 | 0.00 |

**Reading.** Trained on lab data, the model flags this developer workstation's routine
automation as malicious: PowerShell `Add-Type` compiling with `csc → cvtres`, and
`powershell -NoProfile` started by tooling. Once that activity is in training, holding
≤ 1 FP/h needs a threshold so high that the model detects almost nothing (8% of unseen
techniques, versus 29% for the rules).

**Conclusion.** Using process-start fields alone, benign developer activity and attacker
tradecraft overlap too much to meet the false-positive budget with useful recall. **The
verdict stays "do not integrate"**, now on agent-native evidence:
- v3 passes G2 only by detecting nothing;
- G1 fails against the rules (−21 pp, CI [−31, −10]).

**Directions this points to:**
1. Context the agent already has, but a single process start lacks: the provenance graph's
   lineage, image writers and network activity.
2. Benign data from several machines and kinds of user, so a developer's workstation isn't
   the only "normal".
3. Per-environment baselines (the rarity detector) rather than one global classifier.

**Caveats.**
- One VM, one user (a developer with heavy automation), 4.5 h.
- The user's own evening testing is in the data and is treated as benign. If any attack
  simulation was run, those rows are mislabelled.
- Probe and heartbeat cadence (kit issue 4) was not used.


## Addendum 2 (2026-10-23): OpTC benign data (runs v4, v5)

**What the data is.** The two approved OpTC files (19 Sep 2019 benign period, host ranges
`AIA-51-75` and `AIA-201-225`) were downloaded by the user, then verified and pinned.

**How it's used:**
- the process creates of `AIA-51-75` join training (at most 50 rows per image);
- `AIA-201-225` (25 hosts, 100 observed host-hours) is held-out test **E7**;
- gate G2 covers E7, set before the run.

**v4 had an artefact.** 28% of OpTC process creates give a bare image name (`PING.EXE`), a
shape the Officer agent never produces (it always reports a full path). Every one of those
rows is benign, so `path_class=unknown` became a top feature: the model learned "no path
means benign". v4's numbers are kept but superseded.

**v5 (final)** excludes those rows from training and from E7 (training-plan D12).

| v5, Variant A | Result |
|---|---|
| E2 recall @ ≤1 FP/h (unseen techniques) | 0.566 [0.427, 0.690]; LR 0.535, heuristic 0.700, rules 0.292 |
| E2 paired vs LR / rules / heuristic | +0.032 [−0.07, +0.13] / **+0.274 [+0.10, +0.44]** / −0.134 [−0.25, −0.03] |
| E1 ceiling (random split) | 0.870 |
| E3 recall @ alert (OTRF) | 0.442 [0.320, 0.582], precision 0.98; LR 0.310, rules 0.195 |
| E4 FP/h alert / high (BOTSv1 desktop, 4.3 h) | 1.86 / 0.70; recall on Cerber 0.41 / 0 |
| E6 FP/h alert / high (agent VM, held-out half, 2.1 h) | 0.93 / 0.00; heuristic 62, rules 7.0 |
| E7 FP/h alert / high (OpTC, 25 hosts, 100 h) | **0.65 / 0.00**; LR 0 / 0, heuristic 6.9, rules **80.1** |
| E5 ROC-AUC (WinLOLBIN-GT, synthetic) | 0.655 |
| Robustness (E3, recall @ alert 0.442) | caret 0.133, env-var 0.451, case/whitespace/argswap unchanged, renamed binary 0.593 |
| Calibration (OOF) | ECE 0.021, Brier 0.064 |
| Per-technique | 19 of 94 groups with zero recall; 34 at ≥ 0.8 |
| Leakage | 0 harness tokens, 0 shared keys; source predictability AUC: attack_data 0.83, OpTC 0.86 |
| Reproducibility | `model.json` A `114a2b36…`, B `c89a9485…` bit-identical across rebuilds; golden error 0.0 |

**Gates for v5:**

| Gate | Result |
|---|---|
| G1 | **FAIL**: beats rules, but not LR, and loses to the heuristic |
| G2 | **FAIL**: E4 is over budget; E6 and E7 are within it at both thresholds |
| G3 | PASS: E3 0.44 vs E2 0.57 (−12 pp) |
| G4 | PASS by its letter; **flagged** for source predictability and environment fingerprints |
| G5 | PASS |
| G6 | PASS |

**The rules on realistic benign data.** They raise 80 false positives per host-hour on the
held-out OpTC hosts. The single biggest contributor should be identified before the rules
are used anywhere near alert volume. This is a finding about the existing engine, outside
the ML scope.

## Addendum 3 (2026-10-23): five more OpTC ranges, featurizer v3, labeller v4 (run v6)

**What changed** (training-plan D15–D17):
- **More benign data:** 125 more OpTC hosts from the same day (five 25-host ranges) join
  training. E7 (`AIA-201-225`) stays held out.
- **Featurizer v3:** carets are stripped before normalising.
- **Labeller v4:** more OS housekeeping binaries and two infrastructure agents. This was
  decided after seeing v5's errors, and it changes some E3 labels.

Raw numbers: [`results/v6.json`](results/v6.json). The bundle's manifest is in
[`results/bundle_manifest_v6.json`](results/bundle_manifest_v6.json).

| v6, Variant A | Result | v5 |
|---|---|---|
| Pool | 5,548 rows (4,506 / 1,042), 259 groups, **923 observed host-hours** | 5,205 (4,514 / 691), 327 h |
| `alert` / `high` raw-score thresholds | **2.97 / 4.50** | 4.42 / 6.41 |
| E2 recall @ alert (unseen techniques) | 0.776 [0.661, 0.866]; LR 0.875, heuristic 0.231, rules 0.293 | 0.566 |
| E2 paired vs LR / rules / heuristic | **−0.099 [−0.214, −0.019]** / +0.484 [+0.305, +0.614] / +0.545 [+0.423, +0.657] | +0.03 / +0.27 / −0.13 |
| E2 PR-AUC vs LR | +0.018 [−0.003, +0.067] | |
| E1 ceiling (random split) | 0.932 | 0.870 |
| E3 recall @ alert (OTRF; labels changed by v4) | 0.823 [0.742, 0.906], precision 0.94; LR 0.854, rules 0.219 | 0.442 |
| E4 FP/h alert / high (BOTSv1 desktop, 4.3 h) | **5.81** [3.76, 8.58] / **1.16** [0.38, 2.71]; Cerber recall 0.74 / 0.22 | 1.86 / 0.70 |
| E6 FP/h alert / high (agent VM, held-out half, 2.1 h) | **8.85** [5.33, 13.82] / **3.73** [1.61, 7.34] | 0.93 / 0.00 |
| E7 FP/h alert / high (OpTC, 25 hosts, 100 h) | 0.65 [0.50, 0.83] / 0.01 [0.00, 0.06]; rules 80.1 | 0.65 / 0.00 |
| E5 ROC-AUC (WinLOLBIN-GT, synthetic) | 0.666 | 0.655 |
| Robustness (E3, recall @ alert 0.823) | caret **0.823** (fixed), env-var 0.844, case/whitespace/argswap unchanged, renamed binary 0.875 | caret 0.133 |
| Calibration (OOF) | ECE 0.018, Brier 0.063 | 0.021 / 0.064 |
| Per-technique | 4 of 93 groups with zero recall; 61 at ≥ 0.8 | 19 of 94; 34 |
| Leakage | 0 train/test duplicate keys; **one top-30 bucket shares a harness token** (`cmd#1467`: `atomics ..` with OpTC's `c:\ncr\` scripts); source predictability AUC OpTC **0.98**, attack_data 0.89 | OpTC 0.86 |
| Reproducibility | `model.json` A `ad12b163…`, B `bcd8887b…` bit-identical on a rebuild at a later commit; all metrics identical; golden error 0.0 | |

The E4/E6 intervals are exact Poisson intervals on the event counts.

**Why recall rose and false positives rose with it.** The thresholds are set on the pool,
to ≤ 1 false positive per *pooled* observed host-hour.
- The new ranges tripled the pool's benign hours (327 → 923), and 719 of them (78%) are
  now OpTC.
- The model separates OpTC almost perfectly: source-predictability AUC 0.98.
- So the pooled budget is met at a much lower threshold (alert 4.42 → 2.97).
- That buys E2 recall, but the cost is paid by every environment that is not OpTC:
  - BOTSv1 desktop: 3× more false positives;
  - your VM: 9× more;
  - held-out OpTC hosts: unchanged at 0.65/h.

**What drives E6.** The top-scoring benign starts on your VM are:
- Office Click-to-Run's `integrator.exe` registering ETW manifests (`wevtutil im`) and
  creating or deleting scheduled tasks (`schtasks /Create … /XML`);
- a Java installer run from `%TEMP%`;
- `powershell → w32tm /query`.

They are rare and attacker-shaped, and they are genuinely benign.

**Gates for v6:**

| Gate | Result |
|---|---|
| G1 | **FAIL**: beats rules and the heuristic, but is significantly *worse* than LR at the alert budget (−10 pp) |
| G2 | **FAIL**: E4 5.81/h and E6 8.85/h at alert; only E7 meets the budget |
| G3 | PASS: E3 0.82 vs E2 0.78 (E3 labels changed post-hoc) |
| G4 | **FAIL** by its letter (one top-30 bucket carries a harness token); source predictability 0.98 for OpTC |
| G5 | PASS |
| G6 | PASS |

**Lessons, stated as findings:**
1. **More benign volume from one environment did not help. It moved the operating point
   toward that environment.**
2. A false-positive budget fitted on a pooled mixture is a property of the mixture. A
   threshold that is safe for deployment must hold **per environment**, for example the
   maximum over held-out environments. That needs benign data from many *environments*,
   not many hosts of one.
3. The caret fix works as designed. Recall under caret insertion now equals baseline recall,
   by construction.
4. **Variant B is worse than in v5:** E2 0.99, but E4 46 false positives per hour. Missing
   integrity is now an even stronger "benign" signal. It is not evaluated further.

## Addendum 4 (2026-10-23): run v7, leave-one-environment-out

**What changed** (training-plan D20, D21), all committed before the first real-data run (`91f7551`):
- **ATLASv2 became training data** before any model scored it (project-owner decision).
- **Protocol:** six environments; each is held out entirely in turn. Rows are de-duplicated
  *within* an environment, keys seen with both labels are never trained on (27), and attack rows
  sharing a command template share a group (55 groups merged).
- **Thresholds:** each training environment must meet the budget on its own observed hours
  (minimax), replacing the pooled budget that let OpTC set the operating point.
- **Training:** environments weighted equally; a parent-less copy of each row at the agent's
  observed rate (30%), so a missing parent cannot mean "benign".
- **Featurizer v4:** closed vocabulary (137 named binaries, everything else `other`), roles and
  role pairs, 43 documented command-line indicators (monotone: they can only raise a score);
  no hashed n-grams, no user category, no integrity level.

| Environment | Observed host-hours | Benign / attack units |
|---|---|---|
| attack_range (Splunk attack_data) | 194.2 | 270 / 5,328 |
| mordor (OTRF atomic + compound) | 5.6 | 460 / 246 |
| botsv1 | 8.7 | 322 / 51 |
| officer_vm (your VM) | 4.5 | 884 / 0 |
| optc | 818.6 | 5,229 / 0 |
| atlasv2 | 512.6 | 690 / 19 |

**The v6 recipe under this protocol** (featurizer v3, pooled budget, no ATLASv2):

| Held out | FP/h at alert [95% CI] | Recall on distinct attack rows [CI] |
|---|---|---|
| attack_range | 0.00 [0.00, 0.02] | 0.009 [0.007, 0.012] |
| mordor | 22.5 [18.8, 26.8] | 0.34 [0.28, 0.40] |
| botsv1 | 6.13 [4.59, 8.01] | 0.65 [0.50, 0.78] |
| officer_vm | 31.0 [26.1, 36.6] | — |
| optc | 18.0 [17.7, 18.3] | — |
| atlasv2 | 2.00 [1.88, 2.13] | 0.74 [0.49, 0.91] |

Macro recall 0.43, +14 pp over the rules (CI [+9, +24]). **Its recall is bought with false
positives in environments it has not seen.**

**The v7 candidates** (selection rule fixed in advance: no candidate met S1, so the lowest
worst-environment false-positive rate wins):

| Candidate | Worst FP/h at alert (environment) | Macro recall | vs rules [CI] | vs heuristic [CI] |
|---|---|---|---|---|
| `v7_lgb` | 1.56 (officer_vm) | 0.013 | −0.28 [−0.31, −0.22] | −0.02 [−0.07, +0.02] |
| `v7_lr` | 7.15 (officer_vm) | 0.075 | −0.22 [−0.26, −0.16] | +0.04 [+0.00, +0.08] |
| `v7_tokens` | 1.22 (optc) | 0.034 | −0.26 [−0.31, −0.18] | +0.00 [−0.06, +0.07] |
| **`v7_lgb_no_stats` (selected)** | **1.16 (botsv1)** | **0.099** | **−0.20 [−0.25, −0.12]** | **+0.07 [+0.03, +0.10]** |

**Selected recipe, per unseen environment:**

| Held out | FP/h alert [CI] | Recall [CI] | ROC-AUC | Partial AUC (FPR ≤ 1%) | Rules: FP/h, recall |
|---|---|---|---|---|---|
| attack_range | 0.00 [0.00, 0.02] | 0.000 [0.000, 0.001] | 0.86 | 0.83 | 13.3, 0.38 |
| mordor | 0.00 [0.00, 0.66] | 0.000 [0.000, 0.015] | 0.72 | 0.56 | 31.0, 0.20 |
| botsv1 | 1.16 [0.55, 2.13] | 0.078 [0.022, 0.189] | 0.86 | 0.52 | 6.8, 0.33 |
| officer_vm | 0.00 [0.00, 0.82] | — | — | — | 9.8, — |
| optc | 0.00 [0.00, 0.005] | — | — | — | 79.3, — |
| atlasv2 | 0.00 [0.00, 0.007] | 0.32 [0.13, 0.57] | 0.85 | 0.69 | 0.58, 0.26 |

**Who sets the threshold.** In every fold the binding environment is one of the three small
ones (BOTSv1 8.7 h, OTRF 5.6 h, your VM 4.5 h). Their budgets allow 4–9 false positives, and
each has a few attacker-shaped benign starts: BOTSv1's authorised Nessus scan (`cmd → netsh
advfirewall show`, `schtasks /query /XML`), your VM's PowerShell compiling with `csc`, OTRF lab
administration. Those outrank nearly every attack.

**ATLASv2 in training** (same recipe, ATLASv2 removed from training):

| Held out | FP/h at alert with / without ATLASv2 | Recall with / without |
|---|---|---|
| officer_vm | **0.00 / 7.15** (32 events only without) | — |
| botsv1 | 1.16 / 0.12 (9 events only with) | 0.078 / 0.020 |
| attack_range, mordor, optc | 0.00 / 0.00 | ~0 / ~0 |
| macro recall difference | | +0.014 [−0.006, +0.039] |

**Criteria** (S1–S6, fixed in `pdtrain/loeo.py` before the run):

| | Result | Evidence |
|---|---|---|
| S1 | **FAIL** | BOTSv1 1.16 FP/h at alert; all others ≤ 0.01 |
| S2 | **FAIL** | −20 pp vs rules (CI [−25, −12]); +7 pp vs heuristic |
| S3 | pass, **uninformative** | framework hold-out 0.063 vs technique hold-out 0.054: both near zero |
| S4 | **FAIL** | benign environments still identifiable (OvR AUC 0.84); no top-30 feature is single-environment |
| S5 | pass, **uninformative** | recall before mutation is already 0.000–0.012 |
| S6 | PASS | `model.json`, thresholds and golden vectors bit-identical on a rebuild; pure-Python scorer error 0.0 |

**Caveats.**
- Three environments have under 10 observed hours: one event moves their FP/h by 0.1–0.2,
  and the thresholds they force are noisy.
- Minimax over environments is the strictest reasonable policy. Per-site burn-in thresholds
  (learnt on a site's first days) were not evaluated.
- BOTSv1's "malicious" rows include lineage descendants (`iexplore.exe`, `notepad.exe` under
  the infection) that no process-start model can recognise; the human label audit is still
  not done.
- The sealed recording was not recorded or used: no candidate qualified for it.

**Known issue found during the run.** Profile names containing a space escape the path
normalisation (`c:\users\first last\…` keeps `last`), so in v1–v3 the user's surname reached
hashed tokens. v4's base features have no path tokens; the token variant only admits tokens seen
in three or more environments. Fixing `normalize_text` changes de-duplication keys and needs a
featurizer bump.
