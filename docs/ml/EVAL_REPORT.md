# Evaluation report: process-start classifier (bundle v1)

Date: 2026-10-23. Engine commit `d03c4c1`, featurizer v2, labeller v3, LightGBM 4.7.0.
Raw numbers: [`results/final.json`](results/final.json) (run 2, reproduced bit-for-bit by a rebuild)
and [`results/run1_before_fixes.json`](results/run1_before_fixes.json).
Plan: [`training-plan.md`](training-plan.md) (deviations listed at its end).
Model: [`MODEL_CARD.md`](MODEL_CARD.md). Data: [`DATASHEET.md`](DATASHEET.md).

## Verdict: do not integrate

Two of the six pre-registered gates fail.

1. **G1 fails.** On techniques it never saw, the LightGBM model catches fewer attacks than a
   plain logistic regression on the same features, at the same false-positive budget. The
   difference is −32 percentage points, 95% CI [−44, −20].
2. **G2 fails.** On the one real held-out desktop it raises 3.0 false positives per host-hour
   at the alert threshold, 95% CI [1.6, 5.2]. The budget is ≤ 1.

**The binding constraint is benign data, not the model.** After de-duplication there are
152 distinct benign process starts to train on, and 4.3 host-hours of realistic benign
activity to test on. Every learned model here, and the rules, fails the false-positive
budget on the real desktop.

**What would change the verdict:** thousands of benign host-hours (OpTC, blocked by a Google
Drive quota; or recordings from the agent on your own VM), followed by a re-run of this
exact pipeline with the same gates.

**What the model does show:**
- it beats the engine's rules on the same input by +30 percentage points of recall at a
  matched false-positive budget (CI [+18, +43]);
- it holds up on a different lab's attacks (E3).

So a supervised process-start signal is worth pursuing. This model, trained on this data,
is not ready to raise alerts. Running it in shadow mode as a research signal would be
acceptable under the plan; alerting would not.

**Variant B (adding integrity level) brings no measurable gain.** PR-AUC changes by +0.0004,
CI [−0.0002, +0.0018]. On this evidence the agent change to emit integrity level is not
justified for the model.

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
