# Panopticon multi-level correlation detection model: research synthesis and plan

## Context

Runs v1–v7 trained a classifier on single Windows process starts. Measured leave-one-environment-out, it either:
- floods unseen environments with false positives (v6 recipe: 6–31 per host-hour), or
- when every environment must stay within budget, detects about 10% of attacks, 20 pp below the rules (v7).

The model family is not the cause. LR, LightGBM and token variants hit the same ceiling, and 27 identical inputs carry both labels. **A single process start is ambiguous.** A Nessus scan's `netsh advfirewall show`, or a developer's `powershell → csc`, is indistinguishable from tradecraft.

What separates them is context:
- who launched the chain;
- what the process did next;
- whether that behaviour is normal for this host and fleet;
- whether several weak signals line up along a kill chain.

This plan pivots to **multi-level correlation**:

`event signals → process-in-context model → rarity gate → storyline/host risk → alerts and response`

**Decisions already taken by the project owner:**
- **Models:** tabular, plus a sequence model as a *training-only comparison arm*.
- **Data:** re-read all local raw data with every event family, and re-stream ATLASv2 with every event family.
- **ML in response:** evidence plus read-only collection only.
- **Timeline:** as soon as possible.

---

## 1. The supplied paper (Karat et al., Procedia CS 233, 2024): what we take, what we leave

**What it does.**
- A CNN-LSTM classifies Cuckoo-sandbox API-call sequences.
- Each sequence is the first 100 non-repeated calls of the parent process, mapped to 308 IDs.
- Architecture: Embedding (8) → Conv1D (32 filters, kernel 9) → MaxPool (2) → LSTM (512) → sigmoid.
- Reported 96% validation accuracy on a random 75/25 split.
- Data: Oliveira (42,797 malware / 1,079 benign) and MalbehavD-V1 (1,285 / 1,285, MIT licence), merged to 2,500 / 1,000.
- Correlation rules over Sysmon logs assign severities.

**What we take:**
- judge a process by what it *does after* starting;
- combine rule severity with model scores;
- its architecture, as our comparison arm (§6).

**What we leave, and why:**
- **Wrong granularity.** Our agent has no API-call hooking (Sysmon/ETW events only), so the model cannot run on our telemetry.
- **Wrong target.** It classifies sandbox executables, not misuse of signed Windows binaries.
- **Inflated evaluation.**
  - A random split leaks malware families (TESSERACT).
  - Accuracy at 2.5:1 prevalence is not a false-positive rate.
  - Oliveira is 40:1, so always answering "malware" scores about 97.5%.
  - The "zero-day" claims rest on no held-out families.
  - These are Arp et al.'s (USENIX Sec 2022) sampling-bias, base-rate and lab-only pitfalls, the same ones our v1–v6 runs hit.

## 2. How industry does it (DOC = vendor docs, VR = vendor research, MKT = marketing, PR = peer-reviewed)

| System | Where ML sits | Mechanism we reuse |
|---|---|---|
| Microsoft Defender [DOC/VR] | Process tree, incident | Client-side behaviour sequences *trigger* cloud ML on the process tree. Per-signal scores are fed chronologically to a CNN-BiLSTM. GraphWeaver (2024) correlates alerts **without ML**: shared entities, per-entity windows (8–72 h), entity priority, and caps on detector volume and cardinality against "black-hole" incidents. Attack disruption needs ≥ 99% precision, audit mode and reversible actions. |
| CrowdStrike [MKT/VR] | Process tree | Indicators of attack are sequences of intent. The LOLBin model reads the child, parent and grandparent command lines. Command-line BERT embeddings feed boosted trees. Models run silently before going live. |
| Cortex XDR [DOC] | Causality chain | **Spawner / Causality-Group-Owner (CGO) rule**: a chain is rooted at the first child of a spawner (explorer, services…). Baseline ≥ 30 endpoints × 2 weeks. Noisy detectors (≥ 5k/day) are auto-disabled. |
| Elastic [DOC] | Process plus anomaly | ProblemChild (trained on attack_data, BOTSv1 and ART, as we did) fires **only together with** an unsupervised "rare for parent / host" model. Fleet-population rarity. |
| Splunk RBA [DOC] | Entity risk index | Rules write **risk events** (`risk_object`, `score = impact × confidence / 100`, tactic, `threat_object`), not alerts. Deduplicated. Incident at Σ > 100/24 h, or ≥ 3 tactics from ≥ 4 sources in 7 d. A 2026 evaluation: AUROC 0.92 vs 0.72 for raw severity. |
| Google SecOps [DOC] | Entity risk | `max + 0.2 × Σ rest`, so weak hits cannot add up to an incident. |
| Symantec RapSheet [PR, S&P 2020] | Alert provenance graph | Score from the longest alert subsequence in both time **and kill-chain order**. 58k alerts → 681 graphs → the 5 malicious ones ranked on top. |

**Problems they report:**
- benign triggers (GUIDE: 46% of incidents are benign positives);
- a base rate of about 0.01%;
- over-correlation;
- dependency explosion (Windows registry and IPC noise);
- exclusion rot;
- the need for per-environment baselines;
- explainability;
- gated automated response.

**Microsoft's GUIDE dataset** (CDLA-2.0; 13 M evidences, 1 M incidents labelled TP/BP/FP) has no telemetry and its detector IDs are opaque. **It is not used:** its features do not map onto our rules.

## 3. Academic work: what holds up

| Approach | Examples | Verdict |
|---|---|---|
| Rules plus tactic progression | HOLMES (S&P'19), RapSheet, CAPTAIN (NDSS'25: rule parameters tuned on benign data, −90% false alarms) | **Adopt.** The engine already has ATT&CK-tagged rules and incidents. |
| Rarity of provenance paths | NoDoze (NDSS'19, −84–86% false alarms) | **Adopt** as a gate. Weakness: mimicry (Goyal et al., NDSS'23). |
| GNN / temporal-graph anomaly detection | ThreaTrace, ShadeWatcher, KAIROS, FLASH, MAGIC, ORTHRUS | **Reject.** Results rest on flawed DARPA labels and data snooping. A simple network or an **allowlist of executables seen in training** matches them (Bilot et al., USENIX Sec'25; Guerra et al., NDSS'27). Heavy dependencies, poor portability. |
| Sequence models | DeepLog, Tiresias (3.4 B events), ATLAS (LSTM; trained and tested on the same 10 scripts) | Comparison arm only. Too little, too diverse data. |

**Evaluation lessons adopted:**
- hold out whole environments;
- time-split burn-in;
- thresholds calibrated on benign/validation data only;
- false positives per host-hour;
- scenario-level recall;
- nodes an analyst must inspect;
- always compare against the allowlist and rules-only baselines.

---

## 4. The decision: a process-in-context model plus transparent correlation, built on existing engine code

**Core decision.**
- **The unit of decision becomes a process incarnation in context,** re-scored when its behaviour changes. A process start alone is no longer the unit.
- **Analyst-facing alerts and response come from the storyline/incident level.** ML scores are **bounded risk contributions**, never stand-alone verdicts. This follows Microsoft's rules-trigger-ML design, Splunk RBA and Elastic's AND-gate.

**Model decision.**
- **L1 is a shallow, monotone LightGBM** over process-in-context features, served by the existing pure-Python scorer (`ml/scorer.py`).
- **L3 is a transparent risk index.** Its thresholds are tuned on benign data only.
- **Why not deeper models:**
  - the literature shows simple models match GNNs and deep models;
  - we have about 20 multi-stage scenarios and about 5.6k distinct attack processes, 95% of them from one lab;
  - explainability and fail-open serving are hard requirements.
- **The CNN-LSTM is a training-only comparison arm** (§6).

| Level | Scores | Built from (existing code) | Output |
|---|---|---|---|
| L0 signals | single events | YAML rules; enrichments (`enrichment.DERIVED_FIELDS`) | rule alerts → L3 risk events |
| **L1 process in context** | one process incarnation, at **event-triggered checkpoints**: start, the first time each behaviour bit turns on (≤ 8), stop | `features.FeatureExtractor` (as-of behaviour), extended to schema v3; the v5 process-start dense block (`ml/featurizer.py`, minus the stats features) | score per process |
| L2 rarity | prevalence per host and fleet, after a benign burn-in | `behavioral/rarity.py`, extended | **AND-gate and a fixed L3 contribution only.** Not an L1 feature: attack environments have no burn-in. |
| **L3 storyline/host risk** | process tree rooted at `enrichment.tree_root` (already Cortex's CGO rule, using `provenance/boundary.py` spawners) and host | new `provenance/storyline.py`; `incident._score` factor; `risk_scorer.py` unchanged | `CORR-STORY-001` alert, incident factor, COLLECT recommendations |

### L1 features: environment-invariant by construction
- **G0 start:** the v5 dense block (roles, 43 indicators, path class, masquerade). The v7 *score* is not stacked, to avoid nested-OOF leakage.
- **G1 lineage:**
  - roles of up to 4 ancestors (`featurizer.ROLE_OF`);
  - depth;
  - "descends from" office, browser, script host, server app, `wmiprvse`, `psexesvc` or `services`, walked through `registry.ancestors()`. `tree_root` can't be used here because wmiprvse is a boundary process;
  - the image writer's role and the image's age.
- **G2 lifetime and children:** child-role bits and capped child count. **Not monotone.**
- **G3–G7 behaviour bits** (from one shared `edge_bits(edge, graph)` helper in `features.py`, used by both extraction and checkpoint triggers):
  - executable or script written to a user-writable path;
  - persistence registry key (Run, Services, IFEO, Winlogon);
  - unsigned or user-writable module load;
  - LSASS read access;
  - remote thread, outbound and inbound;
  - public destination, and a non-standard port.

  Each bit comes with a **capped count of distinct objects**. Raw event counts are excluded, because the Sysmon config decides their density. **Monotone +1 constraints apply to the bits only.**
- **Excluded from L1 v1:**
  - rule-hit features: the engine writes rule tags onto edges *after* the behavioural stage runs, so they would differ between training and serving; rules belong in L3;
  - script blocks and DNS: they fail the admission rule below;
  - rarity.

### Event-family availability: the shortcut that bit us twice (integrity level, parent name)
Expected availability, to be confirmed by a census in P0:

| Group | attack_range | mordor | botsv1 | officer_vm | optc | atlasv2 |
|---|---|---|---|---|---|---|
| G0 start, G1 lineage, G2 children | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Public network | ✓ | ✓ | ✓ | – | ✓ | ✓ |
| File drops, image writer | ✓ | ✓ | – | – | partial | ✓ |
| Persistence registry | ✓ | ✓ | – | – | ✓ | ✓ |
| Module (path / signature) | ✓ | ✓ | ✓ | – | path only | ? |
| LSASS read / remote thread | ✓ | ✓ | – | – | – / ✓ | ? |
| DNS, script block | ✓ | ✓ | – | – | – | – |

**Rules:**
1. **Admission.** A group enters L1 only if it is available in at least one benign-only environment with ≥ 100 host-hours **and** in at least two environments with attacks. This keeps DNS, script blocks and probably LSASS-read out of L1; they stay in L3 through the rules.
2. **Availability is decided per (environment, host).** A family that is collected but silent is 0. A family that is not collected is NaN.
3. **Matched-rate dropout.** Masked copies of rows from both classes are added, with each group dropped at the rate it is missing in benign training hours. This generalises the existing `PARENT_MISSING_RATE` augmentation. Availability flags are never model inputs.
4. **Evaluation** uses the same masking. A starts-only ablation is reported for every environment.

**Label exclusions in training:**
- processes the engine only inferred (start never seen);
- injection targets after the injection;
- lab infrastructure (`is_lab_infrastructure`).

### L3: an RBA-style storyline risk index (new `provenance/storyline.py`, `StorylineRiskIndex`)
- **Key:** (host, `tree_root` node), or the incident id once the actor is inside an incident.
- **Risk events and their points:**
  - rules: level × confidence;
  - L1: 15 or 25 points by band;
  - rarity, through the AND-gate: 5 or 10 points;
  - **ML plus rarity together capped at 40% of the threshold.**
- **Aggregation:**
  - deduplicate on (source, id, object);
  - `max + 0.2 × Σ rest`;
  - add a capped bonus for the longest run of distinct tactics in both time order and kill-chain order (RapSheet/HOLMES).
- **Fires** when the aggregate is ≥ T, or on ≥ 3 tactics from ≥ 3 distinct rules. T is tuned on benign environments only (minimax), CAPTAIN-style.
- **What it emits:**
  - a separate `CORR-STORY-001` alert at **level ≤ 11** (level 12 would trigger the default TERMINATE in `active_response`), with no tactic, kept out of the host risk meter;
  - when the storyline is already in an open `PROV-CAMPAIGN` incident, an **itemised incident factor** instead of a separate alert.
- **`PROV-CAMPAIGN` stays rule-anchored and unchanged** (manager contract).
- Implements `prune()`.

### Response orchestration (project owner: evidence plus read-only collection)

| Trigger | Recommendation | Tier |
|---|---|---|
| `CORR-STORY-001` | `COLLECT_PROCESS_INFO` on the storyline root (needs pid + ticks, else fails closed) | AUTO_SAFE |
| `CORR-STORY-001` with network bits, or the existing `CORR-RISK-001` | `COLLECT_NETWORK_CONNECTIONS` | AUTO_SAFE |
| Rule-anchored `PROV-CAMPAIGN` | Unchanged: TERMINATE / QUARANTINE from the rules. ML only adds an incident factor. | ANALYST_APPROVAL |
| Anything ML- or rarity-only | **Never** TERMINATE, QUARANTINE or ISOLATE. A test checks this across every replay. | — |

Every alert carries:
- the top L1 feature contributions;
- its contributing risk events (source, tactic, points);
- the storyline path.

---

## 5. Data: full-family replay (re-read local data plus re-stream ATLASv2, as approved)

**Replay (new `pdtrain/replay.py`)**, one event stream per (source, recording, host):
1. Map raw events to canonical events with the existing `datasets/otrf.py` OtrfAdapter (Sysmon 1, 3, 5, 7, 8, 10, 11–14, 22, 23, 26, 4104), fed by `datasets/sysmon_xml.py` for attack_data and BOTSv1. `pdtrain/normalize.py` currently drops everything except event 1; that is changed.
2. Drive `build_detection_run(rules, behavioral_detectors=[CheckpointTap])`. The tap emits no signals, so the engine is unchanged.
3. The tap tracks the bit state per node from the current edge and calls `FeatureExtractor.extract(p, as_of=event_time)` at each trigger. Serving can call it the same way, so training and serving agree by construction.
4. It also records per-process token sequences for §6, and all alerts with their tagged edges and times.
5. `ctx.prune` runs every simulated hour.
6. Output is cached per host on (raw sha, git sha, rules hash).

**Known engine edge cases to handle:**
- **Edge cap.** The 4,096-edge-per-node cap (`graph.py:255`) silently drops late behaviour; count how many processes hit it.
- **Timestamp ties.** Timestamps are rounded to the millisecond, so a checkpoint may include later events in the same millisecond. Order by arrival.
- **Stop events.** A stop resolves at `when − 1 µs`.

**Labels.** Labels come from `experiment.labelled_raw`, **before** de-duplication: conflicts are exactly what context should resolve.
- The join is `row_id` (EID 1 `event.id`) ↔ `registry.resolve_event(...).node_id`.
- The full-family readers must reuse the existing dataset ids.
- A Sysmon `ProcessGuid` audit measures misattribution. Targets: ≥ 99.5% of rows joined and ≤ 0.5% misattributed.

| Environment | Source work | Role |
|---|---|---|
| attack_range, mordor, botsv1 | local; adapters exist | attacks and background |
| optc | new `datasets/ecar.py` (eCAR → canonical: PROCESS CREATE/TERMINATE, FLOW START outbound, MODULE LOAD (unsigned unknown), FILE CREATE/RENAME/DELETE, REGISTRY, THREAD REMOTE_CREATE). Two host ranges, one on each side of the hold-out, to keep replay cost down. | benign fleet; rarity |
| atlasv2 | `pdtrain/atlasv2.py` gains `stream_all_families()` writing `data/canonical/atlasv2/`. **Started first, in the background.** EID 1 row_ids must match. | 4 benign days + attack day; time-split burn-in |
| officer_vm | starts and stops only | lineage-only environment; starts-only ablation |

## 6. Comparison arm: CNN-LSTM (the paper's architecture), training only
- **Model:** new `pdtrain/seq_arm.py`, with a `seq = ["torch"]` extra in `pyproject.toml`. The paper's layers, unchanged.
- **Input:** the replay's per-process token sequences: closed vocabulary, family:object-class, about 150 tokens, at most 100 per process. Prefixes are scored at the same checkpoints as L1.
- **Protocol:** the same folds, thresholds and masking as L1. Masking a family means deleting its tokens.
- **Adoption rule (fixed in advance):** recall must exceed L1's by ≥ 0.05 with CI lower bound > 0, and it must pass C1 and C4. Otherwise it is published as a negative result. Serving it would need its own ADR.

## 7. Evaluation (fixed in `pdtrain/context_loeo.py` and training-plan D25 before the decision run)

**Units.**
- L1 scores observed-start process incarnations.
- A process's score is the maximum over its checkpoints; it alerts once.
- Its checkpoints share a total weight of 1.

**Protocol.**
- Leave one environment out, reusing `pdtrain/loeo.py` helpers (`_thresholds`, `evaluate`, `macro_paired`, `poisson_ci`, `clopper_pearson`, `_merge_templates`, capping and weighting).
- The ATLASv2 burn-in time split.
- An end-to-end L3 simulation (`pdtrain/l3_sim.py`) over the recorded alerts and checkpoints.

**Baselines, all on the same units and host-hours:**
- B1: the rules, **re-measured on the full replay** (v7's rules ran on starts only, so 25 of 73 event-type conditions never fired);
- B2: the v7 bundle;
- B3: the allowlist of executables seen in training (Guerra et al.);
- B4: the rarity AND-gate;
- B5: the heuristic.

**L1 criteria:**

| | Criterion |
|---|---|
| C1 | ≤ 1.0 false positive per host-hour at alert in **every** held-out environment; ≤ 0.1 at high where ≥ 20 h (minimax). |
| C2 | Macro recall minus v7 ≥ +0.15 (CI lower > 0). L1 minus the full-replay rules: CI lower > −0.05. |
| C3 | Macro partial AUC (FPR ≤ 1%) ≥ 0.75 (v7: 0.65). BOTSv1 ≥ 0.65 (v7: 0.52). |
| C4 | Benign-environment predictability macro AUC ≤ 0.70 (v7: 0.84). No group alone > 0.80. The availability mask predicts the label at AUC ≤ 0.55. |
| C5 | Starts, lineage and lifetime only (everything else masked): false positives ≤ v7 + 0.2 per host-hour in every environment. |
| C6 | Median time-to-detect ≤ 120 s after start. |
| C7 | Bit-identical rebuild; golden parity ≤ 1e-9 including NaN vectors; tap features equal post-hoc features on the corpus fixtures. |
| C8 | Each held-out mutation family, and the test-time loss of any one group, costs ≤ 0.10 recall. |

**L3 criteria (end to end):**

| | Criterion |
|---|---|
| E1 | Analyst-facing alerts (`PROV-CAMPAIGN`, `CORR-STORY`, `CORR-RISK`) ≤ 1.0 per 100 host-hours on OpTC and ATLASv2 benign days (upper bound ≤ 2.0), and ≤ rules-only + 0.5. |
| E2 | ML- or rarity-driven COLLECT intents ≤ 0.05 per host-hour (upper bound ≤ 0.1). |
| E3 | Scenario recall (OTRF compound 11, BOTSv1 2, ATLASv2 10, attack_range and mordor one per recording) minus rules-only ≥ +0.10, CI lower > 0. Compound scenarios ≥ 0.70. |
| E4 | Median first malicious start → first L3 alert ≤ 15 min. |
| E5 | Processes per alert: median ≤ 15, p95 ≤ 100; median purity ≥ 0.6. |
| E6 | Zero TERMINATE or ISOLATE recommendations without a rule-anchored incident (test). |

**Decision rules (fixed in advance):**
- **L1 integration:** L1 goes into the engine (shadow mode, behind a flag) only if C1–C8 pass. **Kill rule:** if C1 or C2 fails, ship L3 with rules plus rarity only. Rules at 6.8–79 false positives per host-hour are the larger practical problem, and L3 alone addresses it.
- **L3 enablement:** L3 is enabled if E1–E6 pass.
- **Final gate:** integration also needs the sealed agent recording (see Verification).

## 8. Phases (fastest honest first result; days are estimates)

| Phase | Work | Files |
|---|---|---|
| **P0** (day 0) | Start the ATLASv2 all-family re-stream (background). Family census per environment × family (density per benign process-hour, key attributes). Pre-register criteria, groups, admission rule and recipes (≤ 2 candidates). | `pdtrain/atlasv2.py`, new `pdtrain/census.py`, new `pdtrain/context_loeo.py`, `docs/ml/training-plan.md` (D25) |
| **P1** (days 1–5) | Feature schema v3 (`edge_bits`, ancestors); context featurizer; eCAR adapter; replay with CheckpointTap; label join and audit; L1 LOEO with baselines B1–B5. **First honest L1 result.** | `panopticon_detection/features.py`, new `panopticon_detection/ml/context_featurizer.py` (stdlib-only, own version, explicit NaN), new `panopticon_detection/datasets/ecar.py`, new `pdtrain/replay.py`, `pdtrain/normalize.py`, `tests/test_features.py` |
| **P2** (days 5–8) | Storyline risk index and offline L3 simulation; E1–E6 | new `panopticon_detection/provenance/storyline.py`, new `pdtrain/l3_sim.py` |
| **P3** (days 7–9) | Rarity extension (image→registry-key class, image→module class, command template) and the ATLASv2/OpTC/VM burn-in protocol | `panopticon_detection/behavioral/rarity.py` |
| **P4** (in parallel) | CNN-LSTM comparison arm | new `pdtrain/seq_arm.py`, `pyproject.toml` extra |
| **P5** (only if the criteria pass) | `MLStage` (ML-CTX-001 at level 7, ML-CTX-002 at level 9; prunable). `StorylineRiskIndex` in `DetectionRun` after incidents. Incident factor via an injected provider. Corpus scenarios: dev powershell→csc, Nessus-like scan, must-not-merge, ML-only storyline gets COLLECT only. Fix the edge cap if > 1% of units hit it. Amend ADR 001/002/003. Docs. | new `panopticon_detection/ml/stage.py`, `panopticon_detection/detection_run.py`, `panopticon_detection/factory.py`, `panopticon_detection/provenance/incident.py`, `tests/corpus/`, `docs/adr/00{1,2,3}`, `docs/ml/*` |

**ADR amendments:**
- **ADR 001:**
  - the scoring unit becomes a process incarnation at event-triggered checkpoints;
  - the featurizer becomes the stateful `FeatureExtractor` plus a versioned vectorizer;
  - `MLStage` needs `prune`.
- **ADR 002:**
  - a `CORR-STORY` row: COLLECT only, level ≤ 11, no tactic, cannot open `PROV-CAMPAIGN`, outside the risk meter;
  - a tighter auto-COLLECT budget (E2);
  - count recommendation *intents*, because replayed events lack ticks.
- **ADR 003:** the bundle pins the feature-schema and vectorizer versions, the admitted groups and the checkpoint policy; golden vectors include NaN.

**Out of scope, but blocking deployment** (manager repo, separate change):
- manager ingest rejects schema 0.5 (`manager/routers/ingest.py:27`);
- the vendored engine pin is stale (no `incident.py`, no rarity).

## Verification
- **Unit and corpus tests:**
  - `pytest -q`, with new tests for `edge_bits`, the context featurizer (golden vectors including NaN), the eCAR adapter, replay label join and tap/post-hoc equality, `StorylineRiskIndex` (dedup, `max + 0.2Σ`, kill-chain bonus, `prune`), and the E6 response-safety test;
  - the corpus scenarios via `tests/test_corpus.py`;
  - `ruff check .`, `scripts/check_rule_sourcing.py`, and `scripts/check_runtime_deps.py` (the engine stays `pyyaml` + `pydantic`; torch is training-only).
- **End to end:**
  - `pdtrain replay` → `pdtrain context-loeo` (decision run; results + criteria) → `pdtrain l3-sim`;
  - a rebuild must give a bit-identical model and identical metrics, as for v7;
  - the census and join audit are published in `docs/ml/results/`.
- **Final:** a **sealed agent recording with all families** (a VM running the real agent: ordinary use plus a scripted Atomic session), recorded by the project owner. It is scored once with the frozen bundle (`pdtrain/final_test.py` generalised to process-in-context). This is the only honest serving-parity test; integration waits for it to pass C1 and E1.
