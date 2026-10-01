# Behavioral intelligence: features and the rarity baseline

This is the engine's first learned detector, and the groundwork for later ones.
It is deliberately small: a count table, no ML framework, no new dependency.

## Why it exists

Rules recognise behavior someone has already described: `winword.exe` starting
`powershell.exe -enc …`. They say nothing about behavior nobody anticipated.

The rarity baseline asks a different question: *is this normal here?* It learns
how processes usually start, from telemetry believed to be benign, and reports a
process start that falls outside that.

| Not this | This |
|---|---|
| a malware classifier | a measurement of how unusual a process start is |
| a probability that something is malicious | a category (`unseen` / `uncommon` / `common`) plus the raw counts behind it |
| a zero-day detector | **previously unseen behavioral detection** |

It can flag unusual *post-exploitation behavior*, such as an Office application
starting a script host it has never started before. It cannot see an exploit
primitive, and it cannot prove an attack is a zero-day.

## Why it does not replace rules

Rare is not bad. Software updates, a new tool, an administrator's one-off script
and a user opening an application for the first time are all rare and all
legitimate. A rarity signal is therefore **evidence, never a verdict**:

* It is a low-level alert: level 4 for `unseen`, level 2 for `uncommon`.
* It carries **no ATT&CK tactic**. "Unusual" is not a technique, and none is
  invented. So it can **join** an incident but can never **open** one; only a
  terminal-tactic rule detection anchors an incident.
* It never carries a response recommendation.
* It is kept out of the host risk meter, so it cannot push a host toward an
  isolation recommendation.

## Why the provenance graph stays central

A behavioral signal takes the same path as every other detection. There is no
second graph, correlation engine or incident engine.

```
process_create event
  -> EventGraphBuilder               (existing: registry + graph)
  -> FeatureExtractor.extract_event  (features.py)
  -> RarityBaseline.score            (behavioral/rarity.py)
  -> BehavioralSignal                (behavioral/signal.py)
  -> .to_alert() -> Alert            (existing representation)
  -> dedup, emit, tag_from_alert     (existing)
  -> tag on the process's FORKED edge (existing graph)
  -> IncidentTracker.on_tag          (existing correlation)
```

Because the signal is a tag on the graph, it becomes part of an incident's story
when it sits inside that incident's causal scope. Replaying
`tests/corpus/office_macro_to_c2_and_persistence` against a baseline learned from
`tests/corpus/benign_workstation` produces three `BHV-RARE-001` signals:
`explorer.exe -> winword.exe`, `winword.exe -> powershell.exe` and
`powershell.exe -> svchelper.exe`. All three appear as stages of the one
incident rooted at `winword.exe`. The incident's root, tactics, score,
confidence, revisions and recommendation are identical to the run without a
baseline (`tests/test_behavioral_integration.py`). The first of the three is
legitimate: the benign session never opened Word. That is exactly the kind of
rare-but-normal event that keeps this signal out of the verdict.

## Features (`panopticon_detection/features.py`)

`FeatureExtractor.extract(process, as_of)` turns one process incarnation into a
`ProcessFeatures` record. **It is the only feature code.** Live scoring,
`--export-features` and `--learn-baseline` all call it, so training and
detection can never compute features differently.

| Group | Fields | Source |
|---|---|---|
| Identity | `host_id`, `node_id`, `pid`, `parent_pid`, `name`, `executable`, `path_class`, `start_time`, `user`, `inferred` | process registry |
| Lineage | `parent_name`, `grandparent_name`, `tree_root_name`, `depth`, `parent_child` | registry ancestry, `enrichment.tree_root` |
| Command line | `cmdline_length`, `cmdline_token_count`, `cmdline_entropy`, `cmdline_obfuscated`, `cmdline_evasion_count` | existing deobfuscator and entropy calculator |
| Provenance | `image_writer_name`, `image_age_seconds` | graph join `enrichment.image_write_for` (the same code as the rule fields) |
| Behavior, as of `as_of` | `child_count`, `file_write_count`, `executable_write_count`, `registry_write_count`, `network_connect_count`, `public_connect_count`, `module_load_count` | graph edges whose source is the process |

At process creation every behavior count is 0, because nothing has happened
yet. An export after a replay sees the process's whole observed life.
`feature_schema_version` (currently 1) changes whenever a field changes meaning.

**Deliberately absent, because no telemetry produces them today (schema 0.3):**
- the signer of a process's own image (only `image_load` carries signatures);
- process lifetime (no process-stop event);
- hash prevalence;
- DNS;
- script content;
- process access / injection.

## The rarity algorithm (`panopticon_detection/behavioral/rarity.py`)

`RarityBaseline` counts three things over the learning data:

| Dimension | Example key | Scored as |
|---|---|---|
| `parent_child` | `explorer.exe -> chrome.exe` | `BHV-RARE-001` |
| `name_path_class` | `svchost.exe @ system` | `BHV-RARE-002`, **only for a program the baseline already knows** ("a known program running from an unusual place"), so a new program is reported once, not twice |
| `name` | `chrome.exe` | supports the above |

For each dimension, a new process start is classified as:

| Category | Meaning |
|---|---|
| `not_ready` | the baseline has not seen enough to judge (cold start); no signal |
| `unseen` | count 0; signal at level 4 |
| `uncommon` | count 1 … `uncommon_max_count` (default 2; 0 disables); signal at level 2 |
| `common` | more frequent; no signal |

Each signal carries:
- `observed_count`, the times this value was seen;
- `baseline_total`, the process starts learned from;
- `relative_frequency`, their ratio.

These are measurements, not probabilities. The alert's `confidence` is a fixed
0.3, only because `Alert` requires a confidence; it has no statistical meaning.

**Readiness.** The baseline judges nothing until it has seen
`min_observations` process starts (default 200) **and** `min_relationships`
distinct parent→child pairs (default 25). The CLI prints
`Rarity baseline …: NOT READY … no rarity signals will be emitted` rather than
treating every first sighting as suspicious.

**Frozen at detection time.** The baseline is learned offline and never updated
by the detector. Replay stays deterministic, and an intruder cannot teach the
baseline during an incident that their activity is normal. Inferred processes
(whose start the agent never saw) are not learned from.

## Workflow

```bash
# 1. Learn from telemetry you believe is benign
panopticon-detect --rules rules --officer-ndjson benign.ndjson --learn-baseline baseline.json

# 2. Detect with it
panopticon-detect --rules rules --officer-ndjson today.ndjson --baseline baseline.json \
  --output-file alerts.ndjson

# 3. Export the same features for analysis or a future model
panopticon-detect --rules rules --officer-ndjson today.ndjson --export-features features.jsonl
```

`--baseline-min-observations`, `--baseline-min-relationships` and
`--baseline-uncommon-max` tune a baseline when it is learned; the values are
stored in the file. These flags are batch-mode only (not `--reliable`). The
manager does not load a baseline yet.

## The baseline file

An illustrative example, with counts abbreviated:

```json
{
  "baseline_type": "process_rarity",
  "format_version": 1,
  "feature_schema_version": 1,
  "baseline_version": "<12 hex chars>",
  "created_at": "2026-10-01T12:00:00+00:00",
  "readiness": {"min_observations": 200, "min_relationships": 25},
  "thresholds": {"uncommon_max_count": 2},
  "observed_from": "2026-09-15T09:00:00",
  "observed_to": "2026-09-19T17:30:00",
  "total_observations": 812,
  "counts": {
    "name": {"chrome.exe": 140, "svchost.exe": 96},
    "parent_child": {"explorer.exe -> chrome.exe": 131, "services.exe -> svchost.exe": 96},
    "name_path_class": {"chrome.exe @ program_files": 140, "svchost.exe @ system": 96}
  }
}
```

`baseline_version` is a hash of everything except `created_at`, so the same
data and settings always give the same version. Every signal names the version
that produced it. Loading refuses:
- an unknown type or format;
- a different feature schema;
- a version that does not match the contents, i.e. an edited or corrupted file.

## Adding the next detector

A detector is any object with `name`, `version`, `evaluate(event, extractor) ->
List[BehavioralSignal]` and `prune(before) -> int`. Pass it to
`build_detection_run(rules, behavioral_detectors=[...])`. A command-line
classifier, an Isolation Forest over `ProcessFeatures`, a supervised classifier
or a sequence model would each:
- read features from the shared extractor;
- report `BehavioralSignal`s with an explanation and a model version;
- inherit tagging, correlation and incident membership unchanged.

## Limitations

- **Cold start.** Nothing is judged until the baseline is ready; a new
  deployment has a blind period.
- **Baseline poisoning.** If the learning window already contains an intrusion,
  the intrusion is learned as normal. Learn from a window you have reason to
  trust, and relearn from a clean one after an incident.
- **Legitimate rare behavior.** New software, updates and first-time use are all
  rare. Expect signals for them; that is why they are evidence, not verdicts.
- **Environment-specific.** Counts are fleet-wide in this version, not per host
  or per user. A baseline learned on one environment does not transfer to
  another.
- **Concept drift.** Normal changes over time; relearn periodically. There is no
  automatic decay yet.
- **No ground truth.** Nothing labels a signal as a true or false positive, so
  precision is not measured yet.
- **Cannot prove maliciousness.** It reports unusualness only.
- **Telemetry limits.** Only the schema 0.3 families are visible; in-memory
  script execution, process injection, DNS and WMI are not.
- **Bounded counts.** Behavior counts read graph adjacency, which is capped at
  4096 edges per node, and the graph is pruned to its retention window.
