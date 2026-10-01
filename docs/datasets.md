# Datasets and the telemetry → feature → detection matrix

This engine learns and is evaluated on telemetry shaped exactly like what the
Officer agent emits. Rather than teach the engine other formats, a small adapter
converts an external dataset into **canonical Panopticon events** (the agent's
own wire schema), after which everything is the ordinary pipeline:

```
external dataset ──► panopticon_detection.datasets adapter ──► canonical NDJSON
   ──► OfficerIngestionAdapter ──► normalizer ──► provenance graph
   ──► rules / behavioral detectors ──► FeatureExtractor (the same one used live)
```

The canonical format is the source of truth; no dataset-specific field ever
reaches the detection engine or the feature extractor.

## Selected dataset: OTRF Security-Datasets

[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT), pinned
to one commit in `panopticon_detection/datasets/sources.py`. Chosen because its
recordings are **real Windows Sysmon + PowerShell events** — the same event IDs
the agent decodes — covering the fileless and credential-theft techniques this
engine now targets. Each recording is one JSON object per line, one Windows
event with its EventData flattened.

Verified facts that shaped the adapter (see `panopticon_detection/datasets/otrf.py`):

- **Timestamps.** The exported `@timestamp`/`TimeCreated` are often hours off
  Sysmon's own `UtcTime` (collector local time mislabelled UTC). The adapter uses
  `UtcTime` for Sysmon events and corrects PowerShell events by the median
  offset measured from the same file.
- **Labels are per recording, not per event.** A recording maps to one ATT&CK
  technique in its metadata YAML, but it also contains unrelated OS activity and
  usually exercises more techniques than it lists. The adapter reports the
  dataset-level mapping in a manifest and **never stamps a label on an event** —
  so these labels do not support a supervised per-process classifier yet.
- **Metadata-only is preserved.** Registry `value_data` stays null; script text
  is capped and hashed exactly as the agent caps it.

## Reproduction

```bash
panopticon-dataset sources                      # list the vetted, hash-pinned recordings
panopticon-dataset fetch empire_launcher_vbs --dest data/otrf
panopticon-dataset normalize --format otrf \
    --input data/otrf/empire_launcher_vbs.zip \
    --metadata data/otrf/SDWIN-190518182022.yaml \
    --output data/canonical/empire_launcher_vbs.ndjson
panopticon-detect --rules rules \
    --officer-ndjson data/canonical/empire_launcher_vbs.ndjson \
    --export-features data/features/empire_launcher_vbs.jsonl
```

`fetch` refuses a download whose SHA-256 does not match the pin. Downloaded and
generated data lives under `/data/` (git-ignored); the trimmed, committed
fixtures under `tests/datasets/otrf/` are what CI replays.

## Telemetry → feature → detection/ML matrix

| Telemetry (schema) | Canonical event | Feature(s) it feeds | Detection / ML use | Status |
|---|---|---|---|---|
| Process create (0.3) | `process_create` | name, lineage, path_class, parent→child rarity | process rules; rarity baseline | shipped |
| Network connect (0.3) | `network_connect` | public-egress counts, beacon cadence | C2 rules; beacon detector | shipped |
| File create/delete (0.3) | `file_*` | image-writer join, dropped-exe counts | dropper rules | shipped |
| Registry (0.3) | `registry_*` | Run-key writes | persistence rules | shipped |
| Image load (0.3) | `image_load` | unsigned-from-userdir | DLL rules | shipped |
| Process stop (0.5) | `process_terminate` | `lifetime_seconds` | lifetime features | shipped |
| DNS (0.5) | `dns_query` | domain count, DGA-likeness, failed lookups | DNS/DGA analysis; rarity | shipped |
| Process access (0.5) | `process_access` | LSASS-access count, access mask, minidump call trace | `DET-CRED-010/011`; cross-process rarity | shipped |
| Remote thread (0.5) | `remote_thread` | injected-thread count; causal INJECTED edge | `DET-INJ-010/011` | shipped |
| Script block (0.5) | `script_block` | obfuscation, length, AMSI-tamper text | `DET-PS-010` | shipped |
| WMI (Sysmon 19–21) | — | — | persistence via WMI | not collected (no PID to join) |
| Authentication (4624/4625) | — | — | lateral movement, brute force | not collected (needs a session entity) |

## Remaining gaps for ML

- **Labels.** Per-recording technique labels cannot train a supervised process
  classifier. A labelled benign-vs-malicious corpus needs either per-process
  labelling or recording benign and attack sessions separately in a lab.
- **Clean benign baseline.** Every OTRF recording mixes attack and OS noise.
  Record benign-only sessions with the finished agent (see the agent's
  `docs/V5_TELEMETRY.md`) to set rarity thresholds and measure false positives.
- **Volume/scale data.** DARPA OpTC (1,000 hosts) is the realistic-scale option
  but is large and in a different (eCAR) format; a second adapter would be needed.
