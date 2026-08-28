# V3 — Multi-family telemetry ingestion (eyedetect)

V3 lets the detection engine ingest five telemetry families — **process,
network, file, registry, image load** — from the Officer agent's
**Schema 0.3** NDJSON, through the unchanged V2 reliability pipeline.

Status legend: **implemented** / **tested** (pytest here) / **live-verified**
(real Windows) / **planned**.

## 1. Architecture

```
Officer NDJSON (Schema 0.1 / 0.2 / 0.3)
   -> LiveTelemetryStream (file or officer-agent.exe subprocess)  [unchanged]
   -> OfficerIngestionAdapter.transform_officer_event
        category == "process"  -> the original, well-tested transform
        category in {network,file,registry,image_load} -> src.ingestion.telemetry.normalize
   -> engine-internal event dict: identity + host + user + PROCESS CONTEXT
        + event_type (network_connect | file_create | registry_write | image_load | process_create ...)
        + flattened family block (network.* / file.* / registry.* / image.*)
        + _raw_officer_event (verbatim, for forensics)
   -> [V2] BoundedEventQueue -> DetectionRun.process_event -> AlertSpool -> IncrementalAlertWriter -> alerts.ndjson
```

`src/ingestion/telemetry.py` is a **category-dispatch registry**
(`_NORMALIZERS`), not an if/else ladder. Adding a family is one function plus
one dict entry; `register_family(name, fn)` does it without editing the module.
An unrecognized `event.category` degrades to process context and **never
raises** — an unknown family must not break ingestion.

The V2 layer (`src/reliability/*`) is telemetry-type agnostic and was **not
modified**.

## 2. Family field mapping

The normalizer flattens each Schema 0.3 family block to the dotted aliases the
existing rules already read:

| Family | `event_type` | Engine-internal fields |
|---|---|---|
| process | `process_create` / `process_terminate` | unchanged |
| network | `network_connect` | `network.direction`, `.protocol`, `.source_ip`, `.source_port`, `.destination_ip`, `.destination_port`, `.destination_hostname` |
| file | `file_create` / `file_delete` / `file_rename` | `file.operation`, `.path`, `.target_path`, `.previous_path`, `.hash` |
| registry | `registry_write` (set_value), `registry_add_key`, `registry_delete_key`, `registry_rename_key` | `registry.key_path` (+ `.key` alias), `.value_name`, `.value_type`, `.value_data` (metadata-only, usually `null`) |
| image_load | `image_load` | `image.path`, `.is_signed` (+ `.signed` alias), `.signature_status`, `.sha256` |

`event_type` values were chosen to match the vocabulary the current rule set
already uses (`DET-NET-001` -> `network_connect`, `DET-PERS-001` ->
`registry_write`, `DET-PROC-014` -> `image_load`).

## 3. Detection rules

No large V3 ruleset. Network and registry already had applicable rules; two
minimal, deterministic demonstration rules were added for the rest:

* `DET-FILE-001` -- file created in a Startup folder (`event_type: file_create`).
* `DET-IMG-001` -- unsigned module loaded from a user-writable path
  (`event_type: image_load`; metadata-only, no PE analysis).

`DET-PROC-011` and existing heuristics are unchanged.

## 4-8. Schema / build / test / run

* **Schema:** `panopticon-agent/schema/event.schema.json` v0.3 (additive).
  `OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS = ("0.1","0.2","0.3")`.
  There is no `jsonschema` dependency; the adapter is duck-typed and tolerant.
* **Setup:** `pip install -r requirements.txt` (unchanged -- no new deps).
* **Test:** `pytest -v tests/` -- **151 passed, 2 skipped** (was 138/2; the 138
  prior tests are unchanged and green). `tests/test_v3_telemetry_ingestion.py`
  covers per-family normalization, process 0.2 back-compat, unknown-family
  fallback, `LiveTelemetryStream` routing, every family reaching the evaluator,
  and one real detection per family.
* **Run (batch):**
  `python src/main.py --rules rules --officer-ndjson samples/v3/mixed_families_sample.ndjson`
* **Run (V2 reliable):**
  `python src/main.py --rules rules --officer-ndjson samples/v3/mixed_families_sample.ndjson --reliable --spool-db spool/v3.db --output-file alerts.ndjson --max-events 20 --no-auto-remediate`
  -> 5 SYNTHETIC events -> 6 alerts delivered, 0 failed, 0 dropped, spool clean.

## 9. Live validation

Requires the Officer agent running elevated on a real Windows host with Sysmon
configured for the V3 Event IDs (see `panopticon-agent/docs/V3_TELEMETRY.md`
section 8 and `panopticon-agent/docs/sysmon/`).

The engine has **no stdin-pipe ingestion**. There are two supported paths:

* `--officer --officer-bin <path>\officer-agent.exe --officer-source sysmon` —
  the engine spawns `officer-agent.exe` as a managed subprocess and reads its
  stdout, then shuts it down cleanly on stop; or
* `--officer-ndjson <file>` — ingest an NDJSON file previously captured from
  `officer-agent.exe` stdout.

Both combine with `--reliable` (V2 pipeline). Example:

```
python src/main.py --rules rules --officer --officer-bin <path>\officer-agent.exe \
  --officer-source sysmon --reliable --spool-db spool/v3.db \
  --output-file alerts.ndjson --no-auto-remediate --duration 60
```

**Live-verified:** completed on Windows 11 (build 26220, x64, elevated, Sysmon
v15.21). 385 real Sysmon-derived events across all five families flowed through
this engine and the unchanged V2 pipeline: 385 processed, 0 failed, 0 dropped,
30 alerts persisted/delivered, spool clean; `DET-NET-001`, `DET-FILE-001`,
`DET-IMG-001` and `DET-PROC-011` all fired on real telemetry. Registry
telemetry (EID 12/13) was live-verified including the metadata-only guarantee
(`registry.value_data` never populated); firing `DET-PERS-001` live was
intentionally out of scope because it requires writing a real persistence key.
`samples/v3/mixed_families_sample.ndjson` remains SYNTHETIC and is not evidence
of live capture.

## 10-11. Limitations / known issues

* `samples/v3/mixed_families_sample.ndjson` is hand-authored, not captured.
* Cross-family correlation of a network/file/registry/image event back to its
  process-start event is by PID/name, not a shared `entity_id` (the agent
  cannot derive the start-time-based ID without a process start time).
* The engine does not validate incoming events against the JSON Schema; it
  relies on the agent's `deserialize_event` and its own tolerant `dict.get`.
* See `SECURITY_REVIEW_V3.md` for the medium finding (wider Sysmon
  subscription volume) and low findings.
