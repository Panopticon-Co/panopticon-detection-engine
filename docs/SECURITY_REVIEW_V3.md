# Security Review — V3 Telemetry Expansion

Scope: the V3 code added this cycle across both repositories.

* **panopticon-agent** — `schema/event.schema.json` (0.3), the raw/normalized
  telemetry model, `pipeline/serializer.cpp`, `pipeline/normalizer.cpp`,
  `core/entity_id.cpp`, `collectors/sysmon_telemetry_decoder.{hpp,cpp}`,
  `collectors/sysmon_event_collector.cpp`, `src/main.cpp`.
* **panopticon-detection-engine** — `src/ingestion/telemetry.py`,
  `src/ingestion/officer_adapter.py`, `rules/file/DET-FILE-001*.yaml`,
  `rules/process/DET-IMG-001*.yaml`.
* **panopticon-console** — the client-side family column in `static/app.js` /
  `static/index.html`.

The V2 reliability layer (`src/reliability/*`) was **not modified** for V3 and
is out of scope here; see `SECURITY_REVIEW_V2.md`.

Result: **no high-severity findings. One medium, five low / informational.**

## Checklist

| Area | Finding |
|---|---|
| Windows API usage | Only additions are a wider `EvtSubscribe` XPath (a static `const wchar_t[]` literal, not attacker-influenced) and continued `EvtRender(EvtRenderEventXml)`. No new handle types, no new privileged calls. |
| Privilege requirements | Unchanged. The Sysmon Operational channel already required elevation for EID 1; EID 3/7/11/12-14 read from the same channel with the same rights. No new capability requested. |
| Subprocess invocation | None added. The engine's only child process is still the optional Officer subprocess (`live_stream.stream_from_officer_process`, unchanged V1 code, list-form argv, no `shell=True`). |
| Command construction | N/A — no command lines are built in V3 code. |
| Path handling | The decoders copy `Image` / `TargetFilename` / `ImageLoaded` / `TargetObject` verbatim as opaque strings. No path is opened, canonicalized, resolved or used for filesystem access anywhere in the telemetry path. |
| SQLite handling | No V3 change. The alert spool schema, PRAGMAs and bind-parameter usage are exactly V2. |
| Temporary files | None created by V3 code. |
| NDJSON parsing | `deserialize_event` (agent) rejects unknown top-level keys, enforces exactly one family block per non-process category and none on a process event, and regex-validates `event.id` / `timestamp` / `entity_id` / all `sha256` fields. The engine's `telemetry.normalize` is pure `dict.get` with defaults — a missing or malformed field becomes `None`, never an exception. |
| Event size limits | **Low finding (2).** `SysmonTelemetryDecoder` has no explicit cap on the rendered XML size; it relies on `EvtRender` sizing the buffer to what Windows delivers and on `tinyxml2` handling it. A pathologically large single event would cause a large-but-bounded allocation on the callback thread. Recommendation: add a byte cap in `render_event_xml` before parsing. |
| Malformed Windows event handling | `tinyxml2::XMLDocument::Parse` failure, missing `Event`/`System`/`EventData`, missing/invalid `EventID`, missing `UtcTime`, invalid integers/ports, and unsupported Event IDs all return `std::nullopt` with an error string. The collector callback's existing `try/catch(...)` boundary is retained, so no exception can cross into the Windows Event Log callback. Verified by `test_sysmon_telemetry_decoder_rejects_process_and_unknown_ids` and the bad-number paths. |
| `sniff_event_id` robustness | **Low finding (3).** The helper accumulates decimal digits into an `int`; an XML body with a multi-thousand-digit run between `<EventID>` and the first non-digit could overflow. Impact is limited to mis-routing to "unsupported EID" (rejected) — no memory unsafety, no crash. Recommendation: bound the digit count or parse with `std::from_chars`. |
| Attacker-controlled strings reaching HTML | The console writes every value through `textContent` / `createTextNode`. The new `familyOf()` compares `alert.tags` / evidence key names but never renders them; the rendered badge text is one of five fixed constants (`process`/`network`/`file`/`registry`/`image load`). CSP (`default-src 'none'; script-src 'self'`), `X-Content-Type-Options: nosniff` and the localhost bind are unchanged. No new XSS surface. |
| Accidental collection of sensitive data | **By design, none of the new families collect content:** no packet payloads or bytes (network is 5-tuple metadata only), no file contents (path + operation + optional hash), **no registry value contents** (`value_data` is left `null` by the decoder and only passed through by the normalizer if a producer explicitly included it; the schema keeps the field but the agent never populates it), no memory, no PE parsing. `image.path` / `file.path` / `command_line` can contain usernames and paths — the same exposure class as V1 process telemetry, already covered by the repo privacy note. |
| Credential / secret leakage | The registry decoder's `Details` handling maps the Sysmon type token (`DWORD`/`QWORD`/`Binary Data`/…) to a `REG_*` name and discards the rest, so a secret stored in a registry value is never read into an event. No auth tokens anywhere. |
| Unbounded memory growth | The bounded ingestion queue is unchanged (hard-capped `deque`, drop-counted). `_raw_officer_event` still keeps one full copy of each event in flight — **Low finding (5), inherited from V2** — bounded by queue capacity. `telemetry.normalize` allocates one output dict per event and returns it; nothing accumulates. |
| Unbounded SQLite growth | No V3 change; the V2 `done`/`delivered` tombstone-growth note in `V2_RELIABILITY.md` still applies. |
| Infinite retry loops | No V3 change; `RetryPolicy` still bounds attempts and enforces a minimum delay. |
| Collector failure handling | Each family gets an isolated `if constexpr` arm in the agent's `RawEvent` visitor; a normalization failure for one event writes one stderr line and drops that event only. The Sysmon subscription and its teardown / `logman` orphan sweep are unchanged. |
| Resource exhaustion from the wider subscription | **Medium finding (1).** Subscribing to Sysmon EID 3 (network) and 7 (image load) is materially higher volume than EID 1 alone. On a host whose Sysmon config does not filter these, Officer will emit far more events. The bounded queue + overflow accounting keep memory bounded and losses visible, but sustained pressure is real. Mitigation: ship / document a Sysmon config that scopes EID 3/7/11/12-14 to security-relevant paths and hives; treat broad EID 7 collection as opt-in. Documented in `docs/V3_TELEMETRY.md` and the agent README. |
| Maintainability (not security) | **Informational (4).** `sysmon_telemetry_decoder.cpp` carries its own copies of the Sysmon-XML helpers (`child_text`, `field`, `parse_integer`, `parse_sysmon_utc`, `extract_sha256`) rather than sharing them with `sysmon_process_decoder.cpp`. This was deliberate — it keeps the live V1/V2 process decoder byte-for-byte unchanged — but a follow-up should extract a shared `sysmon_xml_util` header. |

## Recommendations (none blocking for the V3 milestone)

1. Ship a reference Sysmon configuration that scopes the new Event IDs; make
   broad image-load (EID 7) collection explicitly opt-in.
2. Add a byte cap to `render_event_xml` before `tinyxml2` parsing.
3. Harden `sniff_event_id` against an over-long digit run.
4. Extract the shared Sysmon-XML helpers into one header.
5. Revisit the `_raw_officer_event` full-copy retention (V2 item) before any
   long-running deployment.
