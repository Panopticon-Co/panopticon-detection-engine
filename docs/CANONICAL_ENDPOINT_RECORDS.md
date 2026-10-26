# Canonical endpoint integration

Endpoint record 1.0 is a distinct ingestion contract. The full envelope and
domain payload survive normalization, including installation/boot/device scope,
collector epoch/sequence, native record tokens and unresolved process facts.
Known observation families retain rule aliases; other kinds/domains expose
`endpoint_<kind>_<category>` plus `endpoint_data` for explicit domain rules.
This does not imply rules or acquisition exist for every endpoint capability.

`EndpointIngestionAdapter` verifies exact/source identity digests and preserves
creation tokens losslessly. Only native-exact references supply an internal
integer response token. Source GUIDs, PID-only facts, unknown boot scope and
wall-clock timestamps cannot manufacture executable native targets.

The registry uses a separate canonical entity index. Process activity may arrive
before creation; the entity remains explicit and its creation observation remains
unknown until supplied. Parent links require explicit reference proof, never a
PID/time match. Legacy telemetry continues through its existing heuristic index;
canonical and legacy identities are not automatically aliased. UTC parsing is
independent of the Manager machine's local timezone.

All alerts triggered by canonical records carry `endpoint_context`, identifying
the triggering record, endpoint, provenance and subject. Their replay identities
are agent-scoped SHA-256 digests of rule, record and evidence, including behavioral
alerts. A context describes the trigger, not all campaign participants. Existing
legacy alert IDs remain compatible.

Manager migration 13 adds pending/claimed/done/failed state to its retained
canonical records, backfills pending state on upgrade and indexes the queue.
Both ingestion protocols receive reserved bounded batch capacity. Stale claims
recover; one poison record is retained as failed without stopping other records.
Canonical pending/claimed/failed counts are exported by Manager metrics.

Development validation includes C++-generated fixtures, same-timestamp PID reuse,
cross-boot identity, activity-before-start, unresolved parents, strict identity
proof and pruning. Manager verifies authenticated ingestion through the actual
worker and an isolated native WinHTTP HTTPS fixture through durable ACK and rule
alert. These are component/integration evidence, not live sensor or fleet
qualification. Graph persistence/rebuild, admission budgets, verified source
aliases, state freshness/rules, full evidence/response lifecycle, Console
investigation and seven-day operational qualification remain open.

The coordinated engine files are also present in Manager's vendored engine
checkout. No unrelated upstream changes or Linux endpoint changes are included.
Publishing commits and updating the submodule pin remains release work.

Canonical observation payloads now include original decoded `source_facts` and
separate cache `enrichment`; both survive in `endpoint_data` and the retained raw
record. Normalization-failure evidence uses
`endpoint_evidence_normalization_failure`. It can retain exact native identity
despite a rejected hash, while unknown/malformed source aliases remain unresolved.
Invalid UTF-8 source fields are lossless hex-byte objects, not repaired text.
Rules must distinguish capture time from retained source event time and observed
facts from cached hints. Manager's native-artifact regression processes six such
records through the actual worker and preserves all facts without guessed actors.
Original native bytes and full domain evidence rules remain unfinished.

## Officer family mapping (2026-10-27)

`EndpointIngestionAdapter` maps endpoint-record 1.0 families onto the engine's
existing vocabulary so current rules apply to canonical telemetry:

| Canonical category | Engine event_type | Notes |
|---|---|---|
| process, network, file, registry, image_load | as the legacy family | legacy-shaped `data` through `OfficerIngestionAdapter` |
| process_stop | `process_terminate` | closes the same canonical instance (`end_observed`) |
| process_access | `process_access` | decimal `granted_access` converted exactly to the `0x` form; `target_reference` verified |
| remote_thread | `remote_thread` | decimal `start_address` converted exactly; `target_reference` verified |
| dns | `dns_query` | answers from the bounded `query_results` text |
| other kinds/categories | `endpoint_<kind>_<category>` | full payload under `endpoint_data` |

Lossless hex-byte text (invalid UTF-8) becomes `None` in rule-facing string
fields; the exact value stays in `endpoint_data`. Per-event alerts get
agent-scoped SHA-256 IDs; correlation alerts (incidents) keep their own IDs.
Field semantics: panopticon-contracts `docs/ENDPOINT_TELEMETRY_CATALOG.md`.
Tests consume the shared family fixtures from a sibling contracts checkout.
