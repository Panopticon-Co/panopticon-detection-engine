# panopticon-detection-engine

Detection, correlation and alerting engine for the **Panopticon&Co** EDR
platform. Ingests endpoint telemetry, evaluates single-event and stateful YAML
rules, correlates detections into causal incidents over a provenance graph, and
emits explainable alerts.

The engine **detects and recommends. It never executes a response.** Response
actions — the closed seven-action set, its approval tiers and its dispatch —
live in [`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine)
and [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager).

## Where it sits

```
Windows / Linux endpoint
  -> panopticon-agent ("Officer") / panopticon-linux-agent
  -> POST /api/v1/ingest            (panopticon-manager)
  -> THIS ENGINE                    (vendored at vendor/eyedetect)
  -> alerts + response recommendations
  -> panopticon-response-engine     (translate -> tier -> analyst approval)
  -> panopticon-console
```

It also runs standalone against NDJSON telemetry, which is how the samples and
CI smoke tests exercise it.

## Quick start

```bash
pip install -e ".[dev]"
pytest -q

# Replay agent-shaped telemetry and show the provenance graph it built
panopticon-detect --rules rules \
  --officer-ndjson samples/officer_live_sample.ndjson --graph-stats
```

Requires Python 3.10+. Dependencies are `pyyaml` and `pydantic` — nothing else.

## How correlation works

A detection is not an isolated alert; it is a tag on the provenance graph, and
related tags become one **incident**.

1. **Identity.** Every event is joined to the process that caused it by
   `(host_id, pid, timestamp)`, resolved through per-PID time intervals. This is
   PID-reuse-safe and works across all five telemetry families -- which an
   `entity_id` index cannot, because the agent derives that id differently for
   process events than for everything else. A process first seen acting (the
   agent started on a running machine) is inferred and flagged `inferred`.
2. **Graph.** Each event becomes one timestamped edge between typed entities:
   processes, files, sockets, registry keys. A loaded DLL is the same file node
   a process wrote, so "dropped then loaded" is one path.
3. **Direction.** Walks follow *information flow* -- parent to child, writer to
   file, file to the process that ran it -- never the reverse, and never forward
   in time. They stop at boundary hubs (`explorer.exe`, `services.exe`,
   `svchost.exe`...), so two programs a user launched are never merged just
   because they share a parent.
4. **Incidents.** Each detection's causal scope is its backward walk plus
   everything downstream of its tree's entry point. A scope that touches an open
   incident joins it (persistence set by a dropped payload attaches to the macro
   that dropped it); a terminal-tactic detection whose scope already holds two
   tactics opens one. The incident is emitted when it opens and re-emitted only
   when it gains a tactic or its severity band rises -- one incident with
   revisions, not a pile of overlapping alerts.
5. **Root and score.** The root is the entry point (`winword.exe`, never the
   `explorer.exe` hub above it); the provenance origin (e.g. the browser that
   downloaded the payload) is reported separately. The score is itemised --
   stage severity, tactic breadth, and named context factors (Office/browser
   entry, user-writable execution, public egress, obfuscation) -- and every
   alert lists why.

## Detection

| Kind | Examples |
|---|---|
| Single-event rules | encoded PowerShell, LSASS MiniDump, shadow-copy deletion |
| Sequence rules | Office-spawned script host then public egress (by process tree); payload dropped then Run key set |
| Threshold / value_count rules | mass extension-changing renames; internal horizontal sweep; vertical port scan; discovery-tool burst |
| Statistical | per-process C2 beaconing (jitter-tolerant, measured FP/TP in its docstring) |

Rules read raw fields and derived ones computed once per event: `path_class`,
`network.destination_scope`, `file.extension_changed`, the process-tree entry
point, and graph joins such as `process.image_writer_name` /
`process.image_age_seconds` ("this image was written 7s ago by powershell").
Named lists (`$office`, `$script_hosts`...) live in `rules/lists/`. Every alert
records the conditions that matched and the values they saw.

## Layout

| Path | Role |
|---|---|
| `panopticon_detection/provenance/` | Identity, temporal graph, directed walks, tagging, incidents, host risk |
| `panopticon_detection/evaluator/` | Condition matching, single-event and stateful rule evaluation |
| `panopticon_detection/enrichment.py` | Derived fields, cached per event |
| `panopticon_detection/rules/` | Rule types, loading, named lists, validation |
| `panopticon_detection/behavioral/` | C2 beaconing; DNS/DGA analysis (awaiting DNS telemetry) |
| `panopticon_detection/ingestion/` | The one normalizer, its field registry, agent adapters |
| `panopticon_detection/reliability/` | Bounded queue, SQLite spool, retry, health, metrics |
| `panopticon_detection/alerting/` | Alert model and formatters |
| `rules/` | 64 rules (58 single, 2 sequence, 1 threshold, 3 value_count) |
| `tests/corpus/` | Replay scenarios: agent-schema telemetry and the expected verdict |

## Rules

`scripts/check_rule_sourcing.py` fails CI if any rule reads telemetry nothing
produces -- an `event_type` the normalizer never emits, or any condition,
`by`, counted or evidence field that neither the normalizer nor the enrichment
layer produces for that event type. The producible set is derived by running
the normalizer, not hand-kept. A rule that can never fire is not coverage, it is
a claim: 38 such rules were deleted for their event type, and three more for
fields like `process.ppid_spoofed`.

Every rule declares its `level` (no default), and unknown keys are rejected.

```bash
python scripts/check_rule_sourcing.py
```

## Evidence that it works

`tests/corpus/` holds six replay scenarios, each agent-schema NDJSON (valid
against `panopticon-agent/schema/event.schema.json`) plus the expected verdict:
the Office macro -> payload -> C2 -> persistence -> beacon chain as **one**
incident rooted at `winword.exe`; download-execute-dump with the browser named
as origin; ransomware precursors and encryption; reconnaissance that stays a
set of alerts; siblings under `explorer.exe` that must not merge; and a benign
session that must produce nothing. `tests/test_corpus.py` replays each through
the full engine and checks it twice for determinism.

## Current limitations

Stated plainly rather than left for a reader to discover:

- The provenance graph and incidents are **in-memory** and do not survive a
  restart; persistence (or replaying the last horizon on start) is next.
- No agent emits a process-stop event yet, so process end times are *inferred*
  from the next process to occupy the same PID.
- Telemetry is five families: process start, network connect, file
  create/delete/rename, registry, image load. There is no DNS, authentication,
  process-access or script-block telemetry, so those detections do not exist.
- Boundary processes are recognised by name; a masquerading binary named
  `svchost.exe` would stop a walk (masquerading is a detection of its own).
- Stateful windows assume near-ordered arrival; a late event is counted but
  never evicts newer ones, and a sequence step that arrives out of order does
  not advance a match.
- The incident score is a transparent heuristic, not a learned model.
- This is a capstone-grade engine: a CLI and a library, with no HTTP API, no
  database server and no message queue.

## License

See [LICENSE](LICENSE).
