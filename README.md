# panopticon-detection-engine

Detection, correlation and alerting engine for the **Panopticon&Co** EDR
platform. Ingests endpoint telemetry, evaluates it against YAML rules,
reconstructs multi-stage attacks from a provenance graph, and emits alerts.

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

Multi-stage detection is a **graph query**, not a list of hardcoded rule
sequences.

1. **Identity.** Every event is joined to the process that caused it by
   `(host_id, pid, timestamp)`, resolved through per-PID time intervals. This
   is PID-reuse-safe and works across all five telemetry families — which an
   `entity_id`-keyed index cannot, because the agent derives that id with a
   different formula for process events than for everything else.
2. **Graph.** Each event becomes one timestamped edge between typed entities:
   processes, files, sockets, registry keys, modules.
3. **Tags.** A rule match is written onto the edge its event created, so the
   detection becomes part of the graph's structure.
4. **Campaigns.** A match on a terminal tactic (Impact, Exfiltration, C2,
   Credential Access, Lateral Movement) anchors a backward traversal. The walk
   only ever steps to edges at or before the time reached so far — nothing can
   be caused by its own future. Every tagged edge it reaches is a stage of the
   same campaign, whichever process it happened in.

Because stages are found rather than enumerated, a chain spanning several
processes — a dropper spawning a loader spawning a beacon — correlates without
anyone writing a rule for that specific sequence.

The traversal also names the campaign's **root** process, which is what makes a
`TERMINATE_PROCESS` recommendation actionable: the root's node carries the
`start_time_ticks` the agent observed, and without that token the response
engine correctly refuses to build a `KILL_PROCESS` command.

## Layout

| Path | Role |
|---|---|
| `panopticon_detection/provenance/` | Identity resolution, temporal graph, tagging, campaign traversal |
| `panopticon_detection/evaluator/` | Rule matching, operators, deobfuscation, entropy, thresholds |
| `panopticon_detection/rules/` | YAML rule loading and pydantic validation |
| `panopticon_detection/behavioral/` | C2 beaconing, port scans, DNS/DGA, ransomware tripwires |
| `panopticon_detection/ingestion/` | Agent schema adapters and telemetry streams |
| `panopticon_detection/reliability/` | Bounded queue, SQLite spool, retry, health, metrics |
| `panopticon_detection/alerting/` | Alert model and formatters |
| `rules/` | 54 rules, all firing on telemetry the agents emit |

## Rules

`scripts/check_rule_sourcing.py` fails CI if any rule targets an `event_type`
the normalizer cannot produce. A rule that can never fire is not coverage, it
is a claim, so 38 such rules were deleted rather than carried.

```bash
python scripts/check_rule_sourcing.py
```

## Current limitations

Stated plainly rather than left for a reader to discover:

- The provenance graph is **in-memory** and does not survive a restart.
  Persistence is the next planned step.
- No agent emits a process-stop event yet, so process end times are *inferred*
  from the next process to occupy the same PID.
- Campaign scoring uses a static prior over edge kinds as a stand-in for a
  learned baseline. The weights need real telemetry to tune.
- This is a capstone-grade engine: a CLI and a library, with no HTTP API, no
  database server and no message queue.

## License

See [LICENSE](LICENSE).
