"""Track A: score the integrated engine on the declared replay scenario suite.

    python scripts/eval_demo_suite.py [--json out.json] [--markdown out.md]

The suite is every scenario under ``tests/corpus/`` (agent-schema NDJSON plus an
``expected.json`` written with the scenario). Each is replayed through the real
normalizer and the fully wired engine -- the path the manager's detection worker
takes -- and scored against its own expectations:

* **attack scenarios** (an expected incident, or must-fire rules): detected if
  at least one alert fires; *incident correct* if the engine forms exactly the
  expected incidents with the expected root process;
* **benign / must-not-merge scenarios**: every alert is a false positive and
  every incident a false incident.

Denominators are scenarios, not events or executions. Latency is in *event
time* (first event of the scenario to the first alert / incident), which is the
engine's contribution; ingest and polling delay are measured on the live
pipeline, not here. The response class column applies the manager's staging
policy (docs/integration/CONTRACT.md section 6) to each recommendation; the
manager's own tests are the authority on what it actually stages.

These are synthetic, engineering-validation replays. They are not field results
and say nothing about generalisation (see docs/ml/EVAL_REPORT.md for that).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from panopticon_detection.factory import build_detection_run  # noqa: E402
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter  # noqa: E402
from panopticon_detection.provenance.identity import parse_timestamp  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
AUTO_SAFE = {"COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS"}


def response_class(alert) -> str:
    """The manager's staging decision for this alert's recommendation."""
    rec = alert.active_response
    if not rec:
        return "none"
    action = rec.get("action")
    if action in AUTO_SAFE:
        return "auto"
    if alert.detection_source == "behavioral":
        return "record-only (behavioral)"
    if action == "TERMINATE_PROCESS":
        ok = isinstance(rec.get("target_pid"), int) and isinstance(rec.get("target_start_time_ticks"), int)
        return "analyst-approval" if ok else "record-only (no start_time_ticks)"
    if action == "QUARANTINE_FILE":
        return "analyst-approval" if rec.get("target_file") else "record-only (no path)"
    if action == "ISOLATE_HOST":
        return "analyst-approval"
    return "record-only (untranslatable)"


def wire_lines(name: str, etw_twins: bool):
    """The scenario's wire events; with ``etw_twins``, as the live agent sends them.

    The live agent reports every process creation twice: ETW Kernel-Process
    (carrying ``start_time_ticks``, no command line) just before Sysmon EID 1.
    Corpus scenarios hold the Sysmon report only. The twin is added
    mechanically: same instant, pid, image and parent, ticks = the creation
    time as a FILETIME, as the agent's ETW collector reports it.
    """
    for line in (CORPUS / name / "events.ndjson").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        raw = json.loads(line)
        ev = raw.get("event") or {}
        proc = raw.get("process") or {}
        if etw_twins and ev.get("category") == "process" and ev.get("type") == "start" and not proc.get("start_time_ticks"):
            when = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            twin = copy.deepcopy(raw)
            twin["event"]["id"] = "evt_" + hashlib.sha256(("etw|" + ev["id"]).encode()).hexdigest()
            twin["source"] = {"kind": "etw", "provider": "Microsoft-Windows-Kernel-Process", "channel": None, "record_id": None}
            twin["process"]["command_line"] = None
            twin["process"]["start_time_ticks"] = int((when - FILETIME_EPOCH).total_seconds() * 10_000_000)
            yield json.dumps(twin)
        yield line


def replay(name: str, etw_twins: bool = False):
    run, context = build_detection_run(ROOT / "rules")
    alerts, first_ts, schema, n, started = [], None, set(), 0, time.perf_counter()
    for line in wire_lines(name, etw_twins):
        schema.add(json.loads(line).get("schema_version"))
        event = OfficerIngestionAdapter.parse_line(line)
        if not event:
            continue
        n += 1
        first_ts = first_ts or parse_timestamp(event.get("timestamp"))
        alerts += run.process_event(event)
    elapsed = time.perf_counter() - started
    return alerts, run, first_ts, sorted(schema), n, elapsed


def score(name: str, etw_twins: bool = False) -> dict:
    expected = json.loads((CORPUS / name / "expected.json").read_text(encoding="utf-8"))
    alerts, run, _first_ts, schema, n, elapsed = replay(name, etw_twins)
    again, *_ = replay(name, etw_twins)
    incidents = [a for a in alerts if a.incident_id]
    incident_ids = sorted({a.incident_id for a in incidents})
    atomic = [a for a in alerts if not a.incident_id]
    fired = Counter(a.rule_id for a in atomic)
    want_inc = expected.get("incidents", [])
    if want_inc:
        kind = "attack chain"
    elif expected.get("max_alerts") == 0:
        kind = "benign"
    elif expected.get("must_fire"):
        kind = "single tactic"  # detections expected, but no incident
    else:
        kind = "must not merge"  # related-looking activity that must stay apart
    benign = kind == "benign"
    declared = set(expected.get("must_fire", []))
    for inc in want_inc:
        declared |= set(inc.get("stage_rules_include", []))

    def lag(start, items):
        if start is None or not items:
            return None
        return round((parse_timestamp(items[0].timestamp) - parse_timestamp(start.timestamp)).total_seconds(), 1)

    # Correlation delay in event time: the first detection that ends up a stage
    # of an incident, to that incident's first alert. Detection itself is
    # synchronous (an alert carries its triggering event's timestamp).
    stage_ids = {s.get("alert_id") for a in incidents for s in a.evidence.get("stages", [])}
    first_stage = next((a for a in atomic if a.alert_id in stage_ids), None)

    latest = {}
    for a in incidents:
        latest[a.incident_id] = a
    roots = sorted(a.evidence.get("root_cause_process") for a in latest.values())
    want_roots = sorted(i.get("root") for i in want_inc)
    return {
        "scenario": name,
        "kind": kind,
        "description": expected.get("description", ""),
        "schema_versions": schema,
        "wire_compatible": all(v in ("0.2", "0.3", "0.4") for v in schema),
        "events": n,
        "alerts": len(atomic),
        "rules_fired": dict(sorted(fired.items())),
        "unexpected_rules": sorted(r for r in fired if r not in declared),
        "suppressed_repeats": run.suppressed_duplicates,
        "incidents": len(incident_ids),
        "incident_alerts": len(incidents),
        "incident_roots": roots,
        "incident_tactics": [latest[i].evidence.get("tactics_covered") for i in incident_ids],
        "incident_score": [latest[i].evidence.get("incident_score") for i in incident_ids],
        "expected_incidents": len(want_inc),
        "detected": bool(atomic) if not benign else None,
        "incident_correct": (len(incident_ids) == len(want_inc) and roots == want_roots),
        "stage_to_incident_s": lag(first_stage, incidents),
        "ms_per_event": round(1000 * elapsed / max(n, 1), 2),
        "responses": dict(Counter(response_class(a) for a in alerts if a.active_response)),
        "replay_idempotent": [a.alert_id for a in alerts] == [a.alert_id for a in again],
    }


def summarise(rows: list[dict]) -> dict:
    attack = [r for r in rows if r["kind"] == "attack chain"]
    benign = [r for r in rows if r["kind"] == "benign"]
    apart = [r for r in rows if r["kind"] in ("single tactic", "must not merge")]
    return {
        "scenarios": len(rows),
        "attack_chains": len(attack),
        "attack_chains_detected": sum(1 for r in attack if r["detected"]),
        "attack_chains_incident_correct": sum(1 for r in attack if r["incident_correct"]),
        "no_incident_scenarios": len(apart),
        "no_incident_scenarios_correct": sum(1 for r in apart if r["incident_correct"]),
        "no_incident_scenarios_detected": sum(1 for r in apart if r["detected"]),
        "benign_scenarios": len(benign),
        "benign_events": sum(r["events"] for r in benign),
        "benign_alerts": sum(r["alerts"] for r in benign),
        "benign_incidents": sum(r["incidents"] for r in benign),
        "replay_idempotent": all(r["replay_idempotent"] for r in rows),
        "median_stage_to_incident_s": _median([r["stage_to_incident_s"] for r in attack]),
        "max_ms_per_event": max(r["ms_per_event"] for r in rows),
    }


def _median(values):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else round((vals[mid - 1] + vals[mid]) / 2, 1)


def to_markdown(rows: list[dict], summary: dict) -> str:
    lines = [
        "| Scenario | Kind | Wire 0.2-0.4 | Events | Alerts | Unexpected rules | Incidents (expected) | Root | Stage to incident (s) | Responses |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        resp = ", ".join(f"{k} {v}" for k, v in r["responses"].items()) or "-"
        lines.append(
            f"| {r['scenario']} | {r['kind']} | {'yes' if r['wire_compatible'] else 'no (0.5)'} | {r['events']} "
            f"| {r['alerts']} | {', '.join(r['unexpected_rules']) or '-'} | {r['incidents']} ({r['expected_incidents']}) "
            f"| {', '.join(r['incident_roots']) or '-'} "
            f"| {r['stage_to_incident_s'] if r['stage_to_incident_s'] is not None else '-'} | {resp} |"
        )
    lines.append("")
    lines.append("Summary: " + json.dumps(summary))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    ap.add_argument("--etw-twins", action="store_true", help="add the ETW twin of each process start, as the live agent sends")
    args = ap.parse_args()
    names = sorted(p.name for p in CORPUS.iterdir() if (p / "expected.json").is_file())
    rows = [score(n, args.etw_twins) for n in names]
    summary = summarise(rows)
    md = to_markdown(rows, summary)
    print(md)
    if args.json:
        args.json.write_text(json.dumps({"summary": summary, "scenarios": rows}, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(md + "\n", encoding="utf-8")
    ok = (
        summary["attack_chains_incident_correct"] == summary["attack_chains"]
        and summary["no_incident_scenarios_correct"] == summary["no_incident_scenarios"]
        and summary["benign_incidents"] == 0
        and summary["replay_idempotent"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
