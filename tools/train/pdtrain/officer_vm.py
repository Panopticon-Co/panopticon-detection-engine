"""Benign process starts recorded by the Officer agent on our own Windows VM.

Input: a collection kit package (``officer-endpoint-record-1.0`` NDJSON
segments). Each record wraps the agent's event in ``data``; process starts are
``kind: observation, category: process``.

Known issues of kit 1.0.0, all handled here and counted in the report:

1. **Self tag.** The kit adds a top-level ``"self": true`` (outside the record
   schema) to its own records. The tag is stripped and those records dropped.
2. **Untagged self children.** Only the kit's own PIDs are tagged; their
   children (``conhost.exe`` etc.) are not. Every process whose parent PID is a
   self PID, started while that self process was alive (until its stop, or
   :data:`SELF_CHILD_WINDOW` when no stop was seen), is dropped -- recursively.
   The supervisor and agent PIDs from ``heartbeat.json`` count as self.
3. **Duplicate starts.** Most starts arrive from Sysmon *and* ETW. ETW lacks
   command line, parent name, user and hash, so the Sysmon record is kept and
   the ETW one dropped when they match on PID + image name within
   :data:`PAIR_WINDOW`. Unmatched ETW starts are dropped too: the classifier
   scores Sysmon-sourced starts only (see the model card).
4. Probe/heartbeat cadence is not used here (it does not prove capture gaps).
5. The manifest says kit 1.0.1 (the packager); ``heartbeat.json`` records the
   collecting version (1.0.0). Both are reported.
6. One process can dominate (``git.exe``); rows keep everything, and the
   experiment caps per-image repeats for *training* only.

Everything kept is labelled benign: the user recorded ordinary use and no
attack was run (stated by the user; review list in the report).
"""

from __future__ import annotations

import collections
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from panopticon_detection.datasets import canonical as C
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

PAIR_WINDOW = timedelta(seconds=2)
SELF_CHILD_WINDOW = timedelta(minutes=10)


def _ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed - parsed.utcoffset()).replace(tzinfo=None) if parsed.tzinfo else parsed


def _leaf(path: Optional[str]) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def read_package(folder: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for segment in sorted(Path(folder).glob("segment-*.ndjson")):
        with segment.open(encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    meta: Dict[str, Any] = {}
    for name in ("manifest.json", "heartbeat.json"):
        path = Path(folder) / name
        if path.exists():
            meta[name.split(".")[0]] = json.loads(path.read_text(encoding="utf-8-sig"))
    return records, meta


def _start(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Fields of a process-start record we need, or None."""
    if record.get("kind") != "observation" or record.get("category") != "process":
        return None
    data = record.get("data") or {}
    proc = data.get("process") or {}
    when = _ts((data.get("event") or {}).get("timestamp"))
    if when is None or proc.get("pid") is None:
        return None
    facts = ((data.get("source_facts") or {}).get("process")) or {}
    return {
        "record": record,
        "source": (data.get("source") or {}).get("kind"),
        "pid": proc.get("pid"),
        "ppid": (proc.get("parent") or {}).get("pid", facts.get("parent_pid")),
        "image": proc.get("executable") or facts.get("executable"),
        "name": _leaf(proc.get("name") or proc.get("executable")),
        "when": when,
        "facts": facts,
    }


def prepare(
    records: List[Dict[str, Any]], meta: Dict[str, Any], dataset: str
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Apply issues 1-3 and build rows; returns (rows, counts)."""
    counts: Dict[str, Any] = collections.Counter()
    # -- issue 1: self tag
    self_starts: Dict[int, List[Tuple[datetime, Optional[datetime]]]] = collections.defaultdict(list)
    stops: Dict[int, List[datetime]] = collections.defaultdict(list)
    clean: List[Dict[str, Any]] = []
    for record in records:
        is_self = bool(record.pop("self", False))
        data = record.get("data") or {}
        if record.get("category") == "process_stop":
            pid = (data.get("process") or {}).get("pid")
            when = _ts(record.get("observed_at"))
            if pid is not None and when is not None:
                stops[pid].append(when)
        if is_self:
            counts["dropped_self_tagged"] += 1
            start = _start(record)
            if start:
                self_starts[start["pid"]].append((start["when"], None))
            continue
        clean.append(record)
    heartbeat = meta.get("heartbeat") or {}
    run_start = _ts(heartbeat.get("run_started_utc"))
    run_end = _ts(heartbeat.get("last_event_utc"))
    for key in ("supervisor_pid", "agent_pid"):
        pid = heartbeat.get(key)
        if pid is not None and run_start is not None:
            self_starts[pid].append((run_start - timedelta(minutes=1), run_end))

    def alive_until(pid: int, began: datetime, end: Optional[datetime]) -> datetime:
        if end is not None:
            return end
        later = [s for s in stops.get(pid, []) if s >= began]
        return min(later) if later else began + SELF_CHILD_WINDOW

    starts = [s for s in (_start(r) for r in clean) if s is not None]
    starts.sort(key=lambda s: (s["when"], str(s["pid"])))

    # -- issue 2: untagged children of self processes (recursive, in time order)
    windows: Dict[int, List[Tuple[datetime, datetime]]] = collections.defaultdict(list)
    for pid, spans in self_starts.items():
        for began, end in spans:
            windows[pid].append((began, alive_until(pid, began, end)))
    kept: List[Dict[str, Any]] = []
    for s in starts:
        spans = windows.get(s["ppid"], [])
        if any(b <= s["when"] <= e for b, e in spans):
            counts["dropped_self_children"] += 1
            windows[s["pid"]].append((s["when"], alive_until(s["pid"], s["when"], None)))
            continue
        kept.append(s)

    # -- issue 3: Sysmon/ETW duplicate starts
    sysmon = [s for s in kept if s["source"] == "sysmon"]
    etw = [s for s in kept if s["source"] == "etw"]
    index: Dict[Tuple[Any, str], List[datetime]] = collections.defaultdict(list)
    for s in sysmon:
        index[(s["pid"], s["name"])].append(s["when"])
    for s in etw:
        if any(abs(t - s["when"]) <= PAIR_WINDOW for t in index.get((s["pid"], s["name"]), [])):
            counts["dropped_etw_duplicate"] += 1
        else:
            counts["dropped_etw_unpaired"] += 1
    counts["other_sources"] = sum(1 for s in kept if s["source"] not in ("sysmon", "etw"))

    rows = [_row(s, dataset) for s in sysmon]
    counts["rows"] = len(rows)
    counts["kit_version_collected"] = heartbeat.get("kit_version")
    counts["kit_version_packaged"] = (meta.get("manifest") or {}).get("kit_version")
    return rows, dict(counts)


def _row(s: Dict[str, Any], dataset: str) -> Dict[str, Any]:
    data = json.loads(json.dumps(s["record"]["data"]))
    facts = s["facts"]
    proc = data.setdefault("process", {})
    parent = proc.setdefault("parent", {})
    # Sysmon sometimes leaves the parent *name* empty; the raw ParentImage is in
    # source_facts, and the agent derives parent.name from it the same way.
    if not parent.get("name") and facts.get("parent_executable"):
        parent["name"] = C.basename(facts["parent_executable"])
    data.setdefault("schema_version", "0.3")
    normalized = OfficerIngestionAdapter.transform_officer_event(data)
    host = (data.get("host") or {}).get("id") or "UNKNOWN_HOST"
    return {
        "row_id": (data.get("event") or {}).get("id") or s["record"].get("record_id"),
        "source": "officer_vm",
        "dataset": dataset,
        "techniques": [],
        "tool": "officer-collection-kit",
        "host": host,
        "utc": C.format_timestamp(s["when"]),
        "guid": facts.get("process_guid"),
        "parent_guid": facts.get("parent_process_guid"),
        "pid": s["pid"],
        "image": s["image"],
        "parent_image": facts.get("parent_executable"),
        "command_line": proc.get("command_line"),
        "parent_command_line": None,
        "integrity": None,  # this recording carries no IntegrityLevel
        "label": 0,
        "label_rule": "benign/agent_recording",
        "group": f"officer_vm:{host}",
        "event": {k: v for k, v in normalized.items() if k != "_raw_officer_event"},
    }
