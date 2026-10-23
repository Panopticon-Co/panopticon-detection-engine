"""DARPA OpTC eCAR (benign period) -> the same row shape as the Sysmon sources.

eCAR is the OpTC sensor's own format (FiveDirections/OpTC-data, ecar.md):
one JSON object per line with ``object``/``action``, ``hostname``,
``objectID`` (the created process), ``actorID`` (its creator), ``pid``,
``ppid``, ``principal``, ``timestamp`` and a ``properties`` map holding
``image_path``, ``parent_image_path``, ``command_line``, ``user`` and ``sid``.

Only ``PROCESS``/``CREATE`` records are kept. eCAR has no integrity level, so
OpTC rows can train and test Variant A only. Every row from the *benign*
folder is labelled benign (the red team was not active then).
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from panopticon_detection.datasets import canonical as C
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

ADAPTER = {"id": "dataset-adapter:optc-ecar", "version": "1"}


def _when(value: Any) -> Optional[datetime]:
    """eCAR timestamps: epoch milliseconds or an ISO string with offset -> naive UTC."""
    if value is None:
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        return datetime.fromtimestamp(int(value) / 1000.0, tz=timezone.utc).replace(tzinfo=None)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = (parsed - parsed.utcoffset()).replace(tzinfo=None)
    return parsed


def _int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None  # eCAR uses -1 for "not available"


_DEVICE_PREFIX = "\\device\\harddiskvolume"


def drive_path(path: Optional[str]) -> Optional[str]:
    """``\\Device\\HarddiskVolume1\\x`` -> ``C:\\x`` (eCAR reports kernel device paths;
    Sysmon and the agent report drive paths, and path features must mean the same)."""
    if not path or not path.lower().startswith(_DEVICE_PREFIX):
        return path
    rest = path[len(_DEVICE_PREFIX):]
    digits = len(rest) - len(rest.lstrip("0123456789"))
    if digits == 0 or not rest[digits:].startswith("\\"):
        return path
    return "C:" + rest[digits:]


def row_from_ecar(record: Dict[str, Any], dataset: str) -> Optional[Dict[str, Any]]:
    if record.get("object") != "PROCESS" or record.get("action") != "CREATE":
        return None
    props = record.get("properties") or {}
    host = str(record.get("hostname") or "UNKNOWN_HOST")
    when = _when(record.get("timestamp") or record.get("timestamp_ms"))
    pid, ppid = _int(record.get("pid")), _int(record.get("ppid"))
    image = drive_path(props.get("image_path"))
    if image and "\\" not in image:
        # 28% of OpTC process creates name the image without a path ("PING.EXE").
        # The Officer agent always reports a full path, and every OpTC row is
        # benign, so these rows teach "no path => benign": excluded (run v5).
        return None
    if when is None or pid is None or not image:
        return None
    name, domain = C.split_account(props.get("user") or record.get("principal"))
    parent_image = drive_path(props.get("parent_image_path"))
    process = {
        "entity_id": C.process_entity_id(host, pid, when),
        "pid": pid,
        "name": C.basename(image),
        "executable": image,
        "command_line": props.get("command_line"),
        "sha256": None,
        "parent": {"entity_id": None, "pid": ppid, "name": C.basename(parent_image)},
    }
    event = C.build_event(
        category="process", type_="start",
        event_key=(dataset, host, "ecar", record.get("id") or record.get("objectID")),
        when=when,
        source={"kind": "etw", "provider": "OpTC-eCAR", "channel": None, "record_id": None},
        agent=ADAPTER,
        host={"id": host, "hostname": host, "os": {"name": "Windows", "build": "unknown"}},
        user={"name": name, "domain": domain, "sid": props.get("sid")},
        process=process,
    )
    normalized = OfficerIngestionAdapter.transform_officer_event(event)
    return {
        "row_id": event["event"]["id"],
        "source": "optc",
        "dataset": dataset,
        "techniques": [],
        "tool": "optc-benign",
        "host": host,
        "utc": event["event"]["timestamp"],
        "guid": record.get("objectID"),
        "parent_guid": record.get("actorID"),
        "pid": pid,
        "image": image,
        "parent_image": parent_image,
        "command_line": props.get("command_line"),
        "parent_command_line": None,
        "integrity": None,
        "label": 0,
        "label_rule": "benign/optc_benign_period",
        "group": f"optc:{host}",
        "event": {k: v for k, v in normalized.items() if k != "_raw_officer_event"},
    }


def read_ecar_process_creates(path: Path, dataset: str) -> Iterator[Dict[str, Any]]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"PROCESS"' not in line or '"CREATE"' not in line:
                continue  # cheap pre-filter: most eCAR records are FLOW/FILE/REGISTRY
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = row_from_ecar(record, dataset)
            if row is not None:
                yield row
