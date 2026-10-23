"""DARPA OpTC eCAR records -> canonical agent events (schema 0.5), every family the agent has.

eCAR (FiveDirections/OpTC-data) is one JSON object per line: ``object``/``action``,
``hostname``, ``pid``/``ppid``, ``principal``, ``timestamp`` (ISO with offset) and a
``properties`` map. Mapped:

=========================  =========================================================
eCAR                       canonical event
=========================  =========================================================
PROCESS CREATE             process start (image, parent image, command line, user)
PROCESS TERMINATE          process stop
FLOW START, outbound       network connect (destination ip/port, protocol)
FILE CREATE/RENAME/DELETE  file create / rename / delete
MODULE LOAD                image load (eCAR carries no signature: ``is_signed`` unknown)
REGISTRY ADD/EDIT/REMOVE   registry set_value (ADD, EDIT) / delete_key (REMOVE)
THREAD REMOTE_CREATE       remote thread (target by pid; eCAR names no target image)
=========================  =========================================================

Not mapped, on purpose: PROCESS OPEN (no access mask, so "read LSASS memory"
cannot be told from a harmless handle), FILE READ/WRITE/MODIFY (no agent
equivalent: the agent reports file creation, not every write), FLOW MESSAGE and
inbound flows, THREAD CREATE/TERMINATE, TASK and USER_SESSION. eCAR has no DNS
and no script-block telemetry.

Paths arrive as kernel device paths (``\\Device\\HarddiskVolume1\\...``), long-path
prefixed (``\\\\?\\C:\\...``) or rooted without a drive (``\\Windows\\...``); all are
mapped to ``C:\\...`` so path classes mean what they mean for Sysmon and the agent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from panopticon_detection.datasets import canonical as C

ADAPTER = {"id": "dataset-adapter:optc-ecar", "version": "2"}
_DEVICE_PREFIX = "\\device\\harddiskvolume"
_PROTOCOLS = {"6": "tcp", "17": "udp"}


def when_of(value: Any) -> Optional[datetime]:
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


def drive_path(path: Optional[str]) -> Optional[str]:
    """Device, long-path and drive-less paths -> ``C:\\...``; bare names stay bare."""
    if not path:
        return path
    text = str(path)
    if text.startswith("\\\\?\\"):
        text = text[4:]
    text = text.replace("\\\\", "\\")
    if text.lower().startswith(_DEVICE_PREFIX):
        rest = text[len(_DEVICE_PREFIX):]
        digits = len(rest) - len(rest.lstrip("0123456789"))
        if digits and rest[digits:].startswith("\\"):
            return "C:" + rest[digits:]
        return text
    if text.startswith("\\"):
        return "C:" + text
    return text


def _int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None  # eCAR uses -1 for "not available"


def to_canonical(record: Dict[str, Any], dataset: str) -> Optional[Dict[str, Any]]:
    """One eCAR record as a canonical agent event, or ``None`` when it is not mapped."""
    obj, action = record.get("object"), record.get("action")
    props = record.get("properties") or {}
    host = str(record.get("hostname") or "UNKNOWN_HOST")
    when = when_of(record.get("timestamp") or record.get("timestamp_ms"))
    pid = _int(record.get("pid"))
    if when is None or pid is None:
        return None
    image = drive_path(props.get("image_path"))
    name, domain = C.split_account(props.get("user") or record.get("principal"))
    context = {"entity_id": C.context_entity_id(host, pid, None), "pid": pid,
               "name": C.basename(image), "executable": image}
    block: Optional[Dict[str, Any]] = None

    if obj == "PROCESS" and action == "CREATE":
        category, type_ = "process", "start"
        parent_image = drive_path(props.get("parent_image_path"))
        process = {**context, "entity_id": C.process_entity_id(host, pid, when),
                   "command_line": props.get("command_line"), "sha256": None,
                   "parent": {"entity_id": None, "pid": _int(record.get("ppid")),
                              "name": C.basename(parent_image)}}
    elif obj == "PROCESS" and action == "TERMINATE":
        category, type_, process = "process", "stop", context
    elif obj == "FLOW" and action == "START":
        if str(props.get("direction") or "").lower() != "outbound":
            return None
        category, type_, process = "network", "connect", context
        block = {"direction": "outbound", "protocol": _PROTOCOLS.get(str(props.get("l4protocol"))),
                 "source_ip": props.get("src_ip"), "source_port": _int(props.get("src_port")),
                 "destination_ip": props.get("dest_ip"), "destination_port": _int(props.get("dest_port")),
                 "destination_hostname": None}
    elif obj == "FILE" and action in ("CREATE", "RENAME", "DELETE"):
        path = drive_path(props.get("file_path"))
        if not path:
            return None
        category, process = "file", context
        type_ = {"CREATE": "create", "RENAME": "rename", "DELETE": "delete"}[action]
        new_path = drive_path(props.get("new_path"))
        block = {"operation": type_, "path": new_path if (action == "RENAME" and new_path) else path,
                 "target_path": new_path if action == "RENAME" else None,
                 "previous_path": path if action == "RENAME" else None, "hash": {"sha256": None}}
    elif obj == "MODULE" and action == "LOAD":
        path = drive_path(props.get("module_path"))
        if not path:
            return None
        category, type_, process = "image_load", "load", context
        block = {"path": path, "is_signed": None, "signature_status": None, "hash": {"sha256": None}}
    elif obj == "REGISTRY" and action in ("ADD", "EDIT", "REMOVE"):
        key = props.get("key")
        if not key:
            return None
        category, process = "registry", context
        type_ = "delete_key" if action == "REMOVE" else "set_value"
        block = {"operation": type_, "key_path": key,
                 "value_name": props.get("value") if type_ == "set_value" else None,
                 "value_type": props.get("type") if type_ == "set_value" else None, "value_data": None}
    elif obj == "THREAD" and action == "REMOTE_CREATE":
        target_pid = _int(props.get("tgt_pid"))
        if target_pid is None:
            return None
        category, type_, process = "remote_thread", "create", context
        block = {"target": {"entity_id": C.context_entity_id(host, target_pid, None), "pid": target_pid,
                            "executable": None, "user": None},
                 "new_thread_id": _int(props.get("tgt_tid")), "start_address": props.get("start_address"),
                 "start_module": None, "start_function": None}
    else:
        return None

    return C.build_event(
        category=category, type_=type_,
        event_key=(dataset, host, "ecar", record.get("id") or record.get("objectID"), obj, action),
        when=when,
        source={"kind": "etw", "provider": "OpTC-eCAR", "channel": None, "record_id": None},
        agent=ADAPTER,
        host={"id": host, "hostname": host, "os": {"name": "Windows", "build": "unknown"}},
        user={"name": name, "domain": domain, "sid": props.get("sid")},
        process=process,
        block=block,
    )
