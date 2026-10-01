"""Build canonical Panopticon events (the agent's wire schema) from external data.

A dataset adapter reads somebody else's format and calls this module to produce
events in the shape the Officer agent emits (``panopticon-agent``'s
``schema/event.schema.json``). Those events then enter the engine exactly as
live telemetry does -- ``OfficerIngestionAdapter`` -> normalizer -> graph ->
detectors -> ``FeatureExtractor`` -- so a model trained on a dataset sees
features computed by the same code as the one it will score live.

Rules every adapter follows here:

* Only fields the source genuinely has are set; everything else is ``None``
  (serialised as JSON ``null``), never a guess.
* Identifiers are content-derived (SHA-256), so normalising the same input
  twice gives byte-identical output.
* An event keeps the schema version that introduced its family: process start,
  network, file, registry and image-load events are 0.3; process stop, dns,
  process_access, remote_thread and script_block are 0.5 -- the same rule the
  agent follows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

#: Families introduced by schema 0.5; everything else is 0.3-shaped.
SCHEMA_05_CATEGORIES = frozenset({"dns", "process_access", "remote_thread", "script_block"})

#: The agent's cap on script-block text, in UTF-8 bytes (event.schema.json).
SCRIPT_TEXT_MAX_BYTES = 16384


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _key(*parts: Any) -> str:
    # Length-prefixed like the agent's entity_id.cpp, so "a|b" + "c" can never
    # collide with "a" + "b|c".
    return "".join(f"{len(str(p))}:{p}|" for p in parts)


def event_id(*parts: Any) -> str:
    return "evt_" + sha256_hex(_key("dataset-event-v1", *parts))


def process_entity_id(host: str, pid: Any, start: datetime) -> str:
    """Entity id of a process *start*: host + pid + start time in milliseconds."""
    millis = int(start.replace(tzinfo=timezone.utc).timestamp() * 1000)
    return "proc_" + sha256_hex(_key("dataset-process-entity-v1", host, pid, millis))


def context_entity_id(host: str, pid: Any, guid: Optional[str]) -> str:
    """Entity id of a process seen as *context* (any non-start event).

    Mirrors the agent's two-formula design: like the agent's, a context id is
    not a join key with the start event's id. The engine joins on
    ``(host, pid, time)``.
    """
    return "proc_" + sha256_hex(_key("dataset-process-context-v1", host, pid, guid or ""))


def format_timestamp(when: datetime) -> str:
    """``2020-09-04T20:09:55.760Z`` -- the schema's millisecond UTC format."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return str(path).replace("\\", "/").rstrip("/").split("/")[-1] or None


def split_account(account: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """``"CORP\\alice"`` -> ``("alice", "CORP")``; a bare name has no domain."""
    if not account:
        return None, None
    if "\\" not in account:
        return account, None
    domain, _, name = account.partition("\\")
    return (name or None), (domain or None)


def truncate_script_text(text: Optional[str]) -> Dict[str, Any]:
    """The agent's script-block text policy, applied identically.

    At most the first 16384 UTF-8 bytes, cut on a character boundary; the full
    length (bytes) and a hash of the full text travel with it, so truncation is
    always visible to a consumer.
    """
    if not text:
        return {"text": None, "text_length": 0, "text_truncated": False, "text_sha256": None}
    raw = text.encode("utf-8")
    kept = raw[:SCRIPT_TEXT_MAX_BYTES].decode("utf-8", errors="ignore")
    return {
        "text": kept or None,
        "text_length": len(raw),
        "text_truncated": len(raw) > SCRIPT_TEXT_MAX_BYTES,
        "text_sha256": hashlib.sha256(raw).hexdigest(),
    }


def build_event(
    *,
    category: str,
    type_: str,
    event_key: Tuple[Any, ...],
    when: datetime,
    source: Dict[str, Any],
    agent: Dict[str, str],
    host: Dict[str, Any],
    user: Dict[str, Optional[str]],
    process: Dict[str, Any],
    block: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble one canonical event; ``block`` is the family block, if any."""
    new_shape = category in SCHEMA_05_CATEGORIES or (category == "process" and type_ == "stop")
    event: Dict[str, Any] = {
        "schema_version": "0.5" if new_shape else "0.3",
        "event": {
            "id": event_id(*event_key),
            "category": category,
            "type": type_,
            "timestamp": format_timestamp(when),
        },
        "source": {
            "kind": source["kind"],
            "provider": source["provider"],
            "channel": source.get("channel"),
            "record_id": source.get("record_id"),
        },
        "agent": dict(agent),
        "host": host,
        "user": {"name": user.get("name"), "domain": user.get("domain"), "sid": user.get("sid")},
        "process": {
            "entity_id": process["entity_id"],
            "pid": process["pid"],
            "name": process.get("name"),
            "executable": process.get("executable"),
            "command_line": process.get("command_line"),
            "parent": process.get("parent") or {"entity_id": None, "pid": None, "name": None},
            "hash": {"sha256": process.get("sha256")},
            "start_time_ticks": None,
        },
    }
    if block is not None:
        event[category] = block
    return event
