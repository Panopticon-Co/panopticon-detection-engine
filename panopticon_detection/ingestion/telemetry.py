"""Telemetry-family normalization for Panopticon Schema 0.3 (V3).

V1/V2 carried one telemetry family: process start. V3 adds Network, File,
Registry and Image-Load. Rather than five unrelated code paths, every family
shares one identity/context scaffold and one normalization entrypoint here.

A Schema 0.3 event is a Schema 0.2 event plus:

* ``event.category`` may now be ``process | network | file | registry |
  image_load`` (0.2 allowed only ``process``);
* an optional family block (``network`` / ``file`` / ``registry`` /
  ``image_load``) carrying that family's fields;
* ``process`` stays present on every event as *process context* -- who did it.

Schema 0.2 events remain valid (no family block, ``category == "process"``).
This module never mutates the input. It produces the engine-internal event dict
the rule evaluator consumes, keyed by a synthesized ``event_type`` and with the
family fields flattened to the dotted aliases the rules already read
(``network.destination_ip``, ``registry.key_path``, ``file.path``,
``image.path`` ...).

Dispatch is a registry (``_NORMALIZERS``), not an if/else ladder: adding a
family is one function plus one dict entry.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

TELEMETRY_FAMILIES = ("process", "network", "file", "registry", "image_load")
# 0.4 (Linux agent) shares 0.2/0.3's wire envelope -- see the matching
# comment in officer_adapter.py.
SUPPORTED_SCHEMA_VERSIONS = ("0.1", "0.2", "0.3", "0.4")

# event.type (Schema 0.3) -> engine event_type, chosen to match the vocabulary
# the existing rule set already uses (DET-NET-001 -> network_connect,
# DET-PERS-001 -> registry_write, DET-PROC-014 -> image_load).
_REGISTRY_EVENT_TYPES = {
    "set_value": "registry_write",
    "add_key": "registry_add_key",
    "delete_key": "registry_delete_key",
    "rename_key": "registry_rename_key",
}
_FILE_EVENT_TYPES = {
    "create": "file_create",
    "delete": "file_delete",
    "rename": "file_rename",
}


def _basename(path: Any) -> Any:
    """Final path component for either separator; ``None`` when absent."""
    if not path:
        return None
    return str(path).replace("\\", "/").rstrip("/").split("/")[-1] or None


def _common(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Identity + host + user + process-context fields shared by every family."""
    event_obj = raw.get("event", {}) or {}
    source_obj = raw.get("source", {}) or {}
    agent_obj = raw.get("agent", {}) or {}
    host_obj = raw.get("host", {}) or {}
    user_obj = raw.get("user", {}) or {}
    proc_obj = raw.get("process", {}) or {}
    parent_obj = proc_obj.get("parent", {}) or {}

    user_name = user_obj.get("name")
    domain = user_obj.get("domain")
    full_user = f"{domain}\\{user_name}" if domain and user_name else (user_name or "")

    proc_hash = proc_obj.get("hash")
    sha256 = proc_hash.get("sha256") if isinstance(proc_hash, dict) else proc_obj.get("sha256")

    proc_name = proc_obj.get("name") or _basename(proc_obj.get("executable"))
    parent_name = parent_obj.get("name") or _basename(parent_obj.get("executable"))
    host_id = host_obj.get("id") or host_obj.get("hostname") or raw.get("host_id", "OFFICER-ENDPOINT")

    return {
        "schema_version": raw.get("schema_version", "0.3"),
        "event_id": event_obj.get("id", f"evt_{raw.get('timestamp', '')}"),
        "timestamp": event_obj.get("timestamp") or raw.get("timestamp", ""),
        "telemetry_category": event_obj.get("category", "process"),
        "host_id": host_id,
        "source": {
            "kind": source_obj.get("kind", "unknown"),
            "provider": source_obj.get("provider", ""),
            "channel": source_obj.get("channel"),
            "record_id": source_obj.get("record_id"),
        },
        "agent": {"id": agent_obj.get("id", ""), "version": agent_obj.get("version", "")},
        "host": {
            "id": host_obj.get("id", host_id),
            "hostname": host_obj.get("hostname", host_id),
            "os": host_obj.get("os", {}),
        },
        "user": {"name": user_name, "domain": domain, "sid": user_obj.get("sid"), "full": full_user},
        "process": {
            "entity_id": proc_obj.get("entity_id"),
            "process_guid": proc_obj.get("entity_id"),
            "pid": proc_obj.get("pid"),
            "ppid": parent_obj.get("pid"),
            "name": proc_name,
            "executable": proc_obj.get("executable"),
            "command_line": proc_obj.get("command_line", ""),
            "user": full_user,
            "user_sid": user_obj.get("sid"),
            "file_hash": sha256,
            "sha256": sha256,
            # Opaque, OS-native creation token (schema 0.4). Passed through
            # untouched: response_engine.translate_recommendation needs it to
            # build a PID-reuse-safe KILL_PROCESS and fails closed without it.
            "start_time_ticks": proc_obj.get("start_time_ticks"),
        },
        "parent": {
            "entity_id": parent_obj.get("entity_id"),
            "process_guid": parent_obj.get("entity_id"),
            "pid": parent_obj.get("pid"),
            "name": parent_name,
        },
        "_raw_officer_event": raw,
    }


def _normalize_process(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = _common(raw)
    etype = (raw.get("event", {}) or {}).get("type", "start")
    if etype in ("start", "create"):
        out["event_type"] = "process_create"
    elif etype in ("stop", "terminate"):
        out["event_type"] = "process_terminate"
    else:
        out["event_type"] = f"process_{etype}"
    proc = raw.get("process", {}) or {}
    out["file"] = {"path": proc.get("executable"), "hash": out["process"]["sha256"]}
    return out


def _normalize_network(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = _common(raw)
    n = raw.get("network", {}) or {}
    direction = n.get("direction") or ("outbound" if n.get("initiated", True) else "inbound")
    out["event_type"] = "network_connect"
    out["network"] = {
        "direction": direction,
        "protocol": (n.get("protocol") or "").lower() or None,
        "source_ip": n.get("source_ip") or n.get("src_ip"),
        "source_port": n.get("source_port") or n.get("src_port"),
        "destination_ip": n.get("destination_ip") or n.get("dst_ip"),
        "destination_port": n.get("destination_port") or n.get("dst_port"),
        "destination_hostname": n.get("destination_hostname") or n.get("dst_hostname"),
    }
    return out


def _normalize_file(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = _common(raw)
    f = raw.get("file", {}) or {}
    op = (f.get("operation") or (raw.get("event", {}) or {}).get("type") or "create").lower()
    out["event_type"] = _FILE_EVENT_TYPES.get(op, f"file_{op}")
    f_hash = f.get("hash")
    out["file"] = {
        "operation": op,
        "path": f.get("path") or f.get("target_path"),
        "target_path": f.get("target_path"),
        "previous_path": f.get("previous_path"),
        "hash": f_hash.get("sha256") if isinstance(f_hash, dict) else f_hash,
    }
    return out


def _normalize_registry(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = _common(raw)
    r = raw.get("registry", {}) or {}
    op = (r.get("operation") or (raw.get("event", {}) or {}).get("type") or "set_value").lower()
    out["event_type"] = _REGISTRY_EVENT_TYPES.get(op, f"registry_{op}")
    key = r.get("key_path") or r.get("key") or r.get("target_object")
    out["registry"] = {
        "operation": op,
        # rules read registry.key_path; keep .key as an alias for forward compat.
        "key_path": key,
        "key": key,
        "value_name": r.get("value_name"),
        "value_type": r.get("value_type"),
        # metadata-only: pass value_data through only if the producer included it.
        "value_data": r.get("value_data"),
    }
    return out


def _normalize_image_load(raw: Dict[str, Any]) -> Dict[str, Any]:
    out = _common(raw)
    im = raw.get("image_load", {}) or raw.get("image", {}) or {}
    out["event_type"] = "image_load"
    h = im.get("hash")
    signed = im.get("is_signed")
    if signed is None:
        signed = im.get("signed")
    out["image"] = {
        "path": im.get("path") or im.get("image_loaded"),
        "is_signed": signed,
        "signed": signed,
        "signature_status": im.get("signature_status") or im.get("signature"),
        "sha256": h.get("sha256") if isinstance(h, dict) else (h or im.get("sha256")),
    }
    return out


_NORMALIZERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "process": _normalize_process,
    "network": _normalize_network,
    "file": _normalize_file,
    "registry": _normalize_registry,
    "image_load": _normalize_image_load,
}


def is_panopticon_event(raw: Any) -> bool:
    """True for any Schema 0.1 / 0.2 / 0.3 Panopticon event."""
    if not isinstance(raw, dict):
        return False
    if raw.get("schema_version") in SUPPORTED_SCHEMA_VERSIONS and isinstance(raw.get("event"), dict):
        return True
    return isinstance(raw.get("event"), dict) and "process" in raw and "source" in raw


def category_of(raw: Dict[str, Any]) -> str:
    cat = (raw.get("event", {}) or {}).get("category", "process")
    return cat if cat in _NORMALIZERS else "process"


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize any Panopticon event to the engine-internal shape, dispatching on
    ``event.category``. An unrecognized category falls back to process context
    only -- it never raises, because an unknown family must not break ingestion."""
    return _NORMALIZERS[category_of(raw)](raw)


def register_family(name: str, normalizer: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
    """Extension hook: add a telemetry family without editing this module."""
    _NORMALIZERS[name] = normalizer


# ---------------------------------------------------------------------------
# Field registry
#
# Which dotted fields each engine event_type can actually carry. Derived by
# running every normalizer on a fully populated agent event, so it cannot drift
# from the normalizers themselves. scripts/check_rule_sourcing.py rejects any
# rule condition on a field outside this set (plus the enrichment layer's
# derived fields) -- a rule reading a field nothing produces can never fire.
# ---------------------------------------------------------------------------

_FULL_CONTEXT: Dict[str, Any] = {
    "schema_version": "0.3",
    "source": {"kind": "sysmon", "provider": "p", "channel": "c", "record_id": 1},
    "agent": {"id": "a", "version": "v"},
    "host": {"id": "h", "hostname": "h", "os": {"name": "n"}},
    "user": {"name": "u", "domain": "d", "sid": "s"},
    "process": {
        "entity_id": "e",
        "pid": 1,
        "name": "p.exe",
        "executable": "C:\\p.exe",
        "command_line": "p",
        "start_time_ticks": 1,
        "parent": {"entity_id": "e", "pid": 1, "name": "q.exe"},
        "hash": {"sha256": "0" * 64},
    },
}

_FULL_FAMILY_BLOCKS: Dict[str, Dict[str, Any]] = {
    "network": {"network": {
        "direction": "outbound", "protocol": "tcp", "source_ip": "10.0.0.1",
        "source_port": 1, "destination_ip": "10.0.0.2", "destination_port": 2,
        "destination_hostname": "x",
    }},
    "file": {"file": {
        "operation": "create", "path": "C:\\f", "target_path": "C:\\f",
        "previous_path": "C:\\g", "hash": {"sha256": "0" * 64},
    }},
    "registry": {"registry": {
        "operation": "set_value", "key_path": "HKLM\\k", "value_name": "v",
        "value_type": "REG_SZ", "value_data": "d",
    }},
    "image_load": {"image_load": {
        "path": "C:\\m.dll", "is_signed": True, "signature_status": "Valid",
        "hash": {"sha256": "0" * 64},
    }},
}

_FAMILY_TYPES = {
    "process": ("start", "stop"),
    "network": ("connect",),
    "file": tuple(_FILE_EVENT_TYPES),
    "registry": tuple(_REGISTRY_EVENT_TYPES),
    "image_load": ("load",),
}

# Envelope/bookkeeping keys that are not rule material.
_NOT_FIELDS = {"_raw_officer_event", "host.os"}


def _flatten(prefix: str, value: Any, out: set) -> None:
    if prefix in _NOT_FIELDS:
        return
    if isinstance(value, dict) and value:
        for key, sub in value.items():
            _flatten(f"{prefix}.{key}" if prefix else key, sub, out)
    elif prefix:
        out.add(prefix)


def _build_field_registry() -> Dict[str, frozenset]:
    registry: Dict[str, set] = {}
    for family, types in _FAMILY_TYPES.items():
        for etype in types:
            raw = {
                **_FULL_CONTEXT,
                "event": {"id": "x", "category": family, "type": etype, "timestamp": "t"},
                **_FULL_FAMILY_BLOCKS.get(family, {}),
            }
            if family == "file":
                raw["file"] = {**raw["file"], "operation": etype}
            if family == "registry":
                raw["registry"] = {**raw["registry"], "operation": etype}
            event = normalize(raw)
            fields: set = set()
            _flatten("", event, fields)
            registry.setdefault(event["event_type"], set()).update(fields)
    return {etype: frozenset(fields) for etype, fields in registry.items()}


FIELD_REGISTRY: Dict[str, frozenset] = _build_field_registry()


def producible_fields(event_type: str) -> frozenset:
    """Raw fields the normalizer emits for ``event_type`` (empty if none)."""
    return FIELD_REGISTRY.get(event_type, frozenset())
