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
SUPPORTED_SCHEMA_VERSIONS = ("0.1", "0.2", "0.3")

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

    proc_name = proc_obj.get("name") or (
        proc_obj.get("executable", "").split("\\")[-1] if proc_obj.get("executable") else None
    )
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
            "file_hash": sha256,
            "sha256": sha256,
        },
        "parent": {
            "entity_id": parent_obj.get("entity_id"),
            "pid": parent_obj.get("pid"),
            "name": parent_obj.get("name"),
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
