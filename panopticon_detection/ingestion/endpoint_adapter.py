"""Canonical endpoint records: preserve uncertainty instead of inventing PID joins.

The receiver owns full envelope validation. This adapter independently verifies
process reference digests so standalone engine use cannot launder an invalid
reference into the graph or an executable response recommendation.
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

FAMILIES = {"process", "network", "file", "registry", "image_load"}
# Canonical-only Windows families (data.format windows_sysmon_extended_v1) that the
# engine's 0.5 normalizers and rules already understand under the same names.
EXTENDED_FAMILIES = {"dns", "process_access", "remote_thread"}


def _text(value: Any) -> Any:
    """Exact text, or None for a lossless hex-bytes object (not valid UTF-8)."""
    return value if isinstance(value, str) else None


def _bounded(value: Any) -> Any:
    return _text(value.get("text")) if isinstance(value, dict) else None


def _hex(decimal: Any) -> Any:
    """Canonical decimal-string uint -> the 0x form Sysmon text (and _hex_int) uses."""
    return f"0x{int(decimal):x}" if isinstance(decimal, str) and decimal.isdigit() else None


def _extended_event(raw: dict, payload: dict) -> dict:
    """Engine 0.5 event for a canonical extended family, built from authoritative
    canonical facts. Decimal tokens are converted exactly; nothing is inferred."""
    category = raw["category"]
    process = payload.get("process") or {}
    block = payload.get(category) or {}
    target = block.get("target") or {}
    legacy_target = {"entity_id": target.get("entity_id"), "pid": target.get("pid"),
                     "executable": _text(target.get("executable")), "user": _text(target.get("user"))}
    if category == "process_access":
        family = {"target": legacy_target, "granted_access": _hex(block.get("granted_access")),
                  "call_trace": _bounded(block.get("call_trace"))}
    elif category == "remote_thread":
        family = {"target": legacy_target, "new_thread_id": block.get("new_thread_id"),
                  "start_address": _hex(block.get("start_address")),
                  "start_module": _text(block.get("start_module")),
                  "start_function": _text(block.get("start_function"))}
    else:
        family = {"query_name": _text(block.get("query_name")), "query_status": block.get("query_status"),
                  "query_results": _bounded(block.get("query_results"))}
    provenance = raw["provenance"]
    return {
        "schema_version": "0.5",
        "event": {"id": raw["record_id"], "category": category,
                  "type": (payload.get("event") or {}).get("type"), "timestamp": raw["observed_at"]},
        "source": {"kind": provenance["kind"], "provider": provenance["provider"],
                   "channel": provenance.get("channel"), "record_id": None},
        "agent": {"id": raw["endpoint"]["agent_id"]},
        "host": {"id": raw["endpoint"]["host_id"]},
        "user": {"name": _text(process.get("user"))},
        "process": {"pid": process.get("pid"), "executable": _text(process.get("executable")),
                    "entity_id": process.get("entity_id")},
        category: family,
    }


def verified_reference(reference: Any, endpoint: dict) -> dict | None:
    if reference is None:
        return None
    if not isinstance(reference, dict):
        raise ValueError("process reference must be an object")
    pid = reference.get("observed_pid")
    if type(pid) is not int or not 0 <= pid <= 2**32 - 1:
        raise ValueError("invalid observed PID")
    boot = reference.get("boot_id")
    if boot != endpoint.get("boot_id"):
        raise ValueError("process reference boot scope mismatch")
    if boot is not None and not re.fullmatch(r"boot_[0-9a-f]{64}", boot):
        raise ValueError("invalid boot scope")
    ticks = reference.get("native_creation_ticks")
    if ticks is not None and (
        not isinstance(ticks, str)
        or not re.fullmatch(r"0|[1-9][0-9]{0,19}", ticks)
        or int(ticks) > 2**64 - 1
    ):
        raise ValueError("invalid exact native creation token")
    namespace = reference.get("source_namespace")
    if not isinstance(namespace, str) or not namespace:
        raise ValueError("source namespace required")
    resolution = reference.get("resolution")
    entity_id = reference.get("entity_id")
    host = endpoint.get("host_id")
    if not isinstance(host, str) or not host:
        raise ValueError("host scope required")
    if resolution == "native_exact":
        if boot is None or ticks is None or int(ticks) == 0:
            raise ValueError("native exact reference requires boot and creation token")
        fields = ["native-process-instance-v1", host, boot, str(pid), ticks]
    elif resolution == "source_scoped":
        guid = reference.get("source_guid")
        if not isinstance(guid, str) or not guid:
            raise ValueError("source-scoped reference requires GUID")
        fields = ["source-process-instance-v1", host, boot or "unknown", namespace, str(pid), guid]
    elif resolution in {"unresolved", "native_unscoped"}:
        if entity_id is not None:
            raise ValueError("unresolved reference cannot name an entity")
        return copy.deepcopy(reference)
    else:
        raise ValueError("unknown identity resolution")
    material = "".join(str(len(value.encode("utf-8"))) + ":" + value for value in fields)
    expected = "proc_" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    if entity_id != expected:
        raise ValueError("process identity digest disagrees with exact facts")
    return copy.deepcopy(reference)


class EndpointIngestionAdapter:
    @staticmethod
    def is_endpoint_record(raw: Any) -> bool:
        return isinstance(raw, dict) and raw.get("schema_version") == "1.0" and "kind" in raw

    @staticmethod
    def transform(raw: dict) -> dict:
        if not EndpointIngestionAdapter.is_endpoint_record(raw):
            raise ValueError("canonical endpoint record 1.0 required")
        endpoint = raw["endpoint"]
        subject = verified_reference(raw.get("subject"), endpoint)
        payload = copy.deepcopy(raw["data"])
        kind, category = raw["kind"], raw["category"]
        if kind == "observation" and category in FAMILIES:
            if subject is None:
                raise ValueError("process family requires explicit identity uncertainty")
            if (payload.get("event") or {}).get("category") != category:
                raise ValueError("payload event category contradicts envelope")
            process = payload.get("process") or {}
            if (
                process.get("entity_id") != subject["entity_id"]
                or process.get("pid") != subject["observed_pid"]
                or process.get("start_time_ticks") != subject["native_creation_ticks"]
            ):
                raise ValueError("process payload contradicts authoritative subject")
            out = OfficerIngestionAdapter.transform_officer_event(payload)
        elif kind == "observation" and category in EXTENDED_FAMILIES:
            if subject is None or (payload.get("event") or {}).get("category") != category:
                raise ValueError("extended family requires its subject and matching category")
            if (payload.get("process") or {}).get("entity_id") != subject["entity_id"]:
                raise ValueError("process payload contradicts authoritative subject")
            out = OfficerIngestionAdapter.transform_officer_event(_extended_event(raw, payload))
            target = (payload.get(category) or {}).get("target")
            out["target_reference"] = (
                verified_reference(target.get("identity"), endpoint) if target else None
            )
        elif kind == "observation" and category == "process_stop":
            if subject is None:
                raise ValueError("process stop requires its subject")
            # Closes the canonical instance's interval; a stop adds no ancestry.
            out = {"event_type": "process_terminate", "process": {}, "parent": {}}
        else:
            # State/health/new observation domains remain available to rules
            # under their own vocabulary and retain their entire domain payload.
            out = {"event_type": f"endpoint_{kind}_{category}", "process": {}, "parent": {}}
        out.update(
            schema_version="1.0",
            identity_model="endpoint_record_v1",
            record_kind=kind,
            telemetry_category=category,
            event_id=raw["record_id"],
            timestamp=raw["observed_at"],
            host_id=endpoint["host_id"],
            endpoint=copy.deepcopy(endpoint),
            provenance=copy.deepcopy(raw["provenance"]),
            process_reference=subject,
            endpoint_data=payload,
            _raw_endpoint_record=copy.deepcopy(raw),
        )
        proc = out["process"]
        out["host"] = {**out.get("host", {}), "id": endpoint["host_id"]}
        out["agent"] = {**out.get("agent", {}), "id": endpoint["agent_id"]}
        proc["entity_id"] = subject["entity_id"] if subject else None
        proc["process_guid"] = proc["entity_id"]
        proc["pid"] = subject["observed_pid"] if subject else None
        # Integer is internal Python-only: conversion is exact. Never recover a
        # native target from a source-scoped GUID, PID or wall-clock timestamp.
        proc["start_time_ticks"] = (
            int(subject["native_creation_ticks"])
            if subject and subject["resolution"] == "native_exact"
            else None
        )
        parent = (payload.get("process") or {}).get("parent") or {}
        parent_ref = verified_reference(parent.get("identity"), endpoint)
        out["parent_reference"] = parent_ref
        out["parent"]["entity_id"] = parent_ref["entity_id"] if parent_ref else None
        out["parent"]["process_guid"] = out["parent"]["entity_id"]
        return out
