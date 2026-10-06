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
