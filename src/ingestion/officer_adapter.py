"""Panopticon Schema 0.2 Ingestion Adapter for C++ Officer Agent Telemetry.

Translates live C++ Officer agent JSON events (Schema 0.2 with source provenance,
deterministic SHA-256 entity IDs, and enriched metadata) into eyedetect's native
detection engine representation.
"""

import json
from typing import Any, Dict, Optional

from src.ingestion import telemetry as _telemetry


class OfficerIngestionAdapter:
    """Adapts C++ Officer Panopticon events (Schema 0.1 / 0.2 / 0.3) into eyedetect's pipeline.

    Process telemetry keeps its original, well-tested transform. The non-process
    telemetry families introduced in Schema 0.3 (network / file / registry /
    image_load) are dispatched to :mod:`src.ingestion.telemetry`, which shares
    the same identity/context scaffolding -- one contract, five families.
    """

    SCHEMA_VERSION = "0.2"
    SUPPORTED_SCHEMA_VERSIONS = ("0.1", "0.2", "0.3")

    @classmethod
    def is_officer_event(cls, raw: Dict[str, Any]) -> bool:
        """Checks if the incoming JSON dictionary conforms to Panopticon Schema 0.1-0.3."""
        if not isinstance(raw, dict):
            return False
        if raw.get("schema_version") in cls.SUPPORTED_SCHEMA_VERSIONS and (
            "event" in raw or "source" in raw
        ):
            return True
        # Duck-typing check for Panopticon event structure
        return "event" in raw and "process" in raw and "source" in raw

    @classmethod
    def transform_officer_event(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Performs lossless translation of an Officer JSON event into the engine's internal format.
        
        Preserves all raw source facts while normalizing field aliases so that all 84+ detection
        rules can evaluate conditions with O(1) performance.
        """
        # Schema 0.3: non-process telemetry families dispatch to the shared
        # family normalizer. Process telemetry (0.1/0.2/0.3) keeps this path.
        category = (raw.get("event", {}) or {}).get("category", "process")
        if category in _telemetry.TELEMETRY_FAMILIES and category != "process":
            return _telemetry.normalize(raw)

        event_obj = raw.get("event", {})
        proc_obj = raw.get("process", {})
        parent_obj = proc_obj.get("parent", {})
        user_obj = raw.get("user", {})
        host_obj = raw.get("host", {})
        source_obj = raw.get("source", {})
        agent_obj = raw.get("agent", {})

        # 1. Synthesize canonical event_type
        category = event_obj.get("category", "process")
        etype = event_obj.get("type", "start")
        if category == "process" and etype in ("start", "create"):
            event_type = "process_create"
        elif category == "process" and etype in ("stop", "terminate"):
            event_type = "process_terminate"
        else:
            event_type = f"{category}_{etype}"

        # 2. Extract and format user account
        user_name = user_obj.get("name") if isinstance(user_obj, dict) else None
        domain = user_obj.get("domain") if isinstance(user_obj, dict) else None
        user_sid = user_obj.get("sid") if isinstance(user_obj, dict) else None

        if domain and user_name:
            full_user = f"{domain}\\{user_name}"
        else:
            full_user = user_name or ""

        # 3. Extract process entity ID, executable name, command line, and SHA-256 hash
        proc_name = proc_obj.get("name") or (proc_obj.get("executable", "").split("\\")[-1] if proc_obj.get("executable") else None)
        parent_name = parent_obj.get("name") or (parent_obj.get("executable", "").split("\\")[-1] if parent_obj.get("executable") else None)

        sha256_hash = None
        if isinstance(proc_obj.get("hash"), dict):
            sha256_hash = proc_obj.get("hash", {}).get("sha256")
        elif "sha256" in proc_obj:
            sha256_hash = proc_obj.get("sha256")

        host_id = host_obj.get("id") or host_obj.get("hostname") or raw.get("host_id", "OFFICER-ENDPOINT")

        # 4. Construct unified internal event dictionary
        normalized: Dict[str, Any] = {
            "schema_version": raw.get("schema_version", cls.SCHEMA_VERSION),
            "event_id": event_obj.get("id", f"evt_{raw.get('timestamp', '')}"),
            "timestamp": event_obj.get("timestamp") or raw.get("timestamp", ""),
            "event_type": event_type,
            "host_id": host_id,
            "source": {
                "kind": source_obj.get("kind", "unknown"),
                "provider": source_obj.get("provider", ""),
                "channel": source_obj.get("channel"),
                "record_id": source_obj.get("record_id"),
            },
            "agent": {
                "id": agent_obj.get("id", ""),
                "version": agent_obj.get("version", ""),
            },
            "host": {
                "id": host_obj.get("id", host_id),
                "hostname": host_obj.get("hostname", host_id),
                "os": host_obj.get("os", {}),
            },
            "user": {
                "name": user_name,
                "domain": domain,
                "sid": user_sid,
                "full": full_user,
            },
            "process": {
                "entity_id": proc_obj.get("entity_id"),
                "process_guid": proc_obj.get("entity_id"),  # Alias for ProcessTree tracking
                "pid": proc_obj.get("pid"),
                "ppid": parent_obj.get("pid"),
                "name": proc_name,
                "executable": proc_obj.get("executable"),
                "command_line": proc_obj.get("command_line", ""),
                "user": full_user,
                "user_sid": user_sid,
                "file_hash": sha256_hash,
                "sha256": sha256_hash,
            },
            "parent": {
                "entity_id": parent_obj.get("entity_id"),
                "process_guid": parent_obj.get("entity_id"),
                "pid": parent_obj.get("pid"),
                "name": parent_name,
            },
            "file": {
                "path": proc_obj.get("executable"),
                "hash": sha256_hash,
            },
            # Retain original raw payload for zero-loss forensic auditing
            "_raw_officer_event": raw,
        }

        return normalized

    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """Parses a single JSON line from the Officer agent stream."""
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            return None

        try:
            raw = json.loads(clean_line)
            if not isinstance(raw, dict):
                return None

            if cls.is_officer_event(raw):
                return cls.transform_officer_event(raw)
            return raw
        except json.JSONDecodeError:
            return None
