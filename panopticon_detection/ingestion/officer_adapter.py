"""Ingestion adapter for Officer agent events (Panopticon schema 0.1-0.4).

Recognises agent events and hands them to the shared normalizer; the public
methods here are the entry points the CLI, live stream and manager call.
"""

import json
from typing import Any, Dict, Optional

from panopticon_detection.ingestion import telemetry as _telemetry


class OfficerIngestionAdapter:
    """Recognises Officer events and normalizes them -- one contract, five families."""

    SCHEMA_VERSION = "0.2"
    # 0.4 is the Linux agent's schema version (see
    # panopticon-agent/schema/event.schema.json's enum and
    # manager/routers/ingest.py's _SUPPORTED_SCHEMA_VERSIONS) -- its wire
    # shape is identical to 0.2/0.3's (same event/source/agent/host/user/
    # process envelope), so it is safe to accept explicitly here rather than
    # relying on the duck-typing fallback below to smuggle it through.
    SUPPORTED_SCHEMA_VERSIONS = ("0.1", "0.2", "0.3", "0.4")

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
        """Translate an Officer event into the engine's internal shape.

        Every family, process included, goes through the one normalizer in
        :mod:`panopticon_detection.ingestion.telemetry`. There used to be a
        second, hand-kept process path here; the two drifted (one carried
        ``start_time_ticks`` and ``user_sid``, the other did not).
        """
        return _telemetry.normalize(raw)

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
