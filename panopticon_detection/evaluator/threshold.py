"""Threshold and Frequency-based Detection Engine.

Implements Wazuh-style <frequency> and <timeframe> rules for detecting
brute force attacks, rapid ransomware file encryption, and port scanning.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from panopticon_detection.evaluator.matcher import extract_field


@dataclass
class ThresholdRule:
    """Defines a frequency threshold rule."""
    id: str
    name: str
    description: str
    event_type: str
    frequency: int  # Number of events needed to trigger (e.g. 5)
    timeframe_seconds: int  # Time window (e.g. 10s)
    group_by: List[str]  # e.g. ["host_id", "process.process_guid"]
    level: int = 14  # Wazuh Level (0-16)
    severity: str = "critical"
    confidence: float = 0.95
    active_response: str = "ISOLATE_HOST"
    mitre_tactic: str = "Impact"
    mitre_technique: str = "T1486"


@dataclass
class ThresholdMatch:
    """Result when a threshold rule triggers."""
    rule: ThresholdRule
    host_id: str
    event_count: int
    timeframe_seconds: int
    trigger_event: Dict[str, Any]
    evidence: Dict[str, Any]


class ThresholdEngine:
    """Tracks sliding window event counts grouped by host and process."""

    def __init__(self, rules: Optional[List[ThresholdRule]] = None):
        self.rules = rules or self._default_rules()
        # Key: (rule_id, group_key) -> deque of float timestamps
        self.buckets: Dict[str, deque] = {}

    def ingest_event(self, event: Dict[str, Any]) -> List[ThresholdMatch]:
        """Evaluates an incoming event against threshold rules."""
        event_type = event.get("event_type")
        if not event_type:
            return []

        matches: List[ThresholdMatch] = []
        now_ts = self._parse_timestamp(event.get("timestamp"))

        for rule in self.rules:
            if rule.event_type != event_type:
                continue

            # Build group key
            key_parts = [rule.id]
            for f in rule.group_by:
                val = extract_field(event, f)
                key_parts.append(str(val or "NONE"))
            group_key = ":".join(key_parts)

            if group_key not in self.buckets:
                self.buckets[group_key] = deque()

            queue = self.buckets[group_key]
            queue.append(now_ts)

            # Evict timestamps outside the timeframe
            cutoff = now_ts - rule.timeframe_seconds
            while queue and queue[0] < cutoff:
                queue.popleft()

            # Check if threshold reached
            if len(queue) >= rule.frequency:
                # Trigger threshold alert!
                host_id = event.get("host_id", "UNKNOWN")
                evidence = {
                    "event_frequency": len(queue),
                    "time_window_seconds": rule.timeframe_seconds,
                    "target_process": extract_field(event, "process.name"),
                    "process_guid": extract_field(event, "process.process_guid"),
                    "last_action_file": extract_field(event, "file.path"),
                }
                match = ThresholdMatch(
                    rule=rule,
                    host_id=host_id,
                    event_count=len(queue),
                    timeframe_seconds=rule.timeframe_seconds,
                    trigger_event=event,
                    evidence=evidence,
                )
                matches.append(match)
                # Clear queue so we don't spam duplicate alerts on every consecutive event
                queue.clear()

        return matches

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> float:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                # ISO format parse
                clean_ts = ts_val.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _default_rules() -> List[ThresholdRule]:
        return [
            ThresholdRule(
                id="DET-FREQ-001",
                name="Rapid Mass File Modification / Encryption (Ransomware Behavior)",
                description="Detects a process modifying or writing multiple files within a short time window.",
                event_type="file_create",
                frequency=5,
                timeframe_seconds=10,
                group_by=["host_id", "process.process_guid"],
                level=14,
                severity="critical",
                confidence=0.96,
                active_response="ISOLATE_HOST",
                mitre_tactic="Impact",
                mitre_technique="T1486",
            ),
        ]
