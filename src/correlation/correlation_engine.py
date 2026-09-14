"""Multi-Event Correlation Engine.

Correlates individual, multi-stage telemetry events across sliding time windows
and process hierarchies to detect complex attack chains (e.g. Office -> PowerShell -> Network Outbound).
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from src.alerting.alert import Alert
from src.evaluator.engine import DetectionResult


def _parse_ts(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp tolerantly. Returns ``datetime.min`` when the
    value is missing or unparseable, so callers can treat that as 'unknown' and
    fail open rather than dropping a correlation."""
    if not value:
        return datetime.min
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return datetime.min


@dataclass
class CorrelationRule:
    """Defines a multi-stage correlation sequence."""
    id: str
    name: str
    description: str
    stages: List[str]  # List of matching Rule IDs in expected sequence e.g. ["DET-PROC-001", "DET-NET-001"]
    time_window_seconds: int = 60
    severity: str = "critical"
    confidence: float = 0.95
    mitre_tactic: str = "Execution"
    mitre_technique: str = "T1059"


@dataclass
class CorrelatedIncident:
    """Represents a composite multi-stage attack detection."""
    incident_id: str
    correlation_rule_id: str
    title: str
    severity: str
    confidence: float
    host_id: str
    timestamp: str
    stages_matched: List[str]
    composite_evidence: List[Dict[str, Any]]
    mitre_technique: str
    mitre_tactic: str

    def to_alert(self) -> Alert:
        evidence_summary: Dict[str, Any] = {
            "attack_chain_stages": " -> ".join(self.stages_matched),
            "stage_count": len(self.stages_matched),
        }
        for i, ev in enumerate(self.composite_evidence, start=1):
            evidence_summary[f"stage_{i}_rule"] = ev.get("rule_id")
            for k, v in ev.get("evidence", {}).items():
                evidence_summary[f"stage_{i}_{k}"] = v

        return Alert(
            alert_id=self.incident_id,
            rule_id=self.correlation_rule_id,
            title=f"[CORRELATED INCIDENT] {self.title}",
            description=f"Multi-stage attack chain detected ({len(self.stages_matched)} correlated stages).",
            level=16,
            severity=self.severity,
            confidence=self.confidence,
            host_id=self.host_id,
            timestamp=self.timestamp,
            event_id=None,
            evidence=evidence_summary,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            tags=["attack.correlation", "multi-stage-killchain"],
        )


class CorrelationEngine:
    """Maintains active sliding-window state buffers and checks correlation rules."""

    def __init__(self, correlation_rules: Optional[List[CorrelationRule]] = None):
        self.correlation_rules = correlation_rules or self._default_correlation_rules()
        # Key: (host_id, process_guid or lineage) -> List[Dict] with timestamp and rule_id
        self.alert_history: Dict[str, List[Dict[str, Any]]] = {}

    def ingest_detection(self, detection: DetectionResult) -> List[CorrelatedIncident]:
        """Ingests an atomic detection result and checks for multi-stage correlation matches."""
        rule_id = detection.rule.id
        event = detection.event
        host_id = event.get("host_id", "UNKNOWN")
        proc = event.get("process", {}) or {}

        # Bucket by PID, not process.entity_id / process_guid. The agent derives
        # a *different* entity_id for a process's start event (process-entity-v2:
        # host+pid+start_time) than for its later network/file/registry events
        # (process-context-v1: host+pid+ProcessGuid) -- see panopticon-agent
        # include/.../core/entity_id.hpp -- so an entity_id key can never join the
        # stages of a live same-process chain. The PID is identical across those
        # families. Fall back to entity_id then host for legacy/synthetic events
        # that carry no pid.
        #
        # This joins *same-process* multi-stage chains (certutil -> its own
        # egress; powershell -> its own outbound connection), which is the common
        # EDR shape. Cross-process campaigns (recon in one PID, vssadmin in
        # another) need ProcessTree lineage, not this key -- future work, and the
        # real long-term fix is one unified process GUID across all agent
        # telemetry families.
        token = proc.get("pid")
        if token is None:
            token = proc.get("process_guid") or "HOST"
        key = f"{host_id}:{token}"

        ts_str = event.get("timestamp", datetime.now().isoformat())

        record = {
            "rule_id": rule_id,
            "timestamp_str": ts_str,
            "ts": _parse_ts(ts_str),
            "evidence": detection.matched_evidence,
            "event": event,
        }

        bucket = self.alert_history.setdefault(key, [])
        bucket.append(record)

        # Bound memory: a long-running engine would otherwise accumulate every
        # detection forever. Keep only what could still complete the widest
        # correlation window.
        if record["ts"] != datetime.min:
            widest = max(
                (r.time_window_seconds for r in self.correlation_rules), default=60
            )
            horizon = record["ts"] - timedelta(seconds=widest)
            self.alert_history[key] = [
                r for r in bucket if r["ts"] == datetime.min or r["ts"] >= horizon
            ]

        # Check all correlation rules
        incidents: List[CorrelatedIncident] = []
        for corr_rule in self.correlation_rules:
            incident = self._evaluate_correlation_rule(corr_rule, key, host_id)
            if incident:
                incidents.append(incident)

        return incidents

    def _evaluate_correlation_rule(
        self, corr_rule: CorrelationRule, key: str, host_id: str
    ) -> Optional[CorrelatedIncident]:
        history = self.alert_history.get(key, [])
        if len(history) < len(corr_rule.stages):
            return None

        # Look for an ordered subsequence of the history matching the stages.
        stage_idx = 0
        matched_records = []
        for rec in history:
            if rec["rule_id"] == corr_rule.stages[stage_idx]:
                matched_records.append(rec)
                stage_idx += 1
                if stage_idx == len(corr_rule.stages):
                    break

        if stage_idx == len(corr_rule.stages):
            # Enforce the sliding window: first and last matched stage must fall
            # within time_window_seconds. Fail open if either timestamp is
            # unparseable rather than silently dropping the incident.
            first_ts = matched_records[0]["ts"]
            last_ts = matched_records[-1]["ts"]
            if (
                first_ts != datetime.min
                and last_ts != datetime.min
                and (last_ts - first_ts).total_seconds() > corr_rule.time_window_seconds
            ):
                return None

            # All stages found in sequence and within the window.
            incident = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                correlation_rule_id=corr_rule.id,
                title=corr_rule.name,
                severity=corr_rule.severity,
                confidence=corr_rule.confidence,
                host_id=host_id,
                timestamp=matched_records[-1]["timestamp_str"],
                stages_matched=corr_rule.stages,
                composite_evidence=matched_records,
                mitre_tactic=corr_rule.mitre_tactic,
                mitre_technique=corr_rule.mitre_technique,
            )
            # Clear or prune matched history so it doesn't trigger repeatedly
            self.alert_history[key] = [r for r in history if r not in matched_records]
            return incident

        return None

    @staticmethod
    def _default_correlation_rules() -> List[CorrelationRule]:
        return [
            CorrelationRule(
                id="CORR-001",
                name="Office Document Spawned PowerShell Establishing External Network Connection",
                description="Detects Office spawning PowerShell followed immediately by an outbound network connection.",
                stages=["DET-PROC-001", "DET-NET-001"],
                time_window_seconds=60,
                severity="critical",
                confidence=0.98,
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
            ),
            CorrelationRule(
                id="CORR-002",
                name="Reconnaissance Followed by Ransomware Shadow Copy Deletion",
                description="Detects initial system reconnaissance discovery followed by shadow copy wiping.",
                stages=["DET-PROC-008", "DET-PROC-006"],
                time_window_seconds=60,
                severity="critical",
                confidence=0.95,
                mitre_tactic="Impact",
                mitre_technique="T1490",
            ),
            CorrelationRule(
                id="CORR-003",
                name="LOLBAS Certutil Download Followed by Outbound Network Egress",
                description=(
                    "certutil.exe is invoked to download a remote file and the "
                    "same process then makes an outbound network connection -- a "
                    "single ships-with-Windows binary performing ingress tool "
                    "transfer and command-and-control."
                ),
                stages=["DET-PROC-003", "DET-NET-006"],
                time_window_seconds=60,
                severity="critical",
                confidence=0.95,
                mitre_tactic="Command and Control",
                mitre_technique="T1105",
            ),
        ]
