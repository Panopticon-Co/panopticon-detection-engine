"""Host and Entity Risk Scoring Engine (Threat Meter 0-100).

Aggregates individual low/medium/high anomaly events per Host and User.
Raises a composite Host Compromise Incident when accumulated threat points cross the threshold.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from src.alerting.alert import Alert


@dataclass
class RiskEventRecord:
    timestamp: str
    rule_id: str
    rule_name: str
    level: int
    points_added: int
    summary: str


@dataclass
class HostRiskProfile:
    host_id: str
    current_score: int = 0
    max_score_reached: int = 0
    event_timeline: List[RiskEventRecord] = field(default_factory=list)
    has_alerted: bool = False


class EntityRiskScorer:
    """Tracks running risk scores per endpoint to detect slow-and-low APT campaigns."""

    LEVEL_TO_POINTS = {
        # Level -> Risk points
        1: 5, 2: 5, 3: 5, 4: 5,
        5: 10, 6: 10, 7: 15, 8: 15,
        9: 25, 10: 30, 11: 35,
        12: 45, 13: 50, 14: 55, 15: 65, 16: 80,
    }

    def __init__(self, breach_threshold: int = 75):
        self.breach_threshold = breach_threshold
        # Key: host_id -> HostRiskProfile
        self.host_profiles: Dict[str, HostRiskProfile] = {}

    def record_detection(
        self,
        host_id: str,
        rule_id: str,
        rule_name: str,
        level: int,
        timestamp: str,
        summary: str = "",
    ) -> Optional[Alert]:
        """Adds risk points to host profile and returns an Incident Alert if threshold is breached."""
        if host_id not in self.host_profiles:
            self.host_profiles[host_id] = HostRiskProfile(host_id=host_id)

        profile = self.host_profiles[host_id]
        points = self.LEVEL_TO_POINTS.get(level, 10)
        profile.current_score = min(100, profile.current_score + points)
        profile.max_score_reached = max(profile.max_score_reached, profile.current_score)

        record = RiskEventRecord(
            timestamp=timestamp,
            rule_id=rule_id,
            rule_name=rule_name,
            level=level,
            points_added=points,
            summary=summary,
        )
        profile.event_timeline.append(record)

        # Check if threshold crossed and not previously alerted
        if profile.current_score >= self.breach_threshold and not profile.has_alerted:
            profile.has_alerted = True
            return self._generate_host_compromise_alert(profile)

        return None

    def _generate_host_compromise_alert(self, profile: HostRiskProfile) -> Alert:
        evidence = {
            "accumulated_risk_score": f"{profile.current_score} / 100",
            "contributing_events_count": len(profile.event_timeline),
            "threat_timeline": [
                f"[{r.timestamp}] ({r.rule_id}) {r.rule_name} (+{r.points_added} pts)"
                for r in profile.event_timeline
            ],
        }

        # Deterministic id: one host-compromise alert per host per breach, so a
        # replay / restart recognises it instead of emitting a duplicate.
        _key = f"CORR-RISK-001|{profile.host_id}|{profile.current_score}|{len(profile.event_timeline)}"
        return Alert(
            alert_id="RISK-" + hashlib.sha1(_key.encode("utf-8")).hexdigest()[:8].upper(),
            rule_id="CORR-RISK-001",
            title=f"[HOST COMPROMISE THREAT METER] Critical Threat Accumulation on {profile.host_id}",
            description=f"Host risk score breached threshold ({profile.current_score}/100) across {len(profile.event_timeline)} security events.",
            level=15,
            severity="critical",
            confidence=0.97,
            host_id=profile.host_id,
            timestamp=profile.event_timeline[-1].timestamp if profile.event_timeline else datetime.utcnow().isoformat(),
            event_id=None,
            evidence=evidence,
            active_response={
                "action": "ISOLATE_HOST",
                "host_id": profile.host_id,
                "reason": f"Host Threat Meter crossed critical breach threshold ({profile.current_score}/100)",
            },
            mitre_tactic="Initial Access & Execution",
            mitre_technique="T1059",
            compliance=["PCI-DSS_10.6", "NIST_800-53_SI-4"],
            tags=["attack.risk_score", "host_compromise", "threat_meter"],
        )

    def get_host_score(self, host_id: str) -> int:
        return self.host_profiles.get(host_id, HostRiskProfile(host_id=host_id)).current_score
