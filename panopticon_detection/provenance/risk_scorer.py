"""Host and Entity Risk Scoring Engine (Threat Meter 0-100).

Aggregates individual low/medium/high anomaly events per Host and User.
Raises a composite Host Compromise Incident when accumulated threat points cross the threshold.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from panopticon_detection.alerting.alert import Alert


def _parse_ts(value: Any) -> Optional[datetime]:
    """Best-effort ISO-8601 parse; ``None`` means "cannot decay from this"."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


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
    # Event-time of the most recent contributing detection, used for decay.
    last_seen: Optional[datetime] = None


class EntityRiskScorer:
    """Tracks running risk scores per endpoint to detect slow-and-low APT campaigns."""

    LEVEL_TO_POINTS = {
        # Level -> Risk points
        1: 5, 2: 5, 3: 5, 4: 5,
        5: 10, 6: 10, 7: 15, 8: 15,
        9: 25, 10: 30, 11: 35,
        12: 45, 13: 50, 14: 55, 15: 65, 16: 80,
    }

    # A host's score halves over this span with no new detections. Without
    # decay the meter only ever rises, so it reports a host's *history* rather
    # than its current state -- and once it alerted, it never alerted again.
    DEFAULT_HALF_LIFE_SECONDS = 3600.0

    def __init__(
        self,
        breach_threshold: int = 75,
        half_life_seconds: float = DEFAULT_HALF_LIFE_SECONDS,
        rearm_ratio: float = 0.5,
    ):
        self.breach_threshold = breach_threshold
        self.half_life_seconds = half_life_seconds
        # Once a host has alerted it stays latched until its decayed score falls
        # back below this fraction of the threshold. The hysteresis stops a host
        # hovering at the boundary from emitting an alert on every detection.
        self.rearm_threshold = breach_threshold * rearm_ratio
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
        self._decay(profile, timestamp)

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

        # Re-arm once the host has quietened down, so a second campaign on the
        # same host is not silently swallowed by the first one's latch.
        if profile.has_alerted and profile.current_score < self.rearm_threshold:
            profile.has_alerted = False

        if profile.current_score >= self.breach_threshold and not profile.has_alerted:
            profile.has_alerted = True
            return self._generate_host_compromise_alert(profile)

        return None

    def _decay(self, profile: "HostRiskProfile", timestamp: str) -> None:
        """Apply exponential decay for the quiet time since the last detection.

        Uses the event's own timestamp rather than wall-clock, so a replay of
        historical telemetry decays exactly as the live run did.
        """
        now = _parse_ts(timestamp)
        if now is None:
            return
        if profile.last_seen is not None and now > profile.last_seen:
            elapsed = (now - profile.last_seen).total_seconds()
            if self.half_life_seconds > 0:
                profile.current_score = int(
                    profile.current_score * (0.5 ** (elapsed / self.half_life_seconds))
                )
        profile.last_seen = now

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
