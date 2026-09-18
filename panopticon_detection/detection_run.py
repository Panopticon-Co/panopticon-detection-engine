"""Per-event detection dispatch.

One event flows through here exactly once, in a fixed order:

1. **Record it.** :class:`EventGraphBuilder` turns the event into a provenance
   edge and keeps the process registry current. This happens *before* rule
   evaluation so that ancestry conditions on the event's own process resolve.
2. **Evaluate it.** Atomic rules run against the event.
3. **Tag it.** Each match is written onto the edge the event created, so the
   detection becomes part of the graph rather than a parallel stream.
4. **Search from it.** A match on a terminal tactic anchors a backward
   traversal, which is how multi-stage campaigns are found.
5. **Behavioral analytics.** Ransomware bursts, C2 beaconing, port scans and
   frequency thresholds run as independent detectors on the same event.

``DetectionRun`` holds the constructed engines plus running counters and exposes
:meth:`process_event`. Both the CLI and the manager's detection worker drive
that one method, so their behaviour cannot drift apart.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from panopticon_detection.alerting.active_response import ActiveResponseEngine
from panopticon_detection.alerting.alert import Alert
from panopticon_detection.alerting.formatter import AlertFormatter
from panopticon_detection.provenance.tagging import tag_from_detection


def _print_alert(alert: Alert, fmt: str, story_mode: bool = False) -> None:
    if story_mode:
        return
    if fmt == "console":
        print(AlertFormatter.to_console(alert))
    elif fmt == "json":
        print(AlertFormatter.to_json(alert))
    elif fmt == "ndjson":
        print(AlertFormatter.to_ndjson(alert))


class DetectionRun:
    """Stateful driver that evaluates one event at a time against every engine."""

    def __init__(
        self,
        *,
        graph_builder,
        evaluator,
        threshold_engine,
        campaign_detector,
        risk_scorer,
        beacon_detector,
        port_scan_detector,
        ransomware_shield,
        emit: Optional[Callable[[Alert], None]] = None,
    ) -> None:
        self.graph_builder = graph_builder
        self.evaluator = evaluator
        self.threshold_engine = threshold_engine
        self.campaign_detector = campaign_detector
        self.risk_scorer = risk_scorer
        self.beacon_detector = beacon_detector
        self.port_scan_detector = port_scan_detector
        self.ransomware_shield = ransomware_shield

        self._emit_cb = emit or (lambda _alert: None)

        # Kept for story mode and the end-of-run summary.
        self.all_alerts: List[Alert] = []

        self.events_count = 0
        self.atomic_alerts_count = 0
        self.threshold_alerts_count = 0
        self.beacon_alerts_count = 0
        self.port_scan_alerts_count = 0
        self.ransomware_shield_alerts = 0
        self.campaign_alerts_count = 0
        self.risk_breach_alerts_count = 0
        self.active_responses_count = 0

    # ------------------------------------------------------------------
    def _emit(self, alert: Alert, produced: List[Alert]) -> None:
        produced.append(alert)
        self.all_alerts.append(alert)
        if alert.active_response:
            self.active_responses_count += 1
        self._emit_cb(alert)

    # ------------------------------------------------------------------
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Run every detector against one event; return the alerts produced."""
        produced: List[Alert] = []
        self.events_count += 1
        host_id = event.get("host_id") or "UNKNOWN_HOST"
        ts = event.get("timestamp", "")

        # 1. Record the event in the provenance graph first, so a rule asking
        #    about this process's ancestry can resolve it.
        edge = self.graph_builder.apply(event)

        # 2-4. Atomic rules -> tags on the edge -> campaign search.
        for result in self.evaluator.evaluate_event(event):
            self.atomic_alerts_count += 1
            self._emit(Alert.from_detection_result(result), produced)

            tag = tag_from_detection(result)
            if edge is not None:
                edge.tags.append(tag)
                campaign = self.campaign_detector.on_tagged_edge(edge, tag)
                if campaign is not None:
                    self.campaign_alerts_count += 1
                    self._emit(campaign.to_alert(), produced)

            risk_incident = self.risk_scorer.record_detection(
                host_id=host_id,
                rule_id=result.rule.id,
                rule_name=result.rule.name,
                level=result.rule.level,
                timestamp=ts,
                summary=result.rule.description,
            )
            if risk_incident:
                self.risk_breach_alerts_count += 1
                self._emit(risk_incident, produced)

        # 5. Behavioral analytics. These are independent detectors rather than
        #    rule matches, so they emit directly instead of tagging an edge.
        self._run_ransomware_shield(event, ts, produced)
        self._run_beacon_detector(event, ts, produced)
        self._run_port_scan_detector(event, ts, produced)
        self._run_threshold_engine(event, ts, produced)

        return produced

    # ------------------------------------------------------------------
    def _run_ransomware_shield(self, event, ts, produced) -> None:
        match = self.ransomware_shield.inspect_file_event(event)
        if not match:
            return
        self.ransomware_shield_alerts += 1

        # QUARANTINE_FILE rather than the blanket ISOLATE_HOST this used to
        # request: the shield knows exactly which file tripped it, and the
        # narrower action is the one an analyst can approve quickly.
        # translate_recommendation fails closed if the path is missing.
        self._emit(
            Alert(
                alert_id=f"ALT-RANS-{self.events_count}",
                rule_id="DET-RANS-001",
                title=f"[RANSOMWARE SHIELD] {match.threat_type}",
                description=(
                    f"Process '{match.process_name}' (PID {match.pid}) breached a "
                    f"ransomware protection tripwire across "
                    f"{match.affected_files_count} file(s)."
                ),
                level=16,
                severity="critical",
                confidence=match.confidence,
                host_id=match.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=match.evidence,
                active_response=_action_or_none(
                    ActiveResponseEngine.resolve_action(
                        level=16,
                        event=event,
                        custom_action="QUARANTINE_FILE",
                        reason=f"Ransomware tripwire: {match.threat_type}",
                    )
                ),
                mitre_tactic="Impact",
                mitre_technique="T1486",
                tags=["attack.impact", "ransomware_shield", "canary_tripwire"],
            ),
            produced,
        )

    def _run_beacon_detector(self, event, ts, produced) -> None:
        match = self.beacon_detector.ingest_connection(event)
        if not match:
            return
        self.beacon_alerts_count += 1

        # No active_response: the closed 7-action contract has no per-IP block,
        # and substituting a whole-host isolation for a narrow egress block is
        # exactly the opportunistic mapping the response contract forbids. The
        # alert still reaches the analyst; it simply recommends nothing.
        self._emit(
            Alert(
                alert_id=f"ALT-BCN-{self.events_count}",
                rule_id="DET-NET-004",
                title="[C2 BEACON] Periodic outbound heartbeat detected",
                description=(
                    f"Consistent beaconing to {match.destination_ip}:"
                    f"{match.destination_port} (mean interval "
                    f"{match.mean_interval_seconds}s, CV "
                    f"{match.coefficient_of_variation})."
                ),
                level=14,
                severity="critical",
                confidence=match.confidence,
                host_id=match.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=match.evidence,
                active_response=None,
                mitre_tactic="Command and Control",
                mitre_technique="T1071.001",
                tags=["attack.command_and_control", "c2_beaconing"],
            ),
            produced,
        )

    def _run_port_scan_detector(self, event, ts, produced) -> None:
        for match in self.port_scan_detector.ingest_connection(event):
            self.port_scan_alerts_count += 1
            self._emit(
                Alert(
                    alert_id=f"ALT-SCAN-{self.events_count}",
                    rule_id="DET-NET-005",
                    title=f"[RECONNAISSANCE] {match.scan_type}",
                    description=(
                        f"Host initiated rapid network probes "
                        f"({match.target_summary}) within "
                        f"{match.time_window_seconds}s."
                    ),
                    level=12,
                    severity="high",
                    confidence=0.92,
                    host_id=match.host_id,
                    timestamp=ts,
                    event_id=event.get("event_id"),
                    evidence=match.evidence,
                    active_response=None,
                    mitre_tactic="Discovery",
                    mitre_technique="T1046",
                    tags=["attack.discovery", "port_scan"],
                ),
                produced,
            )

    def _run_threshold_engine(self, event, ts, produced) -> None:
        for match in self.threshold_engine.ingest_event(event):
            self.threshold_alerts_count += 1
            rule = match.rule
            self._emit(
                Alert(
                    alert_id=f"ALT-TH-{rule.id}",
                    rule_id=rule.id,
                    title=f"[FREQUENCY THRESHOLD] {rule.name}",
                    description=rule.description,
                    level=rule.level,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    host_id=match.host_id,
                    timestamp=ts,
                    event_id=event.get("event_id"),
                    evidence=match.evidence,
                    active_response=_action_or_none(
                        ActiveResponseEngine.resolve_action(
                            level=rule.level,
                            event=event,
                            custom_action=rule.active_response,
                            reason=(
                                f"Threshold rule [{rule.id}]: {match.event_count} "
                                f"events in {match.timeframe_seconds}s"
                            ),
                        )
                    ),
                    # ThresholdRule is a plain dataclass with flat
                    # mitre_tactic/mitre_technique -- not the pydantic Rule's
                    # nested `mitre` object. They are different types.
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    tags=["threshold_trigger"],
                ),
                produced,
            )


def _action_or_none(action) -> Optional[Dict[str, Any]]:
    return action.to_dict() if action else None
