"""Per-event detection dispatch, factored out of ``src/main.py``.

``main.py`` historically ran all of this inline in one ``for event in stream``
loop and only wrote alerts after the loop finished. V2 needs the *same* logic
callable one event at a time so the reliable pipeline (queue -> spool -> retry)
can drive it and persist alerts incrementally.

``DetectionRun`` holds the already-constructed detection subsystems (built in
``main.py`` so existing ``patch("src.main.<Engine>")`` test seams keep working)
plus the running counters, and exposes :meth:`process_event`. The legacy loop
and the V2 pipeline both call that one method, so their behaviour cannot drift.

Nothing about detection semantics changed here -- sections A-G are the original
code, with ``all_generated_alerts.append(x)`` + ``_print_alert(x)`` replaced by
a single ``self._emit(x)`` and the local counters promoted to attributes.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from src.alerting.active_response import ActiveResponseEngine
from src.alerting.alert import Alert
from src.alerting.formatter import AlertFormatter


def _print_alert(alert: Alert, fmt: str, story_mode: bool = False) -> None:
    if story_mode:
        return
    if fmt == "console":
        print(AlertFormatter.to_console(alert))
    elif fmt == "json":
        print(AlertFormatter.to_json(alert))
    elif fmt == "ndjson":
        print(AlertFormatter.to_ndjson(alert))


def _print_remediation(report, story_mode: bool = False) -> None:
    if story_mode:
        return
    print("  \033[92m⚡ [AUTO-FIX APPLIED / SYSTEM RESTORED]\033[0m")
    for act in report.actions_executed:
        print(f"      -> Action : {act.action_type:<28} | Target: {act.target_entity} | Status: {act.status}")
    print("=" * 80)


class DetectionRun:
    """Stateful driver that evaluates one event at a time against every engine."""

    def __init__(
        self,
        *,
        evaluator,
        threshold_engine,
        correlation_engine,
        risk_scorer,
        beacon_detector,
        port_scan_detector,
        ransomware_shield,
        identity_engine,
        cloud_engine,
        enterprise_graph,
        remediation_engine,
        auto_remediate: bool = True,
        emit: Optional[Callable[[Alert], None]] = None,
        emit_remediation: Optional[Callable[[Any], None]] = None,
    ) -> None:
        self.evaluator = evaluator
        self.threshold_engine = threshold_engine
        self.correlation_engine = correlation_engine
        self.risk_scorer = risk_scorer
        self.beacon_detector = beacon_detector
        self.port_scan_detector = port_scan_detector
        self.ransomware_shield = ransomware_shield
        self.identity_engine = identity_engine
        self.cloud_engine = cloud_engine
        self.enterprise_graph = enterprise_graph
        self.remediation_engine = remediation_engine
        self.auto_remediate = auto_remediate

        self._emit_cb = emit or (lambda _alert: None)
        self._emit_remediation_cb = emit_remediation or (lambda _report: None)

        # Kept for story mode and the legacy end-of-run summary.
        self.all_alerts: List[Alert] = []

        # counters (were function locals in main.main())
        self.events_count = 0
        self.atomic_alerts_count = 0
        self.threshold_alerts_count = 0
        self.beacon_alerts_count = 0
        self.port_scan_alerts_count = 0
        self.ransomware_shield_alerts = 0
        self.identity_threat_alerts = 0
        self.cloud_threat_alerts = 0
        self.enterprise_campaign_alerts = 0
        self.incident_alerts_count = 0
        self.risk_breach_alerts_count = 0
        self.active_responses_count = 0
        self.remediations_executed = 0

    # ------------------------------------------------------------------
    def _emit(self, alert: Alert, produced: List[Alert]) -> None:
        produced.append(alert)
        self.all_alerts.append(alert)
        self._emit_cb(alert)

    def _emit_remediation(self, report) -> None:
        self._emit_remediation_cb(report)

    # ------------------------------------------------------------------
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Run every detection engine against one event; return alerts produced.

        Side effects (remediation bookkeeping, enterprise graph, risk meter,
        correlation state) are identical to the original inline loop.
        """
        produced: List[Alert] = []
        self.events_count += 1
        host_id = event.get("host_id") or event.get("cloud", {}).get("account_id") or "UNKNOWN_HOST"
        ts = event.get("timestamp", "")

        # A. Atomic & Threat Intel Rules
        results = self.evaluator.evaluate_event(event)
        for res in results:
            self.atomic_alerts_count += 1
            alert = Alert.from_detection_result(res)
            self._emit(alert, produced)

            if alert.active_response:
                self.active_responses_count += 1

            dest_host = event.get("network", {}).get("destination_ip") or event.get("target_host")
            if dest_host:
                campaign = self.enterprise_graph.record_attack_step(
                    source_id=host_id,
                    source_type="ENDPOINT",
                    target_id=dest_host,
                    target_type="ENDPOINT",
                    pivot_mechanism=res.rule.name,
                    rule_id=res.rule.id,
                    timestamp=ts,
                    details={"user": event.get("user", {}).get("name")},
                )
                if campaign:
                    self.enterprise_campaign_alerts += 1
                    ent_alert = Alert(
                        alert_id=campaign.incident_id,
                        rule_id="CORR-ENT-001",
                        title=f"[ENTERPRISE CAMPAIGN] {campaign.title}",
                        description=f"Multi-hop lateral movement pivot path identified: {' -> '.join(campaign.lateral_pivot_path)}",
                        level=16,
                        severity="critical",
                        confidence=campaign.confidence,
                        host_id=campaign.root_cause_asset,
                        timestamp=ts,
                        event_id=event.get("event_id"),
                        evidence={"pivot_chain": campaign.lateral_pivot_path, "root_cause_asset": campaign.root_cause_asset},
                        active_response={"action": "ENTERPRISE_ISOLATE_PIVOT_PATH", "isolated_assets": campaign.lateral_pivot_path},
                        mitre_tactic="Lateral Movement",
                        mitre_technique="T1021",
                        tags=["attack.enterprise_campaign", "multi_hop_pivot", "cross_domain"],
                    )
                    self._emit(ent_alert, produced)

                    if self.auto_remediate:
                        rem_report = self.remediation_engine.remediate_enterprise_campaign(campaign)
                        if rem_report.actions_executed:
                            self.remediations_executed += len(rem_report.actions_executed)
                            self._emit_remediation(rem_report)

            if self.auto_remediate and res.rule.level >= 11:
                rem_report = self.remediation_engine.remediate_threat(
                    rule_id=res.rule.id,
                    threat_name=res.rule.name,
                    event=event,
                    custom_action=res.rule.active_response,
                )
                if rem_report.actions_executed:
                    self.remediations_executed += len(rem_report.actions_executed)
                    self._emit_remediation(rem_report)

            risk_incident = self.risk_scorer.record_detection(
                host_id=host_id,
                rule_id=res.rule.id,
                rule_name=res.rule.name,
                level=res.rule.level,
                timestamp=ts,
                summary=res.rule.description,
            )
            if risk_incident:
                self.risk_breach_alerts_count += 1
                self._emit(risk_incident, produced)

            incidents = self.correlation_engine.ingest_detection(res)
            for inc in incidents:
                self.incident_alerts_count += 1
                inc_alert = inc.to_alert()
                self._emit(inc_alert, produced)

        # B. Cloud & Workload Threat Engine
        cloud_matches = self.cloud_engine.inspect_cloud_event(event)
        for cm in cloud_matches:
            self.cloud_threat_alerts += 1
            c_alert = Alert(
                alert_id=f"ALT-CLOUD-{self.events_count}",
                rule_id="DET-CLOUD-001",
                title=f"[CLOUD THREAT] {cm.threat_type}",
                description=f"Cloud anomaly detected on {cm.cloud_provider} account '{cm.account_or_project_id}' for resource '{cm.resource_id}'.",
                level=15,
                severity="critical",
                confidence=cm.confidence,
                host_id=cm.account_or_project_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=cm.evidence,
                active_response={"action": cm.remediation_required, "target_resource": cm.resource_id},
                mitre_tactic="Exfiltration" if "Storage" in cm.threat_type else "Persistence",
                mitre_technique="T1530" if "Storage" in cm.threat_type else "T1098.001",
                tags=["attack.cloud", f"cloud.{cm.cloud_provider.lower()}", "workload_security"],
            )
            self._emit(c_alert, produced)

            if self.auto_remediate:
                rem_report = self.remediation_engine.remediate_cloud_threat(cm)
                if rem_report.actions_executed:
                    self.remediations_executed += len(rem_report.actions_executed)
                    self._emit_remediation(rem_report)

        # C. ITDR & Identity Analytics Engine (UEBA)
        id_matches = self.identity_engine.ingest_identity_event(event)
        for idm in id_matches:
            self.identity_threat_alerts += 1
            id_alert = Alert(
                alert_id=f"ALT-ID-{self.events_count}",
                rule_id="DET-IDENT-001",
                title=f"[IDENTITY THREAT] {idm.threat_type}",
                description=f"Compromised identity indicator detected for user '{idm.username}'.",
                level=14,
                severity="critical",
                confidence=idm.confidence,
                host_id=idm.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=idm.evidence,
                active_response={"action": idm.remediation_required, "target_user": idm.username},
                mitre_tactic="Credential Access",
                mitre_technique="T1110",
                tags=["attack.credential_access", "attack.initial_access", "identity_threat", "ueba"],
            )
            self._emit(id_alert, produced)

            if self.auto_remediate:
                rem_report = self.remediation_engine.remediate_identity_threat(idm)
                if rem_report.actions_executed:
                    self.remediations_executed += len(rem_report.actions_executed)
                    self._emit_remediation(rem_report)

        # D. Ransomware Shield & Canary Tripwires
        canary_match = self.ransomware_shield.inspect_file_event(event)
        if canary_match:
            self.ransomware_shield_alerts += 1
            canary_alert = Alert(
                alert_id=f"ALT-RANS-{self.events_count}",
                rule_id="DET-RANS-001",
                title=f"[RANSOMWARE SHIELD] {canary_match.threat_type}",
                description=f"Immediate threat detected: Process '{canary_match.process_name}' (PID: {canary_match.pid}) breached ransomware protection tripwire.",
                level=16,
                severity="critical",
                confidence=canary_match.confidence,
                host_id=canary_match.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=canary_match.evidence,
                active_response={"action": "TERMINATE_PROCESS", "target_pid": canary_match.pid, "isolate_host": True},
                mitre_tactic="Impact",
                mitre_technique="T1486",
                tags=["attack.impact", "ransomware_shield", "canary_tripwire"],
            )
            self._emit(canary_alert, produced)

            if self.auto_remediate:
                rem_report = self.remediation_engine.remediate_threat(
                    rule_id="DET-RANS-001",
                    threat_name=canary_match.threat_type,
                    event=event,
                    custom_action="ISOLATE_HOST",
                )
                if rem_report.actions_executed:
                    self.remediations_executed += len(rem_report.actions_executed)
                    self._emit_remediation(rem_report)

        # E. C2 Beaconing Periodic Engine
        beacon_match = self.beacon_detector.ingest_connection(event)
        if beacon_match:
            self.beacon_alerts_count += 1
            # "BLOCK_FIREWALL_IP" has no closed-set equivalent and is not a
            # supported custom_action -- ActiveResponseEngine.resolve_action
            # correctly fails closed (returns None) for it now, rather than
            # opportunistically downgrading to a full ISOLATE_HOST the way it
            # used to. The alert is still raised for analyst visibility; it
            # just carries no active_response recommendation.
            ar_action = ActiveResponseEngine.resolve_action(
                level=14,
                event=event,
                custom_action="BLOCK_FIREWALL_IP",
                reason=f"Periodic C2 Beaconing confirmed to {beacon_match.destination_ip}:{beacon_match.destination_port} (Interval: {beacon_match.mean_interval_seconds}s)",
            )
            if ar_action:
                self.active_responses_count += 1

            beacon_alert = Alert(
                alert_id=f"ALT-BCN-{self.events_count}",
                rule_id="DET-NET-004",
                title="[BEHAVIORAL C2 BEACON] Automated Periodic Heartbeat Detected",
                description=f"Identified consistent outbound beaconing to {beacon_match.destination_ip}:{beacon_match.destination_port} (Mean interval: {beacon_match.mean_interval_seconds}s, CV: {beacon_match.coefficient_of_variation}).",
                level=14,
                severity="critical",
                confidence=beacon_match.confidence,
                host_id=beacon_match.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=beacon_match.evidence,
                active_response=ar_action.to_dict() if ar_action else None,
                mitre_tactic="Command and Control",
                mitre_technique="T1071.001",
                tags=["attack.command_and_control", "c2_beaconing", "heartbeat_analysis"],
            )
            self._emit(beacon_alert, produced)

        # F. Lateral Port Scanner & Subnet Sweeper
        scan_matches = self.port_scan_detector.ingest_connection(event)
        for sm in scan_matches:
            self.port_scan_alerts_count += 1
            scan_alert = Alert(
                alert_id=f"ALT-SCAN-{self.events_count}",
                rule_id="DET-NET-005",
                title=f"[RECONNAISSANCE] {sm.scan_type}",
                description=f"Host initiated rapid network probes ({sm.target_summary}) within {sm.time_window_seconds}s.",
                level=12,
                severity="high",
                confidence=0.92,
                host_id=sm.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=sm.evidence,
                active_response=None,
                mitre_tactic="Discovery",
                mitre_technique="T1046",
                tags=["attack.discovery", "lateral_reconnaissance", "port_scan"],
            )
            self._emit(scan_alert, produced)

        # G. Frequency & Threshold Rules
        thresh_matches = self.threshold_engine.ingest_event(event)
        for tm in thresh_matches:
            self.threshold_alerts_count += 1
            ar_action = ActiveResponseEngine.resolve_action(
                level=tm.rule.level,
                event=event,
                custom_action=tm.rule.active_response,
                reason=f"Threshold rule [{tm.rule.id}] triggered: {tm.event_count} events in {tm.timeframe_seconds}s",
            )
            if ar_action:
                self.active_responses_count += 1

            thresh_alert = Alert(
                alert_id=f"ALT-TH-{tm.rule.id}",
                rule_id=tm.rule.id,
                title=f"[FREQUENCY THRESHOLD] {tm.rule.name}",
                description=tm.rule.description,
                level=tm.rule.level,
                severity=tm.rule.severity,
                confidence=tm.rule.confidence,
                host_id=tm.host_id,
                timestamp=ts,
                event_id=event.get("event_id"),
                evidence=tm.evidence,
                active_response=ar_action.to_dict() if ar_action else None,
                mitre_tactic=tm.rule.mitre_tactic,
                mitre_technique=tm.rule.mitre_technique,
                tags=["attack.impact", "ransomware", "threshold_trigger"],
            )
            self._emit(thresh_alert, produced)

        return produced
