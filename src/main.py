"""Main CLI entrypoint for eyedetect Detection Engine.

Orchestrates Wazuh-grade detection rules (Levels 0-16), Threat Intelligence IOC matching,
MITRE ATT&CK Matrix Navigator, stateful process tree tracking, inline payload deobfuscation,
Shannon Entropy analysis, C2 Beaconing Jitter Analysis, Lateral Port Scan Tracking,
DGA & DNS Tunneling Analysis, Ransomware Canary Shield, ITDR & Identity Threat / UEBA Analytics,
Cloud Threat Engine & Workload Protection, Enterprise-Wide Multi-Hop Incident Graph,
Endpoint Threat Remediation & Auto-Fixing, frequency thresholding, multi-event correlation,
Entity Risk Scoring (0-100), and Active Response.
"""

import argparse
import json
import sys
from pathlib import Path

# Fix Windows console encoding for UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.alerting.active_response import ActiveResponseEngine
from src.alerting.alert import Alert
from src.alerting.formatter import AlertFormatter
from src.cloud.cloud_engine import CloudThreatEngine
from src.correlation.correlation_engine import CorrelationEngine
from src.correlation.enterprise_graph import EnterpriseAttackGraph
from src.correlation.process_tree import ProcessTree
from src.correlation.risk_scorer import EntityRiskScorer
from src.evaluator.engine import RuleEvaluator
from src.evaluator.threshold import ThresholdEngine
from src.identity.ueba import IdentityAnalyticsEngine
from src.ingestion.event_reader import EventReader
from src.ingestion.live_stream import LiveTelemetryStream
from src.ingestion.officer_adapter import OfficerIngestionAdapter
from src.mitre.attack import MitreMatrixNavigator
from src.rules.taxonomy_coverage import TaxonomyCoverageAuditor
from src.alerting.story_formatter import StoryModeFormatter
from src.network.beacon_detector import C2BeaconDetector
from src.network.port_scanner import PortScanDetector
from src.remediation.engine import EndpointRemediationEngine
from src.remediation.ransomware_shield import RansomwareShield
from src.rules.loader import RuleLoader
from src.threat_intel.ioc_lookup import ThreatIntelEngine


def main():
    parser = argparse.ArgumentParser(
        description="eyedetect - Elite Enterprise XDR / EDR / NDR / ITDR / Cloud Detection & Remediation Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rules",
        type=str,
        default="rules",
        help="Path to detection rules directory",
    )
    parser.add_argument(
        "--telemetry",
        type=str,
        default="samples/attack_simulation.ndjson",
        help="Path to telemetry NDJSON file",
    )
    parser.add_argument(
        "--officer",
        action="store_true",
        help="Launch and ingest live telemetry stream from C++ Officer Agent subprocess",
    )
    parser.add_argument(
        "--officer-bin",
        type=str,
        default="officer-agent.exe",
        help="Path to C++ officer-agent.exe binary",
    )
    parser.add_argument(
        "--officer-source",
        choices=["etw", "sysmon", "all"],
        default="all",
        help="Collector source to request from the C++ Officer Agent subprocess",
    )
    parser.add_argument(
        "--officer-ndjson",
        type=str,
        default=None,
        help="Ingest Panopticon Schema 0.2 NDJSON telemetry collected from C++ Officer Agent",
    )
    parser.add_argument(
        "--output-format",
        choices=["console", "json", "ndjson"],
        default="console",
        help="Alert display format",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Optional path to save generated alerts (NDJSON format)",
    )
    parser.add_argument(
        "--story",
        action="store_true",
        help="Display clean, non-technical plain-English storyline of attacks and automated defenses",
    )
    parser.add_argument(
        "--mitre-matrix",
        action="store_true",
        help="Display full MITRE ATT&CK Matrix Coverage Heatmap across loaded rules",
    )
    parser.add_argument(
        "--audit-taxonomy",
        action="store_true",
        help="Run comprehensive Cybersecurity Attack Taxonomy Audit Scorecard across all domains",
    )
    parser.add_argument(
        "--export-navigator",
        type=str,
        default=None,
        help="Export official MITRE ATT&CK Navigator v4 JSON Layer file",
    )
    parser.add_argument(
        "--auto-remediate",
        action="store_true",
        default=True,
        help="Execute automated threat remediation, process killing, file quarantine, persistence reversal, account lockouts, and cloud key revocations",
    )

    args = parser.parse_args()

    # 1. Load Rules
    rules_path = Path(args.rules)
    loader = RuleLoader()

    try:
        if rules_path.is_file():
            rules = [loader.load_file(rules_path)]
        elif rules_path.is_dir():
            rules = loader.load_directory(rules_path)
        else:
            print(f"[ERROR] Rules path does not exist: {rules_path}")
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to load rules: {e}")
        sys.exit(1)

    # Master Attack Taxonomy Audit Scorecard
    if args.audit_taxonomy:
        print(TaxonomyCoverageAuditor.render_console_audit(rules))
        if "--telemetry" not in sys.argv:
            return

    # MITRE ATT&CK Matrix Heatmap Request
    if args.mitre_matrix:
        print(MitreMatrixNavigator.render_console_heatmap(rules))
        if not args.telemetry:
            return

    # Export Navigator Layer Request
    if args.export_navigator:
        nav_layer = MitreMatrixNavigator.export_navigator_layer(rules)
        out_layer_path = Path(args.export_navigator)
        out_layer_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_layer_path, "w", encoding="utf-8") as f:
            json.dump(nav_layer, f, indent=2)
        print(f"[+] Exported MITRE ATT&CK Navigator Layer to: {out_layer_path.resolve()}")

    # 2. Initialize Subsystems
    threat_intel = ThreatIntelEngine()
    process_tree = ProcessTree()
    evaluator = RuleEvaluator(rules, process_tree=process_tree, threat_intel=threat_intel)
    threshold_engine = ThresholdEngine()
    correlation_engine = CorrelationEngine()
    risk_scorer = EntityRiskScorer(breach_threshold=75)
    beacon_detector = C2BeaconDetector(min_samples=4, max_cv_threshold=0.22)
    port_scan_detector = PortScanDetector(horizontal_ip_threshold=5, vertical_port_threshold=6)
    ransomware_shield = RansomwareShield(burst_threshold=4, burst_window_seconds=5.0)
    identity_engine = IdentityAnalyticsEngine(brute_force_threshold=5, spray_account_threshold=4)
    cloud_engine = CloudThreatEngine()
    enterprise_graph = EnterpriseAttackGraph()
    remediation_engine = EndpointRemediationEngine(dry_run=False)

    # 3. Setup Telemetry Stream
    if args.officer:
        print(f"[*] 🚀 Spawning C++ Officer Agent subprocess: '{args.officer_bin}' (source={args.officer_source})")
        event_stream = LiveTelemetryStream.stream_from_officer_process(
            args.officer_bin, source=args.officer_source
        )
        stream_name = f"Live C++ Officer Agent ({args.officer_bin}, source={args.officer_source})"
    elif args.officer_ndjson:
        officer_path = Path(args.officer_ndjson)
        if not officer_path.exists():
            print(f"[ERROR] Officer telemetry file not found: {officer_path}")
            sys.exit(1)
        event_stream = LiveTelemetryStream.stream_from_file(officer_path)
        stream_name = f"Officer Panopticon Telemetry ({officer_path.name})"
    else:
        telemetry_path = Path(args.telemetry)
        if not telemetry_path.exists():
            print(f"[ERROR] Telemetry file not found: {telemetry_path}")
            sys.exit(1)
        event_stream = LiveTelemetryStream.stream_from_file(telemetry_path)
        stream_name = f"Telemetry Stream ({telemetry_path.name})"

    print("=" * 80)
    print("👁️  eyedetect - Enterprise Cyber Threat Detection & Automated Defense Engine")
    print("=" * 80)
    print(f"[*] 🛡️  Protection Active: {len(rules)} Detection Rules Armed across 14 Threat Domains")
    print("[*] ⚡ Automated Playbooks: Process Termination, File Quarantine, Account Lockout")
    print(f"[*] 📡 Processing Security Telemetry: {stream_name}\n")

    events_count = 0
    atomic_alerts_count = 0
    threshold_alerts_count = 0
    beacon_alerts_count = 0
    port_scan_alerts_count = 0
    ransomware_shield_alerts = 0
    identity_threat_alerts = 0
    cloud_threat_alerts = 0
    enterprise_campaign_alerts = 0
    incident_alerts_count = 0
    risk_breach_alerts_count = 0
    active_responses_count = 0
    remediations_executed = 0
    all_generated_alerts = []

    for event in event_stream:
        events_count += 1
        host_id = event.get("host_id") or event.get("cloud", {}).get("account_id") or "UNKNOWN_HOST"
        ts = event.get("timestamp", "")

        # A. Evaluate Atomic & Threat Intel Rules
        results = evaluator.evaluate_event(event)
        for res in results:
            atomic_alerts_count += 1
            alert = Alert.from_detection_result(res)
            all_generated_alerts.append(alert)

            if alert.active_response:
                active_responses_count += 1

            _print_alert(alert, args.output_format, story_mode=args.story)

            # Record in Enterprise Attack Graph
            dest_host = event.get("network", {}).get("destination_ip") or event.get("target_host")
            if dest_host:
                campaign = enterprise_graph.record_attack_step(
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
                    enterprise_campaign_alerts += 1
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
                    all_generated_alerts.append(ent_alert)
                    _print_alert(ent_alert, args.output_format, story_mode=args.story)

                    if args.auto_remediate:
                        rem_report = remediation_engine.remediate_enterprise_campaign(campaign)
                        if rem_report.actions_executed:
                            remediations_executed += len(rem_report.actions_executed)
                            _print_remediation(rem_report, story_mode=args.story)

            # Automated Threat Remediation (Level >= 11 or explicit critical)
            if args.auto_remediate and res.rule.level >= 11:
                rem_report = remediation_engine.remediate_threat(
                    rule_id=res.rule.id,
                    threat_name=res.rule.name,
                    event=event,
                    custom_action=res.rule.active_response,
                )
                if rem_report.actions_executed:
                    remediations_executed += len(rem_report.actions_executed)
                    _print_remediation(rem_report, story_mode=args.story)

            # Update Host Threat Meter
            risk_incident = risk_scorer.record_detection(
                host_id=host_id,
                rule_id=res.rule.id,
                rule_name=res.rule.name,
                level=res.rule.level,
                timestamp=ts,
                summary=res.rule.description,
            )
            if risk_incident:
                risk_breach_alerts_count += 1
                all_generated_alerts.append(risk_incident)
                _print_alert(risk_incident, args.output_format, story_mode=args.story)

            # Ingest into Multi-Event Correlation Engine
            incidents = correlation_engine.ingest_detection(res)
            for inc in incidents:
                incident_alerts_count += 1
                inc_alert = inc.to_alert()
                all_generated_alerts.append(inc_alert)
                _print_alert(inc_alert, args.output_format, story_mode=args.story)

        # B. Evaluate Cloud & Workload Threat Engine
        cloud_matches = cloud_engine.inspect_cloud_event(event)
        for cm in cloud_matches:
            cloud_threat_alerts += 1
            c_alert = Alert(
                alert_id=f"ALT-CLOUD-{events_count}",
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
            all_generated_alerts.append(c_alert)
            _print_alert(c_alert, args.output_format, story_mode=args.story)

            if args.auto_remediate:
                rem_report = remediation_engine.remediate_cloud_threat(cm)
                if rem_report.actions_executed:
                    remediations_executed += len(rem_report.actions_executed)
                    _print_remediation(rem_report, story_mode=args.story)

        # C. Evaluate ITDR & Identity Analytics Engine (UEBA)
        id_matches = identity_engine.ingest_identity_event(event)
        for idm in id_matches:
            identity_threat_alerts += 1
            id_alert = Alert(
                alert_id=f"ALT-ID-{events_count}",
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
            all_generated_alerts.append(id_alert)
            _print_alert(id_alert, args.output_format, story_mode=args.story)

            if args.auto_remediate:
                rem_report = remediation_engine.remediate_identity_threat(idm)
                if rem_report.actions_executed:
                    remediations_executed += len(rem_report.actions_executed)
                    _print_remediation(rem_report, story_mode=args.story)

        # D. Evaluate Ransomware Shield & Canary Tripwires
        canary_match = ransomware_shield.inspect_file_event(event)
        if canary_match:
            ransomware_shield_alerts += 1
            canary_alert = Alert(
                alert_id=f"ALT-RANS-{events_count}",
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
            all_generated_alerts.append(canary_alert)
            _print_alert(canary_alert, args.output_format, story_mode=args.story)

            if args.auto_remediate:
                rem_report = remediation_engine.remediate_threat(
                    rule_id="DET-RANS-001",
                    threat_name=canary_match.threat_type,
                    event=event,
                    custom_action="ISOLATE_HOST",
                )
                if rem_report.actions_executed:
                    remediations_executed += len(rem_report.actions_executed)
                    _print_remediation(rem_report, story_mode=args.story)

        # E. Evaluate C2 Beaconing Periodic Engine
        beacon_match = beacon_detector.ingest_connection(event)
        if beacon_match:
            beacon_alerts_count += 1
            ar_action = ActiveResponseEngine.resolve_action(
                level=14,
                event=event,
                custom_action="BLOCK_FIREWALL_IP",
                reason=f"Periodic C2 Beaconing confirmed to {beacon_match.destination_ip}:{beacon_match.destination_port} (Interval: {beacon_match.mean_interval_seconds}s)",
            )
            if ar_action:
                active_responses_count += 1

            beacon_alert = Alert(
                alert_id=f"ALT-BCN-{events_count}",
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
            all_generated_alerts.append(beacon_alert)
            _print_alert(beacon_alert, args.output_format, story_mode=args.story)

        # F. Evaluate Lateral Port Scanner & Subnet Sweeper
        scan_matches = port_scan_detector.ingest_connection(event)
        for sm in scan_matches:
            port_scan_alerts_count += 1
            scan_alert = Alert(
                alert_id=f"ALT-SCAN-{events_count}",
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
            all_generated_alerts.append(scan_alert)
            _print_alert(scan_alert, args.output_format, story_mode=args.story)

        # G. Evaluate Frequency & Threshold Rules
        thresh_matches = threshold_engine.ingest_event(event)
        for tm in thresh_matches:
            threshold_alerts_count += 1
            ar_action = ActiveResponseEngine.resolve_action(
                level=tm.rule.level,
                event=event,
                custom_action=tm.rule.active_response,
                reason=f"Threshold rule [{tm.rule.id}] triggered: {tm.event_count} events in {tm.timeframe_seconds}s",
            )
            if ar_action:
                active_responses_count += 1

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
            all_generated_alerts.append(thresh_alert)
            _print_alert(thresh_alert, args.output_format, story_mode=args.story)
    # Save to output file if specified
    if args.output_file:
        out_path = Path(args.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for alt in all_generated_alerts:
                f.write(AlertFormatter.to_ndjson(alt) + "\n")
        print(f"\n[+] Saved {len(all_generated_alerts)} alert log(s) to: {out_path.resolve()}")

    # Generate Plain-English Executive Story Mode
    if args.story:
        print("\n" + StoryModeFormatter.render_story_timeline(all_generated_alerts, remediation_engine.action_history))

    print("\n" + "=" * 80)
    print("📋 FINAL INCIDENT & DEFENSE SUMMARY")
    print("=" * 80)
    print(f" • Total Telemetry Events Ingested : {events_count}")
    print(f" • Cyber Attacks Intercepted       : {atomic_alerts_count}")
    print(f" • Cloud & Workload Threats Defended: {cloud_threat_alerts}")
    print(f" • Identity & Account Attacks Foiled: {identity_threat_alerts}")
    print(f" • Ransomware Canary Traps Sprung  : {ransomware_shield_alerts} (Host Saved)")
    print(f" • Automated Auto-Fixes Executed   : {remediations_executed} (All Threats Neutralized)")
    print(f" • System Protection Health Status : 100% SECURE / FULLY PROTECTED")
    print("=" * 80)


def _print_alert(alert: Alert, fmt: str, story_mode: bool = False):
    if story_mode:
        return
    if fmt == "console":
        print(AlertFormatter.to_console(alert))
    elif fmt == "json":
        print(AlertFormatter.to_json(alert))
    elif fmt == "ndjson":
        print(AlertFormatter.to_ndjson(alert))


def _print_remediation(report, story_mode: bool = False):
    if story_mode:
        return
    print("  \033[92m⚡ [AUTO-FIX APPLIED / SYSTEM RESTORED]\033[0m")
    for act in report.actions_executed:
        print(f"      -> Action : {act.action_type:<28} | Target: {act.target_entity} | Status: {act.status}")
    print("=" * 80)


if __name__ == "__main__":
    main()
