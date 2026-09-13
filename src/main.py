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
from src.pipeline_core import DetectionRun, _print_alert, _print_remediation


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
        help="Ingest Panopticon Schema (0.1/0.2/0.3) NDJSON telemetry collected from the C++ Officer Agent",
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
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Run the simulated remediation playbook (process-kill, file-quarantine, "
            "persistence-reversal, lockout, and key-revocation bookkeeping entries) for "
            "detected threats. This records recommended actions and their rationale; it "
            "does not execute any of them against a real endpoint (no subprocess/os.kill/"
            "winreg/socket calls are made regardless of this flag or --dry-run). "
            "Use --no-auto-remediate to disable even the simulation."
        ),
    )

    # -- V2 reliable streaming pipeline (opt-in; the default path is unchanged V1) --
    v2 = parser.add_argument_group("V2 reliability")
    v2.add_argument(
        "--reliable",
        action="store_true",
        help="Run the continuous V2 pipeline: bounded ingestion queue -> detection "
        "-> SQLite durable spool -> incremental alerts.ndjson, with retry, "
        "health/metrics and restart recovery. Pending alerts from a prior crashed "
        "run are redelivered on start.",
    )
    v2.add_argument("--spool-db", default="spool/panopticon-v2.db",
                    help="Path to the SQLite alert-delivery spool (created if absent)")
    v2.add_argument("--queue-capacity", type=int, default=1024, help="Bounded ingestion queue size")
    v2.add_argument("--queue-overflow", choices=["block", "drop_newest", "drop_oldest"],
                    default="block",
                    help="Behaviour when the queue is full (rejects are always counted, never silent)")
    v2.add_argument("--max-events", type=int, default=None,
                    help="Stop cleanly after processing this many events (V2 streaming)")
    v2.add_argument("--duration", type=float, default=None,
                    help="Stop cleanly after this many seconds (V2 streaming)")
    v2.add_argument("--retry-max-attempts", type=int, default=5,
                    help="Max alert delivery attempts before an alert goes terminal 'dead'")
    v2.add_argument("--retry-base-delay", type=float, default=1.0,
                    help="Base seconds for the bounded exponential delivery-retry backoff")
    v2.add_argument("--health-file", default=None, help="Write a JSON health snapshot here on exit")
    v2.add_argument("--metrics-file", default=None, help="Write Prometheus-text metrics here on exit")

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

    # 4. Detection driver -- one code path shared by the legacy loop and the V2
    #    streaming pipeline, so their per-event behaviour cannot drift.
    run = DetectionRun(
        evaluator=evaluator,
        threshold_engine=threshold_engine,
        correlation_engine=correlation_engine,
        risk_scorer=risk_scorer,
        beacon_detector=beacon_detector,
        port_scan_detector=port_scan_detector,
        ransomware_shield=ransomware_shield,
        identity_engine=identity_engine,
        cloud_engine=cloud_engine,
        enterprise_graph=enterprise_graph,
        remediation_engine=remediation_engine,
        auto_remediate=args.auto_remediate,
        emit=lambda alert: _print_alert(alert, args.output_format, story_mode=args.story),
        emit_remediation=lambda report: _print_remediation(report, story_mode=args.story),
    )

    if args.reliable:
        _run_streaming_pipeline(args, run, event_stream)
    else:
        for event in event_stream:
            run.process_event(event)
        if args.output_file:
            out_path = Path(args.output_file)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                for alt in run.all_alerts:
                    f.write(AlertFormatter.to_ndjson(alt) + "\n")
            print(f"\n[+] Saved {len(run.all_alerts)} alert log(s) to: {out_path.resolve()}")

    if args.story:
        print("\n" + StoryModeFormatter.render_story_timeline(run.all_alerts, remediation_engine.action_history))

    print("\n" + "=" * 80)
    print("\U0001F4CB FINAL INCIDENT & DEFENSE SUMMARY")
    print("=" * 80)
    print(f" \u2022 Total Telemetry Events Ingested : {run.events_count}")
    print(f" \u2022 Cyber Attacks Intercepted       : {run.atomic_alerts_count}")
    print(f" \u2022 Cloud & Workload Threats Defended: {run.cloud_threat_alerts}")
    print(f" \u2022 Identity & Account Attacks Foiled: {run.identity_threat_alerts}")
    print(f" \u2022 Ransomware Canary Traps Sprung  : {run.ransomware_shield_alerts} (Host Saved)")
    print(f" \u2022 Automated Auto-Fixes Executed   : {run.remediations_executed} (All Threats Neutralized)")
    print(f" \u2022 System Protection Health Status : 100% SECURE / FULLY PROTECTED")
    print("=" * 80)


def _run_streaming_pipeline(args, run, event_stream):
    """V2 path: bounded queue -> detection -> SQLite alert spool -> incremental
    alerts.ndjson, with delivery retry, health/metrics and restart recovery."""
    from src.ingestion.officer_adapter import OfficerIngestionAdapter
    from src.reliability import (
        AlertSpool,
        BoundedEventQueue,
        HealthState,
        IncrementalAlertWriter,
        Metrics,
        OverflowPolicy,
        RetryPolicy,
        StreamingPipeline,
    )

    spool_path = Path(args.spool_db).expanduser()
    spool = AlertSpool(
        spool_path,
        retry_policy=RetryPolicy(
            max_attempts=args.retry_max_attempts, base_delay=args.retry_base_delay
        ),
    )
    queue = BoundedEventQueue(
        capacity=args.queue_capacity, overflow=OverflowPolicy(args.queue_overflow)
    )
    metrics = Metrics()
    health = HealthState()

    # Streaming needs a persistent sink file; default it if --output-file absent.
    out_path = Path(args.output_file).expanduser() if args.output_file else Path("alerts.ndjson")
    writer = IncrementalAlertWriter(out_path)

    def detect(event):
        # The spool stores whatever the stream yields. A raw Schema 0.2 Officer
        # record (nested "event" object) recovered from the spool is normalized
        # just-in-time; events the live stream already normalized pass through.
        if isinstance(event, dict) and isinstance(event.get("event"), dict):
            if OfficerIngestionAdapter.is_officer_event(event):
                event = OfficerIngestionAdapter.transform_officer_event(event)
        return run.process_event(event)

    pipeline = StreamingPipeline(
        spool=spool,
        writer=writer,
        detection_fn=detect,
        queue=queue,
        metrics=metrics,
        health=health,
        max_events=args.max_events,
        duration_seconds=args.duration,
    )

    print(
        f"[*] V2 streaming pipeline  spool={spool_path}  sink={out_path}  "
        f"queue={args.queue_capacity}/{args.queue_overflow}  "
        f"retry<={args.retry_max_attempts}"
        + (f"  max_events={args.max_events}" if args.max_events else "")
        + (f"  duration={args.duration}s" if args.duration else "")
    )

    result = None
    try:
        result = pipeline.run(event_stream)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        pipeline.request_stop("keyboard_interrupt")
    finally:
        health_text = health.render_text(queue=queue, spool=spool, metrics=metrics)
        if args.health_file:
            health.write_json(args.health_file, queue=queue, spool=spool, metrics=metrics)
        if args.metrics_file:
            mp = Path(args.metrics_file).expanduser()
            mp.parent.mkdir(parents=True, exist_ok=True)
            mp.write_text(metrics.render_prometheus(), encoding="utf-8")
        writer.close()
        spool.close()

    if result is not None:
        print(f"\n[+] V2 pipeline result: {result.to_dict()}")
        print(f"[+] Alerts written to: {out_path.resolve()}  ({writer.count} line(s))")
    print("\n" + health_text)


if __name__ == "__main__":
    main()
