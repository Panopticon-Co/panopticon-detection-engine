"""Command-line entry point for the Panopticon detection engine.

Reads telemetry (a NDJSON file, or a live Officer agent subprocess), runs it
through a :class:`~panopticon_detection.detection_run.DetectionRun`, and prints
or persists the alerts produced.

The engine only ever *recommends* a response. Nothing here executes one: the
closed seven-action command set, its approval tiers and its dispatch live in
panopticon-response-engine and panopticon-manager. An alert's
``active_response`` is a recommendation the manager translates, tiers, and
stages for analyst authorization.
"""

from __future__ import annotations

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

from panopticon_detection.alerting.formatter import AlertFormatter
from panopticon_detection.alerting.story_formatter import StoryModeFormatter
from panopticon_detection.detection_run import _print_alert
from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.live_stream import LiveTelemetryStream
from panopticon_detection.mitre.attack import MitreMatrixNavigator
from panopticon_detection.rules.loader import RuleLoader


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="panopticon-detect",
        description=(
            "Panopticon detection engine: rule evaluation, provenance-graph "
            "correlation, and behavioral analytics over endpoint telemetry."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rules", default="rules", help="Path to the detection rules directory"
    )
    parser.add_argument(
        "--telemetry",
        default="samples/attack_simulation.ndjson",
        help="Path to a telemetry NDJSON file",
    )
    parser.add_argument(
        "--officer",
        action="store_true",
        help="Ingest live telemetry from a C++ Officer agent subprocess",
    )
    parser.add_argument(
        "--officer-bin", default="officer-agent.exe", help="Path to the Officer binary"
    )
    parser.add_argument(
        "--officer-source",
        choices=["etw", "sysmon", "all"],
        default="all",
        help="Collector source to request from the Officer agent",
    )
    parser.add_argument(
        "--officer-ndjson",
        default=None,
        help="Ingest Panopticon-schema NDJSON captured from an Officer agent",
    )
    parser.add_argument(
        "--output-format",
        choices=["console", "json", "ndjson"],
        default="console",
        help="Alert display format",
    )
    parser.add_argument(
        "--output-file", default=None, help="Write generated alerts here as NDJSON"
    )
    parser.add_argument(
        "--story",
        action="store_true",
        help="Render a plain-English narrative of what was detected",
    )
    parser.add_argument(
        "--mitre-matrix",
        action="store_true",
        help="Print MITRE ATT&CK coverage across the loaded rules",
    )
    parser.add_argument(
        "--export-navigator",
        default=None,
        help="Write a MITRE ATT&CK Navigator v4 JSON layer to this path",
    )
    parser.add_argument(
        "--graph-stats",
        action="store_true",
        help="Print provenance graph size after the run",
    )

    reliability = parser.add_argument_group("reliable streaming pipeline")
    reliability.add_argument(
        "--reliable",
        action="store_true",
        help=(
            "Run the continuous pipeline: bounded queue -> detection -> SQLite "
            "spool -> incremental alerts.ndjson, with retry, health/metrics and "
            "restart recovery."
        ),
    )
    reliability.add_argument(
        "--spool-db",
        default="spool/panopticon-v2.db",
        help="Path to the SQLite alert-delivery spool (created if absent)",
    )
    reliability.add_argument(
        "--queue-capacity", type=int, default=1024, help="Bounded ingestion queue size"
    )
    reliability.add_argument(
        "--queue-overflow",
        choices=["block", "drop_newest", "drop_oldest"],
        default="block",
        help="Behaviour when the queue is full (rejects are counted, never silent)",
    )
    reliability.add_argument(
        "--max-events", type=int, default=None, help="Stop after this many events"
    )
    reliability.add_argument(
        "--duration", type=float, default=None, help="Stop after this many seconds"
    )
    reliability.add_argument(
        "--retry-max-attempts",
        type=int,
        default=5,
        help="Delivery attempts before an alert goes terminal 'dead'",
    )
    reliability.add_argument(
        "--retry-base-delay",
        type=float,
        default=1.0,
        help="Base seconds for the bounded exponential delivery-retry backoff",
    )
    reliability.add_argument(
        "--health-file", default=None, help="Write a JSON health snapshot here on exit"
    )
    reliability.add_argument(
        "--metrics-file",
        default=None,
        help="Write Prometheus-text metrics here on exit",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"[ERROR] Rules path does not exist: {rules_path}")
        sys.exit(1)

    # Reporting-only modes need the rule set but no telemetry.
    if args.mitre_matrix or args.export_navigator:
        loader = RuleLoader()
        rules = (
            [loader.load_file(rules_path)]
            if rules_path.is_file()
            else loader.load_directory(rules_path)
        )
        if args.mitre_matrix:
            print(MitreMatrixNavigator.render_console_heatmap(rules))
        if args.export_navigator:
            layer_path = Path(args.export_navigator)
            layer_path.parent.mkdir(parents=True, exist_ok=True)
            layer_path.write_text(
                json.dumps(MitreMatrixNavigator.export_navigator_layer(rules), indent=2),
                encoding="utf-8",
            )
            print(f"[+] Exported ATT&CK Navigator layer to {layer_path.resolve()}")
        if not _telemetry_requested():
            return

    event_stream, stream_name = _open_stream(args)

    try:
        run, context = build_detection_run(
            rules_path,
            emit=lambda alert: _print_alert(
                alert, args.output_format, story_mode=args.story
            ),
        )
    except Exception as exc:
        print(f"[ERROR] Failed to load rules: {exc}")
        sys.exit(1)

    print("=" * 78)
    print("Panopticon detection engine")
    print("=" * 78)
    print(f"[*] {len(run.evaluator.rules)} enabled rule(s) loaded from {rules_path}")
    print(f"[*] Telemetry source: {stream_name}\n")

    if args.reliable:
        _run_streaming_pipeline(args, run, event_stream)
    else:
        for event in event_stream:
            run.process_event(event)
        if args.output_file:
            out_path = Path(args.output_file)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as handle:
                for alert in run.all_alerts:
                    handle.write(AlertFormatter.to_ndjson(alert) + "\n")
            print(f"\n[+] Wrote {len(run.all_alerts)} alert(s) to {out_path.resolve()}")

    if args.story:
        print("\n" + StoryModeFormatter.render_story_timeline(run.all_alerts, []))

    _print_summary(run, context, show_graph=args.graph_stats)


def _telemetry_requested() -> bool:
    return any(
        flag in sys.argv for flag in ("--telemetry", "--officer", "--officer-ndjson")
    )


def _open_stream(args):
    if args.officer:
        print(
            f"[*] Spawning Officer agent: {args.officer_bin} "
            f"(source={args.officer_source})"
        )
        return (
            LiveTelemetryStream.stream_from_officer_process(
                args.officer_bin, source=args.officer_source
            ),
            f"live Officer agent ({args.officer_bin}, source={args.officer_source})",
        )

    path = Path(args.officer_ndjson or args.telemetry)
    if not path.exists():
        print(f"[ERROR] Telemetry file not found: {path}")
        sys.exit(1)
    return LiveTelemetryStream.stream_from_file(path), path.name


def _print_summary(run, context, *, show_graph: bool) -> None:
    """Report what was observed.

    Counts only. The engine detects and recommends; it executes nothing, so it
    is in no position to claim a host was protected or a threat neutralized --
    which is exactly what the previous summary block asserted.
    """
    print("\n" + "=" * 78)
    print("RUN SUMMARY")
    print("=" * 78)
    rows = [
        ("Telemetry events ingested", run.events_count),
        ("Rule detections", run.atomic_alerts_count),
        ("Multi-stage campaigns", run.campaign_alerts_count),
        ("Host risk-threshold breaches", run.risk_breach_alerts_count),
        ("Ransomware tripwires", run.ransomware_shield_alerts),
        ("C2 beacons", run.beacon_alerts_count),
        ("Port scans", run.port_scan_alerts_count),
        ("Frequency thresholds", run.threshold_alerts_count),
        ("Response actions recommended", run.active_responses_count),
    ]
    for label, value in rows:
        print(f"  {label:<34}: {value}")

    if show_graph:
        stats = context.stats()
        print(
            f"  {'Provenance graph':<34}: "
            f"{stats['nodes']} nodes, {stats['edges']} edges "
            f"({stats['tagged_edges']} tagged), {stats['processes']} processes"
        )
    print("=" * 78)


def _run_streaming_pipeline(args, run, event_stream) -> None:
    """Bounded queue -> detection -> SQLite alert spool -> incremental
    alerts.ndjson, with delivery retry, health/metrics and restart recovery."""
    from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
    from panopticon_detection.reliability import (
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

    out_path = (
        Path(args.output_file).expanduser()
        if args.output_file
        else Path("alerts.ndjson")
    )
    writer = IncrementalAlertWriter(out_path)

    def detect(event):
        # The spool stores whatever the stream yielded. A raw Officer record
        # (nested "event" object) recovered from the spool is normalized
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
        f"[*] Streaming pipeline  spool={spool_path}  sink={out_path}  "
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
            health.write_json(
                args.health_file, queue=queue, spool=spool, metrics=metrics
            )
        if args.metrics_file:
            metrics_path = Path(args.metrics_file).expanduser()
            metrics_path.parent.mkdir(parents=True, exist_ok=True)
            metrics_path.write_text(metrics.render_prometheus(), encoding="utf-8")
        writer.close()
        spool.close()

    if result is not None:
        print(f"\n[+] Pipeline result: {result.to_dict()}")
        print(f"[+] Alerts written to {out_path.resolve()} ({writer.count} line(s))")
    print("\n" + health_text)


if __name__ == "__main__":
    main()
