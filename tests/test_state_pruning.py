"""Detection state is bounded, event-time driven, and replay-deterministic.

``DetectionContext.prune`` once reached only the graph and process registry;
every behavioral detector, the threshold engine, the risk timeline, the
campaign dedup set and the rule-inheritance history grew for the life of the
worker. Several of them also fell back to wall-clock time on an unparseable
timestamp, so replaying the same stream could give a different result.
"""

import json
from datetime import datetime
from pathlib import Path

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.behavioral.port_scan import PortScanDetector
from panopticon_detection.evaluator.threshold import ThresholdEngine
from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.provenance.identity import event_epoch, parse_timestamp

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"


def _sample():
    for line in (ROOT / "samples" / "officer_live_sample.ndjson").read_text().splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            yield event


def _ts(second: int) -> str:
    return f"2026-08-18T13:00:{second:02d}Z"


def _connect(second: int, ip: str, port: int, pid: int = 4100) -> dict:
    return {
        "event_type": "network_connect",
        "event_id": f"net-{second}-{ip}-{port}",
        "timestamp": _ts(second),
        "host_id": "HOST-1",
        "process": {"pid": pid, "name": "powershell.exe"},
        "network": {"direction": "outbound", "destination_ip": ip, "destination_port": port},
    }


def _file_create(second: int, n: int) -> dict:
    return {
        "event_type": "file_create",
        "event_id": f"file-{second}-{n}",
        "timestamp": _ts(second),
        "host_id": "HOST-1",
        "process": {"pid": 4100, "name": "powershell.exe", "process_guid": "g"},
        "file": {"path": f"C:\\Users\\u\\doc{n}.locked"},
    }


def test_prune_evicts_every_detector_state_store():
    run, context = build_detection_run(RULES)
    for event in _sample():
        run.process_event(event)
    for i in range(8):
        run.process_event(_connect(i, f"10.0.0.{i}", 445))
    for i in range(6):
        run.process_event(_file_create(20 + i // 3, i))

    assert run.evaluator._matched_rules_history
    assert run.risk_scorer.host_profiles
    assert run.port_scan_detector.alerted_scans
    assert run.ransomware_shield.alerted_pids
    assert run.threshold_engine.buckets
    assert run.beacon_detector.connection_history

    dropped = context.prune(datetime(2100, 1, 1))

    assert dropped["detector_state_removed"] > 0
    assert dropped["edges_removed"] > 0
    assert run.evaluator._matched_rules_history == {}
    assert run.risk_scorer.host_profiles == {}
    assert not run.port_scan_detector.horizontal_sweeps
    assert not run.port_scan_detector.vertical_scans
    assert run.port_scan_detector.alerted_scans == {}
    assert not run.ransomware_shield.process_file_activity
    assert run.ransomware_shield.alerted_pids == {}
    assert run.threshold_engine.buckets == {}
    assert run.beacon_detector.connection_history == {}
    assert context.campaign_detector._reported == {}
    assert context.graph.stats()["edges"] == 0
    assert len(context.registry) == 0


def test_prune_keeps_state_newer_than_the_cutoff():
    run, context = build_detection_run(RULES)
    for i in range(3):
        run.process_event(_connect(i, "10.0.0.9", 443))

    context.prune(datetime(2026, 8, 18, 12, 0, 0))
    assert run.beacon_detector.connection_history


def test_replaying_the_same_stream_gives_identical_alerts():
    def replay():
        run, _ = build_detection_run(RULES)
        alerts = []
        for event in _sample():
            alerts += [a.to_dict() for a in run.process_event(event)]
        return json.dumps(alerts, sort_keys=True, default=str)

    assert replay() == replay()


def test_detectors_skip_events_without_a_usable_time():
    no_time = _connect(0, "10.0.0.1", 443)
    no_time["timestamp"] = "not-a-time"

    beacon = C2BeaconDetector(min_samples=2)
    scan = PortScanDetector()
    threshold = ThresholdEngine()
    assert beacon.ingest_connection(no_time) is None
    assert scan.ingest_connection(no_time) == []
    assert threshold.ingest_event({**no_time, "event_type": "file_create"}) == []
    assert beacon.connection_history == {}
    assert not scan.horizontal_sweeps


def test_a_scan_latch_expires_instead_of_muting_the_host_forever():
    scan = PortScanDetector(horizontal_ip_threshold=3, latch_ttl_seconds=60)
    first = [scan.ingest_connection(_connect(i, f"10.0.0.{i}", 445)) for i in range(3)]
    assert any(first)

    later = []
    for i in range(3):
        event = _connect(i, f"10.0.1.{i}", 445)
        event["timestamp"] = f"2026-08-18T14:00:{i:02d}Z"
        later.append(scan.ingest_connection(event))
    assert any(later), "a genuine scan an hour later must be reported again"


def test_timestamps_normalise_to_utc_not_local_time():
    assert parse_timestamp("2026-08-18T12:00:00+05:30") == datetime(2026, 8, 18, 6, 30)
    assert parse_timestamp("2026-08-18T12:00:00Z") == datetime(2026, 8, 18, 12, 0)
    assert event_epoch("2026-08-18T12:00:00Z") == event_epoch("2026-08-18T17:30:00+05:30")
    assert event_epoch("garbage") is None
    assert event_epoch(True) is None
