"""Detection state is bounded, event-time driven, and replay-deterministic.

Every stateful component -- the provenance graph and registry, open incidents,
sequence and window state of stateful rules, the beacon detector, the risk
meter and alert dedup -- is reachable from ``DetectionContext.prune``. None of
them reads wall-clock time, so replaying a stream reproduces its alerts.
"""

import json
from datetime import datetime
from pathlib import Path

from panopticon_detection.behavioral.beacon import C2BeaconDetector
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
    return f"2026-08-18T13:{second // 60:02d}:{second % 60:02d}Z"


def _connect(second: int, ip: str, port: int, pid: int = 4100) -> dict:
    return {
        "event_type": "network_connect",
        "event_id": f"net-{second}-{ip}-{port}",
        "timestamp": _ts(second),
        "host_id": "HOST-1",
        "process": {"pid": pid, "name": "powershell.exe"},
        "network": {"direction": "outbound", "destination_ip": ip, "destination_port": port},
    }


def _loaded_run():
    run, context = build_detection_run(RULES)
    for event in _sample():
        run.process_event(event)
    for i in range(12):  # internal sweep -> value_count window state
        run.process_event(_connect(i, f"10.0.0.{i + 1}", 445))
    for i in range(4):  # public connections -> beacon history
        run.process_event(_connect(100 + 60 * i, "93.184.216.34", 443, pid=4200))
    return run, context


def test_prune_evicts_every_state_store():
    run, context = _loaded_run()
    assert context.incidents.incidents
    assert run.stateful.state_size()["window_keys"] or run.stateful.state_size()["sequence_keys"]
    assert run.beacon_detector.connection_history
    assert run.risk_scorer.host_profiles
    assert run._last_emitted

    dropped = context.prune(datetime(2100, 1, 1))

    assert dropped["incidents_closed"] >= 1
    assert dropped["edges_removed"] > 0
    assert dropped["detector_state_removed"] > 0
    assert context.incidents.incidents == {}
    assert run.stateful.state_size() == {
        "sequence_keys": 0,
        "open_sequence_matches": 0,
        "window_keys": 0,
        "window_events": 0,
    }
    assert run.beacon_detector.connection_history == {}
    assert run.beacon_detector.alerted_beacons == {}
    assert run.risk_scorer.host_profiles == {}
    assert run._last_emitted == {}
    assert context.graph.stats()["edges"] == 0
    assert len(context.registry) == 0


def test_prune_keeps_state_newer_than_the_cutoff():
    run, context = _loaded_run()
    context.prune(datetime(2026, 8, 18, 12, 0, 0))
    assert run.beacon_detector.connection_history
    assert context.incidents.incidents


def test_replaying_the_same_stream_gives_identical_alerts():
    def replay():
        run, _ = build_detection_run(RULES)
        alerts = []
        for event in _sample():
            alerts += [a.to_dict() for a in run.process_event(event)]
        return json.dumps(alerts, sort_keys=True, default=str)

    assert replay() == replay()


def test_events_without_a_usable_time_touch_no_windowed_state():
    run, _ = build_detection_run(RULES)
    event = _connect(0, "10.0.0.1", 445)
    event["timestamp"] = "not-a-time"
    run.process_event(event)
    assert run.stateful.state_size()["window_keys"] == 0
    beacon = C2BeaconDetector()
    assert beacon.ingest_connection({**event, "network": {**event["network"], "destination_ip": "93.184.216.34"}}) is None


def test_timestamps_normalise_to_utc_not_local_time():
    assert parse_timestamp("2026-08-18T12:00:00+05:30") == datetime(2026, 8, 18, 6, 30)
    assert parse_timestamp("2026-08-18T12:00:00Z") == datetime(2026, 8, 18, 12, 0)
    assert event_epoch("2026-08-18T12:00:00Z") == event_epoch("2026-08-18T17:30:00+05:30")
    assert event_epoch("garbage") is None
    assert event_epoch(True) is None


def test_overlapping_rules_on_one_event_count_once_toward_host_risk():
    """Two rules describing the same startup-folder drop are one piece of
    evidence; they must not push the host risk meter over its threshold."""
    run, _ = build_detection_run(RULES)
    produced = run.process_event({
        "event_id": "evt-startup",
        "event_type": "file_create",
        "timestamp": "2026-09-14T12:00:00Z",
        "host_id": "HOST-1",
        "process": {"pid": 6001, "name": "explorer.exe"},
        "file": {"path": "C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk"},
    })
    rule_ids = [a.rule_id for a in produced]
    assert {"DET-FILE-001", "DET-PERS-007"} <= set(rule_ids)
    assert "CORR-RISK-001" not in rule_ids
    assert len(run.risk_scorer.host_profiles["HOST-1"].event_timeline) == 1
