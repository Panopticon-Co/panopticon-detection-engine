"""Unit and Integration Tests for C++ Officer Agent (Panopticon Schema 0.2) Integration."""

from pathlib import Path

import pytest

from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.ingestion.live_stream import LiveTelemetryStream
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


@pytest.fixture
def rules():
    loader = RuleLoader()
    return loader.load_directory(Path("rules"))


@pytest.fixture
def evaluator(rules):
    threat_intel = ThreatIntelEngine()
    return RuleEvaluator(rules, threat_intel=threat_intel)


def test_officer_event_detection_and_normalization():
    raw_event = {
        "schema_version": "0.2",
        "event": {
            "id": "evt_7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            "category": "process",
            "type": "start",
            "timestamp": "2026-08-18T12:01:05.000Z",
        },
        "source": {
            "kind": "sysmon",
            "provider": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 202,
        },
        "agent": {"id": "officer-agent-001", "version": "0.2.0"},
        "host": {
            "id": "OFFICER-WIN11-LAB",
            "hostname": "OFFICER-WIN11-LAB",
            "os": {"name": "Windows 11 Pro", "build": "26100"},
        },
        "user": {
            "name": "analyst",
            "domain": "LAB",
            "sid": "S-1-5-21-1000-1001",
        },
        "process": {
            "entity_id": "proc_8f14e45fceea167a5a36dedd4bea2543d3b76251b5c46e30ebdf0129f1234567",
            "pid": 4100,
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -w hidden -enc SQBFAFgA...",
            "parent": {
                "entity_id": "proc_1111111111111111111111111111111111111111111111111111111111111111",
                "pid": 3000,
                "name": "winword.exe",
            },
            "hash": {
                "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
            },
        },
    }

    assert OfficerIngestionAdapter.is_officer_event(raw_event) is True

    normalized = OfficerIngestionAdapter.transform_officer_event(raw_event)
    assert normalized["event_type"] == "process_create"
    assert normalized["host_id"] == "OFFICER-WIN11-LAB"
    assert normalized["process"]["name"] == "powershell.exe"
    assert normalized["process"]["pid"] == 4100
    assert normalized["parent"]["name"] == "winword.exe"
    assert normalized["parent"]["pid"] == 3000
    assert normalized["user"]["full"] == "LAB\\analyst"
    assert normalized["process"]["file_hash"] == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"


def test_officer_telemetry_triggers_detection_rules(evaluator):
    sample_file = Path("samples/officer_live_sample.ndjson")
    assert sample_file.exists()

    events = list(LiveTelemetryStream.stream_from_file(sample_file))
    assert len(events) == 6

    matched_rule_ids = set()
    for event in events:
        results = evaluator.evaluate_event(event)
        for res in results:
            matched_rule_ids.add(res.rule.id)

    # Verify that critical EDR rules trigger on live Officer telemetry
    assert "DET-PROC-001" in matched_rule_ids  # Office Spawns PowerShell
    assert "DET-PROC-005" in matched_rule_ids  # LSASS Memory Dump
    assert "DET-PROC-006" in matched_rule_ids  # Volume Shadow Copies Deletion
    assert "DET-PROC-010" in matched_rule_ids  # Threat Intel Mimikatz Hash Match


def test_malformed_officer_json_handling():
    malformed_line = '{"schema_version": "0.2", "event": INVALID_JSON}'
    assert OfficerIngestionAdapter.parse_line(malformed_line) is None

    empty_line = '   '
    assert OfficerIngestionAdapter.parse_line(empty_line) is None
