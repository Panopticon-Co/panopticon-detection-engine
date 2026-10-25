"""Sysmon XML (Splunk XmlWinEventLog, BOTSv1 _raw) -> OTRF-shaped records -> canonical events."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from panopticon_detection.datasets import sysmon_xml as X
from panopticon_detection.datasets.otrf import OtrfAdapter
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

AGENT_SCHEMA = Path(__file__).resolve().parents[2] / "panopticon-agent" / "schema" / "event.schema.json"

_EID1 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
    "<EventID>1</EventID><Version>5</Version><TimeCreated SystemTime='2016-08-10T21:04:10.123456700Z'/>"
    "<EventRecordID>4242</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>ws01.lab.local</Computer><Security UserID='S-1-5-18'/></System><EventData>"
    "<Data Name='UtcTime'>2016-08-10 21:04:10.100</Data>"
    "<Data Name='ProcessGuid'>{A1B2C3D4-0000-0000-0000-000000000001}</Data>"
    "<Data Name='ProcessId'>3456</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>cmd.exe /c whoami &amp; ipconfig</Data>"
    "<Data Name='User'>LAB\\alice</Data><Data Name='IntegrityLevel'>High</Data>"
    "<Data Name='Hashes'>SHA256=0F343B0931126A20F133D67C2B018A3B1E1D7F4D8A3E2F5C6B7A8D9E0F1A2B3C</Data>"
    "<Data Name='ParentProcessGuid'>{A1B2C3D4-0000-0000-0000-000000000002}</Data>"
    "<Data Name='ParentProcessId'>1200</Data>"
    "<Data Name='ParentImage'>C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>"
    "<Data Name='ParentCommandLine'>WINWORD.EXE</Data></EventData></Event>"
)
_EID3 = _EID1.replace("<EventID>1</EventID>", "<EventID>3</EventID>").replace("4242", "4243")


def test_flattens_system_and_event_data():
    record = X.parse_event_xml(_EID1)
    assert record["EventID"] == "1"
    assert record["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert record["Hostname"] == "ws01.lab.local"
    assert record["EventRecordID"] == "4242"
    assert record["CommandLine"] == "cmd.exe /c whoami & ipconfig"  # entity decoded
    assert record["IntegrityLevel"] == "High"
    assert record["SourceName"] == "Microsoft-Windows-Sysmon"


def test_malformed_xml_is_skipped_not_fatal():
    assert X.parse_event_xml("<Event><System>") is None
    found = list(X.iter_xml_events("garbage " + _EID1 + "\n<Event>broken</Even>"))
    assert found == [X.parse_event_xml(_EID1)]


def test_canonical_event_and_integrity_side_table_join():
    records = list(X.only_event_ids(X.iter_xml_events(_EID1 + "\n" + _EID3), {1}))
    assert len(records) == 1
    events, report = OtrfAdapter("unit").normalize(records)
    assert report.events_written == 1
    event = events[0]
    assert event["process"]["name"] == "cmd.exe"
    assert event["process"]["parent"]["name"] == "WINWORD.EXE"
    assert event["user"] == {"name": "alice", "domain": "LAB", "sid": None}
    assert event["event"]["timestamp"] == "2016-08-10T21:04:10.100Z"  # Sysmon's own UtcTime
    table = X.integrity_by_event_id(records, "unit")
    assert table == {event["event"]["id"]: "High"}
    normalized = OfficerIngestionAdapter.transform_officer_event(event)
    assert normalized["event_type"] == "process_create"


def test_canonical_event_is_valid_against_the_agent_schema():
    jsonschema = pytest.importorskip("jsonschema")
    if not AGENT_SCHEMA.is_file():
        pytest.skip("panopticon-agent is not checked out next to this repo")
    validator = jsonschema.Draft202012Validator(json.loads(AGENT_SCHEMA.read_text(encoding="utf-8")))
    events, _ = OtrfAdapter("unit").normalize([X.parse_event_xml(_EID1)])
    assert not list(validator.iter_errors(events[0]))


def test_botsv1_json_export_reader(tmp_path):
    path = tmp_path / "bots.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"preview": False, "result": {"_raw": _EID1, "host": "ws01"}}) + "\n")
        handle.write("not json\n")
        handle.write(json.dumps({"preview": False, "result": {}}) + "\n")
    records = list(X.read_botsv1_json(path))
    assert len(records) == 1 and records[0]["ProcessId"] == "3456"
