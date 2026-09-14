"""V3 Schema 0.3 telemetry-family normalization, ingestion dispatch and detection.

Covers:
* process telemetry stays byte-compatible with the V1/V2 adapter path;
* each new family (network / file / registry / image_load) normalizes to the
  engine-internal shape with the dotted aliases the rules read;
* dispatch is category-driven (registry model); an unknown family degrades to
  process context instead of breaking ingestion;
* the shared LiveTelemetryStream path auto-detects and routes 0.3 events;
* every family reaches RuleEvaluator without error, and an applicable rule per
  family produces a detection.

All inputs are SYNTHETIC fixtures -- not live Windows telemetry.
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion import telemetry as tele
from src.ingestion.live_stream import LiveTelemetryStream
from src.ingestion.officer_adapter import OfficerIngestionAdapter
from src.evaluator.engine import RuleEvaluator
from src.rules.loader import RuleLoader

SAMPLE = PROJECT_ROOT / "samples" / "v3" / "mixed_families_sample.ndjson"


def _load_raw():
    rows = []
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def _by_category(rows):
    return {r["event"]["category"]: r for r in rows}


@pytest.fixture(scope="module")
def raw_rows():
    return _load_raw()


@pytest.fixture(scope="module")
def evaluator():
    rules = RuleLoader().load_directory(PROJECT_ROOT / "rules")
    return RuleEvaluator(rules)


# -- schema detection ------------------------------------------------
def test_is_officer_event_accepts_0_3(raw_rows):
    assert all(OfficerIngestionAdapter.is_officer_event(r) for r in raw_rows)
    assert all(tele.is_panopticon_event(r) for r in raw_rows)


def _linux_agent_schema_0_4_event() -> dict:
    """The exact wire shape panopticon-linux-agent's
    serialize_canonical_process_ndjson (src/event.cpp) actually emits for a
    real process-start event -- schema_version 0.4 is the Linux agent's
    version (see manager/routers/ingest.py's comment 'Schema 0.4 is
    Linux-capable'), structurally identical to 0.2/0.3's envelope."""
    return {
        "schema_version": "0.4",
        "event": {"id": "evt_linux_1", "category": "process", "type": "start", "timestamp": "2026-09-14T12:00:00.000Z"},
        "source": {"kind": "linux_procfs", "provider": "procfs", "channel": None, "record_id": None},
        "agent": {"id": "agent-linux-1", "version": "1.0.0"},
        "host": {"id": "HOST-LINUX-1", "hostname": "linux-host", "os": {"name": "Linux", "build": "6.8.0"}},
        "user": {"name": None, "domain": None, "sid": None},
        "process": {
            "entity_id": "proc_linux1",
            "pid": 4242,
            "name": "cron",
            "executable": "/usr/sbin/cron",
            "command_line": "/usr/sbin/cron -f",
            "start_time_ticks": 123456789,
            "parent": {"entity_id": None, "pid": 1, "name": None},
            "hash": {"sha256": None},
        },
    }


def test_schema_0_4_linux_agent_event_is_recognized_and_normalized_without_duck_typing():
    # Explicit acceptance, not the "event"/"process"/"source" duck-typing
    # fallback -- proves SUPPORTED_SCHEMA_VERSIONS itself now lists "0.4",
    # matching panopticon-agent/schema/event.schema.json's own enum and
    # manager/routers/ingest.py's _SUPPORTED_SCHEMA_VERSIONS, so this can't
    # silently regress back to relying on duck-typing alone.
    event = _linux_agent_schema_0_4_event()
    assert "0.4" in OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS
    assert "0.4" in tele.SUPPORTED_SCHEMA_VERSIONS
    assert OfficerIngestionAdapter.is_officer_event(event) is True
    assert tele.is_panopticon_event(event) is True
    transformed = OfficerIngestionAdapter.transform_officer_event(event)
    assert transformed["process"]["pid"] == 4242
    assert transformed["process"]["start_time_ticks"] == 123456789
    assert transformed["_raw_officer_event"]["process"]["start_time_ticks"] == 123456789


def test_transform_officer_event_preserves_start_time_ticks_exactly():
    # This is the live-ingest identity property: a real KILL_PROCESS
    # recommendation is only ever safely computed if process.start_time_ticks
    # survives POST /api/v1/ingest -> DetectionWorker._normalize ->
    # transform_officer_event unchanged. Asserts exact value equality, not
    # merely "is not None" -- a silently-mutated value would be just as
    # dangerous as a dropped one.
    event = _linux_agent_schema_0_4_event()
    event["process"]["start_time_ticks"] = 133_012_345_670_000_321
    transformed = OfficerIngestionAdapter.transform_officer_event(event)
    assert transformed["process"]["start_time_ticks"] == 133_012_345_670_000_321


def test_transform_officer_event_preserves_missing_start_time_ticks_as_none():
    # An event whose originating collector never observed a start time (the
    # existing, pre-fix contract semantic: nullableStartTimeTicks) must
    # normalize to None, not 0 or a synthesized value -- resolve_action and
    # translate_recommendation both already treat None as "fail closed,"
    # and this test locks that in rather than inventing a new rule.
    event = _linux_agent_schema_0_4_event()
    del event["process"]["start_time_ticks"]
    transformed = OfficerIngestionAdapter.transform_officer_event(event)
    assert transformed["process"]["start_time_ticks"] is None


def test_category_of_falls_back_to_process_for_unknown():
    assert tele.category_of({"event": {"category": "dns"}}) == "process"
    assert tele.category_of({"event": {"category": "network"}}) == "network"
    assert tele.category_of({"event": {"category": "image_load"}}) == "image_load"


# -- process compatibility -----------------------------------------
def test_process_family_matches_the_legacy_adapter_output(raw_rows):
    raw = _by_category(raw_rows)["process"]
    via = OfficerIngestionAdapter.transform_officer_event(raw)
    assert via["event_type"] == "process_create"
    assert via["process"]["name"] == "powershell.exe"
    assert via["process"]["command_line"].startswith("powershell.exe -w hidden")
    assert via["process"]["process_guid"] == raw["process"]["entity_id"]
    assert via["parent"]["pid"] == 1000
    assert via["process"]["sha256"] == raw["process"]["hash"]["sha256"]


# -- network -------------------------------------------------------
def test_network_family_normalization(raw_rows):
    ev = tele.normalize(_by_category(raw_rows)["network"])
    assert ev["event_type"] == "network_connect"
    assert ev["telemetry_category"] == "network"
    n = ev["network"]
    assert n["direction"] == "outbound"
    assert n["protocol"] == "tcp"
    assert n["destination_ip"] == "203.0.113.10"
    assert n["destination_port"] == 443
    assert n["destination_hostname"] == "example.test"
    assert ev["process"]["pid"] == 4242 and ev["process"]["name"] == "powershell.exe"


# -- file --------------------------------------------------------
def test_file_family_normalization(raw_rows):
    ev = tele.normalize(_by_category(raw_rows)["file"])
    assert ev["event_type"] == "file_create"
    assert ev["file"]["operation"] == "create"
    assert ev["file"]["path"].endswith("update.lnk")
    assert ev["process"]["name"] == "powershell.exe"


# -- registry --------------------------------------------------
def test_registry_family_normalization_is_metadata_only(raw_rows):
    ev = tele.normalize(_by_category(raw_rows)["registry"])
    assert ev["event_type"] == "registry_write"
    r = ev["registry"]
    assert r["operation"] == "set_value"
    assert r["key_path"].endswith("CurrentVersion\\Run\\Updater")
    assert r["value_name"] == "Updater"
    assert r["value_data"] is None  # never synthesized


# -- image load ----------------------------------------------
def test_image_load_family_normalization(raw_rows):
    ev = tele.normalize(_by_category(raw_rows)["image_load"])
    assert ev["event_type"] == "image_load"
    im = ev["image"]
    assert im["path"].endswith("payload.dll")
    assert im["is_signed"] is False
    assert im["signature_status"] == "Unavailable"
    assert im["sha256"].startswith("0123456789abcdef")


# -- dispatch model -----------------------------------------
def test_unknown_family_degrades_to_process_context_without_raising():
    raw = {
        "schema_version": "0.3",
        "event": {"id": "evt_x", "category": "dns", "type": "query", "timestamp": "t"},
        "source": {}, "agent": {}, "host": {"id": "H"}, "user": {},
        "process": {"pid": 9, "name": "svc.exe", "parent": {}},
    }
    ev = tele.normalize(raw)  # must not raise
    assert ev["process"]["name"] == "svc.exe"
    assert ev["event_type"].startswith("process_")


def test_register_family_extension_hook():
    tele.register_family("dns", lambda raw: {**tele._common(raw), "event_type": "dns_query"})
    try:
        ev = tele.normalize({"event": {"category": "dns"}, "process": {}, "source": {}})
        assert ev["event_type"] == "dns_query"
    finally:
        tele._NORMALIZERS.pop("dns", None)


# -- stream integration ------------------------------------
def test_live_stream_auto_routes_every_family_from_the_sample_file():
    events = list(LiveTelemetryStream.stream_from_file(SAMPLE))
    assert len(events) == 5
    assert {e["event_type"] for e in events} == {
        "process_create", "network_connect", "file_create", "registry_write", "image_load",
    }
    assert all("_raw_officer_event" in e for e in events)


def test_every_family_reaches_the_rule_evaluator_without_error(evaluator):
    seen = set()
    for event in LiveTelemetryStream.stream_from_file(SAMPLE):
        results = evaluator.evaluate_event(event)
        assert isinstance(results, list)
        seen.add(event["event_type"])
    assert len(seen) == 5


# -- one detection per new family ------------------------
def test_sample_events_fire_their_applicable_family_rule(evaluator):
    fired = {}
    for event in LiveTelemetryStream.stream_from_file(SAMPLE):
        for res in evaluator.evaluate_event(event):
            fired.setdefault(event["event_type"], set()).add(res.rule.id)

    assert "DET-NET-001" in fired.get("network_connect", set())
    assert "DET-PERS-001" in fired.get("registry_write", set())
    assert "DET-FILE-001" in fired.get("file_create", set())
    assert "DET-IMG-001" in fired.get("image_load", set())


def test_process_detection_still_works_on_a_0_2_shaped_event(evaluator):
    """A Schema 0.2 process event (no family block, no schema_version bump) must
    still normalize and evaluate exactly as before -- V1/V2 regression guard."""
    raw = {
        "schema_version": "0.2",
        "event": {"id": "evt_" + "a" * 64, "category": "process", "type": "start",
                  "timestamp": "2026-08-28T12:00:00.000Z"},
        "source": {"kind": "sysmon", "provider": "Microsoft-Windows-Sysmon",
                   "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": 1},
        "agent": {"id": "a", "version": "0.2.0"},
        "host": {"id": "H", "hostname": "H", "os": {"name": "Windows 11", "build": "26100"}},
        "user": {"name": "analyst", "domain": "LAB", "sid": "S-1-5-21-1-1-1-1001"},
        "process": {"entity_id": "proc_" + "b" * 64, "pid": 10,
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell -enc AAAA",
                    "parent": {"entity_id": None, "pid": 4, "name": "winword.exe"},
                    "hash": {"sha256": None}},
    }
    norm = OfficerIngestionAdapter.transform_officer_event(raw)
    assert norm["event_type"] == "process_create"
    assert isinstance(evaluator.evaluate_event(norm), list)
