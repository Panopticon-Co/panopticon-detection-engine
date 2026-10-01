"""OTRF Security-Datasets -> canonical events -> the real engine and features.

Fixtures in tests/datasets/otrf/ are trimmed, unedited OTRF records (see
scripts/make_otrf_fixtures.py and tests/datasets/otrf/README.md). They go
through the adapter, then the same OfficerIngestionAdapter, graph, rules and
FeatureExtractor live agent telemetry goes through.
"""

import hashlib
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from panopticon_detection.datasets import canonical as C
from panopticon_detection.datasets import cli as dataset_cli
from panopticon_detection.datasets.otrf import (
    LABEL_SEMANTICS,
    OtrfAdapter,
    load_metadata,
    read_records,
)
from panopticon_detection.factory import build_detection_run
from panopticon_detection.features import ProcessFeatures
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "datasets" / "otrf"
AGENT_SCHEMA = ROOT.parent / "panopticon-agent" / "schema" / "event.schema.json"
NAMES = sorted(p.stem for p in FIXTURES.glob("*.json"))


def _normalize(name):
    return OtrfAdapter(name).normalize(read_records(FIXTURES / f"{name}.json"))


def _replay(name):
    events, report = _normalize(name)
    run, context = build_detection_run(ROOT / "rules")
    alerts = []
    for event in events:
        alerts += run.process_event(OfficerIngestionAdapter.transform_officer_event(event))
    return events, report, run, context, alerts


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    if not AGENT_SCHEMA.is_file():
        pytest.skip("panopticon-agent is not checked out next to this repo")
    return jsonschema.Draft202012Validator(json.loads(AGENT_SCHEMA.read_text(encoding="utf-8")))


# ------------------------------------------------------------- canonical


@pytest.mark.parametrize("name", NAMES)
def test_every_canonical_event_is_valid_against_the_agent_schema(name):
    validator = _validator()
    events, _ = _normalize(name)
    errors = [(e["event"]["category"], err.message) for e in events for err in validator.iter_errors(e)]
    assert not errors, errors[:3]


def test_the_fixtures_exercise_every_canonical_family():
    seen = set()
    for name in NAMES:
        events, _ = _normalize(name)
        seen |= {(e["event"]["category"], e["event"]["type"]) for e in events}
    assert {
        ("process", "start"), ("process", "stop"), ("network", "connect"), ("file", "create"),
        ("registry", "set_value"), ("image_load", "load"), ("dns", "query"),
        ("process_access", "access"), ("remote_thread", "create"), ("script_block", "execute"),
    } <= seen


@pytest.mark.parametrize("name", NAMES)
def test_normalisation_is_deterministic(name):
    first, _ = _normalize(name)
    second, _ = _normalize(name)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_schema_version_follows_the_family_that_introduced_it():
    events, _ = _normalize("empire_launcher_vbs")
    for event in events:
        category, type_ = event["event"]["category"], event["event"]["type"]
        new = category in C.SCHEMA_05_CATEGORIES or (category, type_) == ("process", "stop")
        assert event["schema_version"] == ("0.5" if new else "0.3")


def test_sysmon_events_use_sysmons_own_utctime():
    events, report = _normalize("psh_lsass_memory_dump_comsvcs")
    rundll32 = [e for e in events if e["process"]["pid"] == 4824 and e["event"]["category"] == "process"]
    # The record's UtcTime is "2020-10-18 23:50:05.910"; its exported TimeCreated
    # is 16 hours earlier -- the collector's local clock labelled as UTC.
    assert [(e["event"]["type"], e["event"]["timestamp"]) for e in rundll32] == [
        ("start", "2020-10-18T23:50:05.910Z"),
        ("stop", "2020-10-18T23:50:06.213Z"),
    ]
    assert report.time_offset_seconds == 57600.0


def test_powershell_events_take_the_files_measured_clock_offset():
    events, report = _normalize("empire_launcher_vbs")
    assert report.time_offset_samples > 0
    (block,) = [e for e in events if e["event"]["category"] == "script_block"]
    # @timestamp 20:10:00.327 corrected by the median UtcTime - @timestamp of
    # this file's Sysmon events (-1 s: the NXLog collector's ingestion delay).
    assert block["event"]["timestamp"] == "2020-09-04T20:09:59.327Z"


def test_script_block_identity_user_and_text_policy():
    events, _ = _normalize("empire_launcher_vbs")
    (block,) = [e for e in events if e["event"]["category"] == "script_block"]
    assert block["source"]["kind"] == "windows_event_log"
    # The image is filled from the Sysmon process create for PID 2316.
    assert block["process"]["pid"] == 2316
    assert block["process"]["executable"].endswith("powershell.exe")
    assert block["user"] == {
        "name": "pgustavo", "domain": "THESHIRE", "sid": "S-1-5-21-2079883792-3656946353-945924832-1104",
    }
    sb = block["script_block"]
    assert sb["text_length"] == len(sb["text"].encode("utf-8")) and sb["text_truncated"] is False
    assert sb["text_sha256"] == hashlib.sha256(sb["text"].encode("utf-8")).hexdigest()


def test_sysmon_user_is_the_process_user_not_the_sysmon_service_account():
    events, _ = _normalize("empire_launcher_vbs")
    starts = [e for e in events if e["event"]["category"] == "process" and e["process"]["pid"] == 2316]
    # The NXLog UserID on this record is S-1-5-18 (Sysmon runs as SYSTEM).
    assert starts[0]["user"] == {"name": "pgustavo", "domain": "THESHIRE", "sid": None}


def test_registry_values_stay_metadata_only():
    events, _ = _normalize("purplesharp_pe_injection_createremotethread")
    registry = [e for e in events if e["event"]["category"] == "registry"]
    assert registry and all(e["registry"]["value_data"] is None for e in registry)


def test_unmapped_channels_are_counted_not_guessed():
    events, report = _normalize("empire_launcher_vbs")
    assert report.skipped[("Security", 4624)] == 1
    assert all(e["source"]["channel"] != "Security" for e in events)
    accounted = (
        report.events_written + sum(report.skipped.values()) + sum(report.rejected.values())
        + report.duplicates_dropped
    )
    assert report.records_read == accounted


def test_records_that_cannot_be_canonical_are_rejected_with_a_reason():
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    records = [
        {"Channel": sysmon, "EventID": 22, "Hostname": "H", "UtcTime": "2020-01-01 00:00:00.000",
         "QueryName": "a.example"},  # no ProcessId
        {"Channel": sysmon, "EventID": 22, "Hostname": "H", "ProcessId": "5"},  # no time at all
        {"Channel": sysmon, "EventID": 10, "Hostname": "H", "UtcTime": "2020-01-01 00:00:01.000",
         "SourceProcessId": "5", "TargetProcessId": "6", "GrantedAccess": "lots", "CallTrace": "-"},
    ]
    events, report = OtrfAdapter("t").normalize(records)
    assert report.rejected == {"no ProcessId": 1, "no usable timestamp": 1}
    (access,) = events
    assert access["process_access"]["granted_access"] is None  # not hex -> not invented
    assert access["process_access"]["call_trace"] is None  # Sysmon's "-" means none


def test_script_text_is_capped_on_a_character_boundary():
    text = "é" * 9000  # 18000 UTF-8 bytes
    capped = C.truncate_script_text(text)
    assert capped["text_truncated"] is True and capped["text_length"] == 18000
    assert len(capped["text"].encode("utf-8")) <= C.SCRIPT_TEXT_MAX_BYTES
    assert capped["text"] == "é" * 8192
    assert capped["text_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert C.truncate_script_text(None) == {
        "text": None, "text_length": 0, "text_truncated": False, "text_sha256": None,
    }


# ----------------------------------------------------------------- labels


def test_labels_are_dataset_level_and_never_written_onto_events():
    meta = load_metadata(FIXTURES / "SDWIN-190518182022.yaml")
    assert meta["attack_mappings"] == [{"technique": "T1059.005", "tactics": ["TA0002"]}]
    assert meta["label_semantics"] == LABEL_SEMANTICS
    events, report = OtrfAdapter("empire_launcher_vbs").normalize(
        read_records(FIXTURES / "empire_launcher_vbs.json"), meta
    )
    assert report.to_dict()["labels"]["attack_mappings"][0]["technique"] == "T1059.005"
    assert not any("label" in key for event in events for key in event)


# ---------------------------------------------------- through the engine


def test_each_recording_fires_the_rule_for_its_technique():
    expected = {
        "empire_launcher_vbs": {"DET-PS-010"},
        "psh_lsass_memory_dump_comsvcs": {"DET-PROC-005", "DET-CRED-010", "DET-CRED-011"},
        "psh_mavinject_dll_notepad": {"DET-INJ-011"},
        "purplesharp_pe_injection_createremotethread": {"DET-INJ-010"},
    }
    new_rules = {"DET-PS-010", "DET-CRED-010", "DET-CRED-011", "DET-INJ-010", "DET-INJ-011"}
    for name, wanted in expected.items():
        fired = {a.rule_id for a in _replay(name)[4]}
        assert wanted <= fired, (name, fired)
        # ... and no other new-telemetry rule fires on it.
        assert fired & new_rules == wanted & new_rules, (name, fired & new_rules)


def test_dataset_features_come_from_the_shared_extractor():
    _, _, run, context, _ = _replay("psh_lsass_memory_dump_comsvcs")
    (rundll32,) = [p for p in context.registry if p.pid == 4824 and not p.inferred]
    features = run.feature_extractor.extract(rundll32)
    assert isinstance(features, ProcessFeatures)
    assert features.parent_name == "powershell.exe"
    assert (features.lsass_access_count, features.access_targets) == (2, ("lsass.exe",))
    assert features.lifetime_seconds == 0.303  # from the recording's own stop event
    assert ProcessFeatures.from_dict(json.loads(json.dumps(features.to_dict()))) == features


def test_script_block_features_from_the_empire_recording():
    _, _, run, context, _ = _replay("empire_launcher_vbs")
    (agent,) = [p for p in context.registry if p.pid == 2316 and p.name == "powershell.exe"]
    features = run.feature_extractor.extract(agent)
    assert (features.script_block_count, features.obfuscated_script_block_count) == (1, 1)
    assert features.script_block_bytes == 1899
    assert features.parent_name == "wscript.exe"


def test_injection_puts_the_injector_upstream_of_the_targets_children():
    _, _, run, context, _ = _replay("purplesharp_pe_injection_createremotethread")
    (ping,) = [p for p in context.registry if p.name == "ping.exe"]
    (purplesharp,) = [p for p in context.registry if p.name == "purplesharp.exe"]
    walk = context.graph.backward(ping.node_id, ping.start_time + timedelta(seconds=1))
    assert purplesharp.node_id in walk.nodes
    assert "injected" in {e.kind.value for e in walk.edges}
    (notepad,) = [p for p in context.registry if p.name == "notepad.exe"]
    assert run.feature_extractor.extract(notepad).injected_thread_count == 1


# -------------------------------------------------------------------- CLI


def test_cli_normalize_then_detect_with_feature_export(tmp_path):
    canonical = tmp_path / "empire.ndjson"
    assert dataset_cli.main([
        "normalize", "--format", "otrf",
        "--input", str(FIXTURES / "empire_launcher_vbs.json"),
        "--metadata", str(FIXTURES / "SDWIN-190518182022.yaml"),
        "--output", str(canonical),
    ]) == 0
    manifest = json.loads((tmp_path / "empire.ndjson.manifest.json").read_text())
    assert manifest["events_written"] == len(canonical.read_text().splitlines())
    assert manifest["labels"]["label_semantics"] == LABEL_SEMANTICS
    assert manifest["input"]["sha256"] == hashlib.sha256(
        (FIXTURES / "empire_launcher_vbs.json").read_bytes()
    ).hexdigest()

    features = tmp_path / "features.jsonl"
    subprocess.run(
        [sys.executable, "-m", "panopticon_detection.cli", "--rules", str(ROOT / "rules"),
         "--officer-ndjson", str(canonical), "--export-features", str(features)],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    records = [json.loads(line) for line in features.read_text().splitlines()]
    agent = [r for r in records if r["pid"] == 2316 and r["name"] == "powershell.exe"]
    assert agent and agent[0]["script_block_count"] == 1


def test_fetch_refuses_a_download_with_the_wrong_hash(tmp_path, monkeypatch):
    payload = b"not the recording"

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return payload

    monkeypatch.setattr(dataset_cli.urllib.request, "urlopen", lambda url, timeout: _Response())
    target = tmp_path / "x.zip"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        dataset_cli._download("https://example.invalid/x.zip", "0" * 64, target)
    assert not target.exists()
    dataset_cli._download("https://example.invalid/x.zip", hashlib.sha256(payload).hexdigest(), target)
    assert target.read_bytes() == payload
