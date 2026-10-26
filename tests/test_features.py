"""Process feature extraction: one extractor, deterministic, from real telemetry only."""

import json

import pytest

from panopticon_detection import enrichment
from panopticon_detection.enrichment import MatchContext
from panopticon_detection.features import (
    FEATURE_SCHEMA_VERSION,
    FeatureExtractor,
    ProcessFeatures,
    read_jsonl,
    write_jsonl,
)
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry, parse_timestamp

TEMP_PAYLOAD = "C:\\Users\\a\\AppData\\Local\\Temp\\p.exe"


def _ts(second):
    return f"2026-09-01T12:00:{second:02d}Z"


def _proc(pid, name, t, exe, ppid=None, parent_name=None, cmd=None):
    parent = {"pid": ppid, "name": parent_name} if ppid else {}
    return {
        "event_id": f"p{pid}",
        "event_type": "process_create",
        "host_id": "H",
        "timestamp": _ts(t),
        "process": {"pid": pid, "name": name, "executable": exe, "command_line": cmd or name},
        "parent": parent,
    }


def _act(pid, t, event_type, **body):
    return {"event_id": f"{event_type}-{pid}-{t}", "event_type": event_type, "host_id": "H",
            "timestamp": _ts(t), "process": {"pid": pid}, **body}


def _chain():
    """winword -> powershell (encoded) -> drops and runs p.exe -> p.exe phones home."""
    graph, registry = ProvenanceGraph(), ProcessRegistry()
    builder = EventGraphBuilder(graph, registry)
    events = [
        _proc(10, "winword.exe", 0, "C:\\Program Files\\Office\\WINWORD.EXE", ppid=5, parent_name="explorer.exe"),
        _proc(20, "powershell.exe", 2, "C:\\Windows\\System32\\powershell.exe", ppid=10,
              cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
        _act(20, 4, "file_create", file={"path": TEMP_PAYLOAD}),
        _act(20, 5, "file_create", file={"path": "C:\\Users\\a\\notes.txt"}),
        _act(20, 6, "registry_write", registry={"key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "p"}),
        _proc(30, "p.exe", 11, TEMP_PAYLOAD, ppid=20),
        _act(30, 20, "network_connect", network={"destination_ip": "93.184.216.34", "destination_port": 443}),
        _act(30, 21, "network_connect", network={"destination_ip": "10.0.0.5", "destination_port": 445}),
    ]
    for event in events:
        builder.apply(event)
    return graph, registry, events


def _features(registry, graph, name, as_of=None):
    process = next(p for p in registry if p.name == name)
    return FeatureExtractor(registry, graph).extract(process, as_of)


def test_extraction_is_deterministic():
    graph, registry, _ = _chain()
    extractor = FeatureExtractor(registry, graph)
    assert extractor.extract_all() == extractor.extract_all()
    graph2, registry2, _ = _chain()
    assert FeatureExtractor(registry2, graph2).extract_all() == extractor.extract_all()


def test_identity_and_lineage():
    graph, registry, _ = _chain()
    f = _features(registry, graph, "p.exe")
    assert f.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert (f.host_id, f.pid, f.parent_pid, f.name) == ("H", 30, 20, "p.exe")
    assert f.executable == TEMP_PAYLOAD and f.path_class == "temp"
    assert f.start_time == "2026-09-01T12:00:11"
    assert f.inferred is False
    assert f.parent_name == "powershell.exe"
    assert f.grandparent_name == "winword.exe"
    assert f.parent_child == "powershell.exe -> p.exe"
    # explorer.exe is a boundary hub, so the tree's entry point is winword.exe.
    assert f.tree_root_name == "winword.exe"
    assert f.depth == 3  # powershell, winword, (inferred) explorer


def test_inferred_parent_is_flagged():
    graph, registry, _ = _chain()
    explorer = next(p for p in registry if p.name == "explorer.exe")
    f = FeatureExtractor(registry, graph).extract(explorer)
    assert f.inferred is True
    assert f.parent_child is None and f.parent_name is None and f.depth == 0


def test_command_line_features():
    graph, registry, _ = _chain()
    f = _features(registry, graph, "powershell.exe")
    assert f.cmdline_length == len(next(p for p in registry if p.name == "powershell.exe").command_line)
    assert f.cmdline_token_count == 6
    assert f.cmdline_obfuscated is True and f.cmdline_evasion_count >= 1
    assert f.cmdline_entropy > 3.0


def test_provenance_matches_the_rule_field():
    graph, registry, events = _chain()
    f = _features(registry, graph, "p.exe")
    assert f.image_writer_name == "powershell.exe"
    assert f.image_age_seconds == 7.0
    # The feature and the rule-facing derived field are one computation.
    ctx = MatchContext(registry=registry, graph=graph)
    launch = next(e for e in events if e["event_id"] == "p30")
    enrichment.reset(launch)
    assert enrichment.derive(launch, "process.image_writer_name", ctx) == f.image_writer_name
    assert enrichment.derive(launch, "process.image_age_seconds", ctx) == f.image_age_seconds


def test_behavior_counts():
    graph, registry, _ = _chain()
    ps = _features(registry, graph, "powershell.exe")
    assert (ps.child_count, ps.file_write_count, ps.executable_write_count) == (1, 2, 1)
    assert ps.registry_write_count == 1
    payload = _features(registry, graph, "p.exe")
    assert (payload.network_connect_count, payload.public_connect_count) == (2, 1)


def test_as_of_excludes_later_activity():
    graph, registry, _ = _chain()
    at_start = _features(registry, graph, "powershell.exe", as_of=parse_timestamp(_ts(2)))
    assert at_start.as_of == "2026-09-01T12:00:02"
    assert (at_start.child_count, at_start.file_write_count, at_start.registry_write_count) == (0, 0, 0)
    mid = _features(registry, graph, "powershell.exe", as_of=parse_timestamp(_ts(5)))
    assert (mid.file_write_count, mid.registry_write_count) == (2, 0)


def test_missing_optional_fields():
    graph, registry = ProvenanceGraph(), ProcessRegistry()
    builder = EventGraphBuilder(graph, registry)
    builder.apply({"event_id": "x", "event_type": "process_create", "host_id": "H",
                   "timestamp": _ts(0), "process": {"pid": 7}})
    f = FeatureExtractor(registry, graph).extract_all()[0]
    assert f.name == "" and f.executable == "" and f.path_class is None
    assert f.parent_pid is None and f.parent_child is None and f.tree_root_name is None
    assert (f.cmdline_length, f.cmdline_token_count, f.cmdline_entropy) == (0, 0, 0.0)
    assert f.cmdline_obfuscated is False and f.image_writer_name is None


def test_extract_event_resolves_the_actor_at_event_time():
    graph, registry, events = _chain()
    f = FeatureExtractor(registry, graph).extract_event(events[-2])
    assert f.name == "p.exe" and f.as_of == "2026-09-01T12:00:20"
    assert f.network_connect_count == 1  # the connection at :21 has not happened yet
    unknown = {"event_type": "network_connect", "host_id": "H", "timestamp": _ts(30), "process": {"pid": 999}}
    assert FeatureExtractor(registry, graph).extract_event(unknown) is None


def test_serialization_round_trip(tmp_path):
    graph, registry, _ = _chain()
    records = FeatureExtractor(registry, graph).extract_all()
    path = tmp_path / "f.jsonl"
    assert write_jsonl(records, path) == len(records)
    assert list(read_jsonl(path)) == records
    first = json.loads(path.read_text().splitlines()[0])
    assert list(first) == list(records[0].to_dict())  # stable field order
    assert ProcessFeatures.from_dict(first) == records[0]


def test_from_dict_rejects_unknown_fields():
    graph, registry, _ = _chain()
    data = FeatureExtractor(registry, graph).extract_all()[0].to_dict()
    data["made_up"] = 1
    with pytest.raises(ValueError, match="made_up"):
        ProcessFeatures.from_dict(data)
