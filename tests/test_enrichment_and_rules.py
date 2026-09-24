"""Enrichment, normalization, rule loading and the field-level sourcing gate."""

import importlib.util
from pathlib import Path

import pytest

from panopticon_detection import enrichment
from panopticon_detection.enrichment import MatchContext, classify_path, destination_scope
from panopticon_detection.ingestion import telemetry
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.rules.validator import RuleValidationError

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------- classifiers


@pytest.mark.parametrize(
    "path,expected",
    [
        ("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe", "temp"),
        ("C:\\Users\\a\\Downloads\\x.exe", "user_writable"),
        ("C:\\ProgramData\\x\\y.exe", "user_writable"),
        ("C:\\Program Files\\App\\app.exe", "program_files"),
        ("C:\\Windows\\System32\\cmd.exe", "system"),
        ("/tmp/.x/implant", "temp"),
        ("/home/bob/run.sh", "user_writable"),
        ("/usr/bin/curl", "system"),
        ("D:\\tools\\x.exe", "other"),
        ("powershell.exe", "unknown"),
        (None, None),
    ],
)
def test_classify_path(path, expected):
    assert classify_path(path) == expected


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("93.184.216.34", "public"),
        ("203.0.113.10", "public"),  # RFC 5737: stands in for an Internet host
        ("10.1.2.3", "private"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.10.1", "link_local"),
        ("224.0.0.251", "multicast"),
        ("not-an-ip", "unknown"),
    ],
)
def test_destination_scope(ip, expected):
    assert destination_scope(ip) == expected


# ---------------------------------------------------- graph-derived fields


def _wired():
    graph, registry = ProvenanceGraph(), ProcessRegistry()
    return graph, registry, EventGraphBuilder(graph, registry)


def _proc(pid, name, t, exe, ppid=None):
    return {
        "event_id": f"p{pid}",
        "event_type": "process_create",
        "host_id": "H",
        "timestamp": f"2026-09-01T12:00:{t:02d}Z",
        "process": {"pid": pid, "name": name, "executable": exe, "command_line": name},
        "parent": {"pid": ppid} if ppid else {},
    }


def test_image_writer_and_age_come_from_the_graph():
    graph, registry, builder = _wired()
    payload = "C:\\Users\\a\\AppData\\Local\\Temp\\p.exe"
    builder.apply(_proc(10, "powershell.exe", 0, "C:\\Windows\\System32\\powershell.exe"))
    builder.apply({
        "event_id": "f1", "event_type": "file_create", "host_id": "H",
        "timestamp": "2026-09-01T12:00:05Z", "process": {"pid": 10}, "file": {"path": payload},
    })
    event = _proc(20, "p.exe", 12, payload, ppid=10)
    builder.apply(event)

    ctx = MatchContext(registry=registry, graph=graph)
    assert enrichment.derive(event, "process.image_writer_name", ctx) == "powershell.exe"
    assert enrichment.derive(event, "process.image_age_seconds", ctx) == 7.0
    assert enrichment.derive(event, "process.path_class", ctx) == "temp"
    assert enrichment.derive(event, "process.tree_root_name", ctx) == "powershell.exe"


def test_an_image_nobody_wrote_has_no_writer():
    graph, registry, builder = _wired()
    event = _proc(20, "cmd.exe", 1, "C:\\Windows\\System32\\cmd.exe")
    builder.apply(event)
    ctx = MatchContext(registry=registry, graph=graph)
    assert enrichment.derive(event, "process.image_writer_name", ctx) is None


def test_extension_change_on_rename():
    ctx = MatchContext()
    changed = {"event_type": "file_rename", "file": {"path": "C:\\d\\a.docx.akira", "previous_path": "C:\\d\\a.docx"}}
    kept = {"event_type": "file_rename", "file": {"path": "C:\\d\\a.docx", "previous_path": "C:\\d\\~a.docx"}}
    assert enrichment.derive(changed, "file.extension_changed", ctx) is True
    assert enrichment.derive(kept, "file.extension_changed", ctx) is False


def test_derived_values_are_computed_once_per_event(monkeypatch):
    calls = []
    real = enrichment.CommandDeobfuscator.deobfuscate

    def counting(cmd):
        calls.append(cmd)
        return real(cmd)

    monkeypatch.setattr(enrichment.CommandDeobfuscator, "deobfuscate", staticmethod(counting))
    event = {"event_type": "process_create", "process": {"command_line": "powershell -enc AAAA"}}
    ctx = MatchContext()
    for field in ("process.deobfuscated_command", "process.is_obfuscated", "process.evasion_techniques"):
        enrichment.derive(event, field, ctx)
    assert len(calls) == 1


# ------------------------------------------------------------ normalizer


def _raw(category="process", etype="start", **extra):
    return {
        "schema_version": "0.4",
        "event": {"id": "evt_1", "category": category, "type": etype, "timestamp": "2026-09-01T12:00:00.000Z"},
        "source": {"kind": "etw", "provider": "p"},
        "agent": {"id": "a", "version": "v"},
        "host": {"id": "h", "hostname": "h", "os": {"name": "Linux", "build": "6"}},
        "user": {"name": "root", "domain": None, "sid": None},
        "process": {
            "entity_id": "proc_x", "pid": 4242, "name": None, "executable": "/usr/bin/curl",
            "command_line": "curl", "start_time_ticks": 998877,
            "parent": {"entity_id": None, "pid": 1, "name": None},
            "hash": {"sha256": None},
        },
        **extra,
    }


def test_one_normalizer_for_every_family():
    raw = _raw()
    assert OfficerIngestionAdapter.transform_officer_event(raw) == telemetry.normalize(raw)


def test_process_context_keeps_start_time_ticks_and_derives_a_linux_name():
    event = telemetry.normalize(_raw())
    assert event["process"]["start_time_ticks"] == 998877
    assert event["process"]["name"] == "curl"
    network = telemetry.normalize(_raw("network", "connect", network={"destination_ip": "1.1.1.1"}))
    assert network["process"]["start_time_ticks"] == 998877


def test_the_field_registry_knows_each_family():
    assert "network.destination_ip" in telemetry.producible_fields("network_connect")
    assert "network.destination_ip" not in telemetry.producible_fields("process_create")
    assert "registry.value_data" in telemetry.producible_fields("registry_write")
    assert "process.ppid_spoofed" not in telemetry.producible_fields("process_create")


# ---------------------------------------------------------- rule loading


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


_RULE = """id: T-1
name: t
level: 10
event_type: process_create
logic:
  all:
    - field: process.name
      operator: in
      value: {value}
"""


def test_named_lists_resolve(tmp_path):
    _write(tmp_path, "lists/shells.yaml", "values: [cmd.exe, powershell.exe]\n")
    _write(tmp_path, "r.yaml", _RULE.format(value="$shells"))
    rule = RuleLoader().load_directory(tmp_path)[0]
    assert rule.logic.all[0].value == ["cmd.exe", "powershell.exe"]


def test_an_unknown_list_is_an_error(tmp_path):
    _write(tmp_path, "r.yaml", _RULE.format(value="$nope"))
    with pytest.raises(RuleValidationError, match="unknown list"):
        RuleLoader().load_directory(tmp_path)


def test_a_misspelled_key_is_rejected_not_ignored(tmp_path):
    _write(tmp_path, "r.yaml", _RULE.format(value="[cmd.exe]") + "severty: high\n")
    with pytest.raises(RuleValidationError):
        RuleLoader().load_directory(tmp_path)


def _gate():
    spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts" / "check_rule_sourcing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_shipped_rules_pass_the_field_gate():
    assert _gate().check(ROOT / "rules") == []


def test_the_gate_catches_a_field_nothing_produces(tmp_path):
    _write(tmp_path, "r.yaml", """id: T-DEAD
name: dead
level: 10
event_type: process_create
logic:
  all:
    - field: process.ppid_spoofed
      operator: equals
      value: true
""")
    problems = _gate().check(tmp_path)
    assert problems and "process.ppid_spoofed" in problems[0]


def test_the_gate_catches_a_derived_field_on_the_wrong_event_type(tmp_path):
    _write(tmp_path, "r.yaml", """id: T-WRONG
name: wrong
level: 10
event_type: process_create
logic:
  all:
    - field: network.destination_scope
      operator: equals
      value: public
""")
    assert _gate().check(tmp_path)
