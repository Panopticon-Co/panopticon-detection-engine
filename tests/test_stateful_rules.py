"""Stateful rules: sequence, threshold and value_count.

Each behaviour below is something the single-event rule language could not
express: order, time windows, counting, distinct values, and keying on a
process identity that spans telemetry families and process trees.
"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from panopticon_detection.evaluator.stateful import StatefulEvaluator
from panopticon_detection.factory import build_detection_run
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.rules.schema import RULE_TYPES, parse_duration

RULES = Path(__file__).resolve().parent.parent / "rules"
BASE = datetime(2026, 9, 1, 12, 0, 0)


def ts(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat() + "Z"


def proc(pid, name, t, ppid=None, exe=None, cmd=None):
    return {
        "event_id": f"p-{pid}-{t}",
        "event_type": "process_create",
        "host_id": "H",
        "timestamp": ts(t),
        "process": {
            "pid": pid,
            "name": name,
            "executable": exe or f"C:\\Windows\\System32\\{name}",
            "command_line": cmd or name,
        },
        "parent": {"pid": ppid} if ppid else {},
    }


def connect(pid, t, ip="93.184.216.34", port=443):
    return {
        "event_id": f"n-{pid}-{t}-{ip}-{port}",
        "event_type": "network_connect",
        "host_id": "H",
        "timestamp": ts(t),
        "process": {"pid": pid},
        "network": {"direction": "outbound", "destination_ip": ip, "destination_port": port},
    }


def file_event(pid, t, path, op="create", previous=None):
    return {
        "event_id": f"f-{pid}-{t}-{path}",
        "event_type": f"file_{op}",
        "host_id": "H",
        "timestamp": ts(t),
        "process": {"pid": pid},
        "file": {"path": path, "previous_path": previous},
    }


def rule(**spec):
    base = {"name": spec.get("id", "rule"), "level": 12, "severity": "high"}
    base.update(spec)
    return RULE_TYPES[base["type"]](**base)


class Harness:
    def __init__(self, *rules):
        self.graph = ProvenanceGraph()
        self.registry = ProcessRegistry()
        self.builder = EventGraphBuilder(self.graph, self.registry)
        self.stateful = StatefulEvaluator(list(rules), registry=self.registry, graph=self.graph)

    def feed(self, *events):
        fired = []
        for event in events:
            self.builder.apply(event)
            fired += [r.rule.id for r in self.stateful.evaluate_event(event)]
        return fired


def _name_is(name):
    return {"all": [{"field": "process.name", "operator": "equals", "value": name}]}


OUTBOUND = {"all": [{"field": "network.direction", "operator": "equals", "value": "outbound"}]}


def seq(by="process", maxspan="60s"):
    return rule(
        id="SEQ",
        type="sequence",
        by=by,
        maxspan=maxspan,
        steps=[
            {"event_type": "process_create", "logic": _name_is("stage.exe")},
            {"event_type": "network_connect", "logic": OUTBOUND},
        ],
    )


# --------------------------------------------------------------- sequence


def test_a_sequence_fires_once_when_its_steps_occur_in_order():
    h = Harness(seq())
    assert h.feed(proc(10, "stage.exe", 0)) == []
    assert h.feed(connect(10, 5)) == ["SEQ"]
    assert h.feed(connect(10, 6), connect(10, 7)) == [], "consumed; must not refire per connection"


def test_a_sequence_respects_maxspan():
    h = Harness(seq(maxspan="30s"))
    assert h.feed(proc(10, "stage.exe", 0), connect(10, 45)) == []


def test_a_sequence_keyed_by_process_ignores_other_processes():
    h = Harness(seq())
    assert h.feed(proc(10, "stage.exe", 0), proc(20, "other.exe", 1), connect(20, 5)) == []


def test_a_sequence_keyed_by_process_tree_spans_parent_and_child():
    """The script host starts; its child is what connects out."""
    h = Harness(seq(by="process_tree"))
    fired = h.feed(
        proc(5, "winword.exe", 0),
        proc(10, "stage.exe", 1, ppid=5),
        proc(11, "child.exe", 2, ppid=10),
        connect(11, 5),
    )
    assert fired == ["SEQ"]


def test_a_sequence_does_not_match_out_of_order():
    r = rule(
        id="ORDER",
        type="sequence",
        by="process",
        maxspan="5m",
        steps=[
            {"event_type": "file_create", "logic": {"all": [{"field": "file.extension", "operator": "equals", "value": ".exe"}]}},
            {"event_type": "network_connect", "logic": OUTBOUND},
        ],
    )
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    assert h.feed(connect(10, 5), file_event(10, 6, "C:\\Users\\u\\x.exe")) == []
    assert h.feed(connect(10, 7)) == ["ORDER"]


def test_sequence_evidence_names_each_step():
    h = Harness(seq())
    h.feed(proc(10, "stage.exe", 0))
    h.builder.apply(connect(10, 5))
    result = h.stateful.evaluate_event(connect(10, 5))
    evidence = result[0].matched_evidence
    assert len(evidence["sequence"]) == 2
    assert evidence["sequence"][0].startswith("step 1: process_create stage.exe[10]")
    assert "93.184.216.34:443" in evidence["sequence"][1]
    assert any(c.startswith("step 2: network.direction") for c in result[0].matched_conditions)


# ------------------------------------------------------ threshold / count


def test_a_threshold_fires_at_count_within_the_window_then_resets():
    r = rule(id="TH", type="threshold", by="process", event_type="network_connect",
             logic=OUTBOUND, count=3, window="10s")
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    assert h.feed(connect(10, 1), connect(10, 2)) == []
    assert h.feed(connect(10, 3)) == ["TH"]
    assert h.feed(connect(10, 4)) == [], "window cleared on fire"


def test_a_threshold_spread_beyond_its_window_does_not_fire():
    r = rule(id="TH", type="threshold", by="process", event_type="network_connect",
             logic=OUTBOUND, count=3, window="10s")
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    assert h.feed(connect(10, 1), connect(10, 20), connect(10, 40)) == []


def test_value_count_counts_distinct_values_only():
    r = rule(id="VC", type="value_count", by="process", event_type="network_connect",
             logic=OUTBOUND, field="network.destination_ip", count=3, window="60s")
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    assert h.feed(*[connect(10, i, ip="10.0.0.1") for i in range(1, 10)]) == []
    assert h.feed(connect(10, 11, ip="10.0.0.2"), connect(10, 12, ip="10.0.0.3")) == ["VC"]


def test_a_composite_key_separates_destinations():
    r = rule(id="VERT", type="value_count", by=["process", "network.destination_ip"],
             event_type="network_connect", logic=OUTBOUND,
             field="network.destination_port", count=3, window="60s")
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    spread = [connect(10, i, ip=f"10.0.0.{i}", port=1000 + i) for i in range(1, 6)]
    assert h.feed(*spread) == [], "five ports on five hosts is not a vertical scan"
    ports = (22, 80, 443)
    assert h.feed(*[connect(10, 20 + i, ip="10.0.0.9", port=p) for i, p in enumerate(ports)]) == ["VERT"]


def test_an_event_that_cannot_be_keyed_is_skipped():
    r = rule(id="TH", type="threshold", by="user", event_type="network_connect",
             logic=OUTBOUND, count=2, window="60s")
    h = Harness(r)
    h.feed(proc(10, "a.exe", 0))
    assert h.feed(connect(10, 1), connect(10, 2)) == []


def test_prune_drops_stale_state():
    h = Harness(seq(), rule(id="TH", type="threshold", by="process", event_type="network_connect",
                            logic=OUTBOUND, count=50, window="60s"))
    h.feed(proc(10, "stage.exe", 0), connect(20, 1))
    assert h.stateful.state_size()["sequence_keys"] == 1
    assert h.stateful.prune(BASE + timedelta(hours=1)) >= 1
    assert h.stateful.state_size() == {
        "sequence_keys": 0, "open_sequence_matches": 0, "window_keys": 0, "window_events": 0,
    }


@pytest.mark.parametrize("value,seconds", [(90, 90), ("90s", 90), ("5m", 300), ("1h", 3600)])
def test_durations(value, seconds):
    assert parse_duration(value) == seconds


def test_a_bad_duration_is_rejected():
    with pytest.raises(Exception):
        seq(maxspan="soon")


# ------------------------------------------- migrated behavioural detections


def _run():
    return build_detection_run(RULES)[0]


def _fired(run, events):
    return [a.rule_id for e in events for a in run.process_event(e)]


def test_an_internal_sweep_is_a_scan_but_browser_fanout_is_not():
    run = _run()
    run.process_event(proc(10, "powershell.exe", 0))
    run.process_event(proc(20, "chrome.exe", 0))
    browser = [connect(20, i, ip=f"93.184.216.{i}") for i in range(1, 15)]
    sweep = [connect(10, 20 + i, ip=f"10.0.0.{i}", port=445) for i in range(1, 12)]
    assert "DET-NET-005" not in _fired(run, browser)
    assert _fired(run, sweep).count("DET-NET-005") == 1


def test_a_vertical_scan_of_one_host_is_detected():
    run = _run()
    run.process_event(proc(10, "scanner.exe", 0))
    events = [connect(10, i, ip="10.0.0.50", port=1000 + i) for i in range(16)]
    assert "DET-NET-008" in _fired(run, events)


def test_mass_renames_changing_extension_is_ransomware_behaviour():
    run = _run()
    run.process_event(proc(10, "crypt.exe", 0, exe="C:\\Users\\u\\AppData\\Local\\Temp\\crypt.exe"))
    renames = [
        file_event(10, 1 + i * 0.5, f"C:\\Users\\u\\Documents\\f{i}.docx.bin", op="rename",
                   previous=f"C:\\Users\\u\\Documents\\f{i}.docx")
        for i in range(12)
    ]
    assert _fired(run, renames).count("DET-RANS-001") == 1


def test_renames_that_keep_the_extension_are_not_ransomware():
    run = _run()
    run.process_event(proc(10, "backup.exe", 0))
    renames = [
        file_event(10, 1 + i, f"C:\\data\\f{i}.docx", op="rename", previous=f"C:\\data\\f{i}.tmp.docx")
        for i in range(12)
    ]
    assert "DET-RANS-001" not in _fired(run, renames)


def test_a_discovery_burst_from_one_parent_is_detected():
    run = _run()
    run.process_event(proc(5, "cmd.exe", 0))
    tools = ["whoami.exe", "ipconfig.exe", "nltest.exe"]
    events = [proc(10 + i, name, 1 + i, ppid=5) for i, name in enumerate(tools)]
    assert "DET-DISC-001" in _fired(run, events)
