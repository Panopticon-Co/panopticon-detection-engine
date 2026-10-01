"""BehavioralSignal: explainable, serialisable, and an ordinary alert/tag downstream."""

import json

from panopticon_detection.behavioral.rarity import RarityBaseline, RarityDetector
from panopticon_detection.behavioral.signal import SIGNAL_CONFIDENCE, BehavioralSignal
from panopticon_detection.features import FeatureExtractor
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.tagging import tag_from_alert


def _proc(pid, name, second, ppid, parent_name, exe):
    return {
        "event_id": f"p{pid}",
        "event_type": "process_create",
        "host_id": "H",
        "timestamp": f"2026-09-01T12:00:{second:02d}Z",
        "process": {"pid": pid, "name": name, "executable": exe, "command_line": name},
        "parent": {"pid": ppid, "name": parent_name},
    }


def _signals():
    """Learn explorer->chrome, then see winword->powershell for the first time."""
    graph, registry = ProvenanceGraph(), ProcessRegistry()
    builder = EventGraphBuilder(graph, registry)
    for i in range(3):
        builder.apply(_proc(100 + i, "chrome.exe", i, 5, "explorer.exe", "C:\\Program Files\\c\\chrome.exe"))
    extractor = FeatureExtractor(registry, graph)
    baseline = RarityBaseline(min_observations=3, min_relationships=1, uncommon_max_count=0)
    baseline.fit(extractor.extract_all())

    event = _proc(300, "powershell.exe", 30, 200, "winword.exe", "C:\\Windows\\System32\\powershell.exe")
    builder.apply(event)
    return RarityDetector(baseline).evaluate(event, extractor), baseline, event


def test_a_signal_explains_itself():
    signals, baseline, event = _signals()
    assert len(signals) == 1
    s = signals[0]
    assert isinstance(s, BehavioralSignal)
    assert (s.detector, s.detector_version, s.model_version) == ("rarity", "1", baseline.version)
    assert (s.rule_id, s.signal_type, s.category) == ("BHV-RARE-001", "rare_parent_child", "unseen")
    assert s.explanation == (
        "Previously unseen parent-child relationship: winword.exe -> powershell.exe "
        f"(0 of 3 process starts in rarity baseline {baseline.version})."
    )
    assert s.measurement == {
        "dimension": "parent_child",
        "value": "winword.exe -> powershell.exe",
        "observed_count": 0,
        "baseline_total": 3,
        "relative_frequency": 0.0,
        "uncommon_max_count": 0,
    }
    # which process and event
    assert (s.host_id, s.event_id, s.pid, s.process_name) == ("H", event["event_id"], 300, "powershell.exe")
    assert s.node_id and s.timestamp == event["timestamp"]
    # which baseline, and the context an analyst needs
    assert s.evidence["baseline"]["baseline_version"] == baseline.version
    assert s.evidence["baseline"]["total_observations"] == 3
    assert s.evidence["process"]["parent_name"] == "winword.exe"


def test_signal_serialises_and_has_a_stable_id():
    signals, _, _ = _signals()
    again, _, _ = _signals()
    data = signals[0].to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["signal_id"] == signals[0].signal_id == again[0].signal_id
    assert data["signal_id"].startswith("BHV-")


def test_a_signal_becomes_an_ordinary_low_level_alert():
    s = _signals()[0][0]
    alert = s.to_alert()
    assert alert.rule_id == "BHV-RARE-001"
    assert alert.alert_id == s.signal_id
    assert alert.description == s.explanation
    assert (alert.level, alert.severity, alert.confidence) == (4, "low", SIGNAL_CONFIDENCE)
    assert alert.active_response is None
    assert alert.mitre_tactic is None and alert.mitre_technique is None
    assert alert.evidence["model_version"] == s.model_version
    assert alert.tags == ["behavioral", "rarity"]
    json.dumps(alert.to_dict())  # serialisable as every other alert is


def test_its_tag_can_join_an_incident_but_never_open_one():
    tag = tag_from_alert(_signals()[0][0].to_alert())
    assert tag.rule_id == "BHV-RARE-001"
    assert tag.tactic == "" and tag.active_response is None
    assert tag.is_anchor() is False
    assert tag.is_anchor(min_level=0) is False  # no tactic, so never terminal


def test_no_signal_for_common_behaviour_or_non_process_events():
    _, baseline, _ = _signals()
    graph, registry = ProvenanceGraph(), ProcessRegistry()
    builder = EventGraphBuilder(graph, registry)
    common = _proc(400, "chrome.exe", 40, 5, "explorer.exe", "C:\\Program Files\\c\\chrome.exe")
    builder.apply(common)
    detector = RarityDetector(baseline)
    extractor = FeatureExtractor(registry, graph)
    assert detector.evaluate(common, extractor) == []
    connect = {"event_type": "network_connect", "host_id": "H", "timestamp": common["timestamp"],
               "process": {"pid": 400}, "network": {"destination_ip": "93.184.216.34"}}
    assert detector.evaluate(connect, extractor) == []
