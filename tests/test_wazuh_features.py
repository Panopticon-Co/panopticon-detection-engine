"""Unit tests for Wazuh-grade features: Threat Intel, Thresholds, Active Response, and Rule Inheritance."""

from panopticon_detection.alerting.active_response import ActiveResponseEngine
from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.evaluator.threshold import ThresholdEngine
from panopticon_detection.rules.schema import Condition, LogicNode, Rule
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


def test_threat_intel_engine():
    ti = ThreatIntelEngine()
    
    # Test Mimikatz SHA256 match
    mimi_hash = "58593a38d72bb01c5f3b7c844cf19597793b8782a20b72c918a287a93540a931"
    match = ti.check_hash(mimi_hash)
    assert match is not None
    assert match["malware_family"] == "Mimikatz"
    assert match["severity_level"] == 15

    # Test unknown hash
    assert ti.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    # Test C2 IP match
    ip_match = ti.check_ip("198.51.100.45")
    assert ip_match is not None
    assert ip_match["threat_type"] == "Cobalt Strike C2 Server"


def test_threshold_engine():
    engine = ThresholdEngine()
    
    events = [
        {"event_type": "file_create", "host_id": "HOST-01", "timestamp": "2026-08-14T20:00:01Z", "process": {"name": "ransom.exe", "process_guid": "{G1}"}, "file": {"path": f"C:\\file_{i}.enc"}}
        for i in range(5)
    ]

    matches = []
    for ev in events:
        res = engine.ingest_event(ev)
        matches.extend(res)

    assert len(matches) == 1
    assert matches[0].rule.id == "DET-FREQ-001"
    assert matches[0].rule.level == 14
    assert matches[0].rule.active_response == "ISOLATE_HOST"


def test_active_response_resolution():
    # Level 15 process termination
    event = {
        "host_id": "HOST-FINANCE-01",
        "process": {"pid": 4500, "process_guid": "{GUID-123}", "name": "mimikatz.exe"},
    }
    action = ActiveResponseEngine.resolve_action(level=15, event=event, custom_action="TERMINATE_PROCESS")
    assert action is not None
    assert action.action == "TERMINATE_PROCESS"
    assert action.target_pid == 4500

    # Level 14 emergency host isolation
    action_iso = ActiveResponseEngine.resolve_action(level=14, event=event, custom_action="ISOLATE_HOST")
    assert action_iso is not None
    assert action_iso.action == "ISOLATE_HOST"
    assert action_iso.host_id == "HOST-FINANCE-01"


def test_rule_inheritance_depends_on():
    parent_rule = Rule(
        id="RULE-PARENT",
        name="Parent Rule",
        event_type="process_create",
        logic=LogicNode(all=[Condition(field="process.name", operator="equals", value="parent.exe")]),
    )

    child_rule = Rule(
        id="RULE-CHILD",
        name="Child Rule (Inherits from Parent)",
        event_type="process_create",
        depends_on_rule="RULE-PARENT",
        logic=LogicNode(all=[Condition(field="process.name", operator="equals", value="child.exe")]),
    )

    evaluator = RuleEvaluator(rules=[parent_rule, child_rule])

    # 1. Child event arrives BEFORE parent rule matched -> Should NOT trigger child rule
    res1 = evaluator.evaluate_event({
        "host_id": "HOST-01",
        "event_type": "process_create",
        "process": {"name": "child.exe"},
    })
    assert len(res1) == 0

    # 2. Parent event arrives -> Triggers parent rule
    res2 = evaluator.evaluate_event({
        "host_id": "HOST-01",
        "event_type": "process_create",
        "process": {"name": "parent.exe"},
    })
    assert len(res2) == 1
    assert res2[0].rule.id == "RULE-PARENT"

    # 3. Child event arrives AFTER parent rule matched on HOST-01 -> Triggers child rule!
    res3 = evaluator.evaluate_event({
        "host_id": "HOST-01",
        "event_type": "process_create",
        "process": {"name": "child.exe"},
    })
    assert len(res3) == 1
    assert res3[0].rule.id == "RULE-CHILD"


def test_threshold_match_survives_detection_run():
    """A threshold rule firing must not crash the pipeline.

    ThresholdRule is a plain dataclass with flat mitre_tactic/mitre_technique;
    the pydantic Rule has a nested `mitre` object. Treating one as the other
    raised AttributeError for every threshold alert, and no test caught it
    because the threshold engine was only ever driven directly, never through
    DetectionRun.
    """
    from panopticon_detection.detection_run import DetectionRun
    from panopticon_detection.evaluator.threshold import ThresholdEngine, ThresholdRule

    rule = ThresholdRule(
        id="DET-TH-TEST",
        name="burst",
        description="burst of file deletions",
        event_type="file_delete",
        frequency=2,
        timeframe_seconds=60,
        group_by=["host_id"],
        level=12,
        severity="high",
        confidence=0.9,
        mitre_tactic="Impact",
        mitre_technique="T1485",
    )
    emitted = []
    run = DetectionRun(
        graph_builder=type("_NoGraph", (), {"apply": lambda self, e: None})(),
        evaluator=type("_NoRules", (), {"evaluate_event": lambda self, e: [], "rules": []})(),
        threshold_engine=ThresholdEngine([rule]),
        campaign_detector=type("_NoCampaigns", (), {"on_tagged_edge": lambda self, e, t: None})(),
        risk_scorer=type("_NoRisk", (), {"record_detection": lambda self, **k: None})(),
        beacon_detector=type("_NoBeacon", (), {"ingest_connection": lambda self, e: None})(),
        port_scan_detector=type("_NoScan", (), {"ingest_connection": lambda self, e: []})(),
        ransomware_shield=type("_NoShield", (), {"inspect_file_event": lambda self, e: None})(),
        emit=emitted.append,
    )

    event = {
        "event_type": "file_delete",
        "host_id": "HOST-TH",
        "timestamp": "2026-09-14T10:00:00Z",
        "process": {"name": "wiper.exe", "pid": 4242},
        "file": {"path": "C:\\data\\a.txt"},
    }
    for _ in range(3):
        run.process_event(dict(event))

    threshold_alerts = [a for a in emitted if a.rule_id == "DET-TH-TEST"]
    assert threshold_alerts, "threshold rule produced no alert"
    assert threshold_alerts[0].mitre_tactic == "Impact"
    assert threshold_alerts[0].mitre_technique == "T1485"
