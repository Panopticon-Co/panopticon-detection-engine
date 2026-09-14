"""Unit and integration tests for the eyedetect detection engine."""

import pytest
from src.rules.loader import RuleLoader
from src.evaluator.engine import RuleEvaluator
from src.evaluator.operators import (
    op_equals,
    op_contains,
    op_in,
    op_regex,
    op_starts_with,
    op_ends_with,
)
from src.rules.schema import Condition, LogicNode, Rule


def test_operators_basic():
    assert op_equals("powershell.exe", "POWERSHELL.EXE", case_sensitive=False)
    assert not op_equals("powershell.exe", "POWERSHELL.EXE", case_sensitive=True)
    assert op_contains("powershell.exe -enc ABC", "-ENC", case_sensitive=False)
    assert op_in("winword.exe", ["excel.exe", "WINWORD.EXE"])
    assert op_regex("powershell.exe -w hidden", r"-w\s+hidden")
    assert op_starts_with("C:\\Windows\\System32", "C:\\windows")
    assert op_ends_with("cmd.exe", ".EXE")


def test_rule_loading_and_validation():
    loader = RuleLoader()
    rule = loader.load_file("rules/process/DET-PROC-001_office_powershell.yaml")
    assert rule.id == "DET-PROC-001"
    assert rule.event_type == "process_create"
    assert rule.severity == "high"


def test_end_to_end_detection_evaluation():
    loader = RuleLoader()
    rules = loader.load_directory("rules")
    evaluator = RuleEvaluator(rules)

    # 1. Benign Event 1: Word spawning print driver
    benign_evt_1 = {
        "event_id": "evt-001",
        "event_type": "process_create",
        "process": {"name": "splwow64.exe", "pid": 1050, "command_line": "splwow64.exe"},
        "parent": {"name": "winword.exe", "pid": 3020},
    }
    assert len(evaluator.evaluate_event(benign_evt_1)) == 0

    # 2. Benign Event 2: Admin opening normal PowerShell
    benign_evt_2 = {
        "event_id": "evt-002",
        "event_type": "process_create",
        "process": {"name": "powershell.exe", "pid": 4100, "command_line": "powershell.exe"},
        "parent": {"name": "explorer.exe", "pid": 1100},
    }
    assert len(evaluator.evaluate_event(benign_evt_2)) == 0

    # 3. Malicious Event 3: Word spawning PowerShell with -enc
    malicious_evt = {
        "event_id": "evt-003",
        "host_id": "HOST-01",
        "event_type": "process_create",
        "process": {
            "name": "powershell.exe",
            "pid": 5520,
            "process_guid": "{GUID-003}",
            "command_line": "powershell.exe -w hidden -encodedcommand SQBFAFgA...",
        },
        "parent": {
            "name": "winword.exe",
            "pid": 3020,
        },
    }

    results = evaluator.evaluate_event(malicious_evt)
    matched_ids = [r.rule.id for r in results]
    assert "DET-PROC-001" in matched_ids

    res = next(r for r in results if r.rule.id == "DET-PROC-001")
    assert res.matched_evidence["process.name"] == "powershell.exe"
    assert res.matched_evidence["parent.name"] == "winword.exe"
    assert "-encodedcommand" in res.matched_evidence["process.command_line"]


def test_one_broken_rule_does_not_disable_other_candidate_rules_for_the_same_event():
    # Regression for a real reliability gap: evaluate_event used to have no
    # per-rule exception isolation, so one rule raising (e.g. an invalid
    # regex pattern) aborted the whole loop and silently withheld every
    # other candidate rule's verdict on that same event -- a broken rule
    # could blind unrelated rules of the same event_type indefinitely.
    broken_rule = Rule(
        id="DET-BROKEN-001",
        name="Deliberately broken rule",
        event_type="process_create",
        logic=LogicNode(all=[Condition(field="process.name", operator="regex", value="[")]),
    )
    healthy_rule = Rule(
        id="DET-HEALTHY-001",
        name="Always matches powershell",
        event_type="process_create",
        logic=LogicNode(all=[Condition(field="process.name", operator="equals", value="powershell.exe")]),
    )
    evaluator = RuleEvaluator([broken_rule, healthy_rule])
    event = {
        "event_id": "evt-broken-001",
        "event_type": "process_create",
        "process": {"name": "powershell.exe", "pid": 1},
    }

    results = evaluator.evaluate_event(event)

    matched_ids = [r.rule.id for r in results]
    assert "DET-HEALTHY-001" in matched_ids
    assert "DET-BROKEN-001" not in matched_ids
    assert evaluator.rule_errors.get("DET-BROKEN-001") == 1

    # A second event confirms the broken rule keeps failing in isolation
    # (observable, not a one-shot fluke) without ever taking the healthy
    # rule down with it.
    results2 = evaluator.evaluate_event(event)
    assert "DET-HEALTHY-001" in [r.rule.id for r in results2]
    assert evaluator.rule_errors.get("DET-BROKEN-001") == 2
