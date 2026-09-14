"""Unit and integration tests for the eyedetect detection engine."""

from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.evaluator.operators import (
    op_contains,
    op_ends_with,
    op_equals,
    op_in,
    op_regex,
    op_starts_with,
)
from panopticon_detection.rules.loader import RuleLoader


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
