"""Privilege-escalation rule coverage.

Scoped to rules that fire on telemetry a Panopticon agent actually emits.
The driver_load, directory_service and k8s_audit cases were removed with the
rules they exercised -- nothing produces those event types.
"""

import pytest

from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.rules.loader import RuleLoader


@pytest.fixture
def evaluator():
    return RuleEvaluator(RuleLoader().load_directory("rules"))


def test_unquoted_service_path_escalation(evaluator):
    evt = {
        "event_type": "process_create",
        "process": {
            "name": "Program.exe",
            "command_line": "C:\\Program.exe",
            "pid": 2040,
            "user": "NT AUTHORITY\\SYSTEM",
            "is_unquoted_service_path": True,
        },
        "host_id": "SRV-FILE-01",
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-PRIV-004" in rule_ids


def test_horizontal_privilege_escalation(evaluator):
    evt = {
        "event_type": "process_create",
        "process": {
            "name": "runas.exe",
            "command_line": "runas.exe /user:hr_manager /netonly powershell.exe",
            "pid": 3100,
            "user": "alice_finance",
        },
        "host_id": "WS-FIN-02",
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-PRIV-006" in rule_ids


def test_application_lpe_privilege_escalation(evaluator):
    evt = {
        "event_type": "process_create",
        "parent": {"name": "vulnerable_backup_agent.exe", "pid": 1050},
        "process": {
            "name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "pid": 1055,
            "user": "NT AUTHORITY\\SYSTEM",
        },
        "host_id": "SRV-BACKUP",
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-PRIV-007" in rule_ids
