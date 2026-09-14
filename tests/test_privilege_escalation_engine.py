"""Unit tests validating detection of all 8 major types of Privilege Escalation."""

import pytest

from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.rules.loader import RuleLoader


@pytest.fixture
def evaluator():
    loader = RuleLoader()
    # Includes rules/unsourced/: this suite exercises rule logic against
    # synthetic events, not the live agent-sourced rule set.
    rules = loader.load_directory("rules", include_unsourced=True)
    return RuleEvaluator(rules)


def test_kernel_byovd_privilege_escalation(evaluator):
    evt = {
        "event_type": "driver_load",
        "driver": {
            "name": "gdrv.sys",
            "path": "C:\\Windows\\Temp\\gdrv.sys",
            "is_kernel_mode": True,
            "loaded_by_process": "malicious_loader.exe",
        },
        "host_id": "WS-SEC-01",
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-PRIV-005" in rule_ids


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


def test_domain_gpo_acl_privilege_escalation(evaluator):
    evt = {
        "event_type": "directory_service",
        "action": "GPO_Modified",
        "user": {"name": "attacker_user"},
        "directory": {
            "target_object": "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local",
            "granted_permissions": "WriteDacl",
        },
        "host_id": "DC-PRIMARY",
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-IDENT-012" in rule_ids


def test_kubernetes_rbac_privilege_escalation(evaluator):
    evt = {
        "event_type": "k8s_audit",
        "k8s": {
            "verb": "create",
            "role_ref": "cluster-admin",
            "subject_kind": "ServiceAccount",
            "subject_name": "default",
        },
        "user": {"name": "compromised-sa"},
        "cloud": {"provider": "KUBERNETES", "account_id": "K8S-PROD"},
    }
    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-CLOUD-004" in rule_ids


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
