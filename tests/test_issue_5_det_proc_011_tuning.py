"""Tests for Issue #5: DET-PROC-011 false positive suppression on PowerShell test harness scripts.

Verifies that benign .ps1 script file executions (e.g. `standalone_driver_run.ps1`) do not
trigger false positive alerts under DET-PROC-011, while genuine high-entropy obfuscated
payloads (e.g. Base64 / EncodedCommand) continue to trigger reliably.
"""

from pathlib import Path

import pytest

from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.rules.loader import RuleLoader

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


@pytest.fixture
def det_proc_011_evaluator():
    loader = RuleLoader()
    rule_path = RULES_DIR / "process" / "DET-PROC-011_obfuscated_high_entropy_script.yaml"
    rule = loader.load_file(rule_path)
    return RuleEvaluator(rules=[rule])


def test_det_proc_011_suppresses_test_harness_false_positive(det_proc_011_evaluator):
    """Verifies that standalone_driver_run.ps1 and other test scripts are ignored."""
    harness_events = [
        {
            "event_type": "process_create",
            "process": {
                "name": "powershell.exe",
                "pid": 28984,
                "command_line": r"powershell.exe -File C:\Users\runneradmin\AppData\Local\Temp\standalone_driver_run.ps1",
            },
        },
        {
            "event_type": "process_create",
            "process": {
                "name": "powershell.exe",
                "pid": 12345,
                "command_line": r"powershell.exe -ExecutionPolicy Bypass -File .\scripts\test_harness.ps1 -Target demo",
            },
        },
        {
            "event_type": "process_create",
            "process": {
                "name": "pwsh.exe",
                "pid": 67890,
                "command_line": r"pwsh.exe -f C:\panopticon\tests\integration_run.ps1",
            },
        },
    ]

    for event in harness_events:
        matches = det_proc_011_evaluator.evaluate_event(event)
        assert len(matches) == 0, f"False positive triggered for: {event['process']['command_line']}"


def test_det_proc_011_fires_on_genuine_obfuscated_payload(det_proc_011_evaluator):
    """Verifies that actual high-entropy obfuscated / EncodedCommand payloads still trigger."""
    malicious_event = {
        "event_type": "process_create",
        "process": {
            "name": "powershell.exe",
            "pid": 9999,
            "command_line": (
                "powershell.exe -EncodedCommand "
                "VwByAGkAdABlAC0ASABvAHMAdAAgAFAAYQBuAG8AcAB0AGkAYwBvAG4ALQBWADEALQBEAGUAbQBvAA=="
            ),
        },
    }

    matches = det_proc_011_evaluator.evaluate_event(malicious_event)
    assert len(matches) == 1
    assert matches[0].rule.id == "DET-PROC-011"
    assert matches[0].rule.level == 11
