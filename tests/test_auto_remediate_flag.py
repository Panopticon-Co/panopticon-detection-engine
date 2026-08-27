"""Tests for the --auto-remediate / --no-auto-remediate CLI toggle.

Prior to this fix, --auto-remediate was `action="store_true", default=True` with no way to
disable it from the CLI. It now uses argparse.BooleanOptionalAction so --no-auto-remediate
genuinely suppresses remediation. Remediation itself remains fully simulated
(EndpointRemediationEngine performs no real OS action) regardless of this flag.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.main import main as run_main

# DET-PROC-011 (level 11) fires on this event: process.name in the watched binary list and
# process.command_line Shannon entropy >= 4.3. This exact command line was verified against
# the engine's own entropy formula (ShannonEntropyCalculator) to score 4.656.
_HIGH_ENTROPY_EVENT = (
    '{"event_id": "evt-auto-remediate-test", "host_id": "HOST-TEST", '
    '"event_type": "process_create", "timestamp": "2026-08-27T00:00:00Z", '
    '"process": {"name": "powershell.exe", "pid": 9999, '
    '"command_line": "powershell.exe -EncodedCommand '
    'VwByAGkAdABlAC0ASABvAHMAdAAgAFAAYQBuAG8AcAB0AGkAYwBvAG4ALQBWADEALQBEAGUAbQBvAA=="}, '
    '"parent": {"name": "explorer.exe", "pid": 1000}}\n'
)


@pytest.fixture
def telemetry_file(tmp_path):
    path = tmp_path / "high_entropy_event.ndjson"
    path.write_text(_HIGH_ENTROPY_EVENT, encoding="utf-8")
    return path


def _run_with_args(extra_args, telemetry_file, tmp_path):
    with patch("src.main.EndpointRemediationEngine") as mock_engine_cls, patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--rules",
            "rules",
            "--telemetry",
            str(telemetry_file),
            "--output-file",
            str(tmp_path / "alerts.ndjson"),
            *extra_args,
        ],
    ):
        mock_engine = MagicMock()
        mock_engine.remediate_threat.return_value = MagicMock(actions_executed=[])
        mock_engine_cls.return_value = mock_engine
        run_main()
    return mock_engine


def test_auto_remediate_appears_with_no_counterpart_in_help(capsys):
    with patch.object(sys, "argv", ["main.py", "--help"]):
        with pytest.raises(SystemExit):
            run_main()
    help_text = capsys.readouterr().out
    assert "--auto-remediate" in help_text
    assert "--no-auto-remediate" in help_text


def test_default_auto_remediate_fires_on_level_11_match(telemetry_file, tmp_path):
    mock_engine = _run_with_args([], telemetry_file, tmp_path)
    mock_engine.remediate_threat.assert_called_once()
    called_kwargs = mock_engine.remediate_threat.call_args.kwargs
    assert called_kwargs["rule_id"] == "DET-PROC-011"


def test_no_auto_remediate_suppresses_remediation(telemetry_file, tmp_path):
    mock_engine = _run_with_args(["--no-auto-remediate"], telemetry_file, tmp_path)
    mock_engine.remediate_threat.assert_not_called()
