"""Tests for --officer-source CLI parsing and propagation to the Officer subprocess.

Covers the wiring introduced to let operators pin the live Officer subprocess to a
single collector source (etw or sysmon) instead of always running both ("all").
No collector, Schema 0.2, or detection-rule behavior is touched by this feature.
"""
import sys
from unittest.mock import MagicMock, patch

import pytest

from panopticon_detection.cli import main as run_main
from panopticon_detection.ingestion.live_stream import LiveTelemetryStream


def _fake_officer_process():
    fake_process = MagicMock()
    fake_process.stdout = iter([])
    fake_process.stderr = iter([])
    fake_process.wait.return_value = 0
    return fake_process


@pytest.mark.parametrize("source", ["etw", "sysmon", "all"])
def test_stream_from_officer_process_forwards_source_flag(source):
    with patch("panopticon_detection.ingestion.live_stream.subprocess.Popen") as mock_popen:
        mock_popen.return_value = _fake_officer_process()
        list(LiveTelemetryStream.stream_from_officer_process("officer-agent.exe", source=source))

    called_cmd = mock_popen.call_args[0][0]
    assert called_cmd == ["officer-agent.exe", "--source", source]


def test_stream_from_officer_process_defaults_to_all():
    with patch("panopticon_detection.ingestion.live_stream.subprocess.Popen") as mock_popen:
        mock_popen.return_value = _fake_officer_process()
        list(LiveTelemetryStream.stream_from_officer_process("officer-agent.exe"))

    called_cmd = mock_popen.call_args[0][0]
    assert called_cmd == ["officer-agent.exe", "--source", "all"]


def test_officer_source_appears_in_help(capsys):
    with patch.object(sys, "argv", ["main.py", "--help"]):
        with pytest.raises(SystemExit):
            run_main()
    help_text = capsys.readouterr().out
    assert "--officer-source" in help_text
    assert "{etw,sysmon,all}" in help_text


def test_officer_source_rejects_invalid_choice(capsys):
    with patch.object(
        sys,
        "argv",
        ["main.py", "--officer", "--officer-source", "bogus"],
    ):
        with pytest.raises(SystemExit):
            run_main()
    stderr = capsys.readouterr().err
    assert "--officer-source" in stderr


@pytest.mark.parametrize("source", ["etw", "sysmon", "all"])
def test_officer_source_propagates_from_cli_to_subprocess(source, tmp_path):
    with patch("panopticon_detection.ingestion.live_stream.subprocess.Popen") as mock_popen, \
         patch.object(
             sys,
             "argv",
             [
                 "main.py",
                 "--officer",
                 "--officer-source",
                 source,
                 "--rules",
                 "rules",
                 "--output-file",
                 str(tmp_path / "alerts.ndjson"),
             ],
         ):
        mock_popen.return_value = _fake_officer_process()
        run_main()

    called_cmd = mock_popen.call_args[0][0]
    assert called_cmd == ["officer-agent.exe", "--source", source]
