"""Artifact-consumption integration test for the compiled officer-agent.exe.

This validates the subprocess-spawn boundary between panopticon-agent's build
artifact and this repo's LiveTelemetryStream -- it does NOT validate the
content of real Windows telemetry. Real ETW/Sysmon process-creation capture
requires an elevated session (and, for Sysmon, an installed Sysmon service)
and is validated separately on real hardware, not here.

Set OFFICER_AGENT_BIN to the path of a built officer-agent.exe to run these
tests; they are skipped otherwise so the rest of the suite stays runnable
without a cross-repo C++ build available.
"""
import os
import subprocess
from pathlib import Path

import pytest

from panopticon_detection.ingestion.live_stream import LiveTelemetryStream

OFFICER_BIN = os.environ.get("OFFICER_AGENT_BIN")

pytestmark = pytest.mark.skipif(
    not OFFICER_BIN or not Path(OFFICER_BIN).is_file(),
    reason="Set OFFICER_AGENT_BIN to a built officer-agent.exe to run artifact-consumption tests",
)


def test_officer_agent_binary_runs_and_reports_usage():
    """The build artifact is a valid, runnable Windows executable with the expected CLI."""
    result = subprocess.run(
        [OFFICER_BIN, "--help"], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0
    assert "--source" in result.stdout


def test_officer_agent_subprocess_stream_completes_cleanly():
    """The subprocess-spawn + stdout-pipe boundary works end to end.

    Unelevated (the expected default here and in CI), the agent's ETW/Sysmon
    collectors fail to start, so it exits immediately having produced zero
    events -- that is documented, correct behavior, not a test failure. If
    this happens to run elevated with real collectors active, any events
    captured are validated for Schema 0.2 shape instead of asserted away.
    """
    events = list(
        LiveTelemetryStream.stream_from_officer_process(OFFICER_BIN, source="etw")
    )
    for event in events:
        assert event["schema_version"] == "0.2"
        assert event["event_type"] in ("process_create", "process_terminate")
        assert "pid" in event["process"]
