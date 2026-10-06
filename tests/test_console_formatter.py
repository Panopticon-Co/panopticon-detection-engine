"""The console view reports what was observed and recommended -- never an action.

It once rendered a hand-written table claiming the engine had "killed malicious
process tree", "blocked the attacker's IP", or, for any unlisted rule, "Threat
neutralized via active containment playbook". The engine executes nothing.
"""

import re
from pathlib import Path

from panopticon_detection.alerting.alert import Alert
from panopticon_detection.alerting.formatter import AlertFormatter
from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

ROOT = Path(__file__).resolve().parent.parent

# Past-tense claims of having acted on a host.
_ACTION_CLAIM = re.compile(
    r"\b(neutraliz\w*|killed|blocked|quarantined|terminated|isolated|intercepted|"
    r"prevented|revoked|sanitized|severed|contained|protected)\b",
    re.IGNORECASE,
)


def _alert(**overrides) -> Alert:
    base = dict(
        alert_id="ALT-1",
        rule_id="DET-TEST-001",
        title="Test detection",
        description="powershell.exe launched with an encoded command",
        level=13,
        severity="high",
        confidence=0.9,
        host_id="HOST-1",
        timestamp="2026-08-18T12:00:00Z",
        event_id="evt-1",
        evidence={},
    )
    base.update(overrides)
    return Alert(**base)


def test_sample_run_console_output_claims_no_action():
    run, _ = build_detection_run(ROOT / "rules")
    rendered = []
    for line in (ROOT / "samples" / "officer_live_sample.ndjson").read_text().splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            rendered += [AlertFormatter.to_console(a) for a in run.process_event(event)]

    assert rendered, "the sample should produce alerts"
    for text in rendered:
        assert not _ACTION_CLAIM.search(text), text


def test_a_recommendation_is_shown_as_needing_approval():
    text = AlertFormatter.to_console(
        _alert(active_response={"action": "TERMINATE_PROCESS", "host_id": "HOST-1", "target_pid": 42})
    )
    assert "TERMINATE_PROCESS" in text
    assert "requires analyst approval" in text
    assert not _ACTION_CLAIM.search(text)


def test_an_alert_with_no_recommendation_says_so():
    text = AlertFormatter.to_console(_alert(active_response=None))
    assert "no action recommended" in text


def test_long_fields_wrap_inside_the_box():
    text = AlertFormatter.to_console(_alert(description="x" * 300, title="y" * 120))
    widths = {len(line) for line in text.splitlines()}
    assert widths == {78}
