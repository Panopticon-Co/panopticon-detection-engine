"""Rule levels are explicit, and the rules that should anchor campaigns can.

Twenty rules once omitted ``level`` and silently defaulted to 7 -- below the
campaign anchor threshold -- so the LSASS-dump and shadow-copy-deletion rules,
both critical and both in terminal tactics, could never start a campaign.
"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.mitre.attack import TACTIC_NAME_TO_ID
from panopticon_detection.provenance.tagging import (
    DEFAULT_ANCHOR_MIN_LEVEL,
    TERMINAL_TACTICS,
    normalise_tactic,
)
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.rules.schema import Rule

RULES = Path(__file__).resolve().parent.parent / "rules"
SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "officer_live_sample.ndjson"


def test_a_rule_without_a_level_is_rejected(tmp_path):
    rule_file = tmp_path / "no_level.yaml"
    rule_file.write_text(
        yaml.safe_dump(
            {
                "id": "DET-TEST-001",
                "name": "No level",
                "event_type": "process_create",
                "severity": "critical",
                "logic": {"all": [{"field": "process.name", "operator": "equals", "value": "x.exe"}]},
            }
        )
    )
    with pytest.raises(ValidationError):
        RuleLoader().load_file(rule_file)


def test_rule_level_is_required_on_the_model():
    with pytest.raises(ValidationError):
        Rule(
            id="X",
            name="x",
            event_type="process_create",
            logic={"all": [{"field": "process.name", "operator": "equals", "value": "x"}]},
        )


def test_every_rule_file_declares_its_level_explicitly():
    missing = [
        p.name
        for p in RULES.rglob("*.yaml")
        if "lists" not in p.relative_to(RULES).parts
        and "level" not in (yaml.safe_load(p.read_text()) or {})
    ]
    assert missing == []


def test_critical_rules_in_terminal_tactics_can_anchor_a_campaign():
    too_low = [
        (r.id, r.level)
        for r in RuleLoader().load_directory(RULES)
        if r.severity == "critical"
        and r.mitre
        and normalise_tactic(r.mitre.tactic) in TERMINAL_TACTICS
        and r.level < DEFAULT_ANCHOR_MIN_LEVEL
    ]
    assert too_low == []


def test_every_rule_tactic_is_a_real_attack_tactic():
    bad = [
        (r.id, r.mitre.tactic)
        for r in RuleLoader().load_directory(RULES)
        if r.mitre and r.mitre.tactic and r.mitre.tactic.lower() not in TACTIC_NAME_TO_ID
    ]
    assert bad == []


def _sample_events():
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            yield event


def test_the_lsass_dump_anchors_a_campaign_without_the_hash_rule():
    """Replay the sample only up to the rundll32 MiniDump -- before mimikatz.exe
    and its threat-intel hash match -- and the LSASS rule alone must anchor."""
    run, _ = build_detection_run(RULES)
    campaigns = []
    for event in _sample_events():
        campaigns += [a for a in run.process_event(event) if a.rule_id == "PROV-CAMPAIGN"]
        if (event.get("process") or {}).get("name") == "rundll32.exe":
            break

    assert campaigns, "DET-PROC-005 should anchor a campaign on its own"
    assert campaigns[0].mitre_tactic == "Credential Access"
    assert "DET-PROC-005" in campaigns[0].evidence["attack_chain"]
