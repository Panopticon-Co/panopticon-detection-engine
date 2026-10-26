"""Track A replay suite (scripts/eval_demo_suite.py) as a regression test.

Pins the claims the capstone report makes about the declared scenario suite:
every attack chain becomes exactly its expected incident, single-tactic and
must-not-merge activity forms none, benign activity raises nothing, replay is
idempotent -- and all of it holds unchanged when each process start arrives
twice (ETW + Sysmon), as it does from the live agent.
"""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval_demo_suite.py"
spec = importlib.util.spec_from_file_location("eval_demo_suite", SCRIPT)
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)

NAMES = sorted(p.name for p in suite.CORPUS.iterdir() if (p / "expected.json").is_file())


@pytest.mark.parametrize("etw_twins", [False, True])
def test_suite_summary(etw_twins):
    summary = suite.summarise([suite.score(n, etw_twins) for n in NAMES])
    assert summary["attack_chains"] >= 4
    assert summary["attack_chains_incident_correct"] == summary["attack_chains"]
    assert summary["no_incident_scenarios_correct"] == summary["no_incident_scenarios"]
    assert summary["benign_alerts"] == 0 and summary["benign_incidents"] == 0
    assert summary["replay_idempotent"]


@pytest.mark.parametrize("name", NAMES)
def test_etw_twin_reports_change_no_detection(name):
    plain, twins = suite.score(name, False), suite.score(name, True)
    assert plain["rules_fired"] == twins["rules_fired"]
    assert plain["incidents"] == twins["incidents"]
    assert plain["incident_roots"] == twins["incident_roots"]


def test_etw_twins_make_kill_recommendations_actionable():
    row = suite.score("office_macro_to_c2_and_persistence", True)
    assert row["responses"].get("analyst-approval", 0) > 0
    assert not any(k.startswith("record-only (no start_time_ticks)") for k in row["responses"])
