"""Replay scenarios: attack (and benign) telemetry -> expected detections and incidents.

Each directory under ``tests/corpus/`` holds agent-schema NDJSON
(``events.ndjson``, valid against ``panopticon-agent/schema/event.schema.json``)
and an ``expected.json`` stating what the engine must and must not conclude:

* ``must_fire`` / ``must_not_fire`` -- rule ids
* ``fire_counts`` -- exact alert counts for rules where "once" matters
* ``max_alerts`` -- a ceiling on total alerts (0 for benign sessions)
* ``incidents`` -- exactly how many incidents, and for each: its root, the
  provenance origin, tactics and stage rules it must contain, processes that
  must *not* be stages, text its causal path must show, and a minimum score

The events go through the real normalizer and the full wired engine, the same
path the manager's detection worker takes. Replay is deterministic, so a
scenario that passes once passes every time.
"""

import json
from collections import Counter
from pathlib import Path

import pytest

from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

ROOT = Path(__file__).resolve().parent.parent
CORPUS = Path(__file__).resolve().parent / "corpus"
SCENARIOS = sorted(p.name for p in CORPUS.iterdir() if (p / "expected.json").is_file())


def replay(name):
    run, context = build_detection_run(ROOT / "rules")
    alerts = []
    for line in (CORPUS / name / "events.ndjson").read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            alerts += run.process_event(event)
    return alerts, context


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario(name):
    expected = json.loads((CORPUS / name / "expected.json").read_text(encoding="utf-8"))
    alerts, context = replay(name)
    fired = Counter(a.rule_id for a in alerts)

    missing = [r for r in expected.get("must_fire", []) if not fired[r]]
    assert not missing, f"expected to fire but did not: {missing}; fired: {dict(fired)}"

    unexpected = [r for r in expected.get("must_not_fire", []) if fired[r]]
    assert not unexpected, f"must not fire but did: {unexpected}"

    for rule_id, count in expected.get("fire_counts", {}).items():
        assert fired[rule_id] == count, f"{rule_id} fired {fired[rule_id]}x, expected {count}x"

    if "max_alerts" in expected:
        assert len(alerts) <= expected["max_alerts"], f"{len(alerts)} alerts: {dict(fired)}"

    incidents = context.incidents.open_incidents()
    assert len(incidents) == len(expected["incidents"]), (
        f"{len(incidents)} incident(s), expected {len(expected['incidents'])}"
    )

    registry = context.registry
    for want in expected["incidents"]:
        root_names = {registry.get(i.root_node_id).name for i in incidents if i.root_node_id}
        assert want["root"] in root_names, f"no incident rooted at {want['root']}: {root_names}"
        incident = next(i for i in incidents if registry.get(i.root_node_id).name == want["root"])

        assert set(want.get("tactics_include", [])) <= set(incident.tactics), incident.tactics
        stage_rules = {s.rule_id for s in incident.stages}
        assert set(want.get("stage_rules_include", [])) <= stage_rules, sorted(stage_rules)
        stage_procs = {s.actor_name for s in incident.stages}
        assert not stage_procs & set(want.get("stage_processes_exclude", [])), stage_procs
        if "min_score" in want:
            assert incident.score >= want["min_score"], incident.breakdown

        latest = [a for a in alerts if a.incident_id == incident.incident_id][-1]
        if "provenance_origin" in want:
            assert latest.evidence["provenance_origin"] == want["provenance_origin"]
        path = "\n".join(latest.evidence["causal_path"])
        for text in want.get("causal_path_includes", []):
            assert text in path, path


@pytest.mark.parametrize("name", SCENARIOS)
def test_replay_is_deterministic(name):
    first = [a.to_dict() for a in replay(name)[0]]
    second = [a.to_dict() for a in replay(name)[0]]
    assert json.dumps(first, sort_keys=True, default=str) == json.dumps(second, sort_keys=True, default=str)


def test_the_office_chain_is_one_incident_not_a_pile_of_alerts():
    """The headline behaviour, spelled out: every detection in the macro ->
    payload -> C2 -> persistence -> beacon chain lands in one incident, and each
    incident alert is an update to that one incident."""
    alerts, context = replay("office_macro_to_c2_and_persistence")
    incident_alerts = [a for a in alerts if a.incident_id]
    assert len({a.incident_id for a in incident_alerts}) == 1
    revisions = [a.evidence["revision"] for a in incident_alerts]
    assert revisions == list(range(1, len(revisions) + 1))

    final = incident_alerts[-1]
    assert final.evidence["root_cause_process"] == "winword.exe"
    # userinit's parent (PID 4, "System") was never observed starting, so it is
    # an inferred ancestor; the lineage shows it rather than hiding the gap.
    assert final.evidence["process_lineage"] == "system -> userinit.exe -> explorer.exe -> winword.exe"
    assert set(final.evidence["score_breakdown"]["context"]["factors"]) >= {
        "initial_access_vector",
        "user_writable_execution",
        "external_network",
        "obfuscated_command",
    }
    # Schema 0.3 carries no start_time_ticks, so no kill command can be built.
    assert final.active_response is None
