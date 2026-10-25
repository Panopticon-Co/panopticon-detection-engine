"""The alert fields downstream consumers depend on (docs/integration/CONTRACT.md).

The manager links an incident to its member alerts through
``evidence.stages[].alert_id`` and its response policy reads
``detection_source``; both must be present and consistent on every replay.
"""

from tests.test_corpus import SCENARIOS, replay

SOURCES = {"rule", "stateful", "behavioral", "correlation"}


def _all_alerts():
    for name in SCENARIOS:
        alerts, _ = replay(name)
        yield name, alerts


def test_every_alert_names_its_detection_source():
    for name, alerts in _all_alerts():
        for a in alerts:
            assert a.detection_source in SOURCES, (name, a.rule_id, a.detection_source)
            if a.incident_id or a.rule_id == "CORR-RISK-001":
                assert a.detection_source == "correlation", (name, a.rule_id)


def test_incident_stages_reference_emitted_alerts():
    checked = 0
    for name, alerts in _all_alerts():
        emitted = {a.alert_id for a in alerts}
        for a in alerts:
            if not a.incident_id:
                continue
            ids = [s["alert_id"] for s in a.evidence["stages"]]
            assert any(ids), (name, a.alert_id)
            for alert_id in ids:
                # None only for a stage whose detection was suppressed as a repeat.
                assert alert_id is None or alert_id in emitted, (name, alert_id)
            checked += 1
    assert checked, "no incident alerts in the corpus"


def test_replay_is_idempotent_on_alert_ids():
    for name in SCENARIOS:
        first, _ = replay(name)
        second, _ = replay(name)
        assert [a.alert_id for a in first] == [a.alert_id for a in second], name


def test_behavioral_alerts_never_recommend_disruptive_actions():
    for name, alerts in _all_alerts():
        for a in alerts:
            if a.detection_source == "behavioral" and a.active_response:
                assert a.active_response["action"].startswith("COLLECT_"), (name, a.rule_id)
