"""The ML stage: bounded evidence next to the rules, fail-open, never an authority (docs/adr/001-003).

Most tests use a hand-built bundle whose score is a parameter, so they pin the
*policy* (what a score may and may not cause) without needing a trained model.
The invariants run over every corpus scenario with the highest score a bundle
can give, the worst case for the "ML cannot widen the response" guarantees.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from panopticon_detection.alerting.formatter import AlertFormatter
from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from tests.ml.bundle_fixture import make_bundle

ROOT = Path(__file__).resolve().parent.parent
CORPUS = Path(__file__).resolve().parent / "corpus"
SCENARIOS = sorted(p.name for p in CORPUS.iterdir() if (p / "events.ndjson").is_file())
REAL = ROOT / "data" / "models" / "v7_v5"
DESTRUCTIVE = {"TERMINATE_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST", "KILL_PROCESS"}
HIGH, ALERT_ONLY, BELOW = 5.0, 1.5, 0.5   # fixture thresholds: alert 1.0, high 2.0


def replay(name, **ml):
    run, context = build_detection_run(ROOT / "rules", **ml)
    alerts = []
    for line in (CORPUS / name / "events.ndjson").read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            alerts += run.process_event(event)
    return alerts, context


@pytest.fixture
def high(tmp_path):
    return str(make_bundle(tmp_path / "high", HIGH))


# --- off by default, fail open ------------------------------------------------
def test_without_a_model_nothing_changes(monkeypatch):
    monkeypatch.delenv("PANOPTICON_MODEL_PATH", raising=False)
    alerts, context = replay("office_macro_to_c2_and_persistence")
    assert all("ml" not in a.to_dict() for a in alerts)
    assert not any(k.startswith("ml_") for k in context.stats())


def test_a_bad_bundle_disables_ml_and_never_raises(tmp_path, caplog):
    alerts, context = replay("office_macro_to_c2_and_persistence", ml_model_path=str(tmp_path / "missing"))
    assert alerts  # rules still run
    assert context.stats()["ml_state"] == "disabled" and context.stats()["ml_error"]
    assert "ML stage DISABLED" in caplog.text
    assert all("ml" not in a.to_dict() for a in alerts)


def test_unknown_mode_disables_ml(high):
    _, context = replay("benign_workstation", ml_model_path=high, ml_mode="turbo")
    assert context.stats()["ml_state"] == "disabled"


def test_environment_selects_the_model_in_shadow_mode(monkeypatch, high):
    monkeypatch.setenv("PANOPTICON_MODEL_PATH", high)
    monkeypatch.delenv("PANOPTICON_ML_MODE", raising=False)
    alerts, context = replay("office_macro_to_c2_and_persistence")
    assert context.stats()["ml_mode"] == "shadow"
    assert not any(a.rule_id.startswith("ML-") for a in alerts)


# --- what the stage emits -----------------------------------------------------
def test_shadow_annotates_rule_alerts_and_emits_nothing(high):
    alerts, _ = replay("office_macro_to_c2_and_persistence", ml_model_path=high, ml_mode="shadow")
    annotated = [a for a in alerts if a.ml]
    assert annotated and not any(a.rule_id.startswith("ML-") for a in alerts)
    note = annotated[0].ml
    assert note["band"] == "high" and note["mode"] == "shadow" and note["raw_score"] == HIGH
    assert "training_prevalence_probability" in note and "probability" not in note


@pytest.mark.parametrize("score, rule, level", [(ALERT_ONLY, "ML-PROC-001", 7), (HIGH, "ML-PROC-002", 9)])
def test_active_emits_bounded_evidence_alerts(tmp_path, score, rule, level):
    bundle = str(make_bundle(tmp_path / "b", score))
    alerts, _ = replay("download_execute_lsass_dump", ml_model_path=bundle, ml_mode="active")
    ml = [a for a in alerts if a.rule_id.startswith("ML-")]
    assert ml and {a.rule_id for a in ml} == {rule}
    for a in ml:
        assert a.level == level and a.detection_source == "ml"
        assert a.mitre_tactic is None and a.mitre_technique is None and a.active_response is None
        assert a.alert_id.startswith("ML-") and a.ml["mode"] == "active"


def test_below_threshold_is_annotated_but_silent(tmp_path):
    bundle = str(make_bundle(tmp_path / "b", BELOW))
    alerts, _ = replay("download_execute_lsass_dump", ml_model_path=bundle, ml_mode="active")
    assert not any(a.rule_id.startswith("ML-") for a in alerts)
    assert any(a.ml and a.ml["band"] is None for a in alerts)


def test_only_scoreable_starts_are_scored(high):
    run, context = build_detection_run(ROOT / "rules", ml_model_path=high, ml_mode="active")
    base = {"event_type": "process_create", "host_id": "H", "timestamp": "2026-01-01T00:00:00Z", "event_id": "e",
            "process": {"pid": 10, "name": "a.exe", "executable": "C:\\a.exe", "command_line": "a.exe -x"},
            "parent": {"name": "b.exe", "pid": 1}}
    assert run.ml_stage.score({**base, "event_type": "network_connect"}) is None
    assert run.ml_stage.score({**base, "process": {**base["process"], "command_line": ""}}) is None
    assert run.ml_stage.score(base).band == "high"
    stats = context.stats()
    assert stats["ml_scored"] == 1 and stats["ml_skipped_no_command_line"] == 1


def test_ml_alerts_are_deterministic(high):
    first = [a.to_dict() for a in replay("office_macro_to_c2_and_persistence", ml_model_path=high, ml_mode="active")[0]]
    second = [a.to_dict() for a in replay("office_macro_to_c2_and_persistence", ml_model_path=high, ml_mode="active")[0]]
    assert first == second


def test_console_shows_the_score_on_rule_alerts_only(high):
    alerts, _ = replay("download_execute_lsass_dump", ml_model_path=high, ml_mode="active")
    rule = next(a for a in alerts if a.ml and not a.rule_id.startswith("ML-"))
    assert "a triage aid, not a verdict" in AlertFormatter.to_console(rule)
    ml = next(a for a in alerts if a.rule_id.startswith("ML-"))
    assert "a triage aid, not a verdict" not in AlertFormatter.to_console(ml)


# --- the model is never an authority -------------------------------------------
@pytest.mark.parametrize("name", SCENARIOS)
def test_ml_never_changes_rule_alerts_incidents_or_responses(name, high):
    base, _ = replay(name)
    with_ml, _ = replay(name, ml_model_path=high, ml_mode="active")

    def key(a):
        return (a.alert_id, a.rule_id, a.level, json.dumps(a.active_response, sort_keys=True))

    base_rules = {key(a) for a in base if a.rule_id != "PROV-CAMPAIGN"}
    ml_rules = {key(a) for a in with_ml if a.rule_id != "PROV-CAMPAIGN" and not a.rule_id.startswith("ML-")}
    assert ml_rules == base_rules, "ML altered a rule, stateful, beacon or risk alert"

    def incidents(alerts):
        return {(a.incident_id, a.evidence.get("root_cause_process")) for a in alerts if a.rule_id == "PROV-CAMPAIGN"}

    assert incidents(with_ml) == incidents(base), "ML opened, closed, merged or re-rooted an incident"

    base_incident_actions = {a.incident_id: (a.active_response or {}).get("action") for a in base
                             if a.rule_id == "PROV-CAMPAIGN"}
    for alert in with_ml:
        if alert.rule_id.startswith("ML-"):
            assert alert.active_response is None
        if alert.rule_id == "PROV-CAMPAIGN" and alert.active_response:
            # the incident's own, rule-anchored recommendation: unchanged by ML
            assert alert.active_response["action"] == base_incident_actions[alert.incident_id]
    assert Counter(a.active_response["action"] for a in with_ml if a.active_response and a.rule_id != "PROV-CAMPAIGN") \
        == Counter(a.active_response["action"] for a in base if a.active_response and a.rule_id != "PROV-CAMPAIGN")


def test_ml_alone_cannot_open_an_incident_or_recommend_anything(high):
    alerts, context = replay("benign_workstation", ml_model_path=high, ml_mode="active")
    assert any(a.rule_id == "ML-PROC-002" for a in alerts)           # the worst case: everything scores high
    assert not any(a.rule_id == "PROV-CAMPAIGN" for a in alerts)
    assert not context.incidents.incidents
    assert not any(a.active_response for a in alerts)
    assert not any(a.rule_id == "CORR-RISK-001" for a in alerts)     # ML is outside the host risk meter


def test_high_score_adds_one_bounded_itemised_factor_to_a_rule_anchored_incident(high):
    def final_breakdown(alerts):
        return [a for a in alerts if a.rule_id == "PROV-CAMPAIGN"][-1].evidence["score_breakdown"]

    base = final_breakdown(replay("office_macro_to_c2_and_persistence")[0])
    boosted = final_breakdown(replay("office_macro_to_c2_and_persistence", ml_model_path=high, ml_mode="active")[0])
    assert "ml_high_confidence_process" not in base["context"]["factors"]
    assert boosted["context"]["factors"]["ml_high_confidence_process"] == 0.08
    assert boosted["context"]["weight"] <= 0.25
    # itemised at 0.08 but inside the existing context cap: it can lift the score by at most
    # what headroom the cap leaves (none, when the rules' own context already filled it)
    headroom = max(0.0, 0.25 - base["context"]["weight"])
    assert abs((boosted["total"] - base["total"]) - min(0.08, headroom)) < 1e-9


def test_the_factor_lifts_an_incident_with_context_headroom(high):
    def breakdown(alerts):
        return [a for a in alerts if a.rule_id == "PROV-CAMPAIGN"][-1].evidence["score_breakdown"]

    base = breakdown(replay("download_execute_lsass_dump")[0])
    boosted = breakdown(replay("download_execute_lsass_dump", ml_model_path=high, ml_mode="active")[0])
    assert boosted["total"] > base["total"]
    assert round(boosted["context"]["weight"] - base["context"]["weight"], 3) <= 0.08


def test_alert_level_ml_does_not_add_an_incident_factor(tmp_path):
    bundle = str(make_bundle(tmp_path / "b", ALERT_ONLY))
    alerts, _ = replay("office_macro_to_c2_and_persistence", ml_model_path=bundle, ml_mode="active")
    last = [a for a in alerts if a.rule_id == "PROV-CAMPAIGN"][-1]
    assert "ml_high_confidence_process" not in last.evidence["score_breakdown"]["context"]["factors"]


# --- the trained model on the demo scenarios (synthetic, not a performance claim) ----
@pytest.mark.skipif(not REAL.is_dir(), reason="trained bundle data/models/v7_v5 not present")
class TestTrainedModelOnCorpus:
    def ml_alerts(self, name):
        alerts, _ = replay(name, ml_model_path=str(REAL), ml_mode="active")
        return [a for a in alerts if a.rule_id.startswith("ML-")]

    @pytest.mark.parametrize("name", ["benign_workstation", "sibling_noise_no_merge"])
    def test_quiet_on_benign_and_noise(self, name):
        assert self.ml_alerts(name) == []

    @pytest.mark.parametrize("name", ["fileless_powershell_lsass_dump", "office_macro_to_c2_and_persistence"])
    def test_flags_the_lab_tradecraft_chains(self, name):
        ml = self.ml_alerts(name)
        assert ml and all(a.active_response is None and a.mitre_tactic is None for a in ml)


# --- failure behaviour and contract mapping ------------------------------------
def _start(pid, cmd, **over):
    event = {"event_type": "process_create", "host_id": "H", "timestamp": f"2026-01-01T00:00:{pid:02d}Z",
             "event_id": f"e{pid}", "process": {"pid": pid, "name": "a.exe", "executable": "C:\\a.exe",
                                                 "command_line": cmd}, "parent": {"name": "b.exe", "pid": 1}}
    event.update(over)
    return event


@pytest.mark.parametrize("bad", [{"process": "not-a-dict"}, {"process": None}, {"process": {"command_line": 7}}])
def test_a_malformed_event_is_counted_never_raised(high, bad):
    run, context = build_detection_run(ROOT / "rules", ml_model_path=high, ml_mode="active")
    assert run.ml_stage.score(_start(3, "a.exe -x", **bad)) is None
    stats = context.stats()
    assert stats["ml_scored"] == 0 and stats["ml_errors"] + stats["ml_skipped_no_command_line"] == 1


def test_a_scorer_fault_leaves_every_rule_alert_intact(high, monkeypatch, caplog):
    plain, _ = replay("download_execute_lsass_dump")
    run, context = build_detection_run(ROOT / "rules", ml_model_path=high, ml_mode="active")

    def boom(_vector):
        raise RuntimeError("scorer fault")
    monkeypatch.setattr(run.ml_stage.bundle.model, "raw_score", boom)
    alerts = []
    for line in (CORPUS / "download_execute_lsass_dump" / "events.ndjson").read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            alerts += run.process_event(event)
    assert [a.to_dict() for a in alerts] == [a.to_dict() for a in plain]
    assert context.stats()["ml_errors"] > 0 and "ML scoring failed" in caplog.text


def test_ml_and_a_rule_on_one_event_stay_two_distinct_findings(high):
    alerts, _ = replay("download_execute_lsass_dump", ml_model_path=high, ml_mode="active")
    by_event = Counter((a.event_id, a.detection_source) for a in alerts if a.event_id)
    shared = {e for (e, src) in by_event if src == "ml"} & {e for (e, src) in by_event if src in ("rule", "stateful")}
    assert shared, "expected at least one start flagged by both a rule and the model"
    for event_id in shared:
        rule = next(a for a in alerts if a.event_id == event_id and a.detection_source in ("rule", "stateful"))
        assert rule.ml and rule.ml["band"] == "high"   # the rule alert carries the score, unchanged otherwise


def test_a_repeated_start_on_one_process_is_deduplicated(high):
    run, _ = build_detection_run(ROOT / "rules", ml_model_path=high, ml_mode="active")
    first = run.process_event(_start(5, "a.exe -x"))
    again = run.process_event({**_start(5, "a.exe -x"), "event_id": "e5-twin"})   # same host, pid, instant
    assert sum(a.rule_id.startswith("ML-") for a in first) == 1
    assert not any(a.rule_id.startswith("ML-") for a in again)


def test_ml_alert_contract_round_trips_through_ndjson(high):
    alerts, _ = replay("download_execute_lsass_dump", ml_model_path=high, ml_mode="active")
    for a in alerts:
        data = json.loads(json.dumps(a.to_dict()))
        assert data["detection_source"] in {"rule", "stateful", "behavioral", "correlation", "ml"}
        if data["rule_id"].startswith("ML-"):
            assert data["detection_source"] == "ml" and data["active_response"] is None
            assert set(data["ml"]) >= {"model_id", "model_version", "artifact_sha256", "featurizer_version",
                                       "mode", "raw_score", "band", "thresholds"}
        elif "ml" in data:
            assert data["ml"]["mode"] == "active"


def test_latency_is_measured(high):
    alerts, context = replay("download_execute_lsass_dump", ml_model_path=high, ml_mode="active")
    stats = context.stats()
    assert stats["ml_scored"] > 0 and stats["ml_latency_max_ms"] >= stats["ml_latency_mean_ms"] > 0
