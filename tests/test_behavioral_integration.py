"""Rarity end to end, through the real engine: corpus telemetry -> features ->
baseline -> BehavioralSignal -> Alert -> graph tag -> existing incident.

The baseline is learned from ``tests/corpus/benign_workstation`` by replaying it
through ``build_detection_run`` and the run's own feature extractor -- the same
path ``panopticon-detect --learn-baseline`` takes. That corpus has 8 process
starts, far below a real deployment's readiness defaults (200 starts, 25
relationships), so the tests lower readiness explicitly and switch "uncommon"
off: against 8 starts every learned pair has a count of 1, which would make all
of normal behavior "uncommon". The thresholds are a test fixture here, not a
recommendation.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from panopticon_detection.behavioral.rarity import RarityBaseline, RarityDetector
from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.provenance.graph import EdgeKind

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "corpus"
OFFICE = "office_macro_to_c2_and_persistence"
BENIGN = "benign_workstation"
FIXTURE_READINESS = {"min_observations": 5, "min_relationships": 3, "uncommon_max_count": 0}


def _replay(name, detectors=()):
    run, context = build_detection_run(ROOT / "rules", behavioral_detectors=detectors)
    alerts = []
    for line in (CORPUS / name / "events.ndjson").read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            alerts += run.process_event(event)
    return run, context, alerts


def _learned(**overrides):
    run, _, _ = _replay(BENIGN)
    baseline = RarityBaseline(**{**FIXTURE_READINESS, **overrides})
    baseline.fit(run.feature_extractor.extract_all())
    return baseline


@pytest.fixture(scope="module")
def office():
    baseline = _learned()
    plain = _replay(OFFICE)
    with_rarity = _replay(OFFICE, [RarityDetector(baseline)])
    return baseline, plain, with_rarity


def test_benign_corpus_learns_a_ready_baseline():
    baseline = _learned()
    assert baseline.is_ready
    assert baseline.total_observations == 8
    assert "cmd.exe -> ipconfig.exe" in baseline.counts["parent_child"]


def test_unseen_office_child_is_signalled_with_an_explanation(office):
    baseline, _, (_, _, alerts) = office
    rare = {a.evidence["measurement"]["value"]: a for a in alerts if a.rule_id == "BHV-RARE-001"}
    assert set(rare) == {
        # Honest example of legitimate rare behavior: the user never opened Word
        # in the benign session, so its launch is unseen too.
        "explorer.exe -> winword.exe",
        "winword.exe -> powershell.exe",
        "powershell.exe -> svchelper.exe",
    }
    signal = rare["winword.exe -> powershell.exe"]
    assert signal.description == (
        "Previously unseen parent-child relationship: winword.exe -> powershell.exe "
        f"(0 of 8 process starts in rarity baseline {baseline.version})."
    )
    assert signal.evidence["model_version"] == baseline.version
    assert signal.evidence["detector"] == "rarity"
    assert all(a.active_response is None for a in alerts if a.rule_id.startswith("BHV-"))


def test_the_signal_is_a_tag_on_the_forked_edge(office):
    _, _, (_, context, _) = office
    tagged = [
        e for e in context.graph.edges.values()
        if any(t.rule_id == "BHV-RARE-001" for t in e.tags)
    ]
    assert len(tagged) == 3
    assert all(e.kind == EdgeKind.FORKED for e in tagged)
    children = {context.registry.get(e.dst).name for e in tagged}
    assert children == {"winword.exe", "powershell.exe", "svchelper.exe"}


def test_the_signal_joins_the_existing_incident(office):
    _, _, (_, context, _) = office
    (incident,) = context.incidents.open_incidents()
    rare_stages = {s.actor_name for s in incident.stages if s.rule_id == "BHV-RARE-001"}
    assert rare_stages == {"winword.exe", "powershell.exe", "svchelper.exe"}


def test_rarity_changes_nothing_about_the_incident_verdict(office):
    _, (_, plain_ctx, plain_alerts), (_, rare_ctx, rare_alerts) = office
    (before,) = plain_ctx.incidents.open_incidents()
    (after,) = rare_ctx.incidents.open_incidents()
    assert after.incident_id == before.incident_id
    assert after.tactics == before.tactics
    assert after.score == before.score
    assert after.breakdown == before.breakdown
    assert plain_ctx.registry.get(before.root_node_id).name == "winword.exe"
    assert rare_ctx.registry.get(after.root_node_id).name == "winword.exe"

    def incident_alerts(alerts):
        return [a for a in alerts if a.incident_id]

    assert len(incident_alerts(rare_alerts)) == len(incident_alerts(plain_alerts))
    last_before, last_after = incident_alerts(plain_alerts)[-1], incident_alerts(rare_alerts)[-1]
    assert (last_after.level, last_after.severity, last_after.confidence) == (
        last_before.level, last_before.severity, last_before.confidence
    )
    assert last_after.active_response == last_before.active_response


def test_rarity_never_feeds_host_risk(office):
    _, (plain_run, _, _), (rare_run, _, _) = office

    def risk(run):
        return {h: (p.current_score, len(p.event_timeline)) for h, p in run.risk_scorer.host_profiles.items()}

    assert risk(rare_run) == risk(plain_run)
    assert rare_run.behavioral_signals_count == 3


def test_rule_alerts_are_unchanged_by_rarity(office):
    _, (_, _, plain_alerts), (_, _, rare_alerts) = office

    def rule_alerts(alerts):
        return [a.to_dict() for a in alerts if not a.rule_id.startswith("BHV-") and not a.incident_id]

    assert rule_alerts(rare_alerts) == rule_alerts(plain_alerts)


def test_benign_activity_against_its_own_baseline_is_silent():
    _, _, alerts = _replay(BENIGN, [RarityDetector(_learned())])
    assert alerts == []


def test_a_baseline_that_is_not_ready_emits_nothing():
    baseline = _learned(min_observations=1000)
    assert not baseline.is_ready
    run, _, alerts = _replay(OFFICE, [RarityDetector(baseline)])
    assert not [a for a in alerts if a.rule_id.startswith("BHV-")]
    assert run.behavioral_signals_count == 0


def test_replay_with_a_baseline_is_deterministic():
    baseline = _learned()

    def alerts():
        _, _, produced = _replay(OFFICE, [RarityDetector(baseline)])
        return json.dumps([a.to_dict() for a in produced], sort_keys=True, default=str)

    assert alerts() == alerts()


def test_prune_reaches_behavioral_detectors(office):
    _, _, (run, context, _) = office
    dropped = context.prune(datetime(2100, 1, 1))
    assert dropped["detector_state_removed"] >= 0
    assert run.behavioral_detectors[0].baseline.is_ready  # the learned baseline is never pruned


def _cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "panopticon_detection.cli", "--rules", str(ROOT / "rules"), *args],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout


def test_cli_learn_detect_and_export(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    features_path = tmp_path / "features.jsonl"
    alerts_path = tmp_path / "alerts.ndjson"

    out = _cli(
        "--officer-ndjson", str(CORPUS / BENIGN / "events.ndjson"),
        "--learn-baseline", str(baseline_path),
        "--baseline-min-observations", "5",
        "--baseline-min-relationships", "3",
        "--baseline-uncommon-max", "0",
    )
    learned = RarityBaseline.load(baseline_path)
    assert learned.version == _learned().version  # CLI and library learn identically
    assert f"Rarity baseline {learned.version}: ready" in out

    out = _cli(
        "--officer-ndjson", str(CORPUS / OFFICE / "events.ndjson"),
        "--baseline", str(baseline_path),
        "--output-format", "json",
        "--output-file", str(alerts_path),
        "--export-features", str(features_path),
    )
    assert "Behavioral signals                : 3" in out
    written = [json.loads(line) for line in alerts_path.read_text().splitlines()]
    assert sum(1 for a in written if a["rule_id"] == "BHV-RARE-001") == 3

    records = [json.loads(line) for line in features_path.read_text().splitlines()]
    names = {r["name"] for r in records}
    assert {"winword.exe", "powershell.exe", "svchelper.exe"} <= names
    payload = next(r for r in records if r["name"] == "svchelper.exe")
    assert payload["image_writer_name"] == "powershell.exe"
    assert payload["parent_child"] == "powershell.exe -> svchelper.exe"


def test_cli_rejects_baseline_flags_in_streaming_mode(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "panopticon_detection.cli", "--rules", str(ROOT / "rules"),
         "--officer-ndjson", str(CORPUS / BENIGN / "events.ndjson"), "--reliable",
         "--export-features", str(tmp_path / "f.jsonl")],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "batch-mode only" in result.stdout
