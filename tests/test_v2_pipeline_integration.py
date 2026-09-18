"""End-to-end integration tests for the V2 --reliable path in src/main.py.

Drives the real CLI entrypoint (panopticon_detection.cli.main). Covers alert parity with the
legacy path, incremental output, deterministic shutdown (--max-events /
--duration), health/metrics files, restart recovery, and V1 CLI compatibility.
"""

import json
import sys
from pathlib import Path

from panopticon_detection.cli import main as run_main
from panopticon_detection.reliability.spool import AlertSpool

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLE = PROJECT_ROOT / "samples" / "officer_live_sample.ndjson"


def _keys(path: Path):
    return sorted(
        (d["rule_id"], d["title"])
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for d in [json.loads(line)]
    )


def _run(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", *argv])
    run_main()


# -- V1 compatibility / parity -------------------------------------------
def test_reliable_alert_set_equals_legacy(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.ndjson"
    reliable = tmp_path / "reliable.ndjson"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE),
          "--output-file", str(legacy), "--output-format", "ndjson"], monkeypatch)
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(tmp_path / "s.db"),
          "--output-file", str(reliable), "--output-format", "ndjson"], monkeypatch)
    assert _keys(legacy) == _keys(reliable)
    assert len(_keys(reliable)) > 0  # DET-PROC-011 chain still fires


def test_legacy_path_unchanged_when_reliable_not_passed(tmp_path, monkeypatch):
    out = tmp_path / "a.ndjson"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE),
          "--output-file", str(out), "--output-format", "ndjson"], monkeypatch)
    assert out.exists() and len(_keys(out)) > 0
    assert not (tmp_path / "s.db").exists()  # no spool created on the legacy path


# -- health / metrics ---------------------------------------------------
def test_reliable_writes_health_and_metrics(tmp_path, monkeypatch):
    health = tmp_path / "health.json"
    metrics = tmp_path / "metrics.prom"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(tmp_path / "s.db"), "--output-file", str(tmp_path / "a.ndjson"),
          "--output-format", "ndjson", "--health-file", str(health),
          "--metrics-file", str(metrics)], monkeypatch)
    doc = json.loads(health.read_text(encoding="utf-8"))
    assert doc["engine_running"] is False
    assert doc["shutdown_reason"] == "stream_end"
    assert doc["counters"]["events_processed"] == doc["counters"]["events_received"]
    assert doc["counters"]["alerts_persisted"] == doc["counters"]["alerts_delivered"]
    assert doc["spool"]["pending"] == 0
    prom = metrics.read_text(encoding="utf-8")
    assert "panopticon_alerts_delivered_total" in prom
    assert "panopticon_events_processed_total" in prom
    assert "panopticon_uptime_seconds" in prom


def test_spool_settled_after_successful_run(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(db), "--output-file", str(tmp_path / "a.ndjson"),
          "--output-format", "ndjson"], monkeypatch)
    s = AlertSpool(db)
    try:
        st = s.stats()
        assert st.pending_total == 0 and st.dead == 0 and st.delivered > 0
    finally:
        s.close()


# -- deterministic shutdown ------------------------------------------
def test_max_events_stops_cleanly(tmp_path, monkeypatch):
    out = tmp_path / "a.ndjson"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(tmp_path / "s.db"), "--output-file", str(out),
          "--output-format", "ndjson", "--max-events", "2",
          "--health-file", str(tmp_path / "h.json")], monkeypatch)
    doc = json.loads((tmp_path / "h.json").read_text(encoding="utf-8"))
    assert doc["counters"]["events_processed"] == 2
    assert doc["shutdown_reason"] == "max_events"
    assert doc["spool"]["pending"] == 0  # the 2 processed events' alerts were delivered


def test_duration_stops_cleanly(tmp_path, monkeypatch):
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(tmp_path / "s.db"), "--output-file", str(tmp_path / "a.ndjson"),
          "--output-format", "ndjson", "--duration", "0.01",
          "--health-file", str(tmp_path / "h.json")], monkeypatch)
    doc = json.loads((tmp_path / "h.json").read_text(encoding="utf-8"))
    assert doc["shutdown_reason"] in ("duration", "stream_end")  # tiny file may finish first
    assert doc["spool"]["pending"] == 0


# -- incremental output --------------------------------------------
def test_output_file_is_valid_ndjson_and_matches_v1_shape(tmp_path, monkeypatch):
    out = tmp_path / "a.ndjson"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(tmp_path / "s.db"), "--output-file", str(out),
          "--output-format", "ndjson"], monkeypatch)
    lines = [line for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    for line in lines:
        d = json.loads(line)  # every line parses
        assert {"alert_id", "rule_id", "title", "severity", "level", "evidence"} <= d.keys()


# -- restart / recovery ----------------------------------------
def test_restart_against_same_spool_and_file_emits_no_duplicates(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    out = tmp_path / "a.ndjson"
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(db), "--output-file", str(out), "--output-format", "ndjson"], monkeypatch)
    first = _keys(out)
    assert first

    # identical second run: every alert_id already delivered -> file unchanged
    _run(["--rules", "rules", "--officer-ndjson", str(SAMPLE), "--reliable",
          "--spool-db", str(db), "--output-file", str(out), "--output-format", "ndjson"], monkeypatch)
    assert _keys(out) == first  # no duplicate lines appended


def test_recovers_alerts_left_pending_by_a_crash(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    out = tmp_path / "a.ndjson"

    # simulate: alerts were persisted to the spool but the process died before
    # they were written to the file
    pre = AlertSpool(db)
    for i in range(4):
        pre.persist({"alert_id": f"ALT-CRASH-{i}", "rule_id": "DET-PROC-011",
                     "title": "pending from crash", "severity": "high", "level": 11,
                     "evidence": {}, "timestamp": "2026-08-28T00:00:00Z"})
    assert pre.stats().pending_total == 4
    pre.close()

    empty = tmp_path / "empty.ndjson"
    empty.write_text("", encoding="utf-8")
    _run(["--rules", "rules", "--officer-ndjson", str(empty), "--reliable",
          "--spool-db", str(db), "--output-file", str(out), "--output-format", "ndjson"], monkeypatch)

    s = AlertSpool(db)
    try:
        assert s.stats().pending_total == 0
        assert s.stats().delivered == 4
    finally:
        s.close()
    ids = {json.loads(line)["alert_id"] for line in out.read_text(encoding="utf-8").splitlines() if line.strip()}
    assert ids == {f"ALT-CRASH-{i}" for i in range(4)}


# -- --no-auto-remediate under --reliable --------------------

