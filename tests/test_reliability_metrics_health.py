"""Tests for V2 metrics (metrics.py) and health (health.py)."""

import json
import time

import pytest

from panopticon_detection.reliability.health import HealthState
from panopticon_detection.reliability.metrics import Metrics


# -- metrics ----------------------------------------------------------------
def test_all_spec_counters_and_gauges_exist_and_start_zero():
    m = Metrics()
    for c in (
        "events_received", "events_processed", "events_failed",
        "alerts_generated", "alerts_persisted", "alerts_delivered",
        "alerts_failed", "retry_attempts",
    ):
        assert m.get(c) == 0
    for g in ("queue_depth", "queue_capacity", "spool_pending", "spool_failed"):
        assert m.get_gauge(g) == 0


def test_counter_increment_and_unknown_names_rejected():
    m = Metrics()
    m.incr("events_processed", 3)
    assert m.get("events_processed") == 3
    with pytest.raises(KeyError):
        m.incr("bogus")
    with pytest.raises(KeyError):
        m.set_gauge("bogus", 1)


def test_latency_and_uptime():
    m = Metrics()
    for v in (0.01, 0.02, 0.03, 0.04, 0.05):
        m.observe_latency(v)
    lat = m.snapshot()["processing_latency_seconds"]
    assert lat["count"] == 5 and lat["min"] == pytest.approx(0.01) and lat["max"] == pytest.approx(0.05)
    time.sleep(0.02)
    assert m.uptime_seconds >= 0.01


def test_prometheus_text_render():
    m = Metrics()
    m.incr("alerts_delivered", 4)
    m.set_gauge("spool_pending", 2)
    text = m.render_prometheus()
    assert "# TYPE panopticon_alerts_delivered_total counter" in text
    assert "panopticon_alerts_delivered_total 4" in text
    assert "panopticon_spool_pending 2" in text
    assert "panopticon_uptime_seconds" in text


def test_snapshot_is_json_serializable():
    json.dumps(Metrics().snapshot())


# -- health ---------------------------------------------------------------
class _QS:
    depth, capacity, max_depth, dropped_total = 3, 10, 7, 1


class _Q:
    stats = _QS()


class _SS:
    pending_ready, pending_retry, delivered, dead = 4, 1, 20, 2
    pending_total = 5
    total = 27


class _Spool:
    def stats(self):
        return _SS()

    def failed_count(self):
        return 1


def test_health_snapshot_carries_every_phase6_field():
    h = HealthState()
    h.set_ingestion_state("streaming")
    h.mark_event_processed()
    h.mark_alert_persisted()
    doc = h.snapshot(queue=_Q(), spool=_Spool(), metrics=Metrics())
    assert doc["engine_running"] is True
    assert doc["ingestion_state"] == "streaming"
    assert doc["queue"]["depth"] == 3 and doc["queue"]["capacity"] == 10
    assert doc["queue"]["dropped_rejected"] == 1
    assert doc["spool"]["pending"] == 5 and doc["spool"]["failed"] == 1 and doc["spool"]["dead"] == 2
    assert doc["counters"]["events_processed"] == 0
    assert doc["counters"]["alerts_generated"] == 0
    assert doc["last_event_processed_at"] is not None
    assert doc["last_alert_persisted_at"] is not None
    assert doc["uptime_seconds"] >= 0


def test_health_error_and_stop():
    h = HealthState()
    h.mark_error("boom")
    h.mark_stopped("max_events")
    doc = h.snapshot()
    assert doc["engine_running"] is False
    assert doc["status"] == "stopped"
    assert doc["ingestion_state"] == "stopped"
    assert doc["last_error"] == "boom"
    assert doc["shutdown_reason"] == "max_events"


def test_health_write_json_atomic(tmp_path):
    h = HealthState()
    out = tmp_path / "x" / "health.json"
    h.write_json(out, queue=_Q(), spool=_Spool(), metrics=Metrics())
    assert out.exists() and not out.with_suffix(".json.tmp").exists()
    assert json.loads(out.read_text(encoding="utf-8"))["queue"]["capacity"] == 10


def test_health_extra_sections_are_extensible():
    doc = HealthState().snapshot(extra={"custom": {"k": 1}})
    assert doc["custom"] == {"k": 1}


def test_health_text_render():
    txt = HealthState().render_text(queue=_Q(), spool=_Spool(), metrics=Metrics())
    assert "engine_running" in txt and "queue" in txt and "spool" in txt and "throughput" in txt
