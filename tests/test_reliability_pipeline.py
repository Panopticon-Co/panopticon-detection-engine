"""Tests for the V2 streaming pipeline (src/reliability/pipeline.py).

Covers the whole queue -> detection -> spool -> sink path plus the V2 spec's
deterministic-shutdown and restart-recovery requirements.
"""

import threading
import time

from panopticon_detection.reliability.alert_sink import IncrementalAlertWriter
from panopticon_detection.reliability.health import HealthState
from panopticon_detection.reliability.metrics import Metrics
from panopticon_detection.reliability.pipeline import StreamingPipeline
from panopticon_detection.reliability.queue import BoundedEventQueue, OverflowPolicy
from panopticon_detection.reliability.retry import RetryPolicy
from panopticon_detection.reliability.spool import AlertSpool


def _event(n):
    return {"event_id": f"evt-{n}", "event_type": "process_create",
            "timestamp": "2026-08-28T00:00:00Z",
            "process": {"pid": 1000 + n, "name": f"p{n}.exe"}}


def _mk(tmp_path, detection_fn, **kw):
    spool = AlertSpool(tmp_path / "spool.db",
                       retry_policy=kw.pop("retry", RetryPolicy(max_attempts=3, base_delay=0.01, jitter=0.0)))
    writer = kw.pop("writer", None) or IncrementalAlertWriter(tmp_path / "alerts.ndjson", fsync=False)
    metrics, health = Metrics(), HealthState()
    pipe = StreamingPipeline(spool=spool, writer=writer, detection_fn=detection_fn,
                             metrics=metrics, health=health, idle_poll=0.01, **kw)
    return pipe, spool, writer, metrics, health


class _Alert:
    def __init__(self, aid, rule="DET-PROC-011"):
        self._d = {"alert_id": aid, "rule_id": rule, "evidence": {}}

    def to_dict(self):
        return dict(self._d)


# -- happy path -------------------------------------------------------------
def test_stream_processed_alerts_persisted_and_delivered(tmp_path):
    def detect(ev):
        return [_Alert(f"ALT-{ev['process']['pid']}")] if ev["process"]["pid"] % 2 == 0 else []

    pipe, spool, writer, metrics, health = _mk(tmp_path, detect)
    try:
        res = pipe.run([_event(i) for i in range(10)])
        assert res.events_received == 10
        assert res.events_processed == 10
        assert res.alerts_generated == 5
        assert res.alerts_persisted == 5
        assert res.alerts_delivered == 5
        assert res.spool_pending == 0 and res.spool_dead == 0
        assert res.stopped_reason == "stream_end"
        assert writer.count == 5
        assert spool.stats().delivered == 5
        assert health.snapshot()["engine_running"] is False
    finally:
        spool.close()


def test_same_alert_twice_is_persisted_and_delivered_once(tmp_path):
    def detect(ev):
        return [_Alert("ALT-DUP")]  # every event yields the same alert_id

    pipe, spool, writer, metrics, _ = _mk(tmp_path, detect)
    try:
        res = pipe.run([_event(i) for i in range(5)])
        assert res.alerts_generated == 5
        assert res.alerts_persisted == 1
        assert res.alerts_delivered == 1
        assert writer.count == 1
    finally:
        spool.close()


# -- detection failure ---------------------------------------------------
def test_detection_exception_is_counted_and_stream_continues(tmp_path):
    def detect(ev):
        if ev["process"]["pid"] == 1003:
            raise RuntimeError("bad event")
        return [_Alert(f"ALT-{ev['process']['pid']}")]

    pipe, spool, writer, metrics, health = _mk(tmp_path, detect)
    try:
        res = pipe.run([_event(i) for i in range(6)])
        assert res.events_failed == 1
        assert res.events_processed == 5
        assert res.alerts_delivered == 5
        assert health.snapshot()["last_error"] is not None
    finally:
        spool.close()


# -- delivery failure + retry ------------------------------------------
def test_transient_delivery_failure_retries_then_succeeds(tmp_path):
    calls = {"n": 0}

    class FlakyWriter:
        def __init__(self):
            self.count = 0

        def write(self, record):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("device busy")
            self.count += 1
            return True

        def flush(self):
            pass

    pipe, spool, writer, metrics, health = _mk(
        tmp_path, lambda ev: [_Alert("ALT-1")],
        writer=FlakyWriter(),
        retry=RetryPolicy(max_attempts=5, base_delay=0.01, jitter=0.0),
    )
    try:
        res = pipe.run([_event(1)])
        assert res.alerts_persisted == 1
        assert res.alerts_failed == 2
        assert res.retry_attempts == 2
        assert res.alerts_delivered == 1
        assert res.spool_pending == 0 and res.spool_dead == 0
    finally:
        spool.close()


def test_permanent_delivery_failure_goes_dead_inspectable_no_hot_loop(tmp_path):
    class DeadWriter:
        count = 0

        def write(self, record):
            raise OSError("permanent")

        def flush(self):
            pass

    t0 = time.monotonic()
    pipe, spool, writer, metrics, health = _mk(
        tmp_path, lambda ev: [_Alert("ALT-X")],
        writer=DeadWriter(),
        retry=RetryPolicy(max_attempts=3, base_delay=0.02, jitter=0.0),
    )
    try:
        res = pipe.run([_event(1)])
        assert res.alerts_delivered == 0
        assert res.alerts_failed == 3
        assert res.spool_dead == 1
        dead = spool.dead_alerts()
        assert len(dead) == 1 and dead[0].payload["alert_id"] == "ALT-X"
        assert time.monotonic() - t0 >= 0.04  # backoff really slept -> not a hot loop
    finally:
        spool.close()


# -- restart / recovery -----------------------------------------------
def test_recover_redelivers_pending_alerts_without_double_emitting(tmp_path):
    db = tmp_path / "spool.db"
    out = tmp_path / "alerts.ndjson"

    # run 1: writer that "crashes the process" right after the file write, before
    # the pipeline can mark_delivered
    class HalfWriter(IncrementalAlertWriter):
        def write(self, record):
            super().write(record)
            raise KeyboardInterrupt("die after write")

    s1 = AlertSpool(db, retry_policy=RetryPolicy(max_attempts=9, base_delay=0.01, jitter=0.0))
    w1 = IncrementalAlertWriter(out, fsync=False)
    StreamingPipeline(spool=s1, writer=w1, detection_fn=lambda ev: [_Alert(f"ALT-{ev['process']['pid']}")],
                           idle_poll=0.01)
    # do it by hand: persist + write, but never mark_delivered (simulated crash)
    for i in range(3):
        rec = _Alert(f"ALT-{1000 + i}").to_dict()
        s1.persist(rec)
        w1.write(rec)
    w1.close()
    assert s1.stats().pending_total == 3   # written to file, not acked
    s1.close()

    # run 2: fresh objects, same db + same file
    s2 = AlertSpool(db, retry_policy=RetryPolicy(max_attempts=9, base_delay=0.01, jitter=0.0))
    w2 = IncrementalAlertWriter(out, fsync=False)   # indexes the 3 existing lines
    p2 = StreamingPipeline(spool=s2, writer=w2, detection_fn=lambda ev: [], idle_poll=0.01)
    try:
        recovered = p2.recover()
        assert recovered == 3
        assert s2.stats().pending_total == 0
        assert s2.stats().delivered == 3
        # file still has exactly 3 lines -> no double emit
        assert len(out.read_text(encoding="utf-8").splitlines()) == 3
        assert w2.skipped_duplicates == 3
    finally:
        s2.close()


def test_full_run_after_restart_recovers_then_streams(tmp_path):
    db = tmp_path / "s.db"
    out = tmp_path / "a.ndjson"
    s1 = AlertSpool(db)
    s1.persist(_Alert("ALT-OLD").to_dict())   # left pending by a prior crash
    s1.close()

    s2 = AlertSpool(db)
    w2 = IncrementalAlertWriter(out, fsync=False)
    pipe = StreamingPipeline(spool=s2, writer=w2,
                             detection_fn=lambda ev: [_Alert(f"ALT-{ev['process']['pid']}")],
                             idle_poll=0.01)
    try:
        res = pipe.run([_event(1), _event(2)])
        assert res.recovered_on_start == 1
        # ALT-OLD (recovered) + ALT-1001 + ALT-1002 all delivered exactly once
        assert res.alerts_delivered == 3
        lines = [line for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(lines) == 3
    finally:
        s2.close()


# -- deterministic shutdown -----------------------------------------
def test_max_events_stops_deterministically_and_drains(tmp_path):
    seen = []
    pipe, spool, writer, metrics, health = _mk(
        tmp_path, lambda ev: seen.append(ev["process"]["pid"]) or [_Alert(f"ALT-{ev['process']['pid']}")],
        max_events=4,
    )
    try:
        res = pipe.run(iter(_event(i) for i in range(1000)))
        assert res.events_processed == 4
        assert res.stopped_reason == "max_events"
        assert res.alerts_delivered == 4
        assert health.snapshot()["shutdown_reason"] == "max_events"
    finally:
        spool.close()


def test_duration_stops_the_stream(tmp_path):
    def slow_source():
        i = 0
        while True:
            yield _event(i)
            i += 1
            time.sleep(0.02)

    pipe, spool, writer, metrics, health = _mk(
        tmp_path, lambda ev: [_Alert(f"ALT-{ev['process']['pid']}")],
        duration_seconds=0.15,
    )
    try:
        res = pipe.run(slow_source())
        assert res.stopped_reason == "duration"
        assert res.events_processed >= 1
        assert res.spool_pending == 0
    finally:
        spool.close()


def test_external_stop_event(tmp_path):
    stop = threading.Event()

    def source():
        i = 0
        while not stop.is_set():
            yield _event(i)
            i += 1
            time.sleep(0.01)

    pipe, spool, writer, metrics, health = _mk(tmp_path, lambda ev: [_Alert(f"ALT-{ev['process']['pid']}")])

    def stopper():
        time.sleep(0.1)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    try:
        res = pipe.run(source(), stop_event=stop)
        assert res.events_processed >= 1
        assert res.spool_pending == 0  # everything persisted got delivered on the final sweep
    finally:
        spool.close()


def test_source_generator_is_closed_on_shutdown_no_orphan(tmp_path):
    closed = {"v": False}

    def source():
        try:
            i = 0
            while True:
                yield _event(i)
                i += 1
        finally:
            closed["v"] = True  # stands in for Officer subprocess / ETW teardown

    pipe, spool, writer, metrics, health = _mk(tmp_path, lambda ev: [], max_events=3)
    try:
        pipe.run(source())
        assert closed["v"] is True
    finally:
        spool.close()


def test_drain_policy_false_discards_queued_on_stop(tmp_path):
    gate = threading.Event()
    processed = []

    def detect(ev):
        processed.append(ev["process"]["pid"])
        if len(processed) == 1:
            gate.wait(timeout=1.0)  # hold the consumer so the queue fills
        return []

    q = BoundedEventQueue(capacity=100, overflow=OverflowPolicy.BLOCK)
    pipe, spool, writer, metrics, health = _mk(tmp_path, detect, queue=q,
                                               max_events=1, drain_on_shutdown=False)
    try:
        res = pipe.run(iter(_event(i) for i in range(50)))
        gate.set()
        assert res.events_processed == 1  # stopped after 1, did not drain the rest
    finally:
        spool.close()


# -- queue overflow ------------------------------------------------
def test_queue_overflow_rejects_are_counted_not_silent(tmp_path):
    # Deterministic: park the consumer inside detection of the first event, wait
    # for the producer to finish flooding a capacity-2 queue, then release.
    q = BoundedEventQueue(capacity=2, overflow=OverflowPolicy.DROP_NEWEST)
    consumer_parked = threading.Event()
    release = threading.Event()

    def detect(ev):
        consumer_parked.set()
        release.wait(timeout=3.0)
        return []

    pipe, spool, writer, metrics, health = _mk(tmp_path, detect, queue=q)

    def controller():
        consumer_parked.wait(3.0)        # first event pulled, consumer stuck
        pipe._producer_done.wait(3.0)    # all 30 puts attempted, queue closed
        release.set()

    threading.Thread(target=controller, daemon=True).start()
    try:
        res = pipe.run(iter(_event(i) for i in range(30)))
        assert res.events_received == 30
        assert res.events_dropped >= 1             # bounded queue actually rejected
        assert res.events_processed <= 3           # only the 1 in-hand + 2 queued
        # rejects are surfaced via events_failed, never silently lost
        assert metrics.get("events_failed") >= res.events_dropped
        assert res.events_processed + res.events_dropped == 30
    finally:
        spool.close()
