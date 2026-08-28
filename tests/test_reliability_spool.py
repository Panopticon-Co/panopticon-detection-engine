"""Tests for the V2 SQLite alert-delivery spool (src/reliability/spool.py)."""

import json
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reliability.retry import RetryPolicy
from src.reliability.spool import (
    SPOOL_SCHEMA_VERSION,
    STATUS_DEAD,
    STATUS_DELIVERED,
    STATUS_PENDING,
    AlertSpool,
    SpoolSchemaError,
)


def _alert(n, rule_id="DET-PROC-011"):
    return {
        "alert_id": f"ALT-{n:08X}",
        "rule_id": rule_id,
        "title": f"alert {n}",
        "evidence": {"process.pid": 1000 + n},
        "timestamp": "2026-08-28T00:00:00.000Z",
    }


@pytest.fixture
def spool(tmp_path):
    s = AlertSpool(
        tmp_path / "spool.db",
        retry_policy=RetryPolicy(max_attempts=3, base_delay=0.01, jitter=0.0),
    )
    yield s
    s.close()


# -- initialization / migration -----------------------------------------
def test_database_initialization(tmp_path):
    p = tmp_path / "s.db"
    s = AlertSpool(p)
    try:
        assert p.exists()
        con = sqlite3.connect(p)
        tbls = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"spool_meta", "alerts"} <= tbls
        con.close()
        assert s.schema_version() == SPOOL_SCHEMA_VERSION
    finally:
        s.close()


def test_reopen_is_safe_and_idempotent(tmp_path):
    p = tmp_path / "s.db"
    AlertSpool(p).close()
    s2 = AlertSpool(p)
    assert s2.schema_version() == SPOOL_SCHEMA_VERSION
    s2.close()


def test_newer_schema_is_refused_not_corrupted(tmp_path):
    p = tmp_path / "s.db"
    AlertSpool(p).close()
    con = sqlite3.connect(p)
    con.execute("UPDATE spool_meta SET value='999' WHERE key='schema_version'")
    con.commit()
    con.close()
    with pytest.raises(SpoolSchemaError):
        AlertSpool(p)


def test_migration_from_a_bare_db_creates_current_schema(tmp_path):
    p = tmp_path / "s.db"
    # a pre-existing db with no spool tables at all
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE unrelated (x INTEGER)")
    con.commit()
    con.close()
    s = AlertSpool(p)
    try:
        assert s.schema_version() == SPOOL_SCHEMA_VERSION
        assert s.persist(_alert(1)) == "new"
    finally:
        s.close()


# -- persist / claim --------------------------------------------------
def test_persist_and_claim_roundtrip(spool):
    assert spool.persist(_alert(1)) == "new"
    batch = spool.claim_deliverable()
    assert len(batch) == 1
    assert batch[0].alert_id == "ALT-00000001"
    assert batch[0].payload["rule_id"] == "DET-PROC-011"
    assert batch[0].attempts == 0


def test_persist_accepts_objects_with_to_dict(spool):
    class A:
        def to_dict(self):
            return _alert(2)

    assert spool.persist(A()) == "new"
    assert spool.claim_deliverable()[0].alert_id == "ALT-00000002"


def test_persist_requires_alert_id(spool):
    with pytest.raises(ValueError):
        spool.persist({"rule_id": "x"})


def test_duplicate_persist_is_ignored(spool):
    assert spool.persist(_alert(7)) == "new"
    assert spool.persist(_alert(7)) == "duplicate"
    assert spool.stats().pending_total == 1


# -- delivery acknowledgement --------------------------------------
def test_mark_delivered_removes_from_claimable_and_keeps_tombstone(spool):
    spool.persist(_alert(3))
    spool.mark_delivered("ALT-00000003")
    assert spool.claim_deliverable() == []
    st = spool.stats()
    assert st.delivered == 1 and st.pending_total == 0
    assert spool.already_delivered("ALT-00000003") is True


def test_duplicate_persist_after_delivery_still_deduped(spool):
    spool.persist(_alert(9))
    spool.mark_delivered("ALT-00000009")
    assert spool.persist(_alert(9)) == "duplicate"
    assert spool.claim_deliverable() == []


# -- retry -------------------------------------------------------
def test_failed_delivery_schedules_a_retry_then_becomes_claimable(spool):
    spool.persist(_alert(4))
    assert spool.mark_failed("ALT-00000004", "disk full", now=1000.0) == "retry"
    assert spool.claim_deliverable(now=1000.0) == []           # backoff not elapsed
    again = spool.claim_deliverable(now=1001.0)
    assert len(again) == 1 and again[0].attempts == 1 and again[0].last_error == "disk full"
    assert spool.failed_count() == 1


def test_retry_exhaustion_moves_to_dead_and_keeps_payload(spool):
    spool.persist(_alert(5))
    for i in range(2):
        assert spool.mark_failed("ALT-00000005", f"e{i}", now=2000.0) == "retry"
    assert spool.mark_failed("ALT-00000005", "final", now=2000.0) == "dead"  # max_attempts=3
    assert spool.claim_deliverable(now=9_999_999) == []
    dead = spool.dead_alerts()
    assert len(dead) == 1
    assert dead[0].attempts == 3
    assert dead[0].last_error == "final"
    assert dead[0].payload["alert_id"] == "ALT-00000005"       # inspectable
    assert spool.dead_count() == 1


def test_requeue_dead(spool):
    spool.persist(_alert(6))
    for i in range(3):
        spool.mark_failed("ALT-00000006", "x", now=3000.0)
    assert spool.requeue_dead("ALT-00000006") is True
    back = spool.claim_deliverable()
    assert len(back) == 1 and back[0].attempts == 0


def test_mark_failed_unknown_id(spool):
    assert spool.mark_failed("ALT-NOPE", "e") == "unknown"


# -- restart / reopen --------------------------------------------
def test_restart_recovers_pending_not_delivered(tmp_path):
    p = tmp_path / "s.db"
    s1 = AlertSpool(p)
    s1.persist(_alert(10))
    s1.persist(_alert(11))
    s1.mark_delivered("ALT-0000000A")   # one delivered, one still pending
    s1.close()                          # simulate crash/stop

    s2 = AlertSpool(p)
    try:
        pending = s2.claim_deliverable()
        assert [a.alert_id for a in pending] == ["ALT-0000000B"]
        assert s2.already_delivered("ALT-0000000A") is True
        assert s2.stats().delivered == 1
    finally:
        s2.close()


# -- corrupt / malformed records -------------------------------
def test_claim_quarantines_a_corrupted_payload_row(spool):
    spool.persist(_alert(30))
    with spool._lock, spool._conn:
        spool._conn.execute("UPDATE alerts SET payload='{not json'")
    assert spool.claim_deliverable() == []          # not returned...
    assert spool.dead_count() == 1                   # ...quarantined, not looped


# -- transactions ---------------------------------------------
def test_persist_rolls_back_on_serialization_failure(spool):
    class Boom:
        def __repr__(self):
            raise RuntimeError("nope")

        __str__ = __repr__

    before = spool.stats().total
    with pytest.raises(RuntimeError):
        spool.persist({"alert_id": "ALT-BOOM", "evidence": Boom()})
    assert spool.stats().total == before


# -- concurrency --------------------------------------------
def test_concurrent_persist_and_one_deliverer_delivers_each_once(tmp_path):
    s = AlertSpool(tmp_path / "s.db", retry_policy=RetryPolicy(max_attempts=2, base_delay=0.01, jitter=0.0))
    n_producers, per = 5, 80
    total = n_producers * per

    def produce(pid):
        for i in range(per):
            s.persist(_alert(pid * 1000 + i))

    delivered = []
    stop = threading.Event()

    def deliver():
        while not stop.is_set():
            for a in s.claim_deliverable(32):
                s.mark_delivered(a.alert_id)
                delivered.append(a.alert_id)
            time.sleep(0.001)

    ths = [threading.Thread(target=produce, args=(p,)) for p in range(n_producers)]
    d = threading.Thread(target=deliver)
    d.start()
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=10)
    deadline = time.time() + 5
    while len(delivered) < total and time.time() < deadline:
        time.sleep(0.02)
    stop.set()
    d.join(timeout=5)
    s.close()

    assert len(delivered) == total
    assert len(set(delivered)) == total
