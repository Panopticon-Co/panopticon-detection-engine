"""Tests for the V2 bounded in-memory event queue (src/reliability/queue.py).

Covers: normal enqueue/dequeue, capacity limit, each overflow policy, graceful
shutdown, empty-queue behaviour, observable stats, and concurrent producer/
consumer access.
"""

import threading
import time

import pytest

from panopticon_detection.reliability.queue import (
    CLOSED,
    EMPTY,
    BoundedEventQueue,
    OverflowPolicy,
    QueueClosed,
)


def test_rejects_bad_capacity():
    with pytest.raises(ValueError):
        BoundedEventQueue(capacity=0)


def test_normal_enqueue_dequeue_is_fifo():
    q = BoundedEventQueue(capacity=8)
    for i in range(5):
        assert q.put(i) is True
    assert len(q) == 5
    out = [q.get_nowait() for _ in range(5)]
    assert out == [0, 1, 2, 3, 4]
    assert len(q) == 0
    s = q.stats
    assert s.enqueued == 5 and s.dequeued == 5 and s.max_depth == 5


def test_none_is_a_legal_payload():
    q = BoundedEventQueue(capacity=2)
    q.put(None)
    got = q.get_nowait()
    assert got is None  # distinct from EMPTY / CLOSED sentinels


def test_empty_queue_nowait_returns_empty_sentinel():
    q = BoundedEventQueue(capacity=2)
    assert q.get_nowait() is EMPTY


def test_empty_queue_get_with_timeout_returns_empty_sentinel():
    q = BoundedEventQueue(capacity=2)
    t0 = time.monotonic()
    assert q.get(timeout=0.05) is EMPTY
    assert time.monotonic() - t0 >= 0.05


def test_capacity_limit_with_drop_newest():
    dropped = []
    q = BoundedEventQueue(
        capacity=3, overflow=OverflowPolicy.DROP_NEWEST, on_drop=dropped.append
    )
    assert all(q.put(i) for i in range(3))
    assert q.put(99) is False  # rejected
    assert dropped == [99]
    assert [q.get_nowait() for _ in range(3)] == [0, 1, 2]
    assert q.stats.dropped_newest == 1
    assert q.stats.dropped_total == 1


def test_capacity_limit_with_drop_oldest():
    dropped = []
    q = BoundedEventQueue(
        capacity=3, overflow=OverflowPolicy.DROP_OLDEST, on_drop=dropped.append
    )
    for i in range(3):
        q.put(i)
    assert q.put(3) is True  # accepted, evicts 0
    assert dropped == [0]
    assert [q.get_nowait() for _ in range(3)] == [1, 2, 3]
    assert q.stats.dropped_oldest == 1
    # queue never exceeds capacity
    assert q.stats.max_depth == 3


def test_block_policy_applies_backpressure_then_unblocks_on_get():
    q = BoundedEventQueue(capacity=1, overflow=OverflowPolicy.BLOCK)
    q.put("a")
    done = threading.Event()

    def producer():
        q.put("b")  # blocks until the consumer frees the slot
        done.set()

    th = threading.Thread(target=producer)
    th.start()
    assert not done.wait(timeout=0.1)  # still blocked
    assert q.get_nowait() == "a"
    assert done.wait(timeout=1.0)  # now it got through
    th.join(timeout=1.0)
    assert q.get_nowait() == "b"


def test_block_policy_times_out_and_reports_drop():
    dropped = []
    q = BoundedEventQueue(
        capacity=1, overflow=OverflowPolicy.BLOCK, on_drop=dropped.append
    )
    q.put("a")
    assert q.put("b", timeout=0.05) is False
    assert dropped == ["b"]
    assert q.stats.dropped_newest == 1


def test_put_after_close_raises():
    q = BoundedEventQueue(capacity=2)
    q.close()
    with pytest.raises(QueueClosed):
        q.put(1)


def test_close_is_idempotent_and_observable():
    q = BoundedEventQueue(capacity=2)
    assert q.closed is False
    q.close()
    q.close()
    assert q.closed is True
    assert q.stats.closed is True


def test_consumer_drains_then_sees_closed_sentinel():
    q = BoundedEventQueue(capacity=4)
    q.put(1)
    q.put(2)
    q.close()
    assert q.get_nowait() == 1
    assert q.get_nowait() == 2
    assert q.get_nowait() is CLOSED
    assert q.get(timeout=0.01) is CLOSED


def test_close_unblocks_a_waiting_consumer():
    q = BoundedEventQueue(capacity=2)
    result = []

    def consumer():
        result.append(q.get())  # blocks (no timeout) until close()

    th = threading.Thread(target=consumer)
    th.start()
    time.sleep(0.05)
    q.close()
    th.join(timeout=1.0)
    assert result == [CLOSED]


def test_close_unblocks_a_blocked_producer_with_queue_closed():
    q = BoundedEventQueue(capacity=1, overflow=OverflowPolicy.BLOCK)
    q.put("a")
    err = []

    def producer():
        try:
            q.put("b")
        except QueueClosed as e:  # pragma: no cover - message not asserted
            err.append(e)

    th = threading.Thread(target=producer)
    th.start()
    time.sleep(0.05)
    q.close()
    th.join(timeout=1.0)
    assert len(err) == 1


def test_drain_returns_the_in_memory_tail():
    q = BoundedEventQueue(capacity=8)
    for i in range(5):
        q.put(i)
    tail = q.drain()
    assert tail == [0, 1, 2, 3, 4]
    assert len(q) == 0


def test_concurrent_producers_and_consumers_lose_nothing():
    q = BoundedEventQueue(capacity=64, overflow=OverflowPolicy.BLOCK)
    n_producers = 4
    per_producer = 500
    produced_total = n_producers * per_producer
    consumed = []
    consumed_lock = threading.Lock()

    def producer(pid):
        for i in range(per_producer):
            q.put((pid, i))

    def consumer():
        while True:
            item = q.get(timeout=1.0)
            if item is CLOSED:
                return
            if item is EMPTY:
                continue
            with consumed_lock:
                consumed.append(item)

    prods = [threading.Thread(target=producer, args=(p,)) for p in range(n_producers)]
    cons = [threading.Thread(target=consumer) for _ in range(3)]
    for t in cons:
        t.start()
    for t in prods:
        t.start()
    for t in prods:
        t.join(timeout=5.0)
    q.close()
    for t in cons:
        t.join(timeout=5.0)

    assert len(consumed) == produced_total
    assert set(consumed) == {(p, i) for p in range(n_producers) for i in range(per_producer)}
    s = q.stats
    assert s.enqueued == produced_total
    assert s.dequeued == produced_total
    assert s.dropped_total == 0
    assert s.depth == 0
    assert s.max_depth <= s.capacity
