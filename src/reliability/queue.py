"""Bounded, thread-safe in-memory event queue for the V2 ingestion path.

This sits between a *producer* (the thread draining an Officer / NDJSON stream)
and a *consumer* (the detection loop). Its whole job is to decouple those two
without letting a fast producer grow memory without limit.

Design points mapped to the V2 requirements:

* **Configurable capacity** -- ``BoundedEventQueue(capacity=...)``.
* **Explicit overflow behaviour** -- ``OverflowPolicy`` chosen at construction;
  never an implicit silent drop.
* **No unbounded growth** -- the backing ``deque`` is hard-capped at ``capacity``.
* **Producer/consumer separation** -- ``put`` and ``get`` are independent and
  safe to call from different threads.
* **Graceful shutdown** -- ``close()`` unblocks every waiter; consumers drain
  what is already queued, then ``get`` returns the ``CLOSED`` sentinel.
* **No dropped events silently** -- every drop increments a counter and, if
  supplied, calls ``on_drop(item)`` so the caller can spool it durably.
* **Observable state** -- ``stats`` returns an immutable snapshot at any time.

Only the standard library is used (``collections.deque`` + ``threading``).
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Deque, Optional


class OverflowPolicy(str, Enum):
    """What ``put`` does when the queue is already at capacity."""

    BLOCK = "block"
    """Block the producer until a slot frees up (natural backpressure)."""

    DROP_NEWEST = "drop_newest"
    """Reject the incoming item. ``put`` returns ``False``; item goes to ``on_drop``."""

    DROP_OLDEST = "drop_oldest"
    """Evict the oldest queued item to make room. The evicted item goes to ``on_drop``."""


class QueueClosed(Exception):
    """Raised by ``put`` when the queue has been closed."""


# Returned by ``get`` once the queue is closed *and* drained. Distinct from
# ``None`` so ``None`` remains a legal queue payload.
CLOSED = object()

# Returned by ``get(timeout=...)`` / ``get_nowait`` when the queue is still open
# but has nothing to hand out right now.
EMPTY = object()


@dataclass(frozen=True)
class QueueStats:
    """Immutable point-in-time view of the queue, safe to log or serialize."""

    capacity: int
    depth: int
    enqueued: int
    dequeued: int
    dropped_newest: int
    dropped_oldest: int
    max_depth: int
    closed: bool

    @property
    def dropped_total(self) -> int:
        return self.dropped_newest + self.dropped_oldest

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["dropped_total"] = self.dropped_total
        return d


class BoundedEventQueue:
    """A capacity-bounded FIFO queue with an explicit overflow policy."""

    def __init__(
        self,
        capacity: int,
        overflow: OverflowPolicy = OverflowPolicy.BLOCK,
        *,
        on_drop: Optional[Callable[[Any], None]] = None,
    ) -> None:
        if capacity < 1:
            raise ValueError("queue capacity must be >= 1")
        self._capacity = int(capacity)
        self._overflow = OverflowPolicy(overflow)
        self._on_drop = on_drop

        self._items: Deque[Any] = deque()
        self._cv = threading.Condition()
        self._closed = False

        # counters (protected by self._cv)
        self._enqueued = 0
        self._dequeued = 0
        self._dropped_newest = 0
        self._dropped_oldest = 0
        self._max_depth = 0

    # -- properties -----------------------------------------------------------
    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def overflow_policy(self) -> OverflowPolicy:
        return self._overflow

    def __len__(self) -> int:
        with self._cv:
            return len(self._items)

    @property
    def closed(self) -> bool:
        with self._cv:
            return self._closed

    @property
    def stats(self) -> QueueStats:
        with self._cv:
            return QueueStats(
                capacity=self._capacity,
                depth=len(self._items),
                enqueued=self._enqueued,
                dequeued=self._dequeued,
                dropped_newest=self._dropped_newest,
                dropped_oldest=self._dropped_oldest,
                max_depth=self._max_depth,
                closed=self._closed,
            )

    # -- producer side ------------------------------------------------------
    def put(self, item: Any, *, timeout: Optional[float] = None) -> bool:
        """Enqueue ``item``.

        Returns ``True`` if the item was stored, ``False`` if it was dropped by
        the overflow policy (``DROP_NEWEST``, or ``BLOCK`` that timed out).
        Raises :class:`QueueClosed` if the queue is closed.

        A dropped item is passed to ``on_drop`` (if configured) *before* this
        method returns, so the caller can persist it and never lose it silently.
        """
        with self._cv:
            if self._closed:
                raise QueueClosed("put() on a closed BoundedEventQueue")

            if len(self._items) >= self._capacity:
                if self._overflow is OverflowPolicy.DROP_NEWEST:
                    self._dropped_newest += 1
                    self._fire_drop(item)
                    return False

                if self._overflow is OverflowPolicy.DROP_OLDEST:
                    evicted = self._items.popleft()
                    self._dropped_oldest += 1
                    self._items.append(item)
                    self._enqueued += 1
                    self._cv.notify()
                    self._fire_drop(evicted)
                    return True

                # BLOCK: wait for room, closure, or timeout.
                ok = self._cv.wait_for(
                    lambda: self._closed or len(self._items) < self._capacity,
                    timeout=timeout,
                )
                if self._closed:
                    raise QueueClosed("BoundedEventQueue closed while put() was blocked")
                if not ok:
                    self._dropped_newest += 1
                    self._fire_drop(item)
                    return False

            self._items.append(item)
            self._enqueued += 1
            if len(self._items) > self._max_depth:
                self._max_depth = len(self._items)
            self._cv.notify()
            return True

    def set_on_drop(self, cb: Optional[Callable[[Any], None]]) -> None:
        """Register (or replace) the overflow callback after construction --
        used when the queue is created by one component but drop-accounting is
        owned by another (the pipeline)."""
        with self._cv:
            self._on_drop = cb

    def _fire_drop(self, item: Any) -> None:
        if self._on_drop is None:
            return
        # Never let a misbehaving callback wedge the queue lock holder's logic;
        # the lock is held here, so the callback must be cheap (spool.put()).
        self._on_drop(item)

    # -- consumer side ----------------------------------------------------
    def get(self, *, timeout: Optional[float] = None) -> Any:
        """Dequeue and return the oldest item.

        Blocks up to ``timeout`` seconds (forever if ``timeout`` is ``None``)
        while the queue is empty and open. Returns:

        * the oldest item, if one is available;
        * :data:`CLOSED` if the queue is closed and fully drained -- the
          shutdown signal for a consumer loop;
        * :data:`EMPTY` if ``timeout`` elapsed while the queue was still open.

        ::

            while True:
                item = q.get(timeout=1.0)
                if item is CLOSED:
                    break
                if item is EMPTY:
                    continue
                handle(item)
        """
        with self._cv:
            if not self._items:
                self._cv.wait_for(
                    lambda: bool(self._items) or self._closed,
                    timeout=timeout,
                )
            if self._items:
                item = self._items.popleft()
                self._dequeued += 1
                self._cv.notify()  # wake a producer blocked on capacity
                return item
            return CLOSED if self._closed else EMPTY

    def get_nowait(self) -> Any:
        """Non-blocking ``get``. Returns :data:`CLOSED` if closed and drained,
        else :data:`EMPTY` if nothing is queued."""
        with self._cv:
            if self._items:
                item = self._items.popleft()
                self._dequeued += 1
                self._cv.notify()
                return item
            return CLOSED if self._closed else EMPTY

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        """Close the queue. Idempotent. Wakes every blocked producer/consumer.

        Items already queued remain retrievable via ``get`` until drained.
        """
        with self._cv:
            if self._closed:
                return
            self._closed = True
            self._cv.notify_all()

    def drain(self) -> list:
        """Remove and return all remaining items (used during shutdown to flush
        the in-memory tail into the durable spool)."""
        with self._cv:
            remaining = list(self._items)
            self._dequeued += len(self._items)
            self._items.clear()
            self._cv.notify_all()
            return remaining
