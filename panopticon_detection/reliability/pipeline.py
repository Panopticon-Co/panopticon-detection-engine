"""V2 streaming pipeline: bounded queue -> detection -> durable spool -> sink.

Turns the V1 batch loop into a continuous, restart-safe local stream while
preserving the Schema 0.2 contract and the alerts.ndjson boundary.

    event source (Officer stdout / NDJSON)         Schema 0.2 dicts, untouched
        │  [producer thread]
        ▼
    BoundedEventQueue                              bounded memory + backpressure
        │  [consumer thread]
        ▼
    detection_fn(event) -> [Alert, ...]            V1 DetectionRun.process_event
        │
        ▼  for each alert
    AlertSpool.persist(alert)   ── durable, status=pending (BEFORE the file write)
        │
        ▼
    IncrementalAlertWriter.write(alert)  ── append + fsync to alerts.ndjson
        │
        ├─ ok       -> spool.mark_delivered
        └─ failure  -> spool.mark_failed -> retry (bounded backoff) or terminal 'dead'

On start, ``recover()`` re-delivers alerts left ``pending`` by a previous
crashed run before the live stream is consumed. Dedup on ``alert_id`` (in both
the spool and the writer's index of the existing file) means recovery never
double-emits.

Shutdown is deterministic: ``max_events`` / ``duration`` / an external stop
event / ``KeyboardInterrupt`` all trigger the same path -- stop the producer,
close the source generator (so the Officer subprocess is terminated, no orphan),
drain the queue per policy, final spool sweep, flush + close.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from panopticon_detection.reliability.health import HealthState
from panopticon_detection.reliability.metrics import Metrics
from panopticon_detection.reliability.queue import CLOSED, EMPTY, BoundedEventQueue, OverflowPolicy
from panopticon_detection.reliability.spool import AlertSpool

DetectionFn = Callable[[Dict[str, Any]], Iterable[Any]]
AlertRenderFn = Callable[[Any], None]


@dataclass
class PipelineResult:
    events_received: int = 0
    events_processed: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    alerts_generated: int = 0
    alerts_persisted: int = 0
    alerts_delivered: int = 0
    alerts_failed: int = 0
    retry_attempts: int = 0
    spool_pending: int = 0
    spool_failed: int = 0
    spool_dead: int = 0
    recovered_on_start: int = 0
    stopped_reason: str = "completed"

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class StreamingPipeline:
    def __init__(
        self,
        *,
        spool: AlertSpool,
        writer,
        detection_fn: DetectionFn,
        queue: Optional[BoundedEventQueue] = None,
        metrics: Optional[Metrics] = None,
        health: Optional[HealthState] = None,
        on_alert_rendered: Optional[AlertRenderFn] = None,
        max_events: Optional[int] = None,
        duration_seconds: Optional[float] = None,
        drain_on_shutdown: bool = True,
        idle_poll: float = 0.1,
    ) -> None:
        self.spool = spool
        self.writer = writer
        self.detection_fn = detection_fn
        self.metrics = metrics or Metrics()
        self.health = health or HealthState()
        self.on_alert_rendered = on_alert_rendered
        self.max_events = max_events
        self.duration_seconds = duration_seconds
        self.drain_on_shutdown = drain_on_shutdown
        self.idle_poll = max(0.0, idle_poll)

        # NB: BoundedEventQueue defines __len__, so an empty one is falsy --
        # use an explicit None check, never `queue or default`.
        self.queue = queue if queue is not None else BoundedEventQueue(
            capacity=1024, overflow=OverflowPolicy.BLOCK
        )
        # Own the drop accounting regardless of who constructed the queue.
        self.queue.set_on_drop(self._on_drop)
        self.metrics.set_gauge("queue_capacity", self.queue.capacity)

        self._stop = threading.Event()
        self._producer_done = threading.Event()
        self._deadline: Optional[float] = None
        self._source_gen = None  # set in run()

    # -- overflow safety net --------------------------------------
    def _on_drop(self, item: Any) -> None:
        # Only reached for DROP_* policies. The event is lost from the stream;
        # count it as rejected and record it -- never silently.
        self.metrics.incr("events_failed")
        self.health.mark_error("queue overflow: event rejected")

    # -- stage 1: source -> queue -------------------------------
    def _produce(self, source: Iterable[Any]) -> None:
        try:
            for item in source:
                if self._stop.is_set() or self._past_deadline():
                    break
                self.metrics.incr("events_received")
                try:
                    self.queue.put(item, timeout=0.5)
                except Exception:
                    break  # queue closed during shutdown
        finally:
            self._producer_done.set()
            self.queue.close()

    def _past_deadline(self) -> bool:
        return self._deadline is not None and time.monotonic() >= self._deadline

    # -- stage 2: queue -> detection -> delivery ---------------
    def _consume(self) -> None:
        processed = 0
        while True:
            if self._stop.is_set() and not self.drain_on_shutdown:
                return
            item = self.queue.get(timeout=0.25)
            if item is CLOSED:
                return
            if item is EMPTY:
                # idle: drive any retry-ready alert deliveries so retries happen
                # continuously during a long run, not only at start/stop.
                self._retry_ready()
                if (self._stop.is_set() or self._past_deadline()) and (
                    self._producer_done.is_set() and len(self.queue) == 0
                ):
                    return
                continue

            self._process_event(item)
            processed += 1
            self.health.mark_event_processed()

            if self.max_events is not None and processed >= self.max_events:
                # hard cap: max_events bounds how many events are processed,
                # regardless of drain policy or queue backlog.
                self._stop.set()
                self._deadline = time.monotonic()
                self.queue.close()
                return

    def _process_event(self, event: Any) -> None:
        t0 = time.perf_counter()
        try:
            alerts = list(self.detection_fn(event) or [])
        except Exception as e:
            self.metrics.incr("events_failed")
            self.health.mark_error(f"detection failed: {e!r}")
            return
        self.metrics.observe_latency(time.perf_counter() - t0)
        self.metrics.incr("events_processed")
        for alert in alerts:
            self.metrics.incr("alerts_generated")
            self._deliver(alert)

    # -- delivery + retry -------------------------------------
    def _deliver(self, alert: Any, *, from_recovery: bool = False) -> None:
        record = alert.to_dict() if hasattr(alert, "to_dict") else alert
        alert_id = record.get("alert_id")

        if not from_recovery:
            outcome = self.spool.persist(alert)
            if outcome == "new":
                self.metrics.incr("alerts_persisted")
                self.health.mark_alert_persisted()
            elif self.spool.already_delivered(alert_id):
                return  # a previous run already delivered this exact alert

        self._attempt_write(alert_id, record)

    def _attempt_write(self, alert_id: str, record: dict) -> bool:
        try:
            written = self.writer.write(record)
        except Exception as e:
            result = self.spool.mark_failed(alert_id, repr(e))
            self.metrics.incr("alerts_failed")
            if result == "retry":
                self.metrics.incr("retry_attempts")
            self.health.mark_error(f"deliver {alert_id}: {e!r}")
            return False

        self.spool.mark_delivered(alert_id)
        if written:
            self.metrics.incr("alerts_delivered")
            if self.on_alert_rendered is not None:
                self.on_alert_rendered(record)
        return True

    # -- retry / recovery -----------------------------------
    def _retry_ready(self) -> int:
        """Deliver every alert whose retry backoff has elapsed. One pass."""
        n = 0
        for sa in self.spool.claim_deliverable(limit=256):
            self._deliver(sa.payload, from_recovery=True)
            n += 1
        if n:
            self._refresh_gauges()
        return n

    def recover(self) -> int:
        """Re-deliver every alert left ``pending`` in the spool by a prior run.
        Safe to call before the live stream: dedup keeps it from double-emitting.
        """
        handled = 0
        while not self._stop.is_set():
            n = self._retry_ready()
            if n == 0:
                break
            handled += n
        return handled

    def _drain_spool(self, *, max_seconds: float = 60.0) -> None:
        """Final sweep: keep delivering until nothing is ``pending`` (every
        alert has either delivered or gone terminal ``dead``). Bounded by
        ``max_seconds`` and guaranteed to terminate because each attempt moves
        an alert strictly toward delivered/dead."""
        deadline = time.monotonic() + max_seconds
        while self.spool.pending_count() > 0 and time.monotonic() < deadline:
            if self._retry_ready() == 0:
                time.sleep(0.02)  # everything left is still in backoff

    def run(self, source: Iterable[Any], *, stop_event: Optional[threading.Event] = None) -> PipelineResult:
        recovered = self.recover()

        if self.duration_seconds is not None:
            self._deadline = time.monotonic() + self.duration_seconds
        if stop_event is not None:
            threading.Thread(target=lambda: (stop_event.wait(), self._stop.set()), daemon=True).start()

        self._source_gen = source
        self.health.set_ingestion_state("streaming")

        producer = threading.Thread(target=self._produce, args=(source,), name="v2-producer")
        producer.start()

        reason = "completed"
        try:
            self._consume()
        except KeyboardInterrupt:
            reason = "keyboard_interrupt"
        finally:
            self._stop.set()
            self.health.set_ingestion_state("draining")
            self.queue.close()
            # Close the source generator so Officer's subprocess/ETW teardown
            # runs now -- no orphan process, no leaked session.
            closer = getattr(source, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass
            producer.join(timeout=5.0)
            # Final sweep: deliver everything still pending (retries included)
            # before we close, so a clean stop leaves the spool settled.
            self._drain_spool()
            try:
                self.writer.flush()
            except Exception:
                pass
            self._refresh_gauges()
            if reason == "completed":
                reason = self._natural_reason()
            self.health.mark_stopped(reason)

        return self._result(recovered, reason)

    def _natural_reason(self) -> str:
        if self.max_events is not None:
            return "max_events"
        if self.duration_seconds is not None:
            return "duration"
        return "stream_end"

    def request_stop(self, reason: str = "requested") -> None:
        self._stop.set()
        self._deadline = time.monotonic()
        self.queue.close()

    # -- helpers ----------------------------------------
    def _refresh_gauges(self) -> None:
        self.metrics.set_gauge("queue_depth", len(self.queue))
        st = self.spool.stats()
        self.metrics.set_gauge("spool_pending", st.pending_total)
        self.metrics.set_gauge("spool_failed", self.spool.failed_count())

    def _result(self, recovered: int, reason: str) -> PipelineResult:
        c = self.metrics.snapshot()["counters"]
        st = self.spool.stats()
        return PipelineResult(
            events_received=c["events_received"],
            events_processed=c["events_processed"],
            events_failed=c["events_failed"],
            events_dropped=self.queue.stats.dropped_total,
            alerts_generated=c["alerts_generated"],
            alerts_persisted=c["alerts_persisted"],
            alerts_delivered=c["alerts_delivered"],
            alerts_failed=c["alerts_failed"],
            retry_attempts=c["retry_attempts"],
            spool_pending=st.pending_total,
            spool_failed=self.spool.failed_count(),
            spool_dead=st.dead,
            recovered_on_start=recovered,
            stopped_reason=reason,
        )
