"""Lightweight, dependency-free metrics for the local V2 pipeline.

Just monotonic counters, instantaneous gauges, a small latency summary and
uptime -- enough to diagnose "is it keeping up and is it healthy" on one
endpoint. No Prometheus server, no OpenTelemetry, no push gateway.
``render_prometheus()`` returns the text exposition format as a plain string so
an operator *can* scrape a dumped file later without this module taking on a
dependency.

Thread-safe: every mutator takes a lock (producer and consumer run on different
threads).
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List

# Names align 1:1 with the V2 spec's Phase 7 list.
_COUNTERS = (
    "events_received",
    "events_processed",
    "events_failed",
    "alerts_generated",
    "alerts_persisted",
    "alerts_delivered",
    "alerts_failed",
    "retry_attempts",
)

_GAUGES = (
    "queue_depth",
    "queue_capacity",
    "spool_pending",
    "spool_failed",
)


class _Latency:
    """Bounded-memory latency summary (count/sum/min/max + recent percentiles)."""

    __slots__ = ("count", "total", "min", "max", "_buf", "_cap")

    def __init__(self, cap: int = 1024) -> None:
        self.count = 0
        self.total = 0.0
        self.min = float("inf")
        self.max = 0.0
        self._buf: List[float] = []
        self._cap = cap

    def observe(self, seconds: float) -> None:
        self.count += 1
        self.total += seconds
        self.min = min(self.min, seconds)
        self.max = max(self.max, seconds)
        if len(self._buf) < self._cap:
            self._buf.append(seconds)
        else:
            self._buf[self.count % self._cap] = seconds

    @property
    def avg(self) -> float:
        return self.total / self.count if self.count else 0.0

    def percentile(self, pct: float) -> float:
        if not self._buf:
            return 0.0
        ordered = sorted(self._buf)
        k = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
        return ordered[k]

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "avg": round(self.avg, 6),
            "min": 0.0 if self.min == float("inf") else round(self.min, 6),
            "max": round(self.max, 6),
            "p50": round(self.percentile(50), 6),
            "p95": round(self.percentile(95), 6),
        }


class Metrics:
    """A tiny registry of counters + gauges + one latency histogram + uptime."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._counters: Dict[str, int] = {n: 0 for n in _COUNTERS}
        self._gauges: Dict[str, float] = {n: 0 for n in _GAUGES}
        self.processing_latency = _Latency()

    # -- counters -----------------------------------------------------
    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            if name not in self._counters:
                raise KeyError(f"unknown counter {name!r}")
            self._counters[name] += amount

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters[name]

    # -- gauges -----------------------------------------------------
    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            if name not in self._gauges:
                raise KeyError(f"unknown gauge {name!r}")
            self._gauges[name] = value

    def get_gauge(self, name: str) -> float:
        with self._lock:
            return self._gauges[name]

    # -- latency / time -------------------------------------------
    def observe_latency(self, seconds: float) -> None:
        with self._lock:
            self.processing_latency.observe(seconds)

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self._started

    # -- rendering -----------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "uptime_seconds": round(self.uptime_seconds, 3),
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "processing_latency_seconds": self.processing_latency.to_dict(),
            }

    def render_prometheus(self) -> str:
        snap = self.snapshot()
        lines: List[str] = []
        for name, val in snap["counters"].items():
            lines.append(f"# TYPE panopticon_{name}_total counter")
            lines.append(f"panopticon_{name}_total {val}")
        for name, val in snap["gauges"].items():
            lines.append(f"# TYPE panopticon_{name} gauge")
            lines.append(f"panopticon_{name} {val}")
        lat = snap["processing_latency_seconds"]
        lines.append("# TYPE panopticon_processing_latency_seconds summary")
        lines.append(f'panopticon_processing_latency_seconds{{quantile="0.5"}} {lat["p50"]}')
        lines.append(f'panopticon_processing_latency_seconds{{quantile="0.95"}} {lat["p95"]}')
        lines.append(f"panopticon_processing_latency_seconds_count {lat['count']}")
        lines.append("# TYPE panopticon_uptime_seconds gauge")
        lines.append(f"panopticon_uptime_seconds {snap['uptime_seconds']}")
        return "\n".join(lines) + "\n"

    def render_text(self) -> str:
        snap = self.snapshot()
        rows = [f"uptime_seconds           {snap['uptime_seconds']}"]
        for k, v in snap["counters"].items():
            rows.append(f"{k:<24}{v}")
        for k, v in snap["gauges"].items():
            rows.append(f"{k:<24}{v}")
        lat = snap["processing_latency_seconds"]
        rows.append(
            f"processing_latency       n={lat['count']} avg={lat['avg']}s "
            f"p50={lat['p50']}s p95={lat['p95']}s max={lat['max']}s"
        )
        return "\n".join(rows) + "\n"
