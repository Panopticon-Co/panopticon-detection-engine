"""Periodic outbound connections from one process (C2 beaconing).

Implants call home on a timer, usually with jitter. This detector keeps, per
(process incarnation, destination), the times of outbound connections to a
public address and flags a series whose gaps are regular:

* robust dispersion -- the median absolute deviation of the gaps relative to
  their median (MAD / median). One late check-in or a burst of retries moves a
  standard deviation a lot and a median barely at all, so moderate jitter still
  reads as periodic while genuinely irregular traffic does not.
* a regular majority -- at least ``min_regular_fraction`` of the gaps within
  +/-``regular_band`` of the median. With few samples a dispersion statistic alone can look
  low by chance; requiring most gaps to agree with the cadence cuts that off.
* enough evidence -- at least ``min_connections`` connections spanning at least
  ``min_span_seconds``; a handful of quick connections is a page load.
* a plausible cadence -- a median gap between ``min_interval`` and
  ``max_interval`` seconds.

Measured on 300 seeded synthetic sessions of 20 connections each (see
tests/test_network_engine.py): 0% false positives on Poisson-arrival traffic,
~1% on gaps drawn uniformly from a capped 5-300s range; detection 100% at
+/-10% jitter, ~99% at +/-20%, ~60% at +/-30%. Heavier jitter than that is a
known miss -- a trade taken deliberately to keep irregular traffic quiet.

Scope and limits, stated plainly: only public destinations are tracked (an
internal service heartbeat looks identical to a beacon); keys are per process
incarnation, so two processes talking to one CDN never pool their timings;
browsers and updaters that poll on a fixed timer will still match, which is why
the alert is a detection for an analyst, not a verdict. Time is event time.
"""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, Optional

from panopticon_detection.enrichment import destination_scope
from panopticon_detection.provenance.identity import event_epoch, naive_utc_epoch


@dataclass
class BeaconMatch:
    host_id: str
    destination_ip: str
    destination_port: Any
    process_name: str
    pid: Optional[int]
    connections: int
    median_interval_seconds: float
    dispersion: float
    confidence: float
    evidence: Dict[str, Any]


class C2BeaconDetector:
    """Flags regular outbound connection cadences per process and destination."""

    def __init__(
        self,
        min_connections: int = 8,
        max_dispersion: float = 0.15,
        min_regular_fraction: float = 0.8,
        regular_band: float = 0.2,
        min_interval: float = 5.0,
        max_interval: float = 3600.0,
        min_span_seconds: float = 120.0,
        history: int = 32,
        latch_ttl_seconds: float = 3600.0,
        registry=None,
    ):
        self.min_connections = min_connections
        self.max_dispersion = max_dispersion
        self.min_regular_fraction = min_regular_fraction
        self.regular_band = regular_band
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.min_span_seconds = min_span_seconds
        self.history = history
        self.latch_ttl_seconds = latch_ttl_seconds
        self.registry = registry
        self.connection_history: Dict[str, Deque[float]] = {}
        self.alerted_beacons: Dict[str, float] = {}

    def _process_key(self, event: Dict[str, Any]) -> str:
        if self.registry is not None:
            actor = self.registry.resolve_event(event)
            if actor is not None:
                return actor.node_id
        proc = event.get("process") or {}
        return f"pid:{proc.get('pid')}"

    def ingest_connection(self, event: Dict[str, Any]) -> Optional[BeaconMatch]:
        if event.get("event_type") != "network_connect":
            return None
        net = event.get("network") or {}
        dest_ip = net.get("destination_ip")
        if not dest_ip or net.get("direction") == "inbound":
            return None
        if destination_scope(dest_ip) != "public":
            return None
        now_ts = event_epoch(event.get("timestamp"))
        if now_ts is None:
            return None

        host_id = event.get("host_id") or "UNKNOWN_HOST"
        dest_port = net.get("destination_port")
        key = f"{host_id}|{self._process_key(event)}|{dest_ip}:{dest_port}"

        last_alert = self.alerted_beacons.get(key)
        if last_alert is not None and now_ts - last_alert < self.latch_ttl_seconds:
            return None

        times = self.connection_history.setdefault(key, deque(maxlen=self.history))
        if times and now_ts < times[-1]:
            return None  # out of order; keeps the gaps meaningful
        times.append(now_ts)
        if len(times) < self.min_connections or times[-1] - times[0] < self.min_span_seconds:
            return None

        gaps = [b - a for a, b in zip(times, list(times)[1:]) if b - a > 0.5]
        if len(gaps) < self.min_connections - 1:
            return None
        median = statistics.median(gaps)
        if not self.min_interval <= median <= self.max_interval:
            return None
        mad = statistics.median(abs(g - median) for g in gaps)
        dispersion = mad / median if median else 1.0
        if dispersion > self.max_dispersion:
            return None
        regular = sum(1 for g in gaps if abs(g - median) <= self.regular_band * median) / len(gaps)
        if regular < self.min_regular_fraction:
            return None

        self.alerted_beacons[key] = now_ts
        times.clear()
        proc = event.get("process") or {}
        confidence = round(max(0.6, 0.95 - dispersion), 2)
        return BeaconMatch(
            host_id=host_id,
            destination_ip=dest_ip,
            destination_port=dest_port,
            process_name=proc.get("name") or "unknown",
            pid=proc.get("pid"),
            connections=len(gaps) + 1,
            median_interval_seconds=round(median, 2),
            dispersion=round(dispersion, 3),
            confidence=confidence,
            evidence={
                "destination": f"{dest_ip}:{dest_port}",
                "process": proc.get("name"),
                "pid": proc.get("pid"),
                "connections_observed": len(gaps) + 1,
                "median_interval_seconds": round(median, 2),
                "interval_dispersion_mad_over_median": round(dispersion, 3),
                "regular_gap_fraction": round(regular, 3),
                "min_interval_seconds": round(min(gaps), 2),
                "max_interval_seconds": round(max(gaps), 2),
            },
        )

    def prune(self, before: datetime) -> int:
        """Drop histories and latches with no activity since ``before``."""
        cutoff = naive_utc_epoch(before)
        stale = [k for k, h in self.connection_history.items() if not h or h[-1] < cutoff]
        for k in stale:
            del self.connection_history[k]
        expired = [k for k, ts in self.alerted_beacons.items() if ts < cutoff]
        for k in expired:
            del self.alerted_beacons[k]
        return len(stale) + len(expired)
