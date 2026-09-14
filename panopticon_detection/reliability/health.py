"""Lightweight local health / status model for the V2 pipeline.

Not a service and not an HTTP endpoint -- a single object the pipeline updates
as it runs and can render on demand to a dict, a text block, or an atomically
written JSON file that an operator (or a later status command) can read. Fields
are exactly those enumerated in the V2 spec's Phase 6.

Extensible: `extra` lets a caller staple additional sections on without changing
this class.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class HealthState:
    started_at: float = field(default_factory=time.time)
    running: bool = True
    ingestion_state: str = "idle"  # idle | streaming | draining | stopped
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    last_event_processed_at: Optional[float] = None
    last_alert_persisted_at: Optional[float] = None
    last_error: Optional[str] = None
    last_error_at: Optional[float] = None
    shutdown_reason: Optional[str] = None

    # -- mutators (thread-safe) --------------------------------------
    def set_ingestion_state(self, state: str) -> None:
        with self._lock:
            self.ingestion_state = state

    def mark_event_processed(self) -> None:
        with self._lock:
            self.last_event_processed_at = time.time()

    def mark_alert_persisted(self) -> None:
        with self._lock:
            self.last_alert_persisted_at = time.time()

    def mark_error(self, err: str) -> None:
        with self._lock:
            self.last_error = str(err)[:2000]
            self.last_error_at = time.time()

    def mark_stopped(self, reason: str) -> None:
        with self._lock:
            self.running = False
            self.ingestion_state = "stopped"
            self.shutdown_reason = reason

    # -- introspection --------------------------------------------
    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at

    def snapshot(
        self,
        *,
        queue: Any = None,
        spool: Any = None,
        metrics: Any = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            doc: Dict[str, Any] = {
                "engine_running": self.running,
                "status": "running" if self.running else "stopped",
                "ingestion_state": self.ingestion_state,
                "pid": os.getpid(),
                "started_at": _iso(self.started_at),
                "uptime_seconds": round(self.uptime_seconds, 3),
                "last_event_processed_at": _iso(self.last_event_processed_at),
                "last_alert_persisted_at": _iso(self.last_alert_persisted_at),
                "last_error": self.last_error,
                "last_error_at": _iso(self.last_error_at),
                "shutdown_reason": self.shutdown_reason,
                "queue": None,
                "spool": None,
                "counters": None,
            }

        if queue is not None:
            qs = queue.stats
            doc["queue"] = {
                "depth": qs.depth,
                "capacity": qs.capacity,
                "max_depth": qs.max_depth,
                "dropped_rejected": qs.dropped_total,
            }
        if spool is not None:
            ss = spool.stats()
            doc["spool"] = {
                "pending": ss.pending_total,
                "pending_ready": ss.pending_ready,
                "retry_waiting": ss.pending_retry,
                "delivered": ss.delivered,
                "failed": spool.failed_count(),
                "dead": ss.dead,
            }
        if metrics is not None:
            snap = metrics.snapshot()
            c = snap["counters"]
            doc["counters"] = {
                "events_received": c["events_received"],
                "events_processed": c["events_processed"],
                "events_failed": c["events_failed"],
                "alerts_generated": c["alerts_generated"],
                "alerts_persisted": c["alerts_persisted"],
                "alerts_delivered": c["alerts_delivered"],
                "alerts_failed": c["alerts_failed"],
                "retry_attempts": c["retry_attempts"],
                "processing_latency_seconds": snap["processing_latency_seconds"],
            }
        if extra:
            doc.update(extra)
        return doc

    def render_text(self, **sections: Any) -> str:
        doc = self.snapshot(**sections)
        lines = [
            f"engine_running          {doc['engine_running']}",
            f"ingestion_state         {doc['ingestion_state']}",
            f"pid                     {doc['pid']}",
            f"uptime_seconds          {doc['uptime_seconds']}",
            f"last_event_processed_at {doc['last_event_processed_at']}",
            f"last_alert_persisted_at {doc['last_alert_persisted_at']}",
            f"last_error              {doc['last_error']}",
        ]
        if doc["queue"]:
            q = doc["queue"]
            lines.append(
                f"queue                   depth={q['depth']}/{q['capacity']} "
                f"dropped_rejected={q['dropped_rejected']}"
            )
        if doc["spool"]:
            s = doc["spool"]
            lines.append(
                f"spool                   pending={s['pending']} retry_waiting={s['retry_waiting']} "
                f"failed={s['failed']} dead={s['dead']} delivered={s['delivered']}"
            )
        if doc["counters"]:
            m = doc["counters"]
            lines.append(
                f"throughput              events {m['events_processed']}/{m['events_received']} "
                f"alerts gen={m['alerts_generated']} persisted={m['alerts_persisted']} "
                f"delivered={m['alerts_delivered']} failed={m['alerts_failed']}"
            )
        return "\n".join(lines) + "\n"

    def write_json(self, path: "str | Path", **sections: Any) -> None:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(self.snapshot(**sections), indent=2), encoding="utf-8")
        os.replace(tmp, p)
