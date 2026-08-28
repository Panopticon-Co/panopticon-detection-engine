"""SQLite durable spool for V2 alert delivery.

Reliability boundary between *alert generation* (the detection engine) and
*alert delivery* (appending to ``alerts.ndjson`` for the console). Every alert
is written here transactionally **before** it is appended to the NDJSON file, so
a crash between "detected" and "written" cannot lose it: on restart the alert is
still ``pending`` and gets delivered.

Design notes mapped to the V2 spec:

* **Local file-backed SQLite**, configurable path, WAL mode, ``busy_timeout`` --
  no server, no network, safe for the single-process local architecture.
* **Schema/version migration** -- ``spool_meta.schema_version`` + an ordered
  ``_MIGRATIONS`` list. An older file is upgraded; a newer file is refused, not
  corrupted.
* **Transactional writes and state transitions** -- every mutation runs inside
  ``with self._conn`` (BEGIN/COMMIT, rollback on exception).
* **Delivery lifecycle** per alert: ``pending -> delivered`` on success;
  ``pending -> pending`` (retry scheduled) or ``pending -> dead`` (retries
  exhausted) on failure. ``dead`` / ``failed`` rows keep their payload so they
  stay inspectable.
* **Identity / dedup** -- ``alert_id`` is the primary key. ``persist`` is
  idempotent (``INSERT ... ON CONFLICT DO NOTHING``) and reports ``new`` vs
  ``duplicate``, so a restart never re-delivers an alert that already went out.
* **Corrupt-record handling** -- a row whose payload will not parse is moved to
  ``dead`` on claim instead of blocking the queue forever.

The spool does not import or know about the console; the NDJSON file is the only
thing downstream and that coupling lives in the pipeline, not here.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from src.reliability.retry import RetryPolicy

SPOOL_SCHEMA_VERSION = 1

STATUS_PENDING = "pending"
STATUS_DELIVERED = "delivered"
STATUS_DEAD = "dead"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_at(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SpoolSchemaError(RuntimeError):
    """Existing file is a spool this build does not understand."""


@dataclass(frozen=True)
class SpooledAlert:
    """One claimed alert row awaiting delivery."""

    alert_id: str
    payload: Dict[str, Any]
    attempts: int
    created_at: str
    last_error: Optional[str]


@dataclass(frozen=True)
class SpoolStats:
    pending_ready: int
    pending_retry: int
    delivered: int
    dead: int

    @property
    def pending_total(self) -> int:
        return self.pending_ready + self.pending_retry

    @property
    def total(self) -> int:
        return self.pending_total + self.delivered + self.dead

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["pending_total"] = self.pending_total
        d["total"] = self.total
        return d


# -- migrations -----------------------------------------------------------
def _migration_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE alerts (
            alert_id        TEXT PRIMARY KEY,
            payload         TEXT,
            rule_id         TEXT,
            created_at      TEXT NOT NULL,
            status          TEXT NOT NULL,
            attempts        INTEGER NOT NULL DEFAULT 0,
            last_attempt_at TEXT,
            next_attempt_at TEXT,
            last_error      TEXT,
            delivered_at    TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX ix_alerts_delivery ON alerts (status, next_attempt_at, created_at)"
    )


# Ordered. Index i upgrades a v(i) file to v(i+1).
_MIGRATIONS: List[Callable[[sqlite3.Connection], None]] = [_migration_1]


class AlertSpool:
    """Durable, deduplicating, retry-aware alert delivery spool (one SQLite file)."""

    def __init__(
        self,
        path: Union[str, Path],
        *,
        retry_policy: Optional[RetryPolicy] = None,
        synchronous: str = "NORMAL",
        busy_timeout_ms: int = 5000,
    ) -> None:
        self.path = Path(path).expanduser()
        self.retry_policy = retry_policy or RetryPolicy()
        self._lock = threading.RLock()

        synchronous = str(synchronous).upper()
        if synchronous not in ("OFF", "NORMAL", "FULL", "EXTRA"):
            raise ValueError(f"invalid synchronous mode: {synchronous!r}")
        busy_timeout_ms = int(busy_timeout_ms)

        is_mem = str(self.path) == ":memory:"
        if not is_mem:
            self.path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if not is_mem:
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute(f"PRAGMA synchronous = {synchronous}")
        self._migrate()

    # -- schema / migration ---------------------------------------------
    def _migrate(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS spool_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._conn.execute(
                "SELECT value FROM spool_meta WHERE key = 'schema_version'"
            ).fetchone()
            current = int(row["value"]) if row else 0

            if current > SPOOL_SCHEMA_VERSION:
                raise SpoolSchemaError(
                    f"spool at {self.path} is schema v{current}; this build supports "
                    f"v{SPOOL_SCHEMA_VERSION}"
                )

            for version in range(current, SPOOL_SCHEMA_VERSION):
                _MIGRATIONS[version](self._conn)

            if current == 0:
                self._conn.execute(
                    "INSERT INTO spool_meta (key, value) VALUES ('created_at', ?)",
                    (_utcnow_iso(),),
                )
            self._conn.execute(
                "INSERT INTO spool_meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SPOOL_SCHEMA_VERSION),),
            )

    # -- write ------------------------------------------------------
    def persist(self, alert: Any) -> str:
        """Durably record a freshly generated alert as ``pending``. Idempotent.

        Returns ``"new"`` if inserted, ``"duplicate"`` if this ``alert_id`` was
        already spooled (any status). Accepts an object with ``.to_dict()`` or a
        plain dict.
        """
        record = alert.to_dict() if hasattr(alert, "to_dict") else alert
        if not isinstance(record, dict):
            raise TypeError("persist() needs an Alert or an alert dict")
        alert_id = record.get("alert_id")
        if not alert_id:
            raise ValueError("alert has no alert_id")
        payload = json.dumps(record, separators=(",", ":"), default=str)
        now = _utcnow_iso()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO alerts
                    (alert_id, payload, rule_id, created_at, status, attempts,
                     last_attempt_at, next_attempt_at, last_error, delivered_at)
                VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL)
                ON CONFLICT(alert_id) DO NOTHING
                """,
                (alert_id, payload, record.get("rule_id"), now, STATUS_PENDING),
            )
            return "new" if cur.rowcount == 1 else "duplicate"

    # -- read / claim ---------------------------------------------
    def claim_deliverable(self, limit: int = 128, *, now: Optional[float] = None) -> List[SpooledAlert]:
        """Return up to ``limit`` alerts ready for delivery, oldest first.

        Ready = ``pending`` with ``next_attempt_at`` unset or already elapsed.
        Claiming does not mutate rows, so a crash before ack simply re-offers
        them (at-least-once; dedup on ``alert_id`` keeps that safe)."""
        if limit < 1:
            return []
        now_iso = _utcnow_iso() if now is None else _iso_at(now)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT alert_id, payload, attempts, created_at, last_error
                FROM alerts
                WHERE status = ?
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY created_at ASC, rowid ASC
                LIMIT ?
                """,
                (STATUS_PENDING, now_iso, int(limit)),
            ).fetchall()

        out: List[SpooledAlert] = []
        for r in rows:
            try:
                payload = json.loads(r["payload"])
            except (TypeError, json.JSONDecodeError):
                self._quarantine(r["alert_id"], "unparseable payload row")
                continue
            out.append(
                SpooledAlert(
                    alert_id=r["alert_id"],
                    payload=payload,
                    attempts=r["attempts"],
                    created_at=r["created_at"],
                    last_error=r["last_error"],
                )
            )
        return out

    def already_delivered(self, alert_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return bool(row) and row["status"] == STATUS_DELIVERED

    # -- state transitions --------------------------------------
    def mark_delivered(self, alert_id: str) -> None:
        """Alert successfully appended to the NDJSON sink. Payload is nulled to
        keep the dedup tombstone small; the row is kept for audit + dedup."""
        now = _utcnow_iso()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE alerts
                SET status = ?, delivered_at = ?, last_attempt_at = ?,
                    next_attempt_at = NULL, last_error = NULL, payload = NULL
                WHERE alert_id = ?
                """,
                (STATUS_DELIVERED, now, now, alert_id),
            )

    def mark_failed(self, alert_id: str, error: str, *, now: Optional[float] = None) -> str:
        """Record a failed delivery attempt.

        Increments ``attempts``. If retries remain, schedules the next attempt
        (row stays ``pending``, returns ``"retry"``). Otherwise the row becomes
        terminal ``dead`` and keeps its payload + error (returns ``"dead"``).
        The alert is never discarded.
        """
        base = time.time() if now is None else now
        stamp = _utcnow_iso()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT attempts FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                return "unknown"
            attempts = row["attempts"] + 1
            if self.retry_policy.is_exhausted(attempts):
                self._conn.execute(
                    """
                    UPDATE alerts
                    SET status = ?, attempts = ?, last_error = ?, last_attempt_at = ?,
                        next_attempt_at = NULL
                    WHERE alert_id = ?
                    """,
                    (STATUS_DEAD, attempts, str(error)[:8192], stamp, alert_id),
                )
                return "dead"
            delay = self.retry_policy.compute_delay(attempts)
            self._conn.execute(
                """
                UPDATE alerts
                SET attempts = ?, last_error = ?, last_attempt_at = ?, next_attempt_at = ?
                WHERE alert_id = ?
                """,
                (attempts, str(error)[:8192], stamp, _iso_at(base + delay), alert_id),
            )
            return "retry"

    def requeue_dead(self, alert_id: str) -> bool:
        """Operator action: send a ``dead`` alert back to ``pending`` with a
        clean attempt counter."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE alerts
                SET status = ?, attempts = 0, next_attempt_at = NULL, last_error = NULL
                WHERE alert_id = ? AND status = ?
                """,
                (STATUS_PENDING, alert_id, STATUS_DEAD),
            )
            return cur.rowcount == 1

    def _quarantine(self, alert_id: str, error: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET status = ?, last_error = ?, last_attempt_at = ? WHERE alert_id = ?",
                (STATUS_DEAD, error, _utcnow_iso(), alert_id),
            )

    # -- introspection -----------------------------------------
    def stats(self, *, now: Optional[float] = None) -> SpoolStats:
        now_iso = _utcnow_iso() if now is None else _iso_at(now)
        with self._lock:
            ready = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE status = ? "
                "AND (next_attempt_at IS NULL OR next_attempt_at <= ?)",
                (STATUS_PENDING, now_iso),
            ).fetchone()["c"]
            retry = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE status = ? "
                "AND next_attempt_at IS NOT NULL AND next_attempt_at > ?",
                (STATUS_PENDING, now_iso),
            ).fetchone()["c"]
            delivered = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE status = ?", (STATUS_DELIVERED,)
            ).fetchone()["c"]
            dead = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE status = ?", (STATUS_DEAD,)
            ).fetchone()["c"]
        return SpoolStats(pending_ready=ready, pending_retry=retry, delivered=delivered, dead=dead)

    def pending_count(self) -> int:
        return self.stats().pending_total

    def failed_count(self) -> int:
        """Alerts that failed at least once and are still awaiting a retry."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE status = ? AND attempts > 0",
                (STATUS_PENDING,),
            ).fetchone()["c"]

    def dead_count(self) -> int:
        return self.stats().dead

    def dead_alerts(self) -> List[SpooledAlert]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT alert_id, payload, attempts, created_at, last_error "
                "FROM alerts WHERE status = ? ORDER BY last_attempt_at ASC",
                (STATUS_DEAD,),
            ).fetchall()
        out = []
        for r in rows:
            try:
                payload = json.loads(r["payload"]) if r["payload"] else {}
            except (TypeError, json.JSONDecodeError):
                payload = {}
            out.append(
                SpooledAlert(
                    alert_id=r["alert_id"], payload=payload, attempts=r["attempts"],
                    created_at=r["created_at"], last_error=r["last_error"],
                )
            )
        return out

    def schema_version(self) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT value FROM spool_meta WHERE key = 'schema_version'"
                ).fetchone()["value"]
            )

    # -- lifecycle -------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._conn.close()

    def __enter__(self) -> "AlertSpool":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
