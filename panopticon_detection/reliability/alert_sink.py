"""Append-safe incremental alert writer (V2 Phase 4).

V1 accumulated every ``Alert`` in a list and dumped the NDJSON file once, after
the whole telemetry stream finished. A continuous V2 session never ends, so the
file would never be written. This writer appends one line per alert the moment
it is generated and flushes deterministically, so ``panopticon-console`` shows
alerts mid-run.

Crash-safety is a property of the format plus a repair on open:

* the file is opened for **append** -- existing bytes are never rewritten;
* each alert is serialized to a single ``json.dumps(...) + "\\n"`` and written
  in one ``write`` call, so an abrupt kill can at worst leave a truncated
  *final* line;
* **on open**, if the file does not end in a newline (a torn final record from a
  crash), the partial tail is truncated back to the last newline *before* any
  append -- a new record is never concatenated onto a broken one;
* on open the existing ``alert_id`` values are indexed, so a restart never
  re-appends an alert that already went to the file (Phase 9: "duplicates are
  not incorrectly emitted").

Output is byte-for-byte the V1 shape (``Alert.to_dict()`` per line), so anything
already reading ``--output-file`` keeps working.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable, Set, Union


def _as_record(alert: Any) -> dict:
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    if isinstance(alert, dict):
        return alert
    raise TypeError(f"cannot serialize alert of type {type(alert).__name__}")


class IncrementalAlertWriter:
    """Line-buffered, append-only, restart-safe NDJSON alert sink."""

    def __init__(
        self,
        path: Union[str, Path],
        *,
        fsync: bool = True,
        fsync_every: int = 1,
        dedupe: bool = True,
    ) -> None:
        self.path = Path(path).expanduser()
        if self.path.is_dir():
            raise IsADirectoryError(
                f"--output-file must be a writable file path, not a directory: {self.path}"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._fsync_every = max(1, int(fsync_every))
        self._since_sync = 0
        self._count = 0
        self._skipped_duplicates = 0
        self._dedupe = dedupe
        self._seen: Set[str] = set()
        self._lock = threading.Lock()

        self._repair_torn_tail()
        if dedupe:
            self._index_existing()

        # line-buffered text append; newline="" keeps our explicit "\n" verbatim
        self._fh = open(self.path, "a", encoding="utf-8", newline="")

    # -- open-time recovery ------------------------------------------
    def _repair_torn_tail(self) -> None:
        """If the file ends mid-record (no trailing newline), drop the partial
        tail so the next append starts a clean line."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size == 0:
            return
        with open(self.path, "rb+") as fh:
            fh.seek(-1, os.SEEK_END)
            if fh.read(1) == b"\n":
                return  # last record is complete
            data = self.path.read_bytes()
            nl = data.rfind(b"\n")
            fh.truncate(nl + 1)  # nl == -1 -> truncate to 0 (whole file was one partial line)

    def _index_existing(self) -> None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("alert_id"):
                self._seen.add(obj["alert_id"])
                self._count += 1

    # -- properties ------------------------------------------------
    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def skipped_duplicates(self) -> int:
        with self._lock:
            return self._skipped_duplicates

    def has(self, alert_id: str) -> bool:
        with self._lock:
            return alert_id in self._seen

    # -- write ---------------------------------------------------
    def write(self, alert: Any) -> bool:
        """Append one alert. Returns ``True`` if written, ``False`` if skipped as
        a duplicate ``alert_id`` (dedupe on)."""
        record = _as_record(alert)
        alert_id = record.get("alert_id")
        line = json.dumps(record, separators=(",", ":"), default=str) + "\n"
        with self._lock:
            if self._dedupe and alert_id and alert_id in self._seen:
                self._skipped_duplicates += 1
                return False
            self._fh.write(line)
            self._fh.flush()
            if alert_id:
                self._seen.add(alert_id)
            self._count += 1
            self._since_sync += 1
            if self._fsync and self._since_sync >= self._fsync_every:
                os.fsync(self._fh.fileno())
                self._since_sync = 0
            return True

    def write_many(self, alerts: Iterable[Any]) -> int:
        return sum(1 for a in alerts if self.write(a))

    def flush(self) -> None:
        with self._lock:
            self._fh.flush()
            if self._fsync:
                os.fsync(self._fh.fileno())
                self._since_sync = 0

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                if self._fsync:
                    try:
                        os.fsync(self._fh.fileno())
                    except OSError:
                        pass
                self._fh.close()

    def __enter__(self) -> "IncrementalAlertWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
