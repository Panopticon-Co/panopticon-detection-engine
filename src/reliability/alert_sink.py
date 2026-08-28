"""Append-safe incremental alert writer (V2 Phase 4).

V1 accumulated every ``Alert`` in a list and dumped the NDJSON file once, after
the whole telemetry stream finished. For a *continuous* pipeline that never ends
that means alerts are never written. This writer appends one line per alert as
soon as it is generated and flushes deterministically, so ``panopticon-console``
(which already tolerates a half-written trailing line) shows alerts mid-run.

Crash-safety comes from the format, not from locking:

* the file is opened for **append** -- existing bytes are never rewritten;
* each alert is serialized to a single line ``json.dumps(...) + "\\n"`` and
  written in one ``write`` call, so an abrupt kill can at worst leave a
  truncated *final* line -- every prior line is intact and parseable;
* ``flush()`` + optional ``os.fsync`` after each line (or each batch) bounds how
  much a crash can lose.

Output is byte-for-byte the same shape V1 produced (``Alert.to_dict()`` per
line), so anything already reading ``--output-file`` keeps working.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable, Union


def _as_record(alert: Any) -> dict:
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    if isinstance(alert, dict):
        return alert
    raise TypeError(f"cannot serialize alert of type {type(alert).__name__}")


class IncrementalAlertWriter:
    """Line-buffered, append-only NDJSON alert sink."""

    def __init__(
        self,
        path: Union[str, Path],
        *,
        fsync: bool = True,
        fsync_every: int = 1,
    ) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._fsync_every = max(1, int(fsync_every))
        self._since_sync = 0
        self._count = 0
        self._lock = threading.Lock()
        # line-buffered text append; newline="" keeps our explicit "\n" verbatim
        self._fh = open(self.path, "a", encoding="utf-8", newline="")

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def write(self, alert: Any) -> None:
        line = json.dumps(_as_record(alert), separators=(",", ":"), default=str) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()
            self._count += 1
            self._since_sync += 1
            if self._fsync and self._since_sync >= self._fsync_every:
                os.fsync(self._fh.fileno())
                self._since_sync = 0

    def write_many(self, alerts: Iterable[Any]) -> int:
        n = 0
        for a in alerts:
            self.write(a)
            n += 1
        return n

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
