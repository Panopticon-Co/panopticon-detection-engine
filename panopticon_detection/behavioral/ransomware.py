"""Ransomware indicators on file telemetry.

Flags three patterns in file events:
- a process touching a file whose path marks it as a canary/decoy (the engine
  does not deploy canaries; this only fires if an operator has planted them)
- a file written with a known ransomware extension (.locked, .wnry, .lockbit ...)
- a burst of file operations from one process in a short window

Detection only: the resulting alert carries a recommendation for an analyst,
nothing here acts on the host.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from panopticon_detection.provenance.identity import event_epoch, naive_utc_epoch


@dataclass
class CanaryTripwireMatch:
    """Represents a tripped ransomware canary or mass encryption burst."""
    host_id: str
    process_name: str
    pid: int
    threat_type: str
    affected_files_count: int
    detected_extensions: List[str]
    confidence: float
    evidence: Dict[str, Any]


class RansomwareShield:
    """Monitors file events for ransomware canary tripwires and mass encryption bursts."""

    RANSOM_EXTENSIONS = {
        ".locked", ".crypto", ".wnry", ".crypted", ".locky", ".enc",
        ".encrypted", ".mallox", ".lockbit", ".blackcat", ".alphv", ".akira",
    }

    CANARY_MARKERS = {"canary", "tripwire", "honeypot", "decoy"}

    def __init__(
        self,
        burst_threshold: int = 4,
        burst_window_seconds: float = 5.0,
        latch_ttl_seconds: float = 3600.0,
    ):
        self.burst_threshold = burst_threshold
        self.burst_window = burst_window_seconds
        self.latch_ttl_seconds = latch_ttl_seconds
        # Key: (host_id, pid) -> deque of (timestamp, filepath)
        self.process_file_activity: Dict[str, deque] = defaultdict(deque)
        # (host_id, pid) -> event time of the last alert. A TTL rather than a
        # permanent set, so a later process that reuses the PID is not muted.
        self.alerted_pids: Dict[str, float] = {}

    def inspect_file_event(self, event: Dict[str, Any]) -> Optional[CanaryTripwireMatch]:
        """Inspects a file modification, rename, or write event for ransomware indicators."""
        event_type = event.get("event_type")
        if event_type not in ("file_modify", "file_rename", "file_create", "file_event"):
            return None

        host_id = event.get("host_id", "UNKNOWN_HOST")
        proc = event.get("process", {})
        pid = proc.get("pid", 0)
        proc_name = proc.get("name", "unknown.exe")
        file_obj = event.get("file", {})
        file_path = file_obj.get("path") or file_obj.get("target_path") or ""

        if not file_path or not pid:
            return None

        # The canary and extension checks are single-event indicators and need
        # no time. The latch and the burst window do, so without a usable time
        # those are skipped rather than run against wall-clock time.
        now_ts = event_epoch(event.get("timestamp"))

        p_key = f"{host_id}:{pid}"
        last_alert = self.alerted_pids.get(p_key)
        if (
            now_ts is not None
            and last_alert is not None
            and now_ts - last_alert < self.latch_ttl_seconds
        ):
            return None

        file_lower = file_path.lower()
        suffix = Path(file_lower).suffix

        # 1. Canary path check: an operator-planted decoy file was touched
        is_canary = any(marker in file_lower for marker in self.CANARY_MARKERS)
        if is_canary:
            self._latch(p_key, now_ts)
            return CanaryTripwireMatch(
                host_id=host_id,
                process_name=proc_name,
                pid=pid,
                threat_type="Ransomware Canary Tripwire Breached",
                affected_files_count=1,
                detected_extensions=[suffix],
                confidence=0.98,
                evidence={
                    "triggered_mechanism": "Decoy Canary File Access",
                    "canary_file_path": file_path,
                    "offending_process": proc_name,
                    "offending_pid": pid,
                    "command_line": proc.get("command_line"),
                },
            )

        # 2. Known Ransomware Extension Suffix Check
        if suffix in self.RANSOM_EXTENSIONS:
            self._latch(p_key, now_ts)
            return CanaryTripwireMatch(
                host_id=host_id,
                process_name=proc_name,
                pid=pid,
                threat_type="Known Ransomware Extension Append Operation",
                affected_files_count=1,
                detected_extensions=[suffix],
                confidence=0.96,
                evidence={
                    "triggered_mechanism": "Ransomware Extension Signature",
                    "target_file": file_path,
                    "ransom_extension": suffix,
                    "offending_process": proc_name,
                    "offending_pid": pid,
                },
            )

        # 3. Rapid Encryption Burst Rate Check
        if now_ts is None:
            return None
        activity_queue = self.process_file_activity[p_key]
        activity_queue.append((now_ts, file_path))

        cutoff = now_ts - self.burst_window
        while activity_queue and activity_queue[0][0] < cutoff:
            activity_queue.popleft()

        if len(activity_queue) >= self.burst_threshold:
            self._latch(p_key, now_ts)
            sample_files = [f for _, f in activity_queue]
            activity_queue.clear()
            return CanaryTripwireMatch(
                host_id=host_id,
                process_name=proc_name,
                pid=pid,
                threat_type="High-Velocity Mass File Modification Burst (Ransomware)",
                affected_files_count=len(sample_files),
                detected_extensions=[Path(f).suffix for f in sample_files],
                confidence=0.94,
                evidence={
                    "triggered_mechanism": "Velocity Threshold Breach",
                    "files_modified_in_window": len(sample_files),
                    "window_seconds": self.burst_window,
                    "sample_targets": sample_files[:6],
                    "offending_process": proc_name,
                    "offending_pid": pid,
                },
            )

        return None

    def _latch(self, key: str, now_ts: Optional[float]) -> None:
        if now_ts is not None:
            self.alerted_pids[key] = now_ts

    def prune(self, before: datetime) -> int:
        """Drop per-process windows and latches with no activity since ``before``."""
        cutoff = naive_utc_epoch(before)
        stale = [
            k for k, q in self.process_file_activity.items() if not q or q[-1][0] < cutoff
        ]
        for k in stale:
            del self.process_file_activity[k]
        expired = [k for k, ts in self.alerted_pids.items() if ts < cutoff]
        for k in expired:
            del self.alerted_pids[k]
        return len(stale) + len(expired)
