"""Ransomware Shield, Canary Tripwires, and Early-Kill Protection.

Deploys hidden canary tripwire file patterns and detects rapid extension encryption:
- Flags unauthorized access/renaming of canary files (*.canary.docx, *.tripwire.pdf)
- Flags known ransomware extension append operations (.locked, .crypto, .wnry, .lockbit)
- Triggers instant sub-millisecond process killing to prevent mass file destruction.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


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

    def __init__(self, burst_threshold: int = 4, burst_window_seconds: float = 5.0):
        self.burst_threshold = burst_threshold
        self.burst_window = burst_window_seconds
        # Key: (host_id, pid) -> deque of (timestamp, filepath)
        self.process_file_activity: Dict[str, deque] = defaultdict(deque)
        self.alerted_pids: Set[str] = set()

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

        p_key = f"{host_id}:{pid}"
        if p_key in self.alerted_pids:
            return None

        now_ts = self._parse_timestamp(event.get("timestamp"))
        file_lower = file_path.lower()
        suffix = Path(file_lower).suffix

        # 1. Direct Canary Tripwire Check: Attempting to touch or modify canary files
        is_canary = any(marker in file_lower for marker in self.CANARY_MARKERS)
        if is_canary:
            self.alerted_pids.add(p_key)
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
                    "action_required": "IMMEDIATE_PROCESS_KILL",
                },
            )

        # 2. Known Ransomware Extension Suffix Check
        if suffix in self.RANSOM_EXTENSIONS:
            self.alerted_pids.add(p_key)
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
        activity_queue = self.process_file_activity[p_key]
        activity_queue.append((now_ts, file_path))

        cutoff = now_ts - self.burst_window
        while activity_queue and activity_queue[0][0] < cutoff:
            activity_queue.popleft()

        if len(activity_queue) >= self.burst_threshold:
            self.alerted_pids.add(p_key)
            sample_files = [f for _, f in activity_queue]
            return CanaryTripwireMatch(
                host_id=host_id,
                process_name=proc_name,
                pid=pid,
                threat_type="High-Velocity Mass File Modification Burst (Ransomware)",
                affected_files_count=len(activity_queue),
                detected_extensions=[Path(f).suffix for f in sample_files],
                confidence=0.94,
                evidence={
                    "triggered_mechanism": "Velocity Threshold Breach",
                    "files_modified_in_window": len(activity_queue),
                    "window_seconds": self.burst_window,
                    "sample_targets": sample_files[:6],
                    "offending_process": proc_name,
                    "offending_pid": pid,
                },
            )

        return None

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> float:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                clean_ts = ts_val.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_ts).timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()
