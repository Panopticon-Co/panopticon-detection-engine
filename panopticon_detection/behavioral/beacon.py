"""C2 Beaconing and Periodic Heartbeat Detection Engine.

Detects Cobalt Strike, Sliver, and Metasploit Command & Control beaconing
by analyzing connection time-delta distributions and mathematical Coefficient of Variation (CV).
"""

import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from panopticon_detection.provenance.identity import event_epoch, naive_utc_epoch


@dataclass
class BeaconMatch:
    """Represents a confirmed periodic C2 beaconing pattern."""
    host_id: str
    destination_ip: str
    destination_port: int
    process_name: str
    process_guid: Optional[str]
    sample_count: int
    mean_interval_seconds: float
    std_dev_seconds: float
    coefficient_of_variation: float
    confidence: float
    evidence: Dict[str, Any]


class C2BeaconDetector:
    """Maintains connection interval histories and identifies automated periodic beaconing."""

    def __init__(
        self,
        min_samples: int = 4,
        max_cv_threshold: float = 0.22,
        latch_ttl_seconds: float = 3600.0,
    ):
        self.min_samples = min_samples
        self.max_cv_threshold = max_cv_threshold
        self.latch_ttl_seconds = latch_ttl_seconds
        # Key: (host_id, dest_ip, dest_port) -> deque of float timestamps
        self.connection_history: Dict[str, deque] = {}
        # key -> event time of the last alert. Suppresses repeats for the TTL
        # only, so a beacon that resumes later is reported again.
        self.alerted_beacons: Dict[str, float] = {}

    def ingest_connection(self, event: Dict[str, Any]) -> Optional[BeaconMatch]:
        """Analyzes an outbound network connection for periodic beaconing."""
        event_type = event.get("event_type")
        if event_type != "network_connect":
            return None

        net = event.get("network", {})
        proc = event.get("process", {})
        host_id = event.get("host_id", "UNKNOWN_HOST")
        dest_ip = net.get("destination_ip")
        dest_port = net.get("destination_port", 0)

        if not dest_ip or net.get("direction") == "inbound":
            return None

        now_ts = event_epoch(event.get("timestamp"))
        if now_ts is None:
            return None

        key = f"{host_id}:{dest_ip}:{dest_port}"
        last_alert = self.alerted_beacons.get(key)
        if last_alert is not None and now_ts - last_alert < self.latch_ttl_seconds:
            return None

        if key not in self.connection_history:
            self.connection_history[key] = deque(maxlen=20)

        history = self.connection_history[key]
        history.append(now_ts)

        if len(history) < self.min_samples:
            return None

        # Calculate time deltas
        deltas = [history[i] - history[i - 1] for i in range(1, len(history))]
        # Filter out negative or zero deltas
        deltas = [d for d in deltas if d > 0.1]

        if len(deltas) < (self.min_samples - 1):
            return None

        mean_interval = sum(deltas) / len(deltas)
        # Skip high-frequency burst streams (e.g. streaming web assets < 1s) or extremely sparse (> 1hr)
        if mean_interval < 1.0 or mean_interval > 3600.0:
            return None

        variance = sum((d - mean_interval) ** 2 for d in deltas) / len(deltas)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval if mean_interval > 0 else 1.0

        # Periodic beaconing matches when CV is low (indicating regular rhythm / heartbeat)
        if cv <= self.max_cv_threshold:
            self.alerted_beacons[key] = now_ts
            history.clear()
            confidence = round(max(0.85, 1.0 - (cv * 1.5)), 2)

            evidence = {
                "detected_pattern": "Automated Periodic C2 Heartbeat",
                "sample_connections_evaluated": len(history),
                "mean_beacon_interval": f"{round(mean_interval, 2)} seconds",
                "interval_jitter_stddev": f"±{round(std_dev, 2)} seconds",
                "coefficient_of_variation": round(cv, 3),
                "target_c2_endpoint": f"{dest_ip}:{dest_port}",
                "originating_process": proc.get("name"),
                "process_guid": proc.get("process_guid"),
            }

            return BeaconMatch(
                host_id=host_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                process_name=proc.get("name", "unknown"),
                process_guid=proc.get("process_guid"),
                sample_count=len(history),
                mean_interval_seconds=round(mean_interval, 2),
                std_dev_seconds=round(std_dev, 2),
                coefficient_of_variation=round(cv, 3),
                confidence=confidence,
                evidence=evidence,
            )

        return None

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
