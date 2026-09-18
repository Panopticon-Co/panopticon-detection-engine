"""Lateral Port Scanning and Subnet Reconnaissance Tracker.

Detects horizontal subnet sweeps (e.g. searching for open port 445/3389 across multiple machines)
and vertical port scans (probing multiple ports on a single machine).
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Set


@dataclass
class PortScanMatch:
    """Represents a confirmed port scanning or subnet reconnaissance incident."""
    scan_type: str  # "Horizontal Subnet Sweep" or "Vertical Port Scan"
    host_id: str
    target_summary: str
    probed_count: int
    time_window_seconds: int
    process_name: str
    evidence: Dict[str, Any]


class PortScanDetector:
    """Tracks sliding window network probes across endpoints."""

    def __init__(
        self,
        horizontal_ip_threshold: int = 5,
        vertical_port_threshold: int = 6,
        time_window_seconds: int = 30,
    ):
        self.horizontal_threshold = horizontal_ip_threshold
        self.vertical_threshold = vertical_port_threshold
        self.time_window = time_window_seconds

        # Key: (host_id, port) -> deque of (timestamp, dest_ip)
        self.horizontal_sweeps: Dict[str, deque] = defaultdict(deque)

        # Key: (host_id, dest_ip) -> deque of (timestamp, port)
        self.vertical_scans: Dict[str, deque] = defaultdict(deque)

        # Suppress repeat alerts
        self.alerted_scans: Set[str] = set()

    def ingest_connection(self, event: Dict[str, Any]) -> List[PortScanMatch]:
        """Analyzes network connection for scanning behavior."""
        event_type = event.get("event_type")
        if event_type != "network_connect":
            return []

        net = event.get("network", {})
        proc = event.get("process", {})
        host_id = event.get("host_id", "UNKNOWN_HOST")
        dest_ip = net.get("destination_ip")
        dest_port = net.get("destination_port")

        if not dest_ip or not dest_port or net.get("direction") == "inbound":
            return []

        now_ts = self._parse_timestamp(event.get("timestamp"))
        cutoff = now_ts - self.time_window
        matches: List[PortScanMatch] = []

        # 1. Check Horizontal Subnet Sweep (Same host, same port -> multiple destination IPs)
        h_key = f"{host_id}:{dest_port}"
        h_queue = self.horizontal_sweeps[h_key]
        h_queue.append((now_ts, dest_ip))

        while h_queue and h_queue[0][0] < cutoff:
            h_queue.popleft()

        distinct_ips = {ip for _, ip in h_queue}
        if len(distinct_ips) >= self.horizontal_threshold and h_key not in self.alerted_scans:
            self.alerted_scans.add(h_key)
            matches.append(
                PortScanMatch(
                    scan_type="Horizontal Subnet Sweep (Lateral Reconnaissance)",
                    host_id=host_id,
                    target_summary=f"Port {dest_port} across {len(distinct_ips)} distinct internal endpoints",
                    probed_count=len(distinct_ips),
                    time_window_seconds=self.time_window,
                    process_name=proc.get("name", "unknown"),
                    evidence={
                        "scan_type": "Horizontal Subnet Sweep",
                        "probed_port": dest_port,
                        "unique_target_hosts_contacted": len(distinct_ips),
                        "sample_targets": sorted(list(distinct_ips))[:8],
                        "originating_process": proc.get("name"),
                        "originating_pid": proc.get("pid"),
                    },
                )
            )

        # 2. Check Vertical Port Scan (Same host, same target IP -> multiple ports)
        v_key = f"{host_id}:{dest_ip}"
        v_queue = self.vertical_scans[v_key]
        v_queue.append((now_ts, dest_port))

        while v_queue and v_queue[0][0] < cutoff:
            v_queue.popleft()

        distinct_ports = {port for _, port in v_queue}
        if len(distinct_ports) >= self.vertical_threshold and v_key not in self.alerted_scans:
            self.alerted_scans.add(v_key)
            matches.append(
                PortScanMatch(
                    scan_type="Vertical Target Port Enumeration",
                    host_id=host_id,
                    target_summary=f"Host {dest_ip} probed across {len(distinct_ports)} distinct ports",
                    probed_count=len(distinct_ports),
                    time_window_seconds=self.time_window,
                    process_name=proc.get("name", "unknown"),
                    evidence={
                        "scan_type": "Vertical Port Scan",
                        "target_host": dest_ip,
                        "unique_ports_scanned": len(distinct_ports),
                        "sample_ports": sorted(list(distinct_ports))[:10],
                        "originating_process": proc.get("name"),
                        "originating_pid": proc.get("pid"),
                    },
                )
            )

        return matches

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
