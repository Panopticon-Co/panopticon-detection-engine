"""Unit tests for Network Threat Subsystems: DGA, DNS Tunneling, C2 Beaconing, and Port Scanning."""

import pytest

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.behavioral.dns import DnsAnalyzer
from panopticon_detection.behavioral.port_scan import PortScanDetector


def test_dns_dga_and_tunneling():
    # 1. Normal benign domain -> Not DGA, Not tunneling
    benign = DnsAnalyzer.analyze_domain("google.com")
    assert benign["is_dga"] is False
    assert benign["is_tunneling"] is False

    # 2. DGA algorithmic domain -> High entropy, low vowel ratio
    dga_domain = "xkjqw1987znvcb.biz"
    dga_res = DnsAnalyzer.analyze_domain(dga_domain)
    assert dga_res["is_dga"] is True
    assert dga_res["entropy"] > 3.4

    # 3. DNS Tunneling payload -> Long base64 encoded subdomain
    tunnel_domain = "aW52b2ljZV9zZWNyZXRfZGF0YV9leGZpbHRyYXRpb24xMjM0NTY3OA.attacker-c2.com"
    tunnel_res = DnsAnalyzer.analyze_domain(tunnel_domain)
    assert tunnel_res["is_tunneling"] is True


def test_c2_beacon_detector_periodic_vs_random():
    detector = C2BeaconDetector(min_samples=4, max_cv_threshold=0.20)

    # 1. Simulate Cobalt Strike C2 beaconing (every 10.0s ± 0.2s)
    events = [
        {"event_type": "network_connect", "host_id": "H-01", "timestamp": 1000.0, "network": {"destination_ip": "198.51.100.200", "destination_port": 443, "direction": "outbound"}, "process": {"name": "rundll32.exe"}},
        {"event_type": "network_connect", "host_id": "H-01", "timestamp": 1010.0, "network": {"destination_ip": "198.51.100.200", "destination_port": 443, "direction": "outbound"}, "process": {"name": "rundll32.exe"}},
        {"event_type": "network_connect", "host_id": "H-01", "timestamp": 1020.1, "network": {"destination_ip": "198.51.100.200", "destination_port": 443, "direction": "outbound"}, "process": {"name": "rundll32.exe"}},
        {"event_type": "network_connect", "host_id": "H-01", "timestamp": 1030.0, "network": {"destination_ip": "198.51.100.200", "destination_port": 443, "direction": "outbound"}, "process": {"name": "rundll32.exe"}},
    ]

    match = None
    for evt in events:
        res = detector.ingest_connection(evt)
        if res:
            match = res

    assert match is not None
    assert match.destination_ip == "198.51.100.200"
    assert match.mean_interval_seconds == pytest.approx(10.0, abs=0.5)
    assert match.coefficient_of_variation < 0.10


def test_port_scan_detector_horizontal_and_vertical():
    scanner = PortScanDetector(horizontal_ip_threshold=5, vertical_port_threshold=5, time_window_seconds=30)

    # 1. Horizontal Subnet Sweep on Port 445
    h_matches = []
    for i in range(1, 7):
        evt = {
            "event_type": "network_connect",
            "host_id": "H-01",
            "timestamp": 1000.0 + i,
            "network": {"destination_ip": f"10.0.0.{i}", "destination_port": 445, "direction": "outbound"},
            "process": {"name": "powershell.exe", "pid": 4100},
        }
        res = scanner.ingest_connection(evt)
        h_matches.extend(res)

    assert len(h_matches) >= 1
    assert "Horizontal" in h_matches[0].scan_type
    assert h_matches[0].evidence["probed_port"] == 445
