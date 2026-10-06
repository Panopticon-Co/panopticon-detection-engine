"""DNS analysis and C2 beacon detection.

Port scans are declarative value_count rules now; see tests/test_stateful_rules.py.
"""

import random

import pytest

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.behavioral.dns import DnsAnalyzer


def test_dns_dga_and_tunneling():
    benign = DnsAnalyzer.analyze_domain("google.com")
    assert benign["is_dga"] is False
    assert benign["is_tunneling"] is False

    dga_res = DnsAnalyzer.analyze_domain("xkjqw1987znvcb.biz")
    assert dga_res["is_dga"] is True
    assert dga_res["entropy"] > 3.4

    tunnel = "aW52b2ljZV9zZWNyZXRfZGF0YV9leGZpbHRyYXRpb24xMjM0NTY3OA.attacker-c2.com"
    assert DnsAnalyzer.analyze_domain(tunnel)["is_tunneling"] is True


def _connect(t, ip="93.184.216.34", port=443, pid=4100, name="rundll32.exe"):
    return {
        "event_type": "network_connect",
        "host_id": "H-01",
        "timestamp": float(t),
        "network": {"destination_ip": ip, "destination_port": port, "direction": "outbound"},
        "process": {"name": name, "pid": pid},
    }


def _feed(detector, events):
    return [m for m in (detector.ingest_connection(e) for e in events) if m]


def test_a_jittered_beacon_is_detected():
    """A 60s implant with +/-10% jitter and one late check-in still reads as periodic."""
    rng = random.Random(7)
    t, times = 0.0, []
    for i in range(10):
        t += 60 * (1 + rng.uniform(-0.1, 0.1)) + (45 if i == 5 else 0)
        times.append(t)

    matches = _feed(C2BeaconDetector(), [_connect(x) for x in times])

    assert len(matches) == 1
    assert matches[0].median_interval_seconds == pytest.approx(60, rel=0.15)
    assert matches[0].dispersion <= 0.2
    assert matches[0].pid == 4100


def _sessions(gap, seeds=200, connections=20):
    fired = 0
    for seed in range(seeds):
        rng = random.Random(seed)
        t, events = 0.0, []
        for _ in range(connections):
            t += gap(rng)
            events.append(_connect(t))
        fired += bool(_feed(C2BeaconDetector(), events))
    return fired / seeds


def test_irregular_traffic_is_not_a_beacon():
    """Poisson arrivals -- how user-driven traffic actually looks -- never fire."""
    assert _sessions(lambda r: r.expovariate(1 / 120)) == 0


def test_capped_uniform_traffic_rarely_fires():
    """A deliberately semi-regular adversarial case: gaps uniform in 5-300s."""
    assert _sessions(lambda r: r.uniform(5, 300)) <= 0.02


def test_twenty_percent_jitter_is_still_detected():
    assert _sessions(lambda r: 60 * (1 + r.uniform(-0.2, 0.2))) >= 0.95


def test_private_destinations_are_not_tracked():
    events = [_connect(60 * i, ip="10.0.0.5") for i in range(10)]
    assert _feed(C2BeaconDetector(), events) == []


def test_a_short_burst_is_not_a_beacon():
    """Eight connections ten seconds apart span under the minimum observation window."""
    events = [_connect(10 * i) for i in range(8)]
    assert _feed(C2BeaconDetector(), events) == []


def test_two_processes_never_pool_their_timings():
    """Each process alone is too sparse; interleaved they would look periodic."""
    events = []
    for i in range(5):
        events.append(_connect(60 * i, pid=100, name="a.exe"))
        events.append(_connect(60 * i + 30, pid=200, name="b.exe"))
    detector = C2BeaconDetector()
    assert _feed(detector, events) == []


def test_the_latch_expires():
    detector = C2BeaconDetector(latch_ttl_seconds=600)
    first = _feed(detector, [_connect(60 * i) for i in range(10)])
    assert len(first) == 1
    later = _feed(detector, [_connect(5000 + 60 * i) for i in range(10)])
    assert len(later) == 1


def test_events_without_a_time_are_skipped():
    event = _connect(0)
    event["timestamp"] = "not-a-time"
    detector = C2BeaconDetector()
    assert detector.ingest_connection(event) is None
    assert detector.connection_history == {}
