"""Threat-intel lookup and response-recommendation resolution.

Frequency thresholds and rule chaining moved to stateful rule types; see
tests/test_stateful_rules.py.
"""

from panopticon_detection.alerting.active_response import ActiveResponseEngine
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


def test_threat_intel_engine():
    ti = ThreatIntelEngine()
    
    # Test Mimikatz SHA256 match
    mimi_hash = "58593a38d72bb01c5f3b7c844cf19597793b8782a20b72c918a287a93540a931"
    match = ti.check_hash(mimi_hash)
    assert match is not None
    assert match["malware_family"] == "Mimikatz"
    assert match["severity_level"] == 15

    # Test unknown hash
    assert ti.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    # Test C2 IP match
    ip_match = ti.check_ip("198.51.100.45")
    assert ip_match is not None
    assert ip_match["threat_type"] == "Cobalt Strike C2 Server"


def test_active_response_resolution():
    # Level 15 process termination
    event = {
        "host_id": "HOST-FINANCE-01",
        "process": {"pid": 4500, "process_guid": "{GUID-123}", "name": "mimikatz.exe"},
    }
    action = ActiveResponseEngine.resolve_action(level=15, event=event, custom_action="TERMINATE_PROCESS")
    assert action is not None
    assert action.action == "TERMINATE_PROCESS"
    assert action.target_pid == 4500

    # Level 14 emergency host isolation
    action_iso = ActiveResponseEngine.resolve_action(level=14, event=event, custom_action="ISOLATE_HOST")
    assert action_iso is not None
    assert action_iso.action == "ISOLATE_HOST"
    assert action_iso.host_id == "HOST-FINANCE-01"
