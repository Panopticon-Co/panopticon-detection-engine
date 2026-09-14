"""Ransomware canary tripwire and mass-encryption burst detection."""

from panopticon_detection.behavioral.ransomware import RansomwareShield


def test_ransomware_canary_tripwire_trigger():
    shield = RansomwareShield()

    canary_event = {
        "event_type": "file_modify",
        "host_id": "LAPTOP-EXEC-01",
        "process": {"name": "wannacry.exe", "pid": 6620, "command_line": "wannacry.exe"},
        "file": {"path": "C:\\Users\\User\\Documents\\quarterly_taxes.canary.docx"},
    }

    match = shield.inspect_file_event(canary_event)
    assert match is not None
    assert "Canary Tripwire" in match.threat_type
    assert match.pid == 6620
    assert match.confidence >= 0.95


def test_ransomware_extension_detection():
    shield = RansomwareShield()

    ransom_event = {
        "event_type": "file_rename",
        "host_id": "LAPTOP-EXEC-01",
        "process": {"name": "lockbit.exe", "pid": 7710},
        "file": {"path": "C:\\Users\\User\\Documents\\database.locked"},
    }

    match = shield.inspect_file_event(ransom_event)
    assert match is not None
    assert "Known Ransomware Extension" in match.threat_type
    assert match.pid == 7710
