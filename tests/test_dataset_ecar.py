"""OpTC eCAR -> canonical events: every mapped family normalises like agent telemetry."""

from __future__ import annotations

from panopticon_detection.datasets.ecar import drive_path, to_canonical
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter


def _record(obj, action, **props):
    return {"object": obj, "action": action, "hostname": "SysClient0201.systemia.com", "pid": 4242, "ppid": 600,
            "principal": "SYSTEMIACOM\\zleazer", "id": f"{obj}-{action}", "timestamp": "2019-09-19T12:20:45.678-04:00",
            "properties": {"image_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\rundll32.exe", **props}}


def _normalized(record):
    event = to_canonical(record, "optc:test")
    return None if event is None else OfficerIngestionAdapter.transform_officer_event(event)


def test_paths_and_time_are_mapped_to_agent_conventions():
    assert drive_path("\\Device\\HarddiskVolume1\\lwabeat\\\\lwabeat.exe") == "C:\\lwabeat\\lwabeat.exe"
    assert drive_path("\\\\?\\C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe").startswith("C:\\Program Files")
    assert drive_path("\\Windows\\SysWOW64\\crypt32.dll") == "C:\\Windows\\SysWOW64\\crypt32.dll"
    assert drive_path("PING.EXE") == "PING.EXE"
    event = to_canonical(_record("PROCESS", "CREATE", command_line="rundll32 x", parent_image_path="cmd.exe"), "d")
    assert event["event"]["timestamp"] == "2019-09-19T16:20:45.678Z"  # -04:00 -> UTC


def test_every_mapped_family_normalizes():
    cases = {
        ("PROCESS", "CREATE"): ({"command_line": "rundll32 x"}, "process_create"),
        ("PROCESS", "TERMINATE"): ({}, "process_terminate"),
        ("FLOW", "START"): ({"direction": "outbound", "src_ip": "10.0.0.5", "src_port": "50000",
                             "dest_ip": "93.184.216.34", "dest_port": "4444", "l4protocol": "6"}, "network_connect"),
        ("FILE", "CREATE"): ({"file_path": "\\Device\\HarddiskVolume1\\Users\\a\\AppData\\x.exe"}, "file_create"),
        ("FILE", "RENAME"): ({"file_path": "C:\\a.tmp", "new_path": "C:\\a.exe"}, "file_rename"),
        ("MODULE", "LOAD"): ({"module_path": "\\Windows\\System32\\clr.dll"}, "image_load"),
        ("REGISTRY", "EDIT"): ({"key": "\\REGISTRY\\USER\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                "value": "upd"}, "registry_write"),
        ("THREAD", "REMOTE_CREATE"): ({"tgt_pid": "880", "tgt_tid": "1"}, "remote_thread"),
    }
    for (obj, action), (props, expected) in cases.items():
        event = _normalized(_record(obj, action, **props))
        assert event is not None and event["event_type"] == expected, (obj, action)
    net = _normalized(_record("FLOW", "START", direction="outbound", dest_ip="93.184.216.34", dest_port="4444",
                              l4protocol="6"))
    assert net["network"]["destination_port"] == 4444 and net["network"]["protocol"] == "tcp"


def test_unmapped_records_are_dropped():
    for obj, action, props in (("FLOW", "START", {"direction": "inbound"}), ("PROCESS", "OPEN", {}),
                               ("FILE", "READ", {"file_path": "C:\\a"}), ("FLOW", "MESSAGE", {})):
        assert to_canonical(_record(obj, action, **props), "d") is None
