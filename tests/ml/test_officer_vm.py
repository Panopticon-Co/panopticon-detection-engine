"""The agent-recorded benign package reader handles the collection kit's known issues."""

from __future__ import annotations

import json

from pdtrain.officer_vm import prepare, read_package


def _start(pid, ppid, name, ts, source="sysmon", self_tag=False, parent_name="explorer.exe", parent_exe=None):
    rec = {
        "kind": "observation", "category": "process", "observed_at": ts,
        "data": {
            "event": {"id": f"evt_{source}_{pid}_{ts}", "category": "process", "type": "start", "timestamp": ts},
            "host": {"id": "vm1", "hostname": "VM1", "os": {"name": "Windows", "build": "26100"}},
            "process": {"pid": pid, "name": name, "executable": f"C:\\Windows\\System32\\{name}",
                        "command_line": None if source == "etw" else f"{name} /x",
                        "parent": {"pid": ppid, "name": None if source == "etw" else parent_name}},
            "source": {"kind": source, "provider": "p", "channel": "c", "record_id": 1},
            "user": {"name": "alice", "domain": "VM1", "sid": None},
            "source_facts": {"process": {"process_guid": f"g{pid}", "parent_process_guid": f"g{ppid}",
                                         "parent_executable": parent_exe}},
        },
    }
    if self_tag:
        rec["self"] = True
    return rec


def _stop(pid, ts, self_tag=False):
    rec = {"kind": "observation", "category": "process_stop", "observed_at": ts, "data": {"process": {"pid": pid}}}
    if self_tag:
        rec["self"] = True
    return rec


def test_known_kit_issues_are_handled():
    records = [
        # 1. self-tagged probe and its stop
        _start(100, 4, "cmd.exe", "2026-10-22T20:00:00.000Z", self_tag=True),
        # 2. untagged child of the probe, and a grandchild, while it is alive
        _start(101, 100, "conhost.exe", "2026-10-22T20:00:00.500Z", parent_name="cmd.exe"),
        _start(102, 101, "whoami.exe", "2026-10-22T20:00:01.000Z", parent_name="conhost.exe"),
        _stop(100, "2026-10-22T20:00:05.000Z", self_tag=True),
        # PID reused by an unrelated process after the probe stopped: kept
        _start(103, 100, "notepad.exe", "2026-10-22T20:30:00.000Z", parent_name="cmd.exe"),
        # 3. Sysmon + ETW pair (ETW dropped), and an unpaired ETW start (dropped)
        _start(200, 50, "git.exe", "2026-10-22T21:00:00.000Z"),
        _start(200, 50, "git.exe", "2026-10-22T21:00:01.200Z", source="etw"),
        _start(300, 50, "svchost.exe", "2026-10-22T21:05:00.000Z", source="etw"),
        # empty parent name recovered from ParentImage
        _start(400, 60, "taskhostw.exe", "2026-10-22T21:10:00.000Z", parent_name=None,
               parent_exe="C:\\Windows\\System32\\svchost.exe"),
        # agent child (heartbeat agent_pid) is self
        _start(500, 8688, "conhost.exe", "2026-10-22T21:20:00.000Z", parent_name="officer-agent.exe"),
    ]
    meta = {
        "heartbeat": {"kit_version": "1.0.0", "agent_pid": 8688, "supervisor_pid": 7,
                      "run_started_utc": "2026-10-22T19:59:00Z", "last_event_utc": "2026-10-22T22:00:00Z"},
        "manifest": {"kit_version": "1.0.1"},
    }
    rows, counts = prepare([json.loads(json.dumps(r)) for r in records], meta, "officer_vm:t")
    names = sorted(r["event"]["process"]["name"] for r in rows)
    assert names == ["git.exe", "notepad.exe", "taskhostw.exe"]
    assert counts["dropped_self_tagged"] == 2
    assert counts["dropped_self_children"] == 3  # conhost, whoami, agent's conhost
    assert counts["dropped_etw_duplicate"] == 1 and counts["dropped_etw_unpaired"] == 1
    assert counts["kit_version_collected"] == "1.0.0" and counts["kit_version_packaged"] == "1.0.1"
    task = next(r for r in rows if r["event"]["process"]["name"] == "taskhostw.exe")
    assert task["event"]["parent"]["name"] == "svchost.exe"
    assert all(r["label"] == 0 and "self" not in r for r in rows)
    assert all(r["event"]["event_type"] == "process_create" for r in rows)


def test_reads_segments_with_bom(tmp_path):
    seg = tmp_path / "segment-1.ndjson"
    seg.write_text("\ufeff" + json.dumps(_start(1, 2, "a.exe", "2026-10-22T20:00:00.000Z")) + "\n\n", encoding="utf-8")
    (tmp_path / "heartbeat.json").write_text("\ufeff" + json.dumps({"kit_version": "1.0.0"}), encoding="utf-8")
    records, meta = read_package(tmp_path)
    assert len(records) == 1 and meta["heartbeat"]["kit_version"] == "1.0.0"
