"""One process creation reported by both ETW and Sysmon is one incarnation.

The agent's ETW Kernel-Process start carries ``start_time_ticks`` but no command
line; its Sysmon EID 1 start carries the command line but no ticks. Both are
stamped with the same creation instant. Treated as two incarnations, the second
replaced the first and the process lost the ticks every kill recommendation
needs (translate_recommendation then fails closed).
"""

from pathlib import Path

from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

ROOT = Path(__file__).resolve().parent.parent


def _start(kind, pid, ppid, name, exe, cmd, ticks, ts, eid):
    return {
        "schema_version": "0.4",
        "event": {"id": eid, "category": "process", "type": "start", "timestamp": ts},
        "source": {"kind": kind, "provider": "x", "channel": None, "record_id": None},
        "agent": {"id": "a", "version": "1"},
        "host": {"id": "H1", "hostname": "H1", "os": {"name": "Windows", "build": "26100"}},
        "user": {"name": "u", "domain": "D", "sid": None},
        "process": {
            "entity_id": None, "pid": pid, "name": name, "executable": exe,
            "command_line": cmd, "start_time_ticks": ticks,
            "parent": {"entity_id": None, "pid": ppid, "name": None},
            "hash": {"sha256": None},
        },
    }


def _run(events):
    run, ctx = build_detection_run(ROOT / "rules")
    alerts = []
    for raw in events:
        alerts += run.process_event(OfficerIngestionAdapter.transform_officer_event(raw))
    return alerts, ctx


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
VSS = r"C:\Windows\System32\vssadmin.exe"


def test_etw_then_sysmon_merge_into_one_incarnation_keeping_ticks():
    alerts, ctx = _run([
        _start("etw", 500, 4, "powershell.exe", PS, None, 133700000000000001, "2026-10-25T10:00:00.000Z", "e1"),
        _start("sysmon", 500, 4, "powershell.exe", PS, "powershell.exe -nop", None, "2026-10-25T10:00:00.000Z", "e2"),
        _start("etw", 600, 500, "vssadmin.exe", VSS, None, 133700000000000002, "2026-10-25T10:00:05.123Z", "e3"),
        _start("sysmon", 600, 500, "vssadmin.exe", VSS, "vssadmin.exe delete shadows /all /quiet", None,
               "2026-10-25T10:00:05.123Z", "e4"),
    ])
    incs = [i for i in ctx.registry._by_node_id.values() if i.pid == 600]
    assert len(incs) == 1
    assert incs[0].start_time_ticks == 133700000000000002
    assert incs[0].command_line.startswith("vssadmin.exe delete")
    recs = [a.active_response for a in alerts if a.rule_id == "DET-PROC-006" and a.active_response]
    assert recs and recs[0].get("target_start_time_ticks") == 133700000000000002


def test_sysmon_first_then_etw_fills_ticks_without_replacing():
    _, ctx = _run([
        _start("sysmon", 700, 4, "cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd /c whoami", None,
               "2026-10-25T10:00:00.000Z", "s1"),
        _start("etw", 700, 4, "cmd.exe", r"C:\Windows\System32\cmd.exe", None, 42, "2026-10-25T10:00:00.000Z", "s2"),
    ])
    incs = [i for i in ctx.registry._by_node_id.values() if i.pid == 700]
    assert len(incs) == 1
    assert incs[0].command_line == "cmd /c whoami" and incs[0].start_time_ticks == 42


def test_pid_reuse_by_a_different_image_is_not_merged():
    _, ctx = _run([
        _start("sysmon", 800, 4, "notepad.exe", r"C:\Windows\notepad.exe", "notepad", None, "2026-10-25T10:00:00.000Z", "r1"),
        _start("sysmon", 800, 4, "calc.exe", r"C:\Windows\calc.exe", "calc", None, "2026-10-25T10:00:00.500Z", "r2"),
    ])
    assert len([i for i in ctx.registry._by_node_id.values() if i.pid == 800]) == 2


def test_same_pid_seconds_apart_is_a_new_incarnation():
    _, ctx = _run([
        _start("sysmon", 900, 4, "cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd", None, "2026-10-25T10:00:00.000Z", "t1"),
        _start("sysmon", 900, 4, "cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd", None, "2026-10-25T10:00:05.000Z", "t2"),
    ])
    assert len([i for i in ctx.registry._by_node_id.values() if i.pid == 900]) == 2


def test_twin_reports_draw_each_creation_edge_once():
    from panopticon_detection.provenance.graph import EdgeKind

    _, ctx = _run([
        _start("etw", 500, 4, "powershell.exe", PS, None, 11, "2026-10-25T10:00:00.000Z", "f1"),
        _start("sysmon", 500, 4, "powershell.exe", PS, "powershell.exe", None, "2026-10-25T10:00:00.000Z", "f2"),
        _start("etw", 600, 500, "vssadmin.exe", VSS, None, 12, "2026-10-25T10:00:05.000Z", "f3"),
        _start("sysmon", 600, 500, "vssadmin.exe", VSS, "vssadmin.exe delete shadows /all", None,
               "2026-10-25T10:00:05.000Z", "f4"),
    ])
    edges = list(ctx.graph.edges.values())
    forks = [e for e in edges if e.kind == EdgeKind.FORKED]
    executed = [e for e in edges if e.kind == EdgeKind.EXECUTED]
    assert len(forks) == 2 and len(executed) == 2
    child = next(e for e in forks if e.attrs.get("command_line", "").startswith("vssadmin"))
    assert any(t.rule_id == "DET-PROC-006" for t in child.tags)
