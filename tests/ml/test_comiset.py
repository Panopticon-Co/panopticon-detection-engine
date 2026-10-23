"""COMISET streaming reader: zip inflate over chunks, EID 1 filter, aggregation."""

from __future__ import annotations

import gzip
import io
import json
import zipfile

from pdtrain.comiset import stream


def _line(eid, pid, cmd, **extra):
    src = {"event_id": str(eid), "log_name": "Microsoft-Windows-Sysmon/Operational", "host_name": "LAB-PC01",
           "event_original_time": "2023-03-01T10:00:00.000Z", "process_id": str(pid),
           "process_path": "C:\\Windows\\System32\\cmd.exe", "CommandLine": cmd,
           "process_parent_path": "C:\\Windows\\explorer.exe", "user_account": "LAB\\student",
           "IntegrityLevel": "Medium", "record_number": str(pid), **extra}
    return json.dumps({"_source": src}, separators=(",", ":"))


def test_keeps_sysmon_process_starts_and_aggregates(tmp_path):
    lines = [
        _line(1, 10, "cmd /c dir"),
        _line(1, 11, "cmd /c dir"),  # same featurized row on the same host -> count 2
        _line(10, 12, "cmd /c whoami"),  # process access: not a start
        _line(1, 13, "cmd /c whoami", Rule_Name="suspicious"),  # rule hit: excluded
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Comiset23_Real_Environment_Dataset.json", "\n".join(lines) + "\n")
    blob = buf.getvalue()
    chunks = [blob[i:i + 101] for i in range(0, len(blob), 101)]
    manifest = stream(tmp_path / "rows", tmp_path / "spool", None, size=len(blob), chunks=chunks, log=lambda *a, **k: None)
    assert manifest["complete"] and manifest["counts"]["sysmon_eid1_lines"] == 3
    rows = [json.loads(x) for x in gzip.open(tmp_path / "rows" / "comiset.jsonl.gz", "rt")]
    by_rule = {r["label_rule"]: r for r in rows}
    assert by_rule["benign/comiset_real_environment"]["count"] == 2
    assert by_rule["benign/comiset_real_environment"]["label"] == 0
    assert by_rule["excluded/comiset_rule_hit"]["label"] is None
