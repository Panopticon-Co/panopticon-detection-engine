"""ATLASv2 streaming reader and REAPr label matching, on a synthetic tar.gz."""

from __future__ import annotations

import gzip
import io
import json
import tarfile

from pdtrain.atlasv2 import filetime_to_utc, parse_reapr, stream

_EVENT = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>{eid}</EventID>"
    "<TimeCreated SystemTime='2022-07-19T15:00:00.000Z'/><EventRecordID>{rid}</EventRecordID>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>h1-pc</Computer></System><EventData>"
    "<Data Name='UtcTime'>{utc}</Data><Data Name='ProcessGuid'>{{G{rid}}}</Data>"
    "<Data Name='ProcessId'>{pid}</Data><Data Name='Image'>{image}</Data>"
    "<Data Name='CommandLine'>{image} -x</Data><Data Name='User'>PC\\alice</Data>"
    "<Data Name='IntegrityLevel'>Medium</Data><Data Name='ParentProcessId'>4</Data>"
    "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data></EventData></Event>"
)


def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text, enc in files:
            data = text.encode(enc)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_reapr_uuid_carries_pid_and_filetime():
    labs = parse_reapr(
        "attack, process_name, process_id, process_uuid, label\n"
        "h1-s1,  c:\\users\\a\\payload.exe, 1504.0, 7DMF69PK-05e59b07-000005e0-00000000-1d89b73f8b9e0f4, attack\n"
        "h1-s1,  c:\\x.exe, 1, 7DMF69PK-05e59b07-00000001-00000000-1d89b73f8b9e0f4, benign\n",
        "h1-s1",
    )
    assert len(labs) == 1 and labs[0]["pid"] == 0x5E0 and labs[0]["host"] == "h1"
    assert labs[0]["start"] == filetime_to_utc("1d89b73f8b9e0f4")


def test_streams_sysmon_members_and_labels_attack_day(monkeypatch, tmp_path):
    import pdtrain.atlasv2 as A

    when = filetime_to_utc("1d89b73f8b9e0f4")
    utc = when.strftime("%Y-%m-%d %H:%M:%S.") + f"{when.microsecond // 1000:03d}"
    benign = "<Events>" + _EVENT.format(
        eid=1, rid=1, utc="2022-07-15 10:00:00.000", pid=10, image="C:\\Windows\\notepad.exe"
    ) + _EVENT.format(eid=3, rid=2, utc="2022-07-15 10:00:01.000", pid=10, image="C:\\Windows\\notepad.exe") + "</Events>"
    attack = "<Events>" + _EVENT.format(
        eid=1, rid=3, utc=utc, pid=0x5E0, image="C:\\Users\\a\\payload.exe"
    ) + _EVENT.format(eid=1, rid=4, utc=utc, pid=77, image="C:\\Windows\\calc.exe") + "</Events>"
    blob = _tar([
        ("atlasv2/data/benign/h1/sysmon/benign-1.xml", benign, "utf-16"),
        ("atlasv2/data/attack/h1/sysmon/s1.xml", attack, "utf-8"),
        ("atlasv2/data/benign/h1/firefox/x.txt", "ignored", "utf-8"),
    ])
    labels = [{"host": "h1", "pid": 0x5E0, "start": when, "image": "payload.exe", "scenario": "h1-s1"}]
    orig = A.label_rows
    monkeypatch.setattr(A, "label_rows", lambda rows, period, host, _labs: orig(rows, period, host, labels))
    chunks = [blob[i:i + 997] for i in range(0, len(blob), 997)]
    manifest = stream(tmp_path / "rows", tmp_path / "spool", None, tmp_path, chunks=chunks, size=len(blob))
    assert manifest["complete"] and manifest["rows"] == 3
    rows = {
        r["event"]["process"]["name"]: r
        for r in map(json.loads, gzip.open(tmp_path / "rows" / "atlasv2.jsonl.gz", "rt"))
    }
    assert rows["notepad.exe"]["label"] == 0 and rows["notepad.exe"]["integrity"] == "Medium"
    assert rows["payload.exe"]["label"] == 1 and rows["payload.exe"]["label_rule"] == "malicious/reapr"
    assert rows["calc.exe"]["label"] == 0


def test_all_families_writes_sorted_runs_with_the_same_start_ids(tmp_path):
    import pdtrain.atlasv2 as A

    events = "<Events>" + "".join(
        _EVENT.format(eid=eid, rid=rid, utc=f"2022-07-15 10:00:0{9 - rid}.000", pid=10 + rid,
                      image="C:\\Windows\\notepad.exe")
        for rid, eid in ((1, 1), (2, 3), (3, 1), (4, 5))
    ) + "</Events>"
    blob = _tar([("atlasv2/data/benign/h1/sysmon/benign-1.xml", events, "utf-16")])
    chunks = [blob[i:i + 997] for i in range(0, len(blob), 997)]
    manifest = A.stream_all_families(tmp_path / "canon", tmp_path / "spool", None, chunks=chunks, size=len(blob))
    assert manifest["complete"] and manifest["process_starts"] == 2
    run = tmp_path / "canon" / "benign" / "h1" / "benign-1" / "run-0000.ndjson.gz"
    written = [json.loads(line) for line in gzip.open(run, "rt")]
    times = [e["event"]["timestamp"] for e in written]
    assert times == sorted(times) and {e["event"]["category"] for e in written} >= {"process", "network"}
    rows_manifest = stream(tmp_path / "rows", tmp_path / "spool", None, tmp_path, chunks=chunks, size=len(blob))
    assert rows_manifest["rows"] == 2
    row_ids = {json.loads(line)["row_id"] for line in gzip.open(tmp_path / "rows" / "atlasv2.jsonl.gz", "rt")}
    starts = {e["event"]["id"] for e in written if e["event"]["category"] == "process" and e["event"]["type"] == "start"}
    assert starts == row_ids
