"""OpTC eCAR process creates -> rows the featurizer reads like any other source."""

from __future__ import annotations

import gzip
import json

from pdtrain.optc import read_ecar_process_creates, row_from_ecar

from panopticon_detection.ml.featurizer import featurize

RECORD = {
    "action": "CREATE", "actorID": "parent-uuid", "hostname": "SysClient0201.systemia.com",
    "id": "event-uuid", "object": "PROCESS", "objectID": "child-uuid", "pid": 4242, "ppid": 1200,
    "principal": "SYSTEMIA\\zleazer", "timestamp": "2019-09-19T10:11:12.345-04:00", "tid": -1,
    "properties": {
        "image_path": "C:\\Windows\\System32\\cmd.exe",
        "parent_image_path": "C:\\Windows\\explorer.exe",
        "command_line": "cmd.exe /c dir",
        "user": "SYSTEMIA\\zleazer", "sid": "S-1-5-21-1-2-3-1001",
    },
}


def test_process_create_becomes_a_normalized_row():
    row = row_from_ecar(RECORD, "optc:test")
    assert row["utc"] == "2019-09-19T14:11:12.345Z"  # offset applied, naive UTC
    assert row["event"]["event_type"] == "process_create"
    assert row["event"]["process"]["name"] == "cmd.exe"
    assert row["event"]["parent"]["name"] == "explorer.exe"
    assert row["event"]["user"]["name"] == "zleazer"
    assert row["integrity"] is None
    assert featurize(row["event"])  # the featurizer accepts it


def test_other_records_and_unusable_ones_are_skipped(tmp_path):
    flow = {**RECORD, "object": "FLOW", "action": "START"}
    no_pid = {**RECORD, "pid": -1}
    epoch = {**RECORD, "timestamp": 1568902272345, "id": "e2"}
    path = tmp_path / "x.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for rec in (RECORD, flow, no_pid, epoch):
            handle.write(json.dumps(rec) + "\n")
        handle.write("{broken PROCESS CREATE\n")
    rows = list(read_ecar_process_creates(path, "optc:test"))
    assert len(rows) == 2
    assert rows[1]["utc"] == "2019-09-19T14:11:12.345Z"


def test_kernel_device_paths_become_drive_paths():
    from pdtrain.optc import drive_path

    assert drive_path("\\Device\\HarddiskVolume1\\Python27\\python.exe") == "C:\\Python27\\python.exe"
    assert drive_path("PING.EXE") == "PING.EXE"
    assert drive_path("\\Device\\HarddiskVolumeX\\y") == "\\Device\\HarddiskVolumeX\\y"
    row = row_from_ecar({**RECORD, "properties": {**RECORD["properties"],
                         "parent_image_path": "\\Device\\HarddiskVolume2\\Windows\\explorer.exe"}}, "t")
    assert row["parent_image"] == "C:\\Windows\\explorer.exe"


def test_bare_image_names_are_excluded():
    bare = {**RECORD, "properties": {**RECORD["properties"], "image_path": "PING.EXE"}}
    assert row_from_ecar(bare, "t") is None
