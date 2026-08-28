"""Tests for the incremental append-safe alert writer (alert_sink.py)."""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reliability.alert_sink import IncrementalAlertWriter


class _Alert:
    def __init__(self, i):
        self._i = i

    def to_dict(self):
        return {"alert_id": f"ALT-{self._i}", "rule_id": "DET-PROC-011", "evidence": {}}


def _lines(p: Path):
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_each_alert_is_visible_immediately(tmp_path):
    out = tmp_path / "alerts.ndjson"
    w = IncrementalAlertWriter(out, fsync=False)
    assert w.write(_Alert(1)) is True
    assert [a["alert_id"] for a in _lines(out)] == ["ALT-1"]
    w.write(_Alert(2))
    assert [a["alert_id"] for a in _lines(out)] == ["ALT-1", "ALT-2"]
    w.close()


def test_accepts_plain_dicts(tmp_path):
    out = tmp_path / "a.ndjson"
    with IncrementalAlertWriter(out, fsync=False) as w:
        w.write({"alert_id": "D1", "evidence": {}})
    assert _lines(out)[0]["alert_id"] == "D1"


def test_dedupe_skips_alert_ids_already_in_the_file_on_restart(tmp_path):
    out = tmp_path / "a.ndjson"
    w1 = IncrementalAlertWriter(out, fsync=False)
    w1.write(_Alert(1))
    w1.write(_Alert(2))
    w1.close()

    # engine restarts, re-attempts delivering ALT-1 and ALT-2 plus a new ALT-3
    w2 = IncrementalAlertWriter(out, fsync=False)
    assert w2.write(_Alert(1)) is False
    assert w2.write(_Alert(2)) is False
    assert w2.write(_Alert(3)) is True
    assert w2.skipped_duplicates == 2
    w2.close()

    assert [a["alert_id"] for a in _lines(out)] == ["ALT-1", "ALT-2", "ALT-3"]


def test_in_process_dedupe(tmp_path):
    with IncrementalAlertWriter(tmp_path / "a.ndjson", fsync=False) as w:
        assert w.write(_Alert(1)) is True
        assert w.write(_Alert(1)) is False
        assert w.count == 1


def test_torn_final_line_is_repaired_on_open_not_concatenated(tmp_path):
    out = tmp_path / "a.ndjson"
    w = IncrementalAlertWriter(out, fsync=False)
    w.write(_Alert(1))
    w.write(_Alert(2))
    w.close()
    # simulate a crash mid-write of a third record (no trailing newline)
    with open(out, "a", encoding="utf-8") as fh:
        fh.write('{"alert_id": "ALT-3", "rule_id": "DET-')

    # reopening must drop the partial tail before appending
    w2 = IncrementalAlertWriter(out, fsync=False)
    w2.write(_Alert(4))
    w2.close()

    got = _lines(out)  # every line parses -> tail was repaired, not corrupted
    assert [a["alert_id"] for a in got] == ["ALT-1", "ALT-2", "ALT-4"]


def test_whole_file_one_partial_line_is_truncated_to_empty(tmp_path):
    out = tmp_path / "a.ndjson"
    out.write_text('{"alert_id": "ALT-partial", "x', encoding="utf-8")
    w = IncrementalAlertWriter(out, fsync=False)
    w.write(_Alert(1))
    w.close()
    assert [a["alert_id"] for a in _lines(out)] == ["ALT-1"]


def test_append_preserves_prior_content_across_reopen(tmp_path):
    out = tmp_path / "a.ndjson"
    with IncrementalAlertWriter(out, fsync=False) as w:
        w.write(_Alert(1))
    with IncrementalAlertWriter(out, fsync=False) as w:
        w.write(_Alert(2))
    assert [a["alert_id"] for a in _lines(out)] == ["ALT-1", "ALT-2"]


def test_count_includes_preexisting_lines(tmp_path):
    out = tmp_path / "a.ndjson"
    with IncrementalAlertWriter(out, fsync=False) as w:
        w.write_many([_Alert(i) for i in range(3)])
    with IncrementalAlertWriter(out, fsync=False) as w:
        assert w.count == 3
        w.write(_Alert(99))
        assert w.count == 4


def test_creates_parent_directory(tmp_path):
    out = tmp_path / "deep" / "nested" / "a.ndjson"
    with IncrementalAlertWriter(out, fsync=False) as w:
        w.write(_Alert(1))
    assert out.exists()


def test_fsync_path_runs(tmp_path):
    out = tmp_path / "a.ndjson"
    with IncrementalAlertWriter(out, fsync=True, fsync_every=2) as w:
        w.write(_Alert(1))
        w.write(_Alert(2))
        w.write(_Alert(3))
        w.flush()
    assert len(_lines(out)) == 3


def test_rejects_a_directory_path(tmp_path):
    # An operator pointing --output-file at a directory should get a clear
    # error at construction, not a raw PermissionError from deep in open().
    with pytest.raises(IsADirectoryError):
        IncrementalAlertWriter(tmp_path)
