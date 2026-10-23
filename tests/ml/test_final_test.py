"""The E9 final-test arithmetic: FP per host-hour, recall with exact intervals."""

from __future__ import annotations

import pytest

pytest.importorskip("lightgbm")

from pdtrain.final_test import clopper_pearson, evaluate  # noqa: E402


def _row(rid, label, rule, utc, key, dataset="atlasv2:benign/h1/sysmon-1.xml"):
    return {"row_id": rid, "label": label, "label_rule": rule, "utc": utc, "dedup_key": key,
            "dataset": dataset, "host": "h1", "image": "C:\\x.exe", "parent_image": "C:\\p.exe",
            "command_line": "x"}


def test_clopper_pearson_edges():
    assert clopper_pearson(0, 10)[0] == 0.0 and clopper_pearson(10, 10)[1] == 1.0
    lo, hi = clopper_pearson(5, 10)
    assert lo == pytest.approx(0.1871, abs=1e-4) and hi == pytest.approx(0.8129, abs=1e-4)


def test_evaluate_counts_fp_per_hour_and_unique_recall():
    rows = [
        _row("b1", 0, "benign/atlasv2_benign_period", "2022-07-15T10:00:00", "k1"),
        _row("b2", 0, "benign/atlasv2_benign_period", "2022-07-15T11:00:00", "k2"),  # 1 host-hour
        _row("b3", 0, "benign/atlasv2_benign_period", "2022-07-15T12:00:00", "k3"),  # 2 host-hours
        _row("m1", 1, "malicious/reapr", "2022-07-19T15:00:00", "m", "atlasv2:attack/h1/sysmon-h1-m1.xml"),
        _row("m2", 1, "malicious/reapr", "2022-07-19T15:00:01", "m", "atlasv2:attack/h1/sysmon-h1-m2.xml"),
        _row("m3", 1, "malicious/reapr", "2022-07-19T15:00:02", "n", "atlasv2:attack/h1/sysmon-h1-m2.xml"),
    ]
    score = {"b1": 0.9, "b2": 0.1, "b3": 0.1, "m1": 0.8, "m2": 0.8, "m3": 0.2}
    res = evaluate(rows, score, {"alert": 0.5})
    assert res["alert"]["fp_events"] == 1 and res["alert"]["fp_per_host_hour"] == 0.5
    assert res["alert"]["recall_events"]["detected"] == 2 and res["alert"]["recall_events"]["n"] == 3
    assert res["alert"]["recall_unique_rows"]["n"] == 2  # m1/m2 are the same featurized row
    assert res["alert"]["recall_by_scenario"]["sysmon-h1-m2"]["detected"] == 1
    assert [m["score"] for m in res["missed_malicious_unique"]] == [0.2]
