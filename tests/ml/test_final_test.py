"""The sealed final test: arithmetic, serving-path scoring and the run-once guard."""

from __future__ import annotations

import gzip
import json

import pytest

pytest.importorskip("lightgbm")

from pdtrain import loeo as L  # noqa: E402
from pdtrain.final_test import bundle_scorer, clopper_pearson, evaluate, run  # noqa: E402

from tests.ml.test_loeo import _row  # noqa: E402


def test_clopper_pearson_edges():
    assert clopper_pearson(0, 10)[0] == 0.0 and clopper_pearson(10, 10)[1] == 1.0
    lo, hi = clopper_pearson(5, 10)
    assert lo == pytest.approx(0.1871, abs=1e-4) and hi == pytest.approx(0.8129, abs=1e-4)


def test_evaluate_counts_fp_per_observed_host_hour():
    rows = [_row("officer_sealed", i, 0, f"x{i}", minute=i * 30) for i in range(5)]  # 2 observed hours
    score = {r["row_id"]: (5.0 if i < 2 else 0.0) for i, r in enumerate(rows)}
    res = evaluate(rows, score, {"alert": 1.0})
    assert res["alert"]["fp_events"] == 2 and res["alert"]["fp_per_host_hour"] == 1.0
    assert res["alert"]["recall"] is None and res["observed_host_hours"] == 2.0


def _bundle(tmp_path):
    raw = [_row("optc", i, 0, f"C:\\Program Files\\app{i % 7}\\app.exe --run {i}",
                image=f"C:\\Program Files\\app{i % 7}\\app.exe", host=f"o{i % 4}", minute=i) for i in range(80)]
    verbs = ("whoami", "certutil -urlcache -f", "vssadmin delete shadows", "net user x /add", "wevtutil cl")
    raw += [_row(src, i, 1, f"cmd /c {verbs[i % 5]} {'abcd'[i // 5]}{src}", parent="winword.exe", group=f"T:{i}")
            for src in ("attack_data", "otrf") for i in range(20)]
    units, _ = L.build_units(raw)
    hours = L.hours_by_environment(raw)
    fit = L.fit(units, hours, L.RECIPES["v7_lgb"])
    L.export(tmp_path / "models" / "vX", fit, units, tmp_path, tmp_path, hours)
    return fit, units


def test_sealed_test_scores_through_the_serving_path_and_runs_once(tmp_path):
    fit, units = _bundle(tmp_path)
    folder = tmp_path / "models" / "vX"
    u = units[0]
    assert bundle_scorer(folder)(u.row) == pytest.approx(L.score_units(fit, [u])[u.uid], abs=1e-9)

    sealed = [_row("officer_sealed", i, 0, f"C:\\Program Files\\app{i % 3}\\app.exe --x {i}",
                   image=f"C:\\Program Files\\app{i % 3}\\app.exe", minute=i * 5) for i in range(30)]
    (tmp_path / "rows").mkdir()
    with gzip.open(tmp_path / "rows" / "officer_sealed.jsonl.gz", "wt") as handle:
        for r in sealed:
            handle.write(json.dumps(r) + "\n")
    with pytest.raises(SystemExit, match="final_candidate"):
        run(tmp_path, tmp_path, "vX")
    result = run(tmp_path, tmp_path, "vX", freeze=True)
    assert result["benign_events"] == 30 and "passes" in result
    assert json.loads((folder / "manifest.json").read_text())["final_candidate"] is True
    with pytest.raises(SystemExit, match="once"):
        run(tmp_path, tmp_path, "vX")
