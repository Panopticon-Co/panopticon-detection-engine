"""The untouched final test (E9): ATLASv2, scored once with a frozen bundle.

Pre-registered (2026-10-23, before the v6 model or any ATLASv2 score existed):

* the bundle (``data/models/<version>``) is frozen -- model and thresholds
  come from the training run; nothing is refit or re-thresholded here;
* scoring uses the pure-Python scorer (``panopticon_detection.ml.scorer``),
  i.e. the serving path, not LightGBM;
* reported per variant: false positives per observed host-hour on ATLASv2's
  benign stream at ``alert`` and ``high`` (also split into the benign period
  and the attack-day background), and recall on REAPr-labelled attack process
  starts with exact (Clopper-Pearson) 95% intervals -- per event, per unique
  featurized row (REAPr warns its attacks are highly redundant) and per
  scenario; the engine's rules on the same process starts as the baseline;
* pass condition: variant A <= 1 FP per observed host-hour at ``alert``.
  Recall is reported, not gated: 191 labels over 16 near-identical scenarios
  cannot carry a pre-set recall bar.
"""

from __future__ import annotations

import collections
import gzip
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from scipy.stats import beta

from panopticon_detection.ml.scorer import TreeModel
from pdtrain.experiment import observed_hours, rules_scores, vector
from pdtrain.label import dedup_key, leaf


def clopper_pearson(k: int, n: int) -> List[float]:
    if n == 0:
        return [float("nan"), float("nan")]
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return [round(lo, 4), round(hi, 4)]


def _scenario(row: Dict[str, Any]) -> str:
    return row["dataset"].rsplit("/", 1)[-1].removesuffix(".xml")


def _recall(rows: Sequence[Dict[str, Any]], hit) -> Dict[str, Any]:
    k = sum(1 for r in rows if hit(r))
    return {"detected": k, "n": len(rows), "recall": round(k / len(rows), 4) if rows else None,
            "ci95": clopper_pearson(k, len(rows))}


def _unique(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        seen.setdefault(row["dedup_key"], row)
    return list(seen.values())


def _example(row: Dict[str, Any], score: float) -> Dict[str, Any]:
    return {"score": round(score, 3), "scenario": _scenario(row), "parent": leaf(row.get("parent_image")),
            "image": leaf(row.get("image")), "command_line": (row.get("command_line") or "")[:140]}


def evaluate(rows: List[Dict[str, Any]], score: Dict[str, float], thresholds: Dict[str, float]) -> Dict[str, Any]:
    benign = [r for r in rows if r["label"] == 0]
    malicious = [r for r in rows if r["label"] == 1]
    hours = observed_hours(benign)
    res: Dict[str, Any] = {}
    for name, t in thresholds.items():
        hit = lambda r, t=t: score[r["row_id"]] >= t  # noqa: E731
        fp = sum(1 for r in benign if hit(r))
        by_period = {}
        for rule in sorted({r["label_rule"] for r in benign}):
            part = [r for r in benign if r["label_rule"] == rule]
            part_hours = observed_hours(part)
            part_fp = sum(1 for r in part if hit(r))
            by_period[rule] = {"fp_events": part_fp, "host_hours": round(part_hours, 2),
                               "fp_per_host_hour": round(part_fp / part_hours, 3) if part_hours else None}
        scenarios = collections.defaultdict(list)
        for r in malicious:
            scenarios[_scenario(r)].append(r)
        res[name] = {
            "threshold": t, "fp_events": fp, "fp_per_host_hour": round(fp / hours, 3) if hours else None,
            "fp_by_period": by_period,
            "recall_events": _recall(malicious, hit),
            "recall_unique_rows": _recall(_unique(malicious), hit),
            "recall_by_scenario": {s: _recall(v, hit) for s, v in sorted(scenarios.items())},
        }
    res["top_benign"] = [_example(r, score[r["row_id"]]) for r in sorted(benign, key=lambda r: -score[r["row_id"]])[:20]]
    lowest = min(thresholds.values())
    missed = [r for r in _unique(malicious) if score[r["row_id"]] < lowest]
    res["missed_malicious_unique"] = [_example(r, score[r["row_id"]]) for r in sorted(missed, key=lambda r: score[r["row_id"]])]
    return res


def run(data: Path, repo: Path, version: str) -> Dict[str, Any]:
    with gzip.open(data / "rows" / "atlasv2.jsonl.gz", "rt", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    manifest = json.loads((data / "rows" / "atlasv2.manifest.json").read_text())
    if not manifest.get("complete"):
        raise SystemExit("ATLASv2 stream incomplete; the final test needs every member")
    labelled = [r for r in rows if r.get("label") is not None]
    for row in labelled:
        row["dedup_key"] = dedup_key(row)
    benign = [r for r in labelled if r["label"] == 0]
    malicious = [r for r in labelled if r["label"] == 1]
    out: Dict[str, Any] = {
        "version": version, "atlasv2_sha256": manifest["sha256"],
        "rows": len(rows), "excluded": len(rows) - len(labelled),
        "benign_events": len(benign), "malicious_events": len(malicious),
        "malicious_unique_rows": len(_unique(malicious)),
        "observed_host_hours": round(observed_hours(benign), 2),
        "bundle_manifest": json.loads((data / "models" / version / "manifest.json").read_text())["files"],
    }
    for variant in ("A", "B"):
        folder = data / "models" / version / f"variant_{variant}"
        model = TreeModel.from_dump(json.loads((folder / "model.json").read_text()))
        thresholds = json.loads((folder / "thresholds.json").read_text())["raw_score"]
        score = {r["row_id"]: model.raw_score(vector(r, variant)) for r in labelled}
        res = evaluate(labelled, score, thresholds)
        hours = out["observed_host_hours"]
        res["passes_primary_condition"] = bool(hours) and res["alert"]["fp_events"] / hours <= 1.0
        out[f"variant_{variant}"] = res
    rules = rules_scores(labelled, repo / "rules")
    out["rules_any_fired"] = evaluate(labelled, rules, {"any": 1e-9})["any"]
    return out
