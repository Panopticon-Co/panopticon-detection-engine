"""The sealed final test: one agent recording from another machine, scored once with a frozen bundle.

History: this test was first ATLASv2 (pre-registered for v6). On the project
owner's decision ATLASv2 became v7 training data before any model scored it
(training-plan D20); the sealed test is now an Officer-kit recording from a
machine and user that no training run has seen (source ``officer_sealed``,
normalized by ``pdtrain normalize --sources officer_sealed``).

Pre-registered rules:

* the bundle (``data/models/<version>``) is frozen and must be marked
  ``final_candidate`` (``--freeze`` marks it, recording the time); nothing is
  refit or re-thresholded here;
* scoring uses the serving path: featurizer v4 and the pure-Python scorer
  (``panopticon_detection.ml.scorer.load_model``), not LightGBM;
* the test runs **once**: a marker file records it, and a second run is refused;
* reported: false positives per observed host-hour at ``alert`` and ``high``
  with exact Poisson intervals, the top-scoring benign starts, and recall with
  exact intervals if the recording contains labelled attacks;
* pass condition: <= 1 false positive per observed host-hour at ``alert``.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scipy.stats import beta, chi2

from panopticon_detection.ml import featurizer as F4
from panopticon_detection.ml.scorer import load_model
from pdtrain.experiment import observed_hours, scrub
from pdtrain.label import leaf


def clopper_pearson(k: int, n: int) -> List[Optional[float]]:
    if n == 0:
        return [None, None]
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return [round(lo, 4), round(hi, 4)]


def poisson_ci(k: int, hours: float) -> List[Optional[float]]:
    if not hours:
        return [None, None]
    lo = chi2.ppf(0.025, 2 * k) / 2 if k > 0 else 0.0
    return [round(lo / hours, 4), round(chi2.ppf(0.975, 2 * k + 2) / 2 / hours, 4)]


def evaluate(rows: List[Dict[str, Any]], score: Dict[str, float], thresholds: Dict[str, float]) -> Dict[str, Any]:
    benign = [r for r in rows if r.get("label") == 0]
    malicious = [r for r in rows if r.get("label") == 1]
    hours = observed_hours(rows)
    out: Dict[str, Any] = {"benign_events": len(benign), "malicious_events": len(malicious),
                           "observed_host_hours": round(hours, 2), "hosts": len({r.get("host") for r in rows})}
    for name, t in thresholds.items():
        fp = sum(1 for r in benign if score[r["row_id"]] >= t)
        tp = sum(1 for r in malicious if score[r["row_id"]] >= t)
        out[name] = {"threshold": t, "fp_events": fp, "fp_per_host_hour": round(fp / hours, 4) if hours else None,
                     "fp_ci95": poisson_ci(fp, hours),
                     "recall": round(tp / len(malicious), 4) if malicious else None,
                     "recall_ci95": clopper_pearson(tp, len(malicious))}
    out["top_benign"] = [
        {"score": round(score[r["row_id"]], 3), "parent": leaf(r.get("parent_image")), "image": leaf(r.get("image")),
         "command_line": (r.get("command_line") or "")[:140]}
        for r in sorted(benign, key=lambda r: -score[r["row_id"]])[:20]]
    return out


def bundle_scorer(folder: Path):
    """Score rows exactly as serving would: featurizer v4 (+ shipped vocabulary) and the pure-Python model."""
    spec = json.loads((folder / "features.json").read_text())
    if spec.get("featurizer_version") != F4.FEATURIZER_VERSION:
        raise SystemExit(f"bundle needs featurizer {spec.get('featurizer_version')}, this is {F4.FEATURIZER_VERSION}")
    model = load_model(json.loads((folder / "model.json").read_text()))
    vocabulary = {t: i for i, t in enumerate(spec.get("vocabulary") or [])}
    dropped = {F4.FEATURE_NAMES.index(n) for n in spec.get("dropped_features") or []}

    def score(row: Dict[str, Any]) -> float:
        vector = F4.featurize(scrub(row)["event"], vocabulary or None)
        return model.raw_score({i: v for i, v in vector.items() if i not in dropped})

    return score


def run(data: Path, repo: Path, version: str, source: str = "officer_sealed", freeze: bool = False) -> Dict[str, Any]:
    folder = data / "models" / version
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    marker = data / "experiment" / f"sealed_{source}_spent.json"
    if marker.exists():
        raise SystemExit(f"the sealed test on {source} was already run ({marker}); it runs once")
    rows_path = data / "rows" / f"{source}.jsonl.gz"
    if not rows_path.exists():
        raise SystemExit(f"no sealed recording at {rows_path}: normalize it first "
                         f"(pdtrain normalize --sources {source})")
    if freeze and not manifest.get("final_candidate"):
        manifest.update(final_candidate=True, frozen_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if not manifest.get("final_candidate"):
        raise SystemExit(f"{folder} is not marked final_candidate; freeze it first (--freeze)")
    with gzip.open(rows_path, "rt", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    rows = [r for r in rows if r.get("label") is not None]
    score_row = bundle_scorer(folder)
    score = {r["row_id"]: score_row(r) for r in rows}
    thresholds = json.loads((folder / "thresholds.json").read_text())["raw_score"]
    result = {"version": version, "source": source, "bundle_files": manifest["files"],
              "rows_sha256": hashlib.sha256(rows_path.read_bytes()).hexdigest(),
              **evaluate(rows, score, thresholds)}
    result["passes"] = result["alert"]["fp_per_host_hour"] is not None and result["alert"]["fp_per_host_hour"] <= 1.0
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"version": version, "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                  "passes": result["passes"]}, indent=2) + "\n", encoding="utf-8")
    return result
