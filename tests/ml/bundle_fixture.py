"""A tiny hand-built model bundle: the ML stage needs no LightGBM and no trained data.

One tree splits on ``cmd_length``; every process start that carries a command
line has ``cmd_length > 0``, so its raw score is exactly ``score``. That makes a
band (below / alert / high) a test parameter rather than something to hunt for.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from panopticon_detection.ml import featurizer as F

ALERT_RAW = 1.0
HIGH_RAW = 2.0
INDEX = list(F.FEATURE_NAMES).index("cmd_length")


def _write(root: Path, name: str, value) -> None:
    (root / name).write_text(json.dumps(value), encoding="utf-8")


def make_bundle(root: Path, score: float, *, featurizer_version: Optional[int] = None, missing_type: str = "None",
                alert: float = ALERT_RAW, high: float = HIGH_RAW) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    names = list(F.FEATURE_NAMES)
    tree = {"split_feature": INDEX, "decision_type": "<=", "threshold": 0.0, "missing_type": missing_type,
            "default_left": True, "left_child": {"leaf_value": 0.0}, "right_child": {"leaf_value": score}}
    _write(root, "model.json", {"objective": "binary sigmoid:1", "num_class": 1, "num_tree_per_iteration": 1,
                                "feature_names": names, "tree_info": [{"tree_structure": tree}]})
    _write(root, "features.json", {"featurizer_version": F.FEATURIZER_VERSION, "feature_names": names,
                                   "vocabulary": []})
    _write(root, "calibration.json", {"method": "platt", "a": 1.0, "b": -2.0})
    _write(root, "thresholds.json", {"raw_score": {"alert": alert, "high": high}})
    _write(root, "golden.json", [{"vector": {str(INDEX): 1.0}, "raw_score": score},
                                 {"vector": {}, "raw_score": 0.0}])
    files = {n: hashlib.sha256((root / n).read_bytes()).hexdigest()
             for n in ("model.json", "features.json", "calibration.json", "thresholds.json", "golden.json")}
    _write(root, "manifest.json", {
        "model_id": "fixture", "recipe": "fixture", "featurizer_version": featurizer_version or F.FEATURIZER_VERSION,
        "training_environments": ["synthetic"], "files": files})
    return root
