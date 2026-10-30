"""Load and validate an exported process-start model bundle (ADR 003).

A bundle is a directory written by ``pdtrain`` (``loeo.export_bundle``)::

    manifest.json     sha256 of every other file, featurizer version, provenance
    model.json        LightGBM ``dump_model()``
    features.json     feature names, featurizer version
    calibration.json  Platt a, b (fitted at training prevalence)
    thresholds.json   raw-score thresholds ``alert`` and ``high``
    golden.json       feature vectors with the raw scores LightGBM produced

:func:`load_bundle` either returns a :class:`Bundle` that this engine can score
identically to the trainer, or raises :class:`ArtifactError`. It checks the file
hashes, that the featurizer version and feature order are exactly the engine's
(a mismatch would score garbage), the model's split types (``scorer`` rejects
anything outside the contract) and, last, that the pure-Python scorer reproduces
the recorded raw scores. Nothing here imports LightGBM.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from panopticon_detection.ml import featurizer as F
from panopticon_detection.ml.scorer import ModelError, TreeModel, load_model

MAX_BUNDLE_BYTES = 25 * 1024 * 1024
GOLDEN_TOLERANCE = 1e-6
_REQUIRED = ("model.json", "features.json", "calibration.json", "thresholds.json")


class ArtifactError(ValueError):
    """The bundle is missing, corrupt, or not servable by this engine."""


@dataclass(frozen=True)
class Bundle:
    path: Path
    model: Any
    model_id: str
    model_version: str          # recipe + first 8 hex of model.json's sha256
    artifact_sha256: str        # sha256 of manifest.json (which pins every file)
    featurizer_version: int
    alert_raw: float
    high_raw: float
    platt_a: float
    platt_b: float
    golden_vectors: int
    golden_max_abs_error: Optional[float]
    training_environments: List[str]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ArtifactError(f"{path.name}: unreadable ({exc})") from exc
    if not isinstance(value, dict) and path.name != "golden.json":
        raise ArtifactError(f"{path.name}: expected a JSON object")
    return value


def _finite(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ArtifactError(f"{name}: not a finite number ({value!r})")
    return float(value)


def load_bundle(directory: Any, *, expect_sha256: Optional[str] = None) -> Bundle:
    root = Path(directory)
    if not root.is_dir():
        raise ArtifactError(f"{root}: not a directory")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ArtifactError("manifest.json missing")
    total = sum(p.stat().st_size for p in root.iterdir() if p.is_file())
    if total > MAX_BUNDLE_BYTES:
        raise ArtifactError(f"bundle is {total} bytes (limit {MAX_BUNDLE_BYTES})")

    manifest = _json(manifest_path)
    artifact_sha = _sha256(manifest_path)
    if expect_sha256 and artifact_sha != expect_sha256.lower():
        raise ArtifactError("manifest sha256 does not match the pinned PANOPTICON_MODEL_SHA256")

    pinned = manifest.get("files")
    if not isinstance(pinned, dict):
        raise ArtifactError("manifest.json has no 'files' hash table")
    for name in _REQUIRED:
        if name not in pinned:
            raise ArtifactError(f"manifest does not pin {name}")
    for name, expected in pinned.items():
        file = root / name
        if not file.is_file():
            raise ArtifactError(f"{name}: listed in the manifest but missing")
        if _sha256(file) != expected:
            raise ArtifactError(f"{name}: sha256 does not match the manifest")

    version = manifest.get("featurizer_version")
    if version != F.FEATURIZER_VERSION:
        raise ArtifactError(
            f"featurizer version {version!r} != engine's {F.FEATURIZER_VERSION}; "
            "rebuild the bundle (a different featurizer scores different numbers)")
    features = _json(root / "features.json")
    if features.get("featurizer_version") != F.FEATURIZER_VERSION:
        raise ArtifactError("features.json featurizer_version disagrees with the manifest")
    if list(features.get("feature_names") or []) != list(F.FEATURE_NAMES):
        raise ArtifactError("feature names/order differ from the engine's featurizer")
    if features.get("vocabulary"):
        raise ArtifactError("token-vocabulary bundles are not supported")

    try:
        model = load_model(_json(root / "model.json"))
    except (ModelError, KeyError, TypeError, ValueError) as exc:
        raise ArtifactError(f"model.json: {exc}") from exc
    if not isinstance(model, TreeModel):
        raise ArtifactError("only tree-ensemble bundles are supported")
    if list(model.feature_names) != list(F.FEATURE_NAMES):
        raise ArtifactError("model.json feature names differ from the engine's featurizer")

    calibration = _json(root / "calibration.json")
    a, b = _finite("calibration.a", calibration.get("a")), _finite("calibration.b", calibration.get("b"))
    raw = (_json(root / "thresholds.json").get("raw_score")) or {}
    alert, high = _finite("thresholds.alert", raw.get("alert")), _finite("thresholds.high", raw.get("high"))
    if not alert <= high:
        raise ArtifactError("thresholds: alert must not exceed high")

    count, worst = 0, None
    golden = root / "golden.json"
    if golden.is_file():
        records = json.loads(golden.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ArtifactError("golden.json: expected a list")
        worst = 0.0
        for record in records:
            vector = {int(k): (float("nan") if v is None else float(v)) for k, v in record["vector"].items()}
            worst = max(worst, abs(model.raw_score(vector) - _finite("golden.raw_score", record["raw_score"])))
            count += 1
        if worst > GOLDEN_TOLERANCE:
            raise ArtifactError(f"scorer disagrees with the trainer on golden vectors (max error {worst:.3g})")

    recipe = str(manifest.get("recipe") or manifest.get("candidate") or "model")
    return Bundle(
        path=root, model=model, model_id=str(manifest.get("model_id") or "panopticon-process-start"),
        model_version=f"{recipe}-{pinned['model.json'][:8]}", artifact_sha256=artifact_sha,
        featurizer_version=int(version), alert_raw=alert, high_raw=high, platt_a=a, platt_b=b,
        golden_vectors=count, golden_max_abs_error=worst,
        training_environments=list(manifest.get("training_environments") or []),
    )
