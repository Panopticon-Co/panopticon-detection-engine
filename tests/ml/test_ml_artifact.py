"""Bundle loading: servable or refused, never guessed at (docs/adr/003)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from panopticon_detection.ml import featurizer as F
from panopticon_detection.ml.artifact import ArtifactError, load_bundle
from tests.ml.bundle_fixture import make_bundle

REAL = Path(__file__).resolve().parents[2] / "data" / "models" / "v7_v5"


def test_valid_bundle_loads(tmp_path):
    bundle = load_bundle(make_bundle(tmp_path / "b", 3.0))
    assert bundle.featurizer_version == F.FEATURIZER_VERSION
    assert (bundle.alert_raw, bundle.high_raw) == (1.0, 2.0)
    assert bundle.golden_vectors == 2 and bundle.golden_max_abs_error == 0.0
    assert bundle.model_version.startswith("fixture-")


def test_missing_directory_and_manifest(tmp_path):
    with pytest.raises(ArtifactError):
        load_bundle(tmp_path / "nope")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ArtifactError, match="manifest"):
        load_bundle(tmp_path / "empty")


def test_tampered_file_is_refused(tmp_path):
    root = make_bundle(tmp_path / "b", 3.0)
    (root / "thresholds.json").write_text(json.dumps({"raw_score": {"alert": 0.1, "high": 0.2}}))
    with pytest.raises(ArtifactError, match="sha256"):
        load_bundle(root)


def test_pinned_manifest_hash(tmp_path):
    root = make_bundle(tmp_path / "b", 3.0)
    with pytest.raises(ArtifactError, match="pinned"):
        load_bundle(root, expect_sha256="0" * 64)
    load_bundle(root, expect_sha256=load_bundle(root).artifact_sha256)


def test_featurizer_version_mismatch_is_refused(tmp_path):
    root = make_bundle(tmp_path / "b", 3.0, featurizer_version=F.FEATURIZER_VERSION - 1)
    with pytest.raises(ArtifactError, match="featurizer version"):
        load_bundle(root)


def _rewrite(root: Path, name: str, edit) -> None:
    """Edit a file and re-pin its hash, so only the intended check can fail."""
    import hashlib
    data = json.loads((root / name).read_text())
    data = edit(data)
    (root / name).write_text(json.dumps(data))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest))


def test_feature_order_mismatch_is_refused(tmp_path):
    root = make_bundle(tmp_path / "b", 3.0)
    _rewrite(root, "features.json", lambda d: {**d, "feature_names": list(reversed(d["feature_names"]))})
    with pytest.raises(ArtifactError, match="feature names"):
        load_bundle(root)


def test_unsupported_split_semantics_are_refused(tmp_path):
    with pytest.raises(ArtifactError, match="missing_type"):
        load_bundle(make_bundle(tmp_path / "b", 3.0, missing_type="Zero"))


def test_threshold_order_and_finiteness(tmp_path):
    with pytest.raises(ArtifactError, match="alert must not exceed high"):
        load_bundle(make_bundle(tmp_path / "b", 3.0, alert=2.0, high=1.0))


def test_golden_disagreement_is_refused(tmp_path):
    root = make_bundle(tmp_path / "b", 3.0)
    _rewrite(root, "golden.json", lambda d: [{**d[0], "raw_score": d[0]["raw_score"] + 0.5}, d[1]])
    with pytest.raises(ArtifactError, match="golden"):
        load_bundle(root)


@pytest.mark.skipif(not REAL.is_dir(), reason="trained bundle data/models/v7_v5 not present")
def test_real_bundle_loads_with_parity():
    bundle = load_bundle(REAL)
    assert bundle.golden_vectors >= 40 and bundle.golden_max_abs_error < 1e-9
    assert 0 < bundle.alert_raw <= bundle.high_raw
