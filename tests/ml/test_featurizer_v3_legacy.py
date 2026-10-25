"""The frozen featurizer-v3 copy that legacy runs (v1-v6) and the v6-recipe baseline use."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("lightgbm")

from pdtrain import featurizer_v3 as F3  # noqa: E402

from tests.ml.test_featurizer import CASES  # noqa: E402

GOLDEN_V3 = Path(__file__).with_name("golden_featurizer_v3.json")


def test_frozen_copy_reproduces_v3_golden_vectors():
    golden = json.loads(GOLDEN_V3.read_text(encoding="utf-8"))
    assert golden["featurizer_version"] == F3.FEATURIZER_VERSION == 3
    assert golden["feature_count"] == len(F3.FEATURE_NAMES)
    computed = [{"id": cid, "event": event, "integrity": integrity,
                 "vector": {str(k): v for k, v in F3.featurize(event, integrity).items()}}
                for cid, event, integrity in CASES]
    assert computed == golden["cases"]
