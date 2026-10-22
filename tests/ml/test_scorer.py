"""The pure-Python tree scorer: contract checks and parity with LightGBM itself."""

from __future__ import annotations

import math
import random

import pytest

from panopticon_detection.ml.scorer import ModelError, TreeModel, platt


def _dump(missing="None", decision="<="):
    return {
        "objective": "binary sigmoid:1",
        "num_class": 1,
        "num_tree_per_iteration": 1,
        "feature_names": ["a", "b", "c"],
        "tree_info": [
            {
                "tree_structure": {
                    "split_feature": 0, "threshold": 0.5, "decision_type": decision,
                    "default_left": True, "missing_type": missing,
                    "left_child": {"leaf_value": -1.0},
                    "right_child": {
                        "split_feature": 2, "threshold": 2.0, "decision_type": "<=",
                        "default_left": False, "missing_type": "NaN",
                        "left_child": {"leaf_value": 0.5},
                        "right_child": {"leaf_value": 2.0},
                    },
                }
            },
            {"tree_structure": {"leaf_value": 0.25}},
        ],
    }


def test_walks_trees_and_treats_absent_features_as_zero():
    model = TreeModel.from_dump(_dump())
    assert model.raw_score({}) == pytest.approx(-0.75)
    assert model.raw_score({0: 1.0, 2: 1.0}) == pytest.approx(0.75)
    assert model.raw_score({0: 1.0, 2: 3.0}) == pytest.approx(2.25)
    assert model.raw_score({0: 1.0, 2: float("nan")}) == pytest.approx(2.25)  # NaN -> right


@pytest.mark.parametrize("missing,decision", [("Zero", "<="), ("None", "==")])
def test_rejects_splits_outside_the_contract(missing, decision):
    with pytest.raises(ModelError):
        TreeModel.from_dump(_dump(missing, decision))


def test_rejects_non_binary_objectives():
    dump = _dump()
    dump["objective"] = "regression"
    with pytest.raises(ModelError):
        TreeModel.from_dump(dump)


def test_platt_is_monotone_and_overflow_safe():
    assert platt(0.0, 1.0, 0.0) == 0.5
    assert platt(1000.0, 1.0, 0.0) == pytest.approx(1.0)
    assert platt(-1000.0, 1.0, 0.0) == pytest.approx(0.0)
    assert platt(1.0, 1.0, 0.0) > platt(0.5, 1.0, 0.0)


def test_parity_with_lightgbm_on_sparse_data():
    lightgbm = pytest.importorskip("lightgbm")
    np = pytest.importorskip("numpy")
    sparse = pytest.importorskip("scipy.sparse")
    rng = random.Random(7)
    rows, cols, vals, y, vectors = [], [], [], [], []
    for i in range(600):
        vec = {j: round(rng.uniform(0.1, 5.0), 3) for j in rng.sample(range(40), 6)}
        vectors.append(vec)
        for j, v in vec.items():
            rows.append(i)
            cols.append(j)
            vals.append(v)
        y.append(1 if vec.get(3, 0) + vec.get(7, 0) > 2.5 else 0)
    x = sparse.csr_matrix((vals, (rows, cols)), shape=(600, 40))
    booster = lightgbm.train(
        {"objective": "binary", "verbose": -1, "num_leaves": 7, "deterministic": True,
         "num_threads": 1, "seed": 1, "min_data_in_leaf": 5},
        lightgbm.Dataset(x, label=np.array(y), feature_name=[f"f{i}" for i in range(40)]),
        num_boost_round=30,
    )
    model = TreeModel.from_dump(booster.dump_model())
    expected = booster.predict(x, raw_score=True)
    for vec, want in zip(vectors, expected):
        assert math.isclose(model.raw_score(vec), want, rel_tol=0, abs_tol=1e-9)
