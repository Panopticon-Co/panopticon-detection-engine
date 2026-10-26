"""Pure-Python evaluation of an exported LightGBM model (``dump_model()`` JSON).

No runtime ML dependency: the trees are compiled once into flat lists and
walked per event. Only what the artifact contract allows is accepted --
numerical ``<=`` splits with ``missing_type`` ``None`` or ``NaN`` -- and
anything else is rejected at load time, never guessed at score time.

``missing_type: "Zero"`` is refused because LightGBM then routes an exact 0.0
down ``default_left`` -- and a sparse vector's absent features *are* 0.0, so a
model trained that way would silently disagree with this scorer.

Not wired into the detection pipeline (see docs/plans/ml-scoring-stage.md).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence


class ModelError(ValueError):
    """The model dump is outside the supported contract."""


@dataclass
class _Tree:
    # Parallel arrays; node i is internal when feature[i] >= 0, else a leaf.
    feature: List[int]
    threshold: List[float]
    nan_left: List[Optional[bool]]  # None: missing_type None (NaN counts as 0.0)
    left: List[int]
    right: List[int]
    value: List[float]

    def predict(self, x: Mapping[int, float]) -> float:
        i = 0
        feature, threshold = self.feature, self.threshold
        while feature[i] >= 0:
            v = x.get(feature[i], 0.0)
            if v != v:  # NaN
                nan_left = self.nan_left[i]
                if nan_left is not None:  # missing_type NaN: the learned default direction
                    i = self.left[i] if nan_left else self.right[i]
                    continue
                v = 0.0  # missing_type None: LightGBM treats a missing value as zero
            if v <= threshold[i]:
                i = self.left[i]
            else:
                i = self.right[i]
        return self.value[i]


def _compile(root: Dict[str, Any], n_features: int) -> _Tree:
    tree = _Tree([], [], [], [], [], [])

    def visit(node: Dict[str, Any]) -> int:
        index = len(tree.feature)
        tree.feature.append(-1)
        tree.threshold.append(0.0)
        tree.nan_left.append(False)
        tree.left.append(-1)
        tree.right.append(-1)
        tree.value.append(0.0)
        if "leaf_value" in node:
            value = float(node["leaf_value"])
            if not math.isfinite(value):
                raise ModelError("non-finite leaf value")
            tree.value[index] = value
            return index
        if node.get("decision_type") != "<=":
            raise ModelError(
                f"unsupported decision_type {node.get('decision_type')!r} (categorical splits are not allowed)"
            )
        missing = node.get("missing_type", "None")
        if missing not in ("None", "NaN"):
            raise ModelError(f"unsupported missing_type {missing!r}")
        feature = int(node["split_feature"])
        threshold = float(node["threshold"])
        if not (0 <= feature < n_features) or not math.isfinite(threshold):
            raise ModelError(f"bad split (feature {feature}, threshold {threshold})")
        tree.feature[index], tree.threshold[index] = feature, threshold
        tree.nan_left[index] = bool(node.get("default_left", True)) if missing == "NaN" else None
        tree.left[index] = visit(node["left_child"])
        tree.right[index] = visit(node["right_child"])
        return index

    visit(root)
    return tree


class TreeModel:
    """A binary LightGBM model: ``raw_score`` is the summed tree output (log-odds)."""

    def __init__(self, trees: Sequence[_Tree], feature_names: Sequence[str]) -> None:
        self.trees = list(trees)
        self.feature_names = list(feature_names)

    @classmethod
    def from_dump(cls, dump: Dict[str, Any]) -> "TreeModel":
        if str(dump.get("objective", "")).split(" ")[0] not in ("binary", "cross_entropy"):
            raise ModelError(f"unsupported objective {dump.get('objective')!r}")
        if int(dump.get("num_class", 1)) != 1 or int(dump.get("num_tree_per_iteration", 1)) != 1:
            raise ModelError("only single-output binary models are supported")
        names = list(dump.get("feature_names") or [])
        trees = [_compile(info["tree_structure"], len(names)) for info in dump.get("tree_info") or []]
        if not trees:
            raise ModelError("model has no trees")
        return cls(trees, names)

    def raw_score(self, x: Mapping[int, float]) -> float:
        return sum(tree.predict(x) for tree in self.trees)


class LinearModel:
    """A linear model (``model_type: "linear"``): ``raw_score = intercept + sum(coef[i] * x[i])``.

    The training tool folds any feature scaling into ``coef`` before export.
    """

    def __init__(self, coef: Sequence[float], intercept: float, feature_names: Sequence[str]) -> None:
        self.coef = [float(c) for c in coef]
        self.intercept = float(intercept)
        self.feature_names = list(feature_names)

    @classmethod
    def from_dump(cls, dump: Dict[str, Any]) -> "LinearModel":
        if dump.get("model_type") != "linear":
            raise ModelError(f"not a linear model: {dump.get('model_type')!r}")
        coef = list(dump.get("coef") or [])
        names = list(dump.get("feature_names") or [])
        if not coef or len(coef) != len(names):
            raise ModelError("coef and feature_names must be non-empty and the same length")
        values = [*coef, dump.get("intercept", 0.0)]
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in values):
            raise ModelError("non-finite coefficient")
        return cls(coef, float(dump.get("intercept", 0.0)), names)

    def raw_score(self, x: Mapping[int, float]) -> float:
        n = len(self.coef)
        return self.intercept + sum(self.coef[i] * v for i, v in x.items() if 0 <= i < n)


def load_model(dump: Dict[str, Any]):
    """``LinearModel`` for ``model_type: "linear"``, else a LightGBM ``TreeModel``."""
    return LinearModel.from_dump(dump) if dump.get("model_type") == "linear" else TreeModel.from_dump(dump)


def platt(raw: float, a: float, b: float) -> float:
    """Calibrated probability ``1 / (1 + exp(-(a * raw + b)))``, overflow-safe."""
    z = a * raw + b
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)
