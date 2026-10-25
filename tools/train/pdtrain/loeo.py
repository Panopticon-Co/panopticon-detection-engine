"""Leave-one-environment-out (LOEO) training and evaluation: the v7 protocol.

Pre-registered (training-plan D21), committed before the first v7 run. Runs
v1-v6 showed that the operating point followed whichever benign environment
dominated the pooled host-hours, and that no held-out set measured a truly
unseen environment. This protocol therefore:

* tags every row with an **environment** (:data:`ENVIRONMENT_OF_SOURCE`) and,
  for each environment in turn, trains on the others and tests on it;
* de-duplicates rows *within* an environment (a unit = one featurized row in
  one environment, with its raw-event count); keys seen with both labels
  anywhere are never trained on;
* sets thresholds on out-of-fold scores of the *training* environments so that
  **every** training environment meets the budget on its own observed hours
  (``minimax``), instead of one pooled budget;
* weights training environments equally (``environment`` weighting) and blanks
  the parent name on a copy of each row at the agent's observed rate, so a
  missing parent cannot mean "benign";
* reports, per held-out environment, false positives per observed host-hour
  (exact Poisson intervals), recall on distinct attack rows (exact binomial
  intervals) and threshold-free ROC / partial AUC, next to the engine's rules
  and a LOLBin heuristic run through the same protocol.

Candidates, the selection rule and criteria S1-S6 are fixed below
(:data:`CANDIDATES`, :data:`SELECTION_RULE`, :data:`CRITERIA`).
"""

from __future__ import annotations

import collections
import hashlib
import json
import platform
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np
import sklearn
from scipy import sparse
from scipy.stats import beta, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.preprocessing import MaxAbsScaler

from panopticon_detection.ml import featurizer as F4
from panopticon_detection.ml.scorer import load_model
from pdtrain import experiment as X
from pdtrain.label import leaf

ENVIRONMENT_OF_SOURCE: Dict[str, str] = {
    "attack_data": "attack_range", "otrf": "mordor", "otrf_compound": "mordor", "botsv1": "botsv1",
    "officer_vm": "officer_vm", "optc": "optc", "atlasv2": "atlasv2",
}
SOURCES: Tuple[str, ...] = tuple(ENVIRONMENT_OF_SOURCE)
ENVIRONMENTS: Tuple[str, ...] = ("attack_range", "mordor", "botsv1", "officer_vm", "optc", "atlasv2")
BUDGETS = X.BUDGETS
SEED = X.SEED
N_INNER = 5
BOOTSTRAP = 1000
MALICIOUS_GROUP_CAP = 300
BENIGN_IMAGE_CAP = 50
#: Parent name missing on 756 of 2,485 agent-recorded process starts (DATASHEET).
PARENT_MISSING_RATE = 0.30
TOKEN_MIN_ENVIRONMENTS = 3
MIN_FRAMEWORK_UNITS = 10
HIGH_BUDGET_MIN_HOURS = 20.0
MUTATIONS = ("quote_split", "envvar_substring", "short_path", "unicode_dash", "flag_prefix", "renamed_copy")

CRITERIA = {
    "S1": "every held-out environment: FP/host-hour <= 1 at alert (point estimate); <= 0.1 at high where the "
          "environment has >= 20 observed host-hours (otherwise the Poisson upper bound is reported)",
    "S2": "macro recall at alert over environments with attacks: model - rules paired-bootstrap 95% CI lower "
          "bound > 0, and model - heuristic lower bound > -0.05",
    "S3": "leave-one-framework-out macro recall >= leave-one-technique-out macro recall - 0.15",
    "S4": "benign environment predictability (one-vs-rest, out-of-fold) macro ROC-AUC <= 0.70, and no top-30 "
          "feature present in only one environment's training rows",
    "S5": "each held-out mutation family: recall drop <= 0.10 on the attack rows it changes",
    "S6": "rebuild gives a bit-identical model.json; golden vectors match the pure-Python scorer",
}
SELECTION_RULE = ("among CANDIDATES, those meeting S1's alert condition in every held-out environment; the "
                  "highest macro recall at alert wins. If none meets it, the lowest worst-environment "
                  "FP/host-hour at alert wins (and S1 fails)")
DECISION_RULE = "shadow integration only if S1-S6 pass and the sealed final test passes (<= 1 FP/host-hour at alert)"


# ======================================================================= recipes


@dataclass(frozen=True)
class Recipe:
    name: str
    features: str                      # "v3" | "v4" | "v4_tokens"
    model: str                         # "lgb" | "lr"
    weighting: str                     # "uniform" | "environment"
    thresholds: str                    # "pooled" | "minimax"
    parent_augment: bool
    benign_cap: str                    # "legacy" (agent-like sources only) | "image50" (every environment)
    params: Tuple[Tuple[str, Any], ...] = ()
    monotone: bool = False
    exclude_train: Tuple[str, ...] = ()
    drop_features: Tuple[str, ...] = ()


_SHALLOW = (("num_leaves", 15), ("max_depth", 4), ("min_data_in_leaf", 50))
_V7 = Recipe("v7_lgb", "v4", "lgb", "environment", "minimax", True, "image50", _SHALLOW, True)
RECIPES: Dict[str, Recipe] = {
    # v6 as trained (featurizer v3, pooled budget, no ATLASv2), evaluated under LOEO
    "v6_recipe": Recipe("v6_recipe", "v3", "lgb", "uniform", "pooled", False, "legacy",
                        (("num_leaves", 31), ("min_data_in_leaf", 50)), False, ("atlasv2",)),
    "v7_lgb": _V7,
    "v7_lr": replace(_V7, name="v7_lr", model="lr", params=(), monotone=False),
    "v7_tokens": replace(_V7, name="v7_tokens", features="v4_tokens"),
    "v7_lgb_no_stats": replace(_V7, name="v7_lgb_no_stats", drop_features=F4.STATS_FEATURES),
}
CANDIDATES: Tuple[str, ...] = ("v7_lgb", "v7_lr", "v7_tokens", "v7_lgb_no_stats")


def without_atlasv2(recipe: Recipe) -> Recipe:
    """The project owner's hypothesis test: the same recipe with ATLASv2 kept out of training."""
    return replace(recipe, name=f"{recipe.name}_no_atlasv2", exclude_train=(*recipe.exclude_train, "atlasv2"))


# ========================================================================== data


def environment(row: Dict[str, Any]) -> str:
    return ENVIRONMENT_OF_SOURCE[row["source"]]


def framework(row: Dict[str, Any]) -> str:
    """Attack tooling family of a malicious row (leave-one-framework-out, S3)."""
    source, tool = row["source"], (row.get("tool") or "")
    name = row["dataset"].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if source == "attack_data":
        return {"atomic_red_team": "atomic_red_team", "cobalt_strike": "cobalt_strike"}.get(tool, "splunk_scenarios")
    if source == "otrf":
        for prefix, fw in (("empire_", "empire"), ("covenant_", "covenant"), ("msf_", "metasploit"),
                           ("psh_metasploit", "metasploit"), ("purplesharp", "purplesharp")):
            if name.startswith(prefix):
                return fw
        return "otrf_manual"
    if source == "otrf_compound":
        return "apt29_manual" if tool == "apt29" else "metasploit"
    if source == "botsv1":
        return "botsv1_intrusions"
    return "atlasv2_scenarios"


@dataclass
class Unit:
    """One featurized row within one environment, with its raw-event count."""

    uid: str
    env: str
    label: int
    key: str
    row: Dict[str, Any]
    count: int
    row_ids: List[str]
    group: str
    framework: Optional[str]
    infra: bool
    conflict: bool


def _scenario_group(row: Dict[str, Any]) -> str:
    # atlasv2:attack/h1/sysmon-h1-m1.xml -> m1; h1-m1 and h2-m1 are the same attack, so one group.
    stem = row["dataset"].rsplit("/", 1)[-1].removesuffix(".xml")
    return f"atlasv2:{stem.rsplit('-', 1)[-1]}"


_TEMPLATE_DIGITS = re.compile(r"[a-z0-9_.<>$-]*\d[a-z0-9_.<>$-]*")


def template(row: Dict[str, Any]) -> str:
    """A command with run-specific tokens collapsed: near-duplicates share one."""
    proc = row["event"].get("process") or {}
    text = F4.normalize_text(proc.get("command_line")) or F4.normalize_text(proc.get("executable"))
    parent = leaf((row["event"].get("parent") or {}).get("name"))
    return f"{parent}>{_TEMPLATE_DIGITS.sub('<d>', text)}"


def _merge_templates(units: List[Unit]) -> int:
    """Union the groups of attack rows that share a template, so near-duplicates never straddle folds."""
    parent: Dict[str, str] = {}

    def find(g: str) -> str:
        parent.setdefault(g, g)
        while parent[g] != g:
            parent[g] = parent[parent[g]]
            g = parent[g]
        return g

    first: Dict[str, str] = {}
    for u in units:
        if u.label != 1 or u.conflict:
            continue
        find(u.group)
        t = template(u.row)
        if t in first:
            a, b = find(first[t]), find(u.group)
            if a != b:
                parent[max(a, b)] = min(a, b)
        else:
            first[t] = u.group
    before = len({u.group for u in units if u.label == 1 and not u.conflict})
    for u in units:
        if u.label == 1 and not u.conflict:
            u.group = f"tpl:{find(u.group)}"
    return before - len({u.group for u in units if u.label == 1 and not u.conflict})


def build_units(raw: Sequence[Dict[str, Any]]) -> Tuple[List[Unit], Dict[str, Any]]:
    labels_by_key: Dict[str, set] = collections.defaultdict(set)
    for r in raw:
        if r.get("label") is not None:
            labels_by_key[r["dedup_key"]].add(r["label"])
    conflicts = {k for k, v in labels_by_key.items() if len(v) > 1}
    buckets: Dict[Tuple[str, int, str], List[Dict[str, Any]]] = collections.defaultdict(list)
    for r in raw:
        if r.get("label") is not None:
            buckets[(environment(r), int(r["label"]), r["dedup_key"])].append(r)
    units: List[Unit] = []
    for (env, label, key), rows in sorted(buckets.items()):
        rows.sort(key=lambda r: (r["utc"], r["row_id"]))
        rep = rows[0]
        if rep["source"] == "atlasv2" and label == 1:
            group = _scenario_group(rep)
        else:
            group = rep.get("group") or f"{env}:{rep.get('host')}"
        units.append(Unit(
            uid=hashlib.sha256(f"{env}|{label}|{key}".encode()).hexdigest()[:20], env=env, label=label, key=key,
            row=rep, count=len(rows), row_ids=[r["row_id"] for r in rows], group=group,
            framework=framework(rep) if label == 1 else None, infra=X.is_lab_infrastructure(rep),
            conflict=key in conflicts,
        ))
    merged = _merge_templates(units)
    info = {"conflict_keys": len(conflicts), "malicious_groups_merged_by_template": merged,
            "units": dict(sorted(collections.Counter(f"{u.env} {u.label}" for u in units).items()))}
    return units, info


def hours_by_environment(raw: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    by_env: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for r in raw:
        by_env[environment(r)].append(r)
    return {env: X.observed_hours(rows) for env, rows in sorted(by_env.items())}


def without_parent(row: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(row["event"])
    event["parent"] = {**(event.get("parent") or {}), "name": None}
    return {**row, "event": event}


def _has_parent(row: Dict[str, Any]) -> bool:
    return bool(((row["event"].get("parent") or {}).get("name") or "").strip())


# ====================================================================== features


class Features:
    """Feature extraction for one recipe (and, with tokens, one fold's vocabulary)."""

    _cache: Dict[Tuple[str, str], Tuple[Dict[int, float], List[str]]] = {}

    def __init__(self, kind: str, drop: Sequence[str] = ()) -> None:
        self.kind = kind
        self.base_names = list(X.F.FEATURE_NAMES) if kind == "v3" else list(F4.FEATURE_NAMES)
        self.drop = frozenset(self.base_names.index(n) for n in drop)
        self.vocabulary: Dict[str, int] = {}

    @property
    def names(self) -> List[str]:
        return self.base_names + [f"tok{i}" for i in range(len(self.vocabulary))]

    def _base(self, cache_key: str, row: Dict[str, Any]) -> Tuple[Dict[int, float], List[str]]:
        key = ("v3" if self.kind == "v3" else "v4", cache_key)
        hit = Features._cache.get(key)
        if hit is None:
            if self.kind == "v3":
                hit = (X.vector(row, "A"), [])
            else:
                event = X.scrub(row)["event"]
                hit = (F4.featurize(event), F4.raw_tokens(event))
            Features._cache[key] = hit
        return hit

    def fit_vocabulary(self, items: Sequence[Tuple[str, Dict[str, Any], str]]) -> None:
        """Keep tokens seen in at least TOKEN_MIN_ENVIRONMENTS training environments."""
        if self.kind != "v4_tokens":
            return
        envs: Dict[str, set] = collections.defaultdict(set)
        for cache_key, row, env in items:
            for token in self._base(cache_key, row)[1]:
                envs[token].add(env)
        kept = sorted(t for t, e in envs.items() if len(e) >= TOKEN_MIN_ENVIRONMENTS)
        self.vocabulary = {t: i for i, t in enumerate(kept)}

    def vector(self, cache_key: Optional[str], row: Dict[str, Any]) -> Dict[int, float]:
        if cache_key is None:  # mutated rows: never cached
            event = X.scrub(row)["event"]
            base, tokens = (X.vector(row, "A"), []) if self.kind == "v3" else (F4.featurize(event), F4.raw_tokens(event))
        else:
            base, tokens = self._base(cache_key, row)
        v = {i: x for i, x in base.items() if i not in self.drop}
        if self.vocabulary:
            offset = len(self.base_names)
            for t in tokens:
                col = self.vocabulary.get(t)
                if col is not None:
                    v[offset + col] = 1.0
        return v

    def matrix(self, items: Sequence[Tuple[Optional[str], Dict[str, Any]]]) -> sparse.csr_matrix:
        data: List[float] = []
        indices: List[int] = []
        indptr = [0]
        for cache_key, row in items:
            for i, x in sorted(self.vector(cache_key, row).items()):
                indices.append(i)
                data.append(x)
            indptr.append(len(indices))
        return sparse.csr_matrix((np.array(data, dtype=np.float64), np.array(indices, dtype=np.int64),
                                  np.array(indptr)), shape=(len(items), len(self.names)))


# ========================================================================= model


class Model:
    def __init__(self, recipe: Recipe, feats: Features) -> None:
        self.recipe, self.feats = recipe, feats
        self.booster: Any = None
        self.scaler: Any = None
        self.lr: Any = None
        self.rounds = 0

    def _params(self) -> Dict[str, Any]:
        params = {**X.BASE_PARAMS, **dict(self.recipe.params)}
        if self.recipe.monotone:
            mono = set(F4.MONOTONE_FEATURES)
            params["monotone_constraints"] = [1 if n in mono else 0 for n in self.feats.names]
        return params

    def fit(self, x, y, w, groups, refit: bool) -> "Model":
        if self.recipe.model == "lr":
            self.scaler = MaxAbsScaler().fit(x)
            self.lr = LogisticRegression(C=1.0, solver="liblinear", max_iter=2000)
            self.lr.fit(self.scaler.transform(x), y, sample_weight=w)
            return self
        tr, va = X._inner_split(groups, y)
        names = self.feats.names
        train_set = lgb.Dataset(x[tr], label=y[tr], weight=w[tr], feature_name=names, free_raw_data=False)
        valid_set = lgb.Dataset(x[va], label=y[va], weight=w[va], reference=train_set)
        booster = lgb.train(self._params(), train_set, num_boost_round=1000, valid_sets=[valid_set],
                            callbacks=[lgb.early_stopping(50, verbose=False)])
        self.rounds = max(1, int(booster.best_iteration or booster.current_iteration()))
        if refit:
            booster = lgb.train(self._params(), lgb.Dataset(x, label=y, weight=w, feature_name=names),
                                num_boost_round=self.rounds)
        self.booster = booster
        return self

    def score(self, x) -> np.ndarray:
        if self.recipe.model == "lr":
            return self.lr.decision_function(self.scaler.transform(x))
        return self.booster.predict(x, raw_score=True, num_iteration=self.rounds)

    def dump(self) -> Dict[str, Any]:
        if self.recipe.model == "lr":
            scale = np.where(self.scaler.scale_ == 0, 1.0, self.scaler.scale_)
            coef = (self.lr.coef_[0] / scale).tolist()
            return {"model_type": "linear", "intercept": float(self.lr.intercept_[0]), "coef": coef,
                    "feature_names": self.feats.names}
        return self.booster.dump_model(num_iteration=self.rounds)

    def importance(self) -> np.ndarray:
        if self.recipe.model == "lr":
            return np.abs(self.lr.coef_[0])
        return self.booster.feature_importance(importance_type="gain", iteration=self.rounds)


# ================================================================== a training fit


@dataclass
class Fit:
    recipe: Recipe
    feats: Features
    model: Model
    thresholds: Dict[str, float]
    per_env_thresholds: Dict[str, Dict[str, float]]
    train_envs: List[str]
    oof: Dict[str, float] = field(default_factory=dict)       # uid -> out-of-fold raw score
    train_units: List[Unit] = field(default_factory=list)


def _capped(units: List[Unit], key: Callable[[Unit], str], cap: int) -> List[Unit]:
    by: Dict[str, List[Unit]] = collections.defaultdict(list)
    for u in units:
        by[key(u)].append(u)
    out: List[Unit] = []
    for _, members in sorted(by.items()):
        out.extend(sorted(members, key=lambda u: u.uid)[:cap])
    return out


def training_units(units: Sequence[Unit], recipe: Recipe, held_out: Optional[str],
                   drop_framework: Optional[str] = None) -> List[Unit]:
    pool = [u for u in units if u.env != held_out and u.env not in recipe.exclude_train
            and not u.conflict and not u.infra
            and not (drop_framework is not None and u.label == 1 and u.framework == drop_framework)]
    malicious = _capped([u for u in pool if u.label == 1], lambda u: u.group, MALICIOUS_GROUP_CAP)
    benign = [u for u in pool if u.label == 0]
    capped_envs = ("officer_vm", "optc") if recipe.benign_cap == "legacy" else ENVIRONMENTS
    image_cap = _capped([u for u in benign if u.env in capped_envs],
                        lambda u: f"{u.env}|{leaf(u.row.get('image'))}", BENIGN_IMAGE_CAP)
    benign = [u for u in benign if u.env not in capped_envs] + image_cap
    return sorted(malicious + benign, key=lambda u: u.uid)


def _weights(train: Sequence[Unit], recipe: Recipe) -> Dict[str, float]:
    if recipe.weighting == "uniform":
        return {u.uid: 1.0 for u in train}
    benign = [u for u in train if u.label == 0]
    malicious = [u for u in train if u.label == 1]
    per_env = collections.Counter(u.env for u in benign)
    share = len(benign) / len(per_env)
    w = {u.uid: share / per_env[u.env] for u in benign}
    scale = len(benign) / max(1, len(malicious))
    w.update({u.uid: scale for u in malicious})
    return w


def _expand(train: Sequence[Unit], recipe: Recipe, w: Dict[str, float]) -> List[Tuple[str, Dict[str, Any], Unit, float]]:
    rows = []
    for u in train:
        if recipe.parent_augment and u.env != "officer_vm" and _has_parent(u.row):
            rows.append((u.uid, u.row, u, w[u.uid] * (1 - PARENT_MISSING_RATE)))
            rows.append((f"{u.uid}#np", without_parent(u.row), u, w[u.uid] * PARENT_MISSING_RATE))
        else:
            rows.append((u.uid, u.row, u, w[u.uid]))
    return rows


def _thresholds(policy: str, units: Sequence[Unit], scores: Dict[str, float],
                hours: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, Dict[str, float]]]:
    per_env: Dict[str, Dict[str, float]] = {}
    by_env: Dict[str, List[Unit]] = collections.defaultdict(list)
    for u in units:
        by_env[u.env].append(u)
    for env, us in sorted(by_env.items()):
        s = np.array([scores[u.uid] for u in us])
        c = np.array([u.count for u in us], dtype=float)
        per_env[env] = {n: X.threshold_for_budget(s, c, hours[env], b) for n, b in BUDGETS.items()}
    if policy == "minimax":
        return {n: max(t[n] for t in per_env.values()) for n in BUDGETS}, per_env
    s = np.array([scores[u.uid] for u in units])
    c = np.array([u.count for u in units], dtype=float)
    total = sum(hours[e] for e in by_env)
    return {n: X.threshold_for_budget(s, c, total, b) for n, b in BUDGETS.items()}, per_env


def fit(units: Sequence[Unit], hours: Dict[str, float], recipe: Recipe, held_out: Optional[str] = None,
        drop_framework: Optional[str] = None) -> Fit:
    """Train on every environment except ``held_out``; thresholds from inner out-of-fold scores."""
    train = training_units(units, recipe, held_out, drop_framework)
    feats = Features(recipe.features, recipe.drop_features)
    feats.fit_vocabulary([(u.uid, u.row, u.env) for u in train])
    rows = _expand(train, recipe, _weights(train, recipe))
    x = feats.matrix([(k, r) for k, r, _, _ in rows])
    y = np.array([u.label for _, _, u, _ in rows])
    w = np.array([wt for _, _, _, wt in rows])
    g = np.array([u.group for _, _, u, _ in rows])
    train_envs = sorted({u.env for u in train})

    # Inner out-of-fold scores: every benign unit of the training environments (including rows the
    # caps left out and lab infrastructure -- a deployment sees them) and the training attack rows.
    thr_units = [u for u in units if u.env in train_envs and u.label == 0]
    oof_units = thr_units + [u for u in train if u.label == 1]
    # Folds are assigned per class: GroupKFold fills the lightest fold first, so large benign host
    # groups would otherwise push every small attack group into one fold.
    fold_of: Dict[str, int] = {}
    for label in (0, 1):
        members = [gr for gr, (_, _, u, _) in zip(g.tolist(), rows) if u.label == label]
        members += [u.group for u in oof_units if u.label == label]
        arr = np.array(members)
        n_splits = min(N_INNER, len(set(members)))
        if n_splits < 2:
            fold_of.update({gr: 0 for gr in members})
            continue
        for k, (_, test_idx) in enumerate(GroupKFold(n_splits=n_splits).split(np.zeros(len(arr)), groups=arr)):
            for gr in set(arr[test_idx].tolist()):
                fold_of[gr] = k
    oof: Dict[str, float] = {}
    ox = feats.matrix([(u.uid, u.row) for u in oof_units])
    ofold = np.array([fold_of[u.group] for u in oof_units])
    rfold = np.array([fold_of[x_] for x_ in g.tolist()])
    for k in range(N_INNER):
        tr = np.where(rfold != k)[0]
        te = np.where(ofold == k)[0]
        if len(te) == 0:
            continue
        if len(set(y[tr].tolist())) < 2:
            raise ValueError(f"inner fold {k} trains on one class only: attack groups are too coarse")
        model = Model(recipe, feats).fit(x[tr], y[tr], w[tr], g[tr], refit=False)
        for i, s in zip(te.tolist(), model.score(ox[te]).tolist()):
            oof[oof_units[i].uid] = float(s)
    thresholds, per_env = _thresholds(recipe.thresholds, thr_units, oof, hours)
    final = Model(recipe, feats).fit(x, y, w, g, refit=True)
    return Fit(recipe, feats, final, thresholds, per_env, train_envs, oof, train)


def score_units(fit_: Fit, units: Sequence[Unit]) -> Dict[str, float]:
    if not units:
        return {}
    scores = fit_.model.score(fit_.feats.matrix([(u.uid, u.row) for u in units]))
    return {u.uid: float(s) for u, s in zip(units, scores.tolist())}


# ======================================================================= metrics


def poisson_ci(k: int, hours: float) -> List[Optional[float]]:
    if not hours:
        return [None, None]
    lo = chi2.ppf(0.025, 2 * k) / 2 if k > 0 else 0.0
    hi = chi2.ppf(0.975, 2 * k + 2) / 2
    return [round(lo / hours, 4), round(hi / hours, 4)]


def clopper_pearson(k: int, n: int) -> List[Optional[float]]:
    if n == 0:
        return [None, None]
    lo = 0.0 if k == 0 else float(beta.ppf(0.025, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(0.975, k + 1, n - k))
    return [round(lo, 4), round(hi, 4)]


def _example(u: Unit, score: float) -> Dict[str, Any]:
    return {"score": round(score, 3), "events": u.count, "parent": leaf(u.row.get("parent_image")),
            "image": leaf(u.row.get("image")), "command_line": (u.row.get("command_line") or "")[:140]}


def evaluate(env_units: Sequence[Unit], score: Dict[str, float], thresholds: Dict[str, float],
             hours: float, details: bool = True) -> Dict[str, Any]:
    benign = [u for u in env_units if u.label == 0]
    malicious = [u for u in env_units if u.label == 1 and not u.conflict]
    out: Dict[str, Any] = {"benign_units": len(benign), "benign_events": sum(u.count for u in benign),
                           "malicious_units": len(malicious), "observed_host_hours": round(hours, 2)}
    for name, t in thresholds.items():
        fp = sum(u.count for u in benign if score[u.uid] >= t)
        det = [score[u.uid] >= t for u in malicious]
        out[name] = {
            "threshold": round(float(t), 6), "fp_events": fp,
            "fp_per_host_hour": round(fp / hours, 4) if hours else None, "fp_ci95": poisson_ci(fp, hours),
            "recall_unique": round(sum(det) / len(det), 4) if det else None,
            "recall_unique_ci95": clopper_pearson(sum(det), len(det)),
            "recall_events": round(sum(u.count for u, d in zip(malicious, det) if d) / sum(u.count for u in malicious), 4)
            if malicious else None,
        }
    if benign and malicious:
        y = np.array([0] * len(benign) + [1] * len(malicious))
        s = np.array([score[u.uid] for u in benign + malicious])
        out["roc_auc"] = round(float(roc_auc_score(y, s)), 4)
        out["pauc_fpr_0.01"] = round(float(roc_auc_score(y, s, max_fpr=0.01)), 4)
    if details:
        out["top_benign"] = [_example(u, score[u.uid]) for u in sorted(benign, key=lambda u: -score[u.uid])[:12]]
        lowest = min(thresholds.values())
        out["missed_malicious"] = [_example(u, score[u.uid]) for u in sorted(malicious, key=lambda u: score[u.uid])
                                   if score[u.uid] < lowest][:12]
    return out


def evaluate_rules(env_units: Sequence[Unit], fired: Dict[str, bool], hours: float) -> Dict[str, Any]:
    benign = [u for u in env_units if u.label == 0]
    malicious = [u for u in env_units if u.label == 1 and not u.conflict]
    fp = sum(sum(1 for r in u.row_ids if fired.get(r)) for u in benign)
    det = [any(fired.get(r) for r in u.row_ids) for u in malicious]
    return {"fp_events": fp, "fp_per_host_hour": round(fp / hours, 4) if hours else None,
            "fp_ci95": poisson_ci(fp, hours),
            "recall_unique": round(sum(det) / len(det), 4) if det else None,
            "recall_unique_ci95": clopper_pearson(sum(det), len(det))}


def macro_paired(per_env: Dict[str, Tuple[List[str], List[bool], List[bool]]]) -> Dict[str, Any]:
    """Macro (over environments) recall difference, bootstrapping groups within each environment."""
    rng = np.random.default_rng(SEED)
    envs = sorted(e for e, (g, _, _) in per_env.items() if g)

    def recall(flags: List[bool]) -> float:
        return sum(flags) / len(flags) if flags else float("nan")

    point_a = [recall(per_env[e][1]) for e in envs]
    point_b = [recall(per_env[e][2]) for e in envs]
    by_group = {e: collections.defaultdict(list) for e in envs}
    for e in envs:
        for gr, a, b in zip(*per_env[e]):
            by_group[e][gr].append((a, b))
    diffs = []
    for _ in range(BOOTSTRAP):
        da, db = [], []
        for e in envs:
            groups = sorted(by_group[e])
            picked = rng.choice(len(groups), size=len(groups), replace=True)
            pairs = [p for i in picked for p in by_group[e][groups[i]]]
            da.append(recall([a for a, _ in pairs]))
            db.append(recall([b for _, b in pairs]))
        diffs.append(float(np.mean(da) - np.mean(db)))
    return {"model": round(float(np.mean(point_a)), 4), "baseline": round(float(np.mean(point_b)), 4),
            "diff": round(float(np.mean(point_a) - np.mean(point_b)), 4),
            "ci95": [round(float(np.percentile(diffs, 2.5)), 4), round(float(np.percentile(diffs, 97.5)), 4)],
            "environments": envs}


# ===================================================================== baselines


def rules_fired(raw: Sequence[Dict[str, Any]], repo: Path, cache: Path) -> Dict[str, bool]:
    """Whether any (non-incident) rule fires on each process start, replayed per recording; cached."""
    rules_hash = hashlib.sha256(b"".join(p.read_bytes() for p in sorted((repo / "rules").rglob("*.yaml")))).hexdigest()
    labelled = [r for r in raw if r.get("label") is not None]
    rows_hash = hashlib.sha256("\n".join(sorted(r["row_id"] for r in labelled)).encode()).hexdigest()
    if cache.exists():
        stored = json.loads(cache.read_text())
        if stored.get("rules_sha256") == rules_hash and stored.get("rows_sha256") == rows_hash:
            return stored["fired"]
    level = X.rules_scores(labelled, repo / "rules")
    fired = {k: v > 0 for k, v in sorted(level.items())}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"rules_sha256": rules_hash, "rows_sha256": rows_hash, "fired": fired}) + "\n")
    return fired


# ===================================================================== protocols


def run_recipe(units: Sequence[Unit], hours: Dict[str, float], recipe: Recipe, fired: Dict[str, bool],
               details: bool = True) -> Tuple[Dict[str, Any], Dict[str, Fit]]:
    by_env: Dict[str, List[Unit]] = collections.defaultdict(list)
    for u in units:
        by_env[u.env].append(u)
    heuristic = {u.uid: float(X.heuristic_score(u.row)) for u in units}
    folds: Dict[str, Any] = {}
    fits: Dict[str, Fit] = {}
    paired_rules: Dict[str, Tuple[List[str], List[bool], List[bool]]] = {}
    paired_heur: Dict[str, Tuple[List[str], List[bool], List[bool]]] = {}
    for env in ENVIRONMENTS:
        env_units = by_env.get(env, [])
        if not env_units:
            continue
        f = fit(units, hours, recipe, held_out=env)
        fits[env] = f
        scores = score_units(f, env_units)
        thr_units = [u for u in units if u.env in f.train_envs and u.label == 0]
        heur_t, _ = _thresholds(recipe.thresholds, thr_units, heuristic, hours)
        res = evaluate(env_units, scores, f.thresholds, hours.get(env, 0.0), details)
        res["thresholds_per_training_environment"] = f.per_env_thresholds
        res["heuristic"] = evaluate(env_units, heuristic, heur_t, hours.get(env, 0.0), details=False)
        res["rules_any_fired"] = evaluate_rules(env_units, fired, hours.get(env, 0.0))
        malicious = [u for u in env_units if u.label == 1 and not u.conflict]
        if malicious:
            groups = [u.group for u in malicious]
            model_flags = [scores[u.uid] >= f.thresholds["alert"] for u in malicious]
            paired_rules[env] = (groups, model_flags, [any(fired.get(r) for r in u.row_ids) for u in malicious])
            paired_heur[env] = (groups, model_flags, [heuristic[u.uid] >= heur_t["alert"] for u in malicious])
        folds[env] = res
    worst = max(folds, key=lambda e: folds[e]["alert"]["fp_per_host_hour"] or 0.0)
    s1_alert = all((folds[e]["alert"]["fp_per_host_hour"] or 0.0) <= BUDGETS["alert"] for e in folds)
    s1_high = all((folds[e]["high"]["fp_per_host_hour"] or 0.0) <= BUDGETS["high"]
                  for e in folds if folds[e]["observed_host_hours"] >= HIGH_BUDGET_MIN_HOURS)
    summary = {
        "worst_environment_alert": worst,
        "worst_fp_per_host_hour_alert": folds[worst]["alert"]["fp_per_host_hour"],
        "fp_per_host_hour_alert": {e: folds[e]["alert"]["fp_per_host_hour"] for e in folds},
        "fp_per_host_hour_high": {e: folds[e]["high"]["fp_per_host_hour"] for e in folds},
        "recall_unique_alert": {e: folds[e]["alert"]["recall_unique"] for e in folds
                                if folds[e]["alert"]["recall_unique"] is not None},
        "S1_alert_every_environment": s1_alert, "S1_high_where_powered": s1_high,
        "macro_recall_vs_rules": macro_paired(paired_rules),
        "macro_recall_vs_heuristic": macro_paired(paired_heur),
    }
    summary["macro_recall_alert"] = summary["macro_recall_vs_rules"]["model"]
    return {"recipe": recipe.__dict__, "folds": folds, "summary": summary}, fits


def compare_without_atlasv2(units: Sequence[Unit], with_res: Dict[str, Any], with_fits: Dict[str, Fit],
                            without_res: Dict[str, Any], without_fits: Dict[str, Fit]) -> Dict[str, Any]:
    """Same recipe with and without ATLASv2 in training, on every other held-out environment."""
    out: Dict[str, Any] = {}
    paired: Dict[str, Tuple[List[str], List[bool], List[bool]]] = {}
    for env in ENVIRONMENTS:
        if env == "atlasv2" or env not in with_res["folds"]:
            continue
        env_units = [u for u in units if u.env == env]
        sa, sb = score_units(with_fits[env], env_units), score_units(without_fits[env], env_units)
        ta, tb = with_fits[env].thresholds["alert"], without_fits[env].thresholds["alert"]
        benign = [u for u in env_units if u.label == 0]
        only_with = sum(u.count for u in benign if sa[u.uid] >= ta and sb[u.uid] < tb)
        only_without = sum(u.count for u in benign if sb[u.uid] >= tb and sa[u.uid] < ta)
        out[env] = {
            "fp_per_host_hour_alert": {"with": with_res["folds"][env]["alert"]["fp_per_host_hour"],
                                       "without": without_res["folds"][env]["alert"]["fp_per_host_hour"]},
            "fp_ci95_alert": {"with": with_res["folds"][env]["alert"]["fp_ci95"],
                              "without": without_res["folds"][env]["alert"]["fp_ci95"]},
            "fp_events_flagged_by_only_one": {"with": only_with, "without": only_without},
            "recall_unique_alert": {"with": with_res["folds"][env]["alert"]["recall_unique"],
                                    "without": without_res["folds"][env]["alert"]["recall_unique"]},
        }
        malicious = [u for u in env_units if u.label == 1 and not u.conflict]
        if malicious:
            paired[env] = ([u.group for u in malicious], [sa[u.uid] >= ta for u in malicious],
                           [sb[u.uid] >= tb for u in malicious])
    out["macro_recall_with_minus_without"] = macro_paired(paired)
    return out


def mutate(row: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Held-out evasions: none has special handling in featurizer v4 (tests/ml/test_featurizer_v4.py)."""
    event = json.loads(json.dumps(row["event"]))
    proc = event.setdefault("process", {})
    cmd = proc.get("command_line") or ""
    stem = (proc.get("name") or leaf(proc.get("executable")) or "").lower().removesuffix(".exe")
    target = stem if len(stem) >= 4 and stem in cmd.lower() else next(
        (w for w in re.findall(r"[A-Za-z]{4,}", cmd)), "")

    def inject(text: str, insert: str) -> str:
        i = text.lower().find(target.lower()) if target else -1
        return text if i < 0 else text[: i + 2] + insert + text[i + 2:]

    if kind == "quote_split":
        proc["command_line"] = inject(cmd, '""')
    elif kind == "envvar_substring":
        proc["command_line"] = inject(cmd, "%LOCALAPPDATA:~0,0%")
    elif kind == "short_path":
        out = re.sub(r"(?i)c:\\program files \(x86\)", r"C:\\PROGRA~2", cmd)
        out = re.sub(r"(?i)c:\\program files", r"C:\\PROGRA~1", out)
        proc["command_line"] = re.sub(r"(?i)(c:\\users\\)([^\\\s\"']{1,6})[^\\\s\"']*", r"\1\2~1", out)
    elif kind == "unicode_dash":
        proc["command_line"] = re.sub(r"(\s)-(?=[A-Za-z])", "\\1\u2013", cmd)
    elif kind == "flag_prefix":
        out = re.sub(r"(?i)(\s)[-/](?:e|ec|enc|encodedcommand)(\s)", r"\1-encodedcomm\2", cmd)
        out = re.sub(r"(?i)(\s)[-/]nop(?:rofile)?\b", r"\1-noprof", out)
        out = re.sub(r"(?i)(\s)[-/]w(?:indowstyle)?(\s+h)", r"\1-windowst\2", out)
        proc["command_line"] = re.sub(r"(?i)(\s)[-/](?:ep|ex|exec|executionpolicy)(\s+bypass)", r"\1-executionp\2", out)
    elif kind == "renamed_copy":
        old = proc.get("name") or ""
        proc["name"] = "updater.exe"
        proc["executable"] = "C:\\ProgramData\\updater.exe"
        proc["command_line"] = re.sub(re.escape(old), "updater.exe", cmd, flags=re.I) if old else cmd
    return {**row, "event": event}


def robustness(units: Sequence[Unit], fits: Dict[str, Fit]) -> Dict[str, Any]:
    """S5: recall drop under each held-out mutation, on the attack rows it changes (LOEO folds)."""
    out: Dict[str, Any] = {}
    for kind in MUTATIONS:
        base_hits = mut_hits = changed = 0
        for env, f in sorted(fits.items()):
            malicious = [u for u in units if u.env == env and u.label == 1 and not u.conflict]
            pairs = [(u, mutate(u.row, kind)) for u in malicious]
            pairs = [(u, m) for u, m in pairs if m["event"] != u.row["event"]]
            if not pairs:
                continue
            base = f.model.score(f.feats.matrix([(u.uid, u.row) for u, _ in pairs]))
            mut = f.model.score(f.feats.matrix([(None, m) for _, m in pairs]))
            t = f.thresholds["alert"]
            base_hits += int((base >= t).sum())
            mut_hits += int((mut >= t).sum())
            changed += len(pairs)
        drop = (base_hits - mut_hits) / changed if changed else None
        out[kind] = {"changed_rows": changed, "recall_before": round(base_hits / changed, 4) if changed else None,
                     "recall_after": round(mut_hits / changed, 4) if changed else None,
                     "drop": round(drop, 4) if drop is not None else None,
                     "passes": drop is None or drop <= 0.10}
    return out


def framework_holdout(units: Sequence[Unit], hours: Dict[str, float], recipe: Recipe,
                      all_fit: Fit) -> Dict[str, Any]:
    """S3: leave-one-framework-out vs leave-one-technique-out (inner out-of-fold) recall at alert."""
    malicious = [u for u in units if u.label == 1 and not u.conflict and not u.infra
                 and u.env not in recipe.exclude_train]
    counts = collections.Counter(u.framework for u in malicious)
    frameworks = sorted(fw for fw, n in counts.items() if n >= MIN_FRAMEWORK_UNITS)
    t_all = all_fit.thresholds["alert"]
    loto, lofo = {}, {}
    for fw in frameworks:
        members = [u for u in malicious if u.framework == fw]
        in_oof = [u for u in members if u.uid in all_fit.oof]
        loto[fw] = round(sum(all_fit.oof[u.uid] >= t_all for u in in_oof) / len(in_oof), 4) if in_oof else None
        f = fit(units, hours, recipe, held_out=None, drop_framework=fw)
        scored = in_oof or members  # the same rows as leave-one-technique-out, for a like-for-like comparison
        s = score_units(f, scored)
        lofo[fw] = round(sum(s[u.uid] >= f.thresholds["alert"] for u in scored) / len(scored), 4)
    macro_loto = float(np.mean([v for v in loto.values() if v is not None])) if loto else None
    macro_lofo = float(np.mean(list(lofo.values()))) if lofo else None
    return {"frameworks": {fw: {"units": counts[fw], "leave_technique_out": loto[fw],
                                "leave_framework_out": lofo[fw]} for fw in frameworks},
            "macro_leave_technique_out": macro_loto, "macro_leave_framework_out": macro_lofo,
            "passes": macro_loto is not None and macro_lofo is not None and macro_lofo >= macro_loto - 0.15}


def environment_probe(units: Sequence[Unit], recipe: Recipe, all_fit: Fit) -> Dict[str, Any]:
    """S4: can the features tell benign environments apart? And are top features single-environment?"""
    benign = [u for u in all_fit.train_units if u.label == 0]
    feats = all_fit.feats
    x = feats.matrix([(u.uid, u.row) for u in benign])
    envs = sorted({u.env for u in benign})
    env_arr = np.array([u.env for u in benign])
    params = {**X.BASE_PARAMS, **dict(recipe.params)} if recipe.model == "lgb" else {**X.BASE_PARAMS}
    auc = {}
    for env in envs:
        y = (env_arr == env).astype(int)
        oof = np.zeros(len(y))
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=SEED % 2**31).split(np.zeros(len(y)), y):
            b = lgb.train(params, lgb.Dataset(x[tr], label=y[tr], feature_name=feats.names), num_boost_round=200)
            oof[te] = b.predict(x[te], raw_score=True)
        auc[env] = round(float(roc_auc_score(y, oof)), 4)
    macro = float(np.mean(list(auc.values())))
    imp = all_fit.model.importance()
    train_x = feats.matrix([(u.uid, u.row) for u in all_fit.train_units])
    train_env = np.array([u.env for u in all_fit.train_units])
    top = []
    for i in np.argsort(-imp)[:30]:
        if imp[i] <= 0:
            break
        present = sorted({str(e) for e in train_env[train_x[:, int(i)].nonzero()[0]].tolist()})
        name = feats.names[int(i)]
        if name.startswith("tok"):
            name = f"{name}:{sorted(feats.vocabulary, key=feats.vocabulary.get)[int(name[3:])]}"
        top.append({"feature": name, "importance": round(float(imp[i]), 3), "environments": present})
    single = [t for t in top if len(t["environments"]) <= 1]
    return {"benign_environment_auc": auc, "macro_auc": round(macro, 4), "top_features": top,
            "single_environment_top_features": single, "passes": macro <= 0.70 and not single}


# ========================================================================== export


def export(out: Path, f: Fit, units: Sequence[Unit], repo: Path, data: Path,
           hours: Dict[str, float]) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    dump = f.model.dump()
    (out / "model.json").write_text(json.dumps(dump, sort_keys=True) + "\n", encoding="utf-8")
    spec = {**F4.feature_spec(), "recipe": f.recipe.__dict__, "dropped_features": list(f.recipe.drop_features),
            "vocabulary": sorted(f.feats.vocabulary, key=f.feats.vocabulary.get) if f.feats.vocabulary else []}
    (out / "features.json").write_text(json.dumps(spec, indent=1) + "\n", encoding="utf-8")
    (out / "thresholds.json").write_text(json.dumps(
        {"raw_score": f.thresholds, "policy": f.recipe.thresholds, "budgets_fp_per_host_hour": BUDGETS,
         "per_training_environment": f.per_env_thresholds,
         "observed_host_hours": {e: round(h, 2) for e, h in hours.items()}}, indent=2) + "\n", encoding="utf-8")
    labelled = [(f.oof[u.uid], 1 if u.label == 1 else 0) for u in units if u.uid in f.oof]
    calib = LogisticRegression(C=1e6, max_iter=1000).fit(np.array([[s] for s, _ in labelled]),
                                                         np.array([y for _, y in labelled]))
    (out / "calibration.json").write_text(json.dumps(
        {"method": "platt", "a": float(calib.coef_[0][0]), "b": float(calib.intercept_[0]),
         "note": "fitted at training prevalence; not a deployment probability"}, indent=2) + "\n", encoding="utf-8")
    golden_units = sorted(f.train_units, key=lambda u: hashlib.sha256(u.uid.encode()).hexdigest())[:50]
    vectors = [f.feats.vector(u.uid, u.row) for u in golden_units]
    raw = f.model.score(f.feats.matrix([(u.uid, u.row) for u in golden_units]))
    golden = [{"uid": u.uid, "vector": {str(k): v for k, v in vec.items()}, "raw_score": float(s)}
              for u, vec, s in zip(golden_units, vectors, raw.tolist())]
    (out / "golden.json").write_text(json.dumps(golden, indent=1) + "\n", encoding="utf-8")
    served = load_model(dump)
    worst = max(abs(served.raw_score(vec) - s) for vec, s in zip(vectors, raw.tolist()))
    files = {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
             for name in ("model.json", "features.json", "thresholds.json", "calibration.json", "golden.json")}
    pins = repo / "tools" / "train" / "pins.json"
    manifest = {
        "model_id": "panopticon-process-start", "recipe": f.recipe.name, "model_type": f.recipe.model,
        "featurizer_version": F4.FEATURIZER_VERSION if f.recipe.features != "v3" else 3,
        "engine_git_sha": X.git_sha(repo), "golden_max_abs_error": float(worst), "rounds": f.model.rounds,
        "training_environments": f.train_envs, "training_units": len(f.train_units),
        "versions": {"lightgbm": lgb.__version__, "scikit_learn": sklearn.__version__, "numpy": np.__version__,
                     "python": platform.python_version()},
        "pins_sha256": hashlib.sha256(pins.read_bytes()).hexdigest() if pins.exists() else None,
        "rows_sha256": {s: hashlib.sha256((data / "rows" / f"{s}.jsonl.gz").read_bytes()).hexdigest()
                        for s in SOURCES if (data / "rows" / f"{s}.jsonl.gz").exists()},
        "final_candidate": False, "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


# ========================================================================= drivers


def load(data: Path, repo: Path) -> Tuple[List[Unit], Dict[str, float], Dict[str, bool], Dict[str, Any]]:
    raw = X.labelled_raw(data / "rows", [s for s in SOURCES if (data / "rows" / f"{s}.jsonl.gz").exists()])
    units, info = build_units(raw)
    hours = hours_by_environment(raw)
    fired = rules_fired(raw, repo, data / "experiment" / "rules_cache.json")
    info["observed_host_hours"] = {e: round(h, 2) for e, h in hours.items()}
    return units, hours, fired, info


def _protocol(info: Dict[str, Any]) -> Dict[str, Any]:
    return {"environments": ENVIRONMENT_OF_SOURCE, "budgets_fp_per_host_hour": BUDGETS, "criteria": CRITERIA,
            "candidates": list(CANDIDATES), "selection_rule": SELECTION_RULE, "decision_rule": DECISION_RULE,
            "parent_missing_rate": PARENT_MISSING_RATE, "token_min_environments": TOKEN_MIN_ENVIRONMENTS,
            "mutations": list(MUTATIONS), "seed": SEED, "data": info}


def run_loeo(data: Path, repo: Path, names: Sequence[str]) -> Dict[str, Any]:
    units, hours, fired, info = load(data, repo)
    out: Dict[str, Any] = {"protocol": _protocol(info), "recipes": {}}
    for name in names:
        out["recipes"][name], _ = run_recipe(units, hours, RECIPES[name], fired)
    return X.jsonable(out)


def select(results: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    passing = [n for n in CANDIDATES if results[n]["summary"]["S1_alert_every_environment"]]
    if passing:
        best = max(passing, key=lambda n: (results[n]["summary"]["macro_recall_alert"], -CANDIDATES.index(n)))
        return best, f"meets S1 at alert in every environment; highest macro recall among {passing}"
    best = min(CANDIDATES, key=lambda n: (results[n]["summary"]["worst_fp_per_host_hour_alert"], CANDIDATES.index(n)))
    return best, "no candidate meets S1 at alert; lowest worst-environment FP/host-hour"


def run_v7(data: Path, repo: Path, version: str) -> Dict[str, Any]:
    units, hours, fired, info = load(data, repo)
    out: Dict[str, Any] = {"protocol": _protocol(info), "recipes": {}}
    fits: Dict[str, Dict[str, Fit]] = {}
    for name in ("v6_recipe", *CANDIDATES):
        out["recipes"][name], fits[name] = run_recipe(units, hours, RECIPES[name], fired)
    chosen, why = select(out["recipes"])
    recipe = RECIPES[chosen]
    out["selection"] = {"selected": chosen, "reason": why}
    twin = without_atlasv2(recipe)
    out["recipes"][twin.name], twin_fits = run_recipe(units, hours, twin, fired, details=False)
    out["atlasv2_in_training"] = compare_without_atlasv2(units, out["recipes"][chosen], fits[chosen],
                                                         out["recipes"][twin.name], twin_fits)
    all_fit = fit(units, hours, recipe, held_out=None)
    summary = out["recipes"][chosen]["summary"]
    s3 = framework_holdout(units, hours, recipe, all_fit)
    s4 = environment_probe(units, recipe, all_fit)
    s5 = robustness(units, fits[chosen])
    manifest = export(data / "models" / version, all_fit, units, repo, data, hours)
    out["criteria"] = {
        "S1": {"passes": summary["S1_alert_every_environment"] and summary["S1_high_where_powered"],
               "alert_every_environment": summary["S1_alert_every_environment"],
               "high_where_powered": summary["S1_high_where_powered"],
               "fp_per_host_hour_alert": summary["fp_per_host_hour_alert"],
               "fp_per_host_hour_high": summary["fp_per_host_hour_high"]},
        "S2": {"passes": (summary["macro_recall_vs_rules"]["ci95"][0] > 0
                          and summary["macro_recall_vs_heuristic"]["ci95"][0] > -0.05),
               "vs_rules": summary["macro_recall_vs_rules"], "vs_heuristic": summary["macro_recall_vs_heuristic"]},
        "S3": s3, "S4": s4, "S5": {"passes": all(v["passes"] for v in s5.values()), "families": s5},
        "S6": {"passes": None, "golden_max_abs_error": manifest["golden_max_abs_error"],
               "note": "bit-identical rebuild checked by `pdtrain v7 --final-only` (see EVAL_REPORT)"},
    }
    out["export"] = manifest
    return X.jsonable(out)


def final_only(data: Path, repo: Path, version: str, recipe_name: str) -> Dict[str, Any]:
    units, hours, _fired, _info = load(data, repo)
    all_fit = fit(units, hours, RECIPES[recipe_name], held_out=None)
    return X.jsonable(export(data / "models" / version, all_fit, units, repo, data, hours))
