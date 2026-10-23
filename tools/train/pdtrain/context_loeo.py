"""Context model (L1) decision run: leave-one-environment-out on replayed process incarnations.

Pre-registered (training-plan D25) and committed before any context model was trained:
the admission rule (:data:`ADMISSION`), the two candidates (:data:`CANDIDATES`), the
baselines, the criteria (:data:`CRITERIA`), the selection and the decision rules.

Unit of evaluation: a process incarnation whose start was observed in a replay
(``pdtrain.replay``) and joined to a labelled process-start row on (environment,
host, pid, start time). Its score is the maximum over its checkpoints (start, each
new behaviour bit, stop); it alerts at most once. A benign false positive is one
benign process that crossed the threshold; rates are per observed host-hour of the
held-out environment (replay census, monitored hosts only).

Thresholds: for each training environment, the lowest threshold that keeps its own
benign processes within budget (inner out-of-fold scores); the strictest wins
(minimax), as in run v7.

Availability: a telemetry family missing on a host makes its feature group NaN
(``ml.context_featurizer``). Training adds masked copies of rows, from both classes,
at the rate each kind of missingness occurs in benign training hours, so missing
telemetry carries no information about the label.
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import json
import platform
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np
import sklearn
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedKFold

from panopticon_detection.enrichment import classify_path
from panopticon_detection.features import ProcessFeatures
from panopticon_detection.ml import context_featurizer as CF
from panopticon_detection.ml import featurizer as F4
from panopticon_detection.ml.scorer import load_model
from pdtrain import experiment as X
from pdtrain import loeo as L
from pdtrain.label import leaf

CONTEXT_EVAL_VERSION = 1
ENVIRONMENTS = L.ENVIRONMENTS
SOURCES = L.SOURCES
BENIGN_ONLY_ENVIRONMENTS = ("optc", "officer_vm")
BUDGETS = X.BUDGETS
SEED = X.SEED
N_INNER = 5
MALICIOUS_GROUP_CAP = 300
BENIGN_IMAGE_CAP = 50
HIGH_BUDGET_MIN_HOURS = 20.0
MUTATIONS = L.MUTATIONS
_NON_RULE_ALERTS = ("PROV-CAMPAIGN", "CORR-RISK", "RISK", "BHV-", "CORR-STORY")

#: A family group enters the model only if its family is collected on hosts covering
#: >= `coverage` of the observed host-hours of >= 1 benign-only environment with
#: >= `benign_min_hours` hours, and of >= `attack_min_envs` environments with attacks.
ADMISSION = {"coverage": 0.5, "benign_min_hours": 100.0, "attack_min_envs": 2}

_SHALLOW = {"num_leaves": 15, "max_depth": 4, "min_data_in_leaf": 50}
CANDIDATES: Dict[str, Dict[str, Any]] = {
    "ctx_lgb": {"params": _SHALLOW, "groups": "admitted"},
    "ctx_lgb_wide": {"params": {"num_leaves": 31, "max_depth": -1, "min_data_in_leaf": 20}, "groups": "admitted"},
}
#: Same-fold models that are a baseline (B2) or an ablation (C5), not candidates.
REFERENCE_MODELS: Dict[str, Dict[str, Any]] = {
    "B2_start_only": {"params": _SHALLOW, "groups": ("start",)},
    "C5_start_lineage_children": {"params": _SHALLOW, "groups": ("start", "lineage", "children")},
}

CRITERIA = {
    "C1": "<= 1.0 FP/host-hour at alert in every held-out environment; <= 0.1 at high where >= 20 h",
    "C2": "macro recall at alert: L1 - B2 (start-only, the v6/v7 ingredients) >= +0.15 with paired 95% CI "
          "lower bound > 0; L1 - B1 (rules, full replay) CI lower bound > -0.05",
    "C3": "macro partial AUC (FPR <= 1%) over environments with attacks >= 0.75; BOTSv1 >= 0.65",
    "C4": "benign-environment predictability macro AUC <= 0.70; no single group alone > 0.80; the "
          "availability pattern alone predicts the label with AUC <= 0.55",
    "C5": "start+lineage+children only: FP/host-hour <= B2's + 0.2 in every environment",
    "C6": "median time to detect (start -> first checkpoint over alert) <= 120 s",
    "C7": "bit-identical rebuild; golden parity <= 1e-9 including NaN vectors",
    "C8": "each held-out mutation family, and losing any one admitted family group at test time, "
          "costs <= 0.10 recall",
}
SELECTION_RULE = ("candidates meeting C1's alert condition in every environment: highest macro recall wins; "
                  "otherwise the lowest worst-environment FP/host-hour wins (and C1 fails)")
DECISION_RULE = ("L1 enters the engine (shadow mode, behind a flag) only if C1-C8 pass. Kill rule: if C1 or C2 "
                 "fails, L1 is not shipped and L3 runs on rules plus rarity only")


# ======================================================================== data


@dataclass
class Proc:
    """One observed-start process incarnation from a replay, joined to its label."""

    uid: str
    env: str
    unit: str
    host: str
    label: int
    row: Dict[str, Any]
    start_ts: str
    start_vector: Dict[int, float]
    families: frozenset
    checkpoints: List[Tuple[str, str, Dict[str, Any]]] = field(default_factory=list)
    rule_alert_ts: Optional[str] = None
    group: str = ""
    framework: Optional[str] = None
    infra: bool = False
    conflict: bool = False  # read by loeo._merge_templates


def _rule_alert(rule_id: str) -> bool:
    return not rule_id.startswith(_NON_RULE_ALERTS)


def load_replays(data: Path) -> Tuple[List[Proc], Dict[str, Any]]:
    labelled = X.labelled_raw(data / "rows", [s for s in SOURCES if (data / "rows" / f"{s}.jsonl.gz").exists()])
    by_key: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
    for row in labelled:
        if row.get("label") is not None and row.get("pid") is not None:
            by_key[(L.environment(row), row.get("host") or "", int(row["pid"]), row["utc"])] = row
    procs: List[Proc] = []
    stats: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    host_hours: Dict[Tuple[str, str], float] = collections.defaultdict(float)
    for path in sorted((data / "replay").glob("*/*.jsonl.gz")):
        starts: Dict[str, Dict[str, Any]] = {}
        cps: Dict[str, List[Tuple[str, str, Dict[str, Any]]]] = collections.defaultdict(list)
        first_alert: Dict[str, str] = {}
        summary: Dict[str, Any] = {}
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for line in handle:
                rec = json.loads(line)
                kind = rec["t"]
                if kind == "unit":
                    summary = rec
                elif kind == "start":
                    starts[rec["node"]] = rec
                elif kind == "cp":
                    cps[rec["node"]].append((rec["kind"], rec["ts"], rec["features"]))
                elif kind == "alert" and rec.get("node") and _rule_alert(rec["rule_id"]):
                    ts = rec.get("ts") or ""
                    if rec["node"] not in first_alert or ts < first_alert[rec["node"]]:
                        first_alert[rec["node"]] = ts
        if not summary or summary.get("error"):
            continue
        env = summary["env"]
        families = {}
        for h, info in summary["hosts"].items():
            families[h] = frozenset(f for f, n in info["families"].items() if n and f in CF.FAMILY_GROUPS)
            if info["families"].get("process"):
                host_hours[(env, h)] += info["hours"]
        for node, start in starts.items():
            stats[env]["starts"] += 1
            row = by_key.get((env, start["host"], int(start["pid"]), start["ts"]))
            if row is None:
                stats[env]["unjoined"] += 1
                continue
            stats[env][f"label_{row['label']}"] += 1
            procs.append(Proc(
                uid=hashlib.sha256(f"{summary['unit']}|{node}".encode()).hexdigest()[:20], env=env,
                unit=summary["unit"], host=start["host"], label=int(row["label"]), row=row, start_ts=start["ts"],
                start_vector={int(k): v for k, v in start["start_vector"].items()},
                families=families.get(start["host"], frozenset()), checkpoints=cps.get(node, []),
                rule_alert_ts=first_alert.get(node),
                group=(L._scenario_group(row) if row["source"] == "atlasv2" and row["label"] == 1
                       else row.get("group") or f"{env}:{start['host']}"),
                framework=L.framework(row) if row["label"] == 1 else None,
                infra=X.is_lab_infrastructure(row)))
    procs = [p for p in procs if p.checkpoints]
    merged = L._merge_templates(procs)
    info = {"join": {e: dict(c) for e, c in sorted(stats.items())}, "malicious_groups_merged_by_template": merged,
            "processes": dict(collections.Counter(f"{p.env} {p.label}" for p in procs))}
    return procs, {"info": info, "host_hours": dict(host_hours)}


def census(data: Path) -> Dict[str, Any]:
    return json.loads((data / "replay" / "census.json").read_text())


def admitted_groups(cen: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    """The admission rule, applied to the replay census (no labels, no scores)."""
    attack_envs = [e for e in ENVIRONMENTS if e not in BENIGN_ONLY_ENVIRONMENTS and e in cen]
    decision: Dict[str, Any] = {}
    groups = list(CF.CORE_GROUPS)
    for group in CF.FAMILY_GROUPS:
        coverage = {e: (cen[e]["hours_with_family"].get(group, 0.0) / cen[e]["host_hours"])
                    if cen[e]["host_hours"] else 0.0 for e in cen}
        benign_ok = [e for e in BENIGN_ONLY_ENVIRONMENTS if e in cen
                     and cen[e]["host_hours"] >= ADMISSION["benign_min_hours"] and coverage[e] >= ADMISSION["coverage"]]
        attack_ok = [e for e in attack_envs if coverage[e] >= ADMISSION["coverage"]]
        ok = bool(benign_ok) and len(attack_ok) >= ADMISSION["attack_min_envs"]
        decision[group] = {"coverage": {e: round(v, 3) for e, v in coverage.items()},
                           "benign_only_envs": benign_ok, "attack_envs": attack_ok, "admitted": ok}
        if ok:
            groups.append(group)
    return groups, decision


# ================================================================== vectors


def _vectors(proc: Proc, groups: Sequence[str], mask: Iterable[str] = ()) -> List[Dict[int, float]]:
    available = set(proc.families) - set(mask)
    return [CF.vectorize(ProcessFeatures.from_dict(feats), proc.start_vector, available=available, groups=groups)
            for _kind, _ts, feats in proc.checkpoints]


def _csr(vectors: Sequence[Dict[int, float]]) -> sparse.csr_matrix:
    data: List[float] = []
    indices: List[int] = []
    indptr = [0]
    for v in vectors:
        for i, x in v.items():
            indices.append(i)
            data.append(x)
        indptr.append(len(indices))
    return sparse.csr_matrix((np.array(data, dtype=np.float64), np.array(indices, dtype=np.int64),
                              np.array(indptr)), shape=(len(vectors), len(CF.FEATURE_NAMES)))


class Matrix:
    """Every checkpoint of every process, vectorised once for one group configuration."""

    def __init__(self, procs: Sequence[Proc], groups: Sequence[str]) -> None:
        self.groups = list(groups)
        vectors: List[Dict[int, float]] = []
        self.rows: Dict[str, Tuple[int, int]] = {}
        for p in procs:
            start = len(vectors)
            vectors.extend(_vectors(p, groups))
            self.rows[p.uid] = (start, len(vectors))
        self.x = _csr(vectors)

    def rows_of(self, procs: Sequence[Proc]) -> Tuple[np.ndarray, List[str]]:
        idx: List[int] = []
        owners: List[str] = []
        for p in procs:
            a, b = self.rows[p.uid]
            idx.extend(range(a, b))
            owners.extend([p.uid] * (b - a))
        return np.array(idx, dtype=np.int64), owners


# ================================================================== training


def _capped(procs: Sequence[Proc]) -> List[Proc]:
    mal: Dict[str, List[Proc]] = collections.defaultdict(list)
    ben: Dict[str, List[Proc]] = collections.defaultdict(list)
    for p in procs:
        (mal[p.group] if p.label == 1 else ben[f"{p.env}|{leaf(p.row.get('image'))}"]).append(p)
    out: List[Proc] = []
    for bucket, cap in ((mal, MALICIOUS_GROUP_CAP), (ben, BENIGN_IMAGE_CAP)):
        for _, members in sorted(bucket.items()):
            out.extend(sorted(members, key=lambda p: p.uid)[:cap])
    return sorted(out, key=lambda p: p.uid)


def _missing_rates(procs: Sequence[Proc], hours_of_host: Dict[Tuple[str, str], float],
                   family_groups: Sequence[str]) -> Tuple[float, Dict[str, float]]:
    """Share of benign training host-hours with no admitted family, and with each one missing."""
    hosts: Dict[Tuple[str, str], frozenset] = {}
    for p in procs:
        if p.label == 0:
            hosts[(p.env, p.host)] = p.families
    total = sum(hours_of_host.get(k, 0.0) for k in hosts) or 1.0
    fam = set(family_groups)
    none = sum(hours_of_host.get(k, 0.0) for k, f in hosts.items() if not (f & fam)) / total
    each = {g: sum(hours_of_host.get(k, 0.0) for k, f in hosts.items() if (f & fam) and g not in f) / total
            for g in family_groups}
    return none, each


def training_set(procs: Sequence[Proc], groups: Sequence[str], rates: Tuple[float, Dict[str, float]],
                 matrix: Matrix):
    """Checkpoint rows with environment-balanced weights and matched-rate masked copies."""
    family_groups = [g for g in groups if g in CF.FAMILY_GROUPS]
    benign = [p for p in procs if p.label == 0]
    malicious = [p for p in procs if p.label == 1]
    per_env = collections.Counter(p.env for p in benign)
    share = len(benign) / max(1, len(per_env))
    weight = {p.uid: share / per_env[p.env] for p in benign}
    scale = len(benign) / max(1, len(malicious))
    weight.update({p.uid: scale for p in malicious})
    none_rate, each_rate = rates
    blocks: List[sparse.csr_matrix] = []
    labels: List[int] = []
    weights: List[float] = []
    group_ids: List[str] = []
    base_idx, base_w, base_y, base_g = [], [], [], []
    extra: List[Dict[int, float]] = []
    for p in procs:
        available = [g for g in family_groups if g in p.families]
        copies: List[Tuple[Tuple[str, ...], float]] = [((), 1.0)]
        if available:
            masked = {tuple(available): none_rate, **{(g,): each_rate.get(g, 0.0) for g in available}}
            masked = {k: v for k, v in masked.items() if v > 0}
            keep = max(0.2, 1.0 - sum(masked.values()))
            total = keep + sum(masked.values())
            copies = [((), keep / total)] + [(k, v / total) for k, v in masked.items()]
        a, b = matrix.rows[p.uid]
        per_cp = weight[p.uid] / max(1, b - a)
        for mask, fraction in copies:
            if not mask:
                base_idx.extend(range(a, b))
                base_w.extend([per_cp * fraction] * (b - a))
                base_y.extend([p.label] * (b - a))
                base_g.extend([p.group] * (b - a))
            else:
                for v in _vectors(p, groups, mask):
                    extra.append(v)
                    labels.append(p.label)
                    weights.append(per_cp * fraction)
                    group_ids.append(p.group)
    blocks.append(matrix.x[np.array(base_idx, dtype=np.int64)])
    if extra:
        blocks.append(_csr(extra))
    x = sparse.vstack(blocks).tocsr()
    return (x, np.array(base_y + labels), np.array(base_w + weights), np.array(base_g + group_ids))


def _params(params: Dict[str, Any], groups: Sequence[str]) -> Dict[str, Any]:
    monotone = set(CF.MONOTONE_FEATURES)
    return {**X.BASE_PARAMS, **params,
            "monotone_constraints": [1 if (n in monotone and CF.GROUP_OF[n] in groups) else 0
                                     for n in CF.FEATURE_NAMES]}


def train(x, y, w, g, params: Dict[str, Any], groups: Sequence[str], refit: bool):
    tr, va = X._inner_split(g, y)
    full = _params(params, groups)
    train_set = lgb.Dataset(x[tr], label=y[tr], weight=w[tr], free_raw_data=False)
    valid_set = lgb.Dataset(x[va], label=y[va], weight=w[va], reference=train_set)
    booster = lgb.train(full, train_set, num_boost_round=1000, valid_sets=[valid_set],
                        callbacks=[lgb.early_stopping(50, verbose=False)])
    rounds = max(1, int(booster.best_iteration or booster.current_iteration()))
    if refit:
        booster = lgb.train(full, lgb.Dataset(x, label=y, weight=w), num_boost_round=rounds)
    return booster, rounds


def scores_of(booster, rounds: int, matrix: Matrix, procs: Sequence[Proc],
              x_override: Optional[sparse.csr_matrix] = None) -> Dict[str, Tuple[float, List[float]]]:
    """uid -> (max over checkpoints, per-checkpoint scores)."""
    if not procs:
        return {}
    if x_override is None:
        idx, owners = matrix.rows_of(procs)
        x = matrix.x[idx]
    else:
        x, owners = x_override, [p.uid for p in procs for _ in p.checkpoints]
    raw = booster.predict(x, raw_score=True, num_iteration=rounds)
    out: Dict[str, List[float]] = collections.defaultdict(list)
    for uid, s in zip(owners, raw.tolist()):
        out[uid].append(float(s))
    return {uid: (max(s), s) for uid, s in out.items()}


@dataclass
class FoldModel:
    booster: Any
    rounds: int
    groups: List[str]
    thresholds: Dict[str, float]
    per_env: Dict[str, Dict[str, float]]
    train_procs: List[Proc]


def fit_fold(procs: Sequence[Proc], hours: Dict[str, float], hours_of_host: Dict[Tuple[str, str], float],
             held_out: Optional[str], spec: Dict[str, Any], matrix: Matrix) -> FoldModel:
    groups = matrix.groups
    pool = [p for p in procs if p.env != held_out]
    train_procs = _capped([p for p in pool if not p.infra])
    rates = _missing_rates(train_procs, hours_of_host, [g for g in groups if g in CF.FAMILY_GROUPS])
    benign_all = [p for p in pool if p.label == 0]
    fold_of: Dict[str, int] = {}
    for label in (0, 1):
        members = [p.group for p in train_procs if p.label == label]
        if label == 0:
            members += [p.group for p in benign_all]
        arr = np.array(members)
        n_splits = min(N_INNER, len(set(members)))
        if n_splits < 2:
            fold_of.update({gr: 0 for gr in members})
            continue
        for k, (_, idx) in enumerate(GroupKFold(n_splits=n_splits).split(np.zeros(len(arr)), groups=arr)):
            for gr in set(arr[idx].tolist()):
                fold_of[gr] = k
    oof: Dict[str, float] = {}
    for k in range(N_INNER):
        tr = [p for p in train_procs if fold_of[p.group] != k]
        te = [p for p in benign_all if fold_of[p.group] == k]
        if not te or len({p.label for p in tr}) < 2:
            continue
        x, y, w, g = training_set(tr, groups, rates, matrix)
        booster, rounds = train(x, y, w, g, spec["params"], groups, refit=False)
        for uid, (s, _) in scores_of(booster, rounds, matrix, te).items():
            oof[uid] = s
    per_env: Dict[str, Dict[str, float]] = {}
    for env in sorted({p.env for p in benign_all}):
        s = np.array([oof[p.uid] for p in benign_all if p.env == env and p.uid in oof])
        if len(s) and hours.get(env):
            per_env[env] = {n: X.threshold_for_budget(s, np.ones(len(s)), hours[env], b) for n, b in BUDGETS.items()}
    thresholds = {n: max(t[n] for t in per_env.values()) for n in BUDGETS}
    x, y, w, g = training_set(train_procs, groups, rates, matrix)
    booster, rounds = train(x, y, w, g, spec["params"], groups, refit=True)
    return FoldModel(booster, rounds, list(groups), thresholds, per_env, train_procs)


# ================================================================== metrics


def evaluate(procs: Sequence[Proc], score: Dict[str, float], thresholds: Dict[str, float], hours: float,
             ttd: Optional[Dict[str, Optional[float]]] = None) -> Dict[str, Any]:
    benign = [p for p in procs if p.label == 0]
    malicious = [p for p in procs if p.label == 1]
    out: Dict[str, Any] = {"benign": len(benign), "malicious": len(malicious), "host_hours": round(hours, 2)}
    for name, t in thresholds.items():
        fp = sum(1 for p in benign if score[p.uid] >= t)
        det = [score[p.uid] >= t for p in malicious]
        out[name] = {"threshold": round(float(t), 6), "fp": fp,
                     "fp_per_host_hour": round(fp / hours, 4) if hours else None, "fp_ci95": L.poisson_ci(fp, hours),
                     "recall": round(sum(det) / len(det), 4) if det else None,
                     "recall_ci95": L.clopper_pearson(sum(det), len(det))}
    if benign and malicious:
        y = np.array([0] * len(benign) + [1] * len(malicious))
        s = np.array([score[p.uid] for p in benign + malicious])
        out["roc_auc"] = round(float(roc_auc_score(y, s)), 4)
        out["pauc_fpr_0.01"] = round(float(roc_auc_score(y, s, max_fpr=0.01)), 4)
    if ttd is not None:
        delays = [d for p in malicious if (d := ttd.get(p.uid)) is not None]
        out["time_to_detect_s"] = {"n": len(delays), "median": float(np.median(delays)) if delays else None,
                                   "p90": float(np.percentile(delays, 90)) if delays else None}
    return out


def _ttd(procs: Sequence[Proc], scored: Dict[str, Tuple[float, List[float]]], t: float) -> Dict[str, Optional[float]]:
    out: Dict[str, Optional[float]] = {}
    for p in procs:
        if p.label != 1 or p.uid not in scored:
            continue
        start = datetime.fromisoformat(p.start_ts.replace("Z", ""))
        out[p.uid] = None
        for (_kind, ts, _f), s in zip(p.checkpoints, scored[p.uid][1]):
            if s >= t:
                out[p.uid] = max(0.0, (datetime.fromisoformat(ts) - start).total_seconds())
                break
    return out


def _flags(procs: Sequence[Proc], score: Dict[str, float], t: float) -> Dict[str, bool]:
    return {p.uid: score.get(p.uid, float("-inf")) >= t for p in procs}


def baselines(procs: Sequence[Proc], hours: Dict[str, float], held_out: str) -> Dict[str, Any]:
    """B1 rules (full replay), B3 allowlist, B5 heuristic, on the held-out environment's processes."""
    env_procs = [p for p in procs if p.env == held_out]
    h = hours.get(held_out, 0.0)

    def triple(p: Proc) -> Tuple[str, str, Optional[str]]:
        return (leaf(p.row.get("parent_image")), leaf(p.row.get("image")), classify_path(p.row.get("image")))

    allowed = {triple(p) for p in procs if p.env != held_out and p.label == 0}
    rules = {p.uid: 1.0 if p.rule_alert_ts is not None else 0.0 for p in env_procs}
    allow = {p.uid: 0.0 if triple(p) in allowed else 1.0 for p in env_procs}
    heur = {p.uid: float(X.heuristic_score(p.row)) for p in procs}
    train_benign = [p for p in procs if p.env != held_out and p.label == 0]
    per_env = {}
    for env in sorted({p.env for p in train_benign}):
        s = np.array([heur[p.uid] for p in train_benign if p.env == env])
        if len(s) and hours.get(env):
            per_env[env] = {n: X.threshold_for_budget(s, np.ones(len(s)), hours[env], b) for n, b in BUDGETS.items()}
    heur_t = {n: max(t[n] for t in per_env.values()) for n in BUDGETS}
    env_heur = {p.uid: heur[p.uid] for p in env_procs}
    return {"B1_rules": evaluate(env_procs, rules, {"alert": 0.5, "high": 0.5}, h),
            "B3_allowlist": evaluate(env_procs, allow, {"alert": 0.5, "high": 0.5}, h),
            "B5_heuristic": evaluate(env_procs, env_heur, heur_t, h),
            "_flags": {"B1": {u: v >= 0.5 for u, v in rules.items()}, "B3": {u: v >= 0.5 for u, v in allow.items()},
                       "B5": _flags(env_procs, env_heur, heur_t["alert"])}}


def run_model(procs, hours, hours_of_host, spec, matrix, envs, details=True):
    folds: Dict[str, Any] = {}
    models: Dict[str, Tuple[FoldModel, Dict[str, float]]] = {}
    for env in envs:
        model = fit_fold(procs, hours, hours_of_host, env, spec, matrix)
        env_procs = [p for p in procs if p.env == env]
        scored = scores_of(model.booster, model.rounds, matrix, env_procs)
        score = {p.uid: scored.get(p.uid, (float("-inf"), []))[0] for p in env_procs}
        res = evaluate(env_procs, score, model.thresholds, hours.get(env, 0.0),
                       _ttd(env_procs, scored, model.thresholds["alert"]))
        res["thresholds_per_training_environment"] = model.per_env
        if details:
            top = sorted((p for p in env_procs if p.label == 0), key=lambda p: -score[p.uid])[:12]
            res["top_benign"] = [{"score": round(score[p.uid], 3), "parent": leaf(p.row.get("parent_image")),
                                  "image": leaf(p.row.get("image")),
                                  "command_line": (p.row.get("command_line") or "")[:140],
                                  "bits": list(p.checkpoints[-1][2].get("behavior_bits") or [])} for p in top]
        folds[env] = res
        models[env] = (model, score)
    worst = max(folds, key=lambda e: folds[e]["alert"]["fp_per_host_hour"] or 0.0)
    summary = {
        "worst_environment_alert": worst, "worst_fp_per_host_hour_alert": folds[worst]["alert"]["fp_per_host_hour"],
        "fp_per_host_hour_alert": {e: folds[e]["alert"]["fp_per_host_hour"] for e in folds},
        "fp_per_host_hour_high": {e: folds[e]["high"]["fp_per_host_hour"] for e in folds},
        "recall_alert": {e: folds[e]["alert"]["recall"] for e in folds if folds[e]["alert"]["recall"] is not None},
        "pauc": {e: folds[e].get("pauc_fpr_0.01") for e in folds if folds[e].get("pauc_fpr_0.01") is not None},
        "C1_alert": all((folds[e]["alert"]["fp_per_host_hour"] or 0.0) <= BUDGETS["alert"] for e in folds),
        "C1_high": all((folds[e]["high"]["fp_per_host_hour"] or 0.0) <= BUDGETS["high"]
                       for e in folds if folds[e]["host_hours"] >= HIGH_BUDGET_MIN_HOURS),
    }
    summary["macro_recall_alert"] = (float(np.mean(list(summary["recall_alert"].values())))
                                     if summary["recall_alert"] else None)
    return {"folds": folds, "summary": summary}, models


def _paired(procs, envs, flags_a: Dict[str, Dict[str, bool]], flags_b: Dict[str, Dict[str, bool]]) -> Dict[str, Any]:
    per_env = {}
    for env in envs:
        mal = [p for p in procs if p.env == env and p.label == 1]
        if mal:
            per_env[env] = ([p.group for p in mal], [flags_a[env][p.uid] for p in mal],
                            [flags_b[env][p.uid] for p in mal])
    return L.macro_paired(per_env)


# ================================================================== probes (C4, C8)


def environment_probe(procs: Sequence[Proc], matrix: Matrix, admitted: Sequence[str]) -> Dict[str, Any]:
    benign = _capped([p for p in procs if p.label == 0 and not p.infra])
    last = np.array([matrix.rows[p.uid][1] - 1 for p in benign], dtype=np.int64)
    x = matrix.x[last]
    envs = np.array([p.env for p in benign])
    params = {**X.BASE_PARAMS, **_SHALLOW}

    def probe(cols: Optional[np.ndarray]) -> Dict[str, float]:
        xx = x if cols is None else x[:, cols]
        auc = {}
        for env in sorted(set(envs.tolist())):
            y = (envs == env).astype(int)
            if y.sum() < 5 or y.sum() > len(y) - 5:
                continue
            oof = np.zeros(len(y))
            for tr, te in StratifiedKFold(5, shuffle=True, random_state=SEED % 2**31).split(np.zeros(len(y)), y):
                b = lgb.train(params, lgb.Dataset(xx[tr], label=y[tr]), num_boost_round=200)
                oof[te] = b.predict(xx[te], raw_score=True)
            auc[env] = round(float(roc_auc_score(y, oof)), 4)
        return auc

    overall = probe(None)
    by_group = {}
    for group in admitted:
        cols = np.array([i for i, n in enumerate(CF.FEATURE_NAMES) if CF.GROUP_OF[n] == group])
        by_group[group] = probe(cols)
    family_groups = [g for g in admitted if g in CF.FAMILY_GROUPS]
    pool = _capped([p for p in procs if not p.infra])
    avail = np.array([[1.0 if g in p.families else 0.0 for g in family_groups] for p in pool]) \
        if family_groups else np.zeros((len(pool), 1))
    y = np.array([p.label for p in pool])
    oof = np.zeros(len(y))
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=SEED % 2**31).split(np.zeros(len(y)), y):
        model = LogisticRegression(max_iter=1000).fit(avail[tr], y[tr])
        oof[te] = model.decision_function(avail[te])
    mask_auc = float(roc_auc_score(y, oof)) if 0 < y.sum() < len(y) else None
    macro = float(np.mean(list(overall.values()))) if overall else None
    group_macro = {g: (float(np.mean(list(v.values()))) if v else None) for g, v in by_group.items()}
    return {"benign_environment_auc": overall, "macro_auc": macro, "group_macro_auc": group_macro,
            "availability_to_label_auc": mask_auc,
            "passes": (macro is not None and macro <= 0.70
                       and all(v is None or v <= 0.80 for v in group_macro.values())
                       and (mask_auc is None or mask_auc <= 0.55))}


def robustness(procs: Sequence[Proc], models: Dict[str, Tuple[FoldModel, Dict[str, float]]],
               matrix: Matrix) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for kind in MUTATIONS:
        before = after = changed = 0
        for env, (model, score) in models.items():
            for p in procs:
                if p.env != env or p.label != 1:
                    continue
                mutated = L.mutate(p.row, kind)
                if mutated["event"] == p.row["event"]:
                    continue
                vec = F4.featurize(X.scrub(mutated)["event"])
                q = Proc(**{**p.__dict__, "start_vector": vec})
                s = max(model.booster.predict(_csr(_vectors(q, model.groups)), raw_score=True,
                                              num_iteration=model.rounds).tolist())
                t = model.thresholds["alert"]
                before += score[p.uid] >= t
                after += s >= t
                changed += 1
        drop = (before - after) / changed if changed else None
        out[kind] = {"changed": changed, "recall_before": round(before / changed, 4) if changed else None,
                     "recall_after": round(after / changed, 4) if changed else None,
                     "drop": round(drop, 4) if drop is not None else None, "passes": drop is None or drop <= 0.10}
    for group in [g for g in matrix.groups if g in CF.FAMILY_GROUPS]:
        before = after = n = 0
        for env, (model, score) in models.items():
            mal = [p for p in procs if p.env == env and p.label == 1 and group in p.families]
            for p in mal:
                s = max(model.booster.predict(_csr(_vectors(p, model.groups, (group,))), raw_score=True,
                                              num_iteration=model.rounds).tolist())
                t = model.thresholds["alert"]
                before += score[p.uid] >= t
                after += s >= t
                n += 1
        drop = (before - after) / n if n else None
        out[f"group_loss:{group}"] = {"changed": n, "drop": round(drop, 4) if drop is not None else None,
                                      "passes": drop is None or drop <= 0.10}
    return out


# ================================================================== export


def export(out: Path, model: FoldModel, procs: Sequence[Proc], matrix: Matrix, admitted: Sequence[str],
           repo: Path, data: Path, hours: Dict[str, float], name: str) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    dump = model.booster.dump_model(num_iteration=model.rounds)
    (out / "model.json").write_text(json.dumps(dump, sort_keys=True) + "\n", encoding="utf-8")
    (out / "features.json").write_text(json.dumps(
        {**CF.spec(), "admitted_groups": list(admitted), "candidate": name,
         "availability": "families not collected on a host are NaN for their whole group",
         "checkpoints": "start, each new behaviour bit (max 8), stop; process score = max"}, indent=1) + "\n")
    (out / "thresholds.json").write_text(json.dumps(
        {"raw_score": model.thresholds, "policy": "minimax", "budgets_fp_per_host_hour": BUDGETS,
         "per_training_environment": model.per_env, "observed_host_hours": hours}, indent=2) + "\n")
    golden_procs = sorted(model.train_procs, key=lambda p: hashlib.sha256(p.uid.encode()).hexdigest())[:40]
    golden_procs += [p for p in procs if not p.families and p.label == 0][:10]  # vectors with NaN groups
    vectors = [v for p in golden_procs for v in _vectors(p, model.groups)]
    raw = model.booster.predict(_csr(vectors), raw_score=True, num_iteration=model.rounds)
    golden = [{"vector": {str(k): (None if v != v else v) for k, v in vec.items()}, "raw_score": float(s)}
              for vec, s in zip(vectors, raw.tolist())]
    (out / "golden.json").write_text(json.dumps(golden, indent=1) + "\n", encoding="utf-8")
    served = load_model(dump)
    worst = max(abs(served.raw_score(vec) - s) for vec, s in zip(vectors, raw.tolist()))
    files = {n: hashlib.sha256((out / n).read_bytes()).hexdigest()
             for n in ("model.json", "features.json", "thresholds.json", "golden.json")}
    pins = repo / "tools" / "train" / "pins.json"
    manifest = {
        "model_id": "panopticon-process-context", "candidate": name, "context_version": CF.CONTEXT_VERSION,
        "start_featurizer_version": F4.FEATURIZER_VERSION, "admitted_groups": list(admitted),
        "engine_git_sha": X.git_sha(repo), "golden_max_abs_error": float(worst),
        "golden_vectors_with_nan": sum(1 for v in vectors if any(x != x for x in v.values())),
        "rounds": model.rounds, "training_processes": len(model.train_procs),
        "versions": {"lightgbm": lgb.__version__, "scikit_learn": sklearn.__version__, "numpy": np.__version__,
                     "python": platform.python_version()},
        "pins_sha256": hashlib.sha256(pins.read_bytes()).hexdigest() if pins.exists() else None,
        "final_candidate": False, "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


# ================================================================== driver


def _select(results: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    passing = [n for n in CANDIDATES if results[n]["summary"]["C1_alert"]]
    if passing:
        best = max(passing, key=lambda n: results[n]["summary"]["macro_recall_alert"] or 0.0)
        return best, f"meets C1 at alert in every environment; highest macro recall among {passing}"
    best = min(CANDIDATES, key=lambda n: results[n]["summary"]["worst_fp_per_host_hour_alert"])
    return best, "no candidate meets C1 at alert; lowest worst-environment FP/host-hour"


def run(data: Path, repo: Path, version: str, log=print) -> Dict[str, Any]:
    procs, loaded = load_replays(data)
    cen = census(data)
    admitted, admission = admitted_groups(cen)
    hours = {env: cen[env]["host_hours"] for env in cen}
    hours_of_host = loaded["host_hours"]
    envs = [e for e in ENVIRONMENTS if any(p.env == e for p in procs)]
    log(f"[context] {len(procs)} processes; admitted groups {admitted}", flush=True)
    out: Dict[str, Any] = {
        "protocol": {"version": CONTEXT_EVAL_VERSION, "criteria": CRITERIA, "selection_rule": SELECTION_RULE,
                     "decision_rule": DECISION_RULE, "candidates": CANDIDATES, "reference_models": REFERENCE_MODELS,
                     "admission": ADMISSION, "budgets": BUDGETS, "seed": SEED},
        "data": {**loaded["info"], "host_hours": hours, "environments": envs},
        "admission": admission, "admitted_groups": admitted, "models": {}, "baselines": {},
    }
    matrices: Dict[Tuple[str, ...], Matrix] = {}
    models: Dict[str, Dict[str, Tuple[FoldModel, Dict[str, float]]]] = {}
    for name, spec in {**CANDIDATES, **REFERENCE_MODELS}.items():
        groups = tuple(admitted) if spec["groups"] == "admitted" else tuple(g for g in spec["groups"] if g in admitted)
        if groups not in matrices:
            matrices[groups] = Matrix(procs, groups)
        out["models"][name], models[name] = run_model(procs, hours, hours_of_host, spec, matrices[groups], envs,
                                                      details=name in CANDIDATES)
        log(f"[context] {name}: {out['models'][name]['summary']['fp_per_host_hour_alert']}", flush=True)
    flags_base: Dict[str, Dict[str, Dict[str, bool]]] = {"B1": {}, "B3": {}, "B5": {}}
    for env in envs:
        res = baselines(procs, hours, env)
        for key in flags_base:
            flags_base[key][env] = res["_flags"][key]
        out["baselines"][env] = {k: v for k, v in res.items() if k != "_flags"}
    model_flags = {name: {env: _flags([p for p in procs if p.env == env], m[env][1], m[env][0].thresholds["alert"])
                          for env in envs} for name, m in models.items()}
    for name in CANDIDATES:
        out["models"][name]["paired"] = {
            "vs_B1_rules": _paired(procs, envs, model_flags[name], flags_base["B1"]),
            "vs_B2_start_only": _paired(procs, envs, model_flags[name], model_flags["B2_start_only"]),
            "vs_B3_allowlist": _paired(procs, envs, model_flags[name], flags_base["B3"]),
            "vs_B5_heuristic": _paired(procs, envs, model_flags[name], flags_base["B5"]),
        }
    chosen, why = _select(out["models"])
    out["selection"] = {"selected": chosen, "reason": why}
    chosen_groups = tuple(admitted)
    summary = out["models"][chosen]["summary"]
    paired = out["models"][chosen]["paired"]
    attack_envs = [e for e in summary["pauc"]]
    c5 = out["models"]["C5_start_lineage_children"]["summary"]["fp_per_host_hour_alert"]
    b2 = out["models"]["B2_start_only"]["summary"]["fp_per_host_hour_alert"]
    ttd = [d for e in envs for d in [out["models"][chosen]["folds"][e].get("time_to_detect_s", {}).get("median")]
           if d is not None]
    log("[context] probes", flush=True)
    probe = environment_probe(procs, matrices[chosen_groups], admitted)
    robust = robustness(procs, models[chosen], matrices[chosen_groups])
    final = fit_fold(procs, hours, hours_of_host, None, CANDIDATES[chosen], matrices[chosen_groups])
    manifest = export(data / "models" / version, final, procs, matrices[chosen_groups], admitted, repo, data,
                      hours, chosen)
    out["criteria"] = {
        "C1": {"passes": summary["C1_alert"] and summary["C1_high"], "alert": summary["fp_per_host_hour_alert"],
               "high": summary["fp_per_host_hour_high"]},
        "C2": {"passes": (paired["vs_B2_start_only"]["diff"] >= 0.15 and paired["vs_B2_start_only"]["ci95"][0] > 0
                          and paired["vs_B1_rules"]["ci95"][0] > -0.05),
               "vs_B2": paired["vs_B2_start_only"], "vs_B1": paired["vs_B1_rules"]},
        "C3": {"passes": (bool(attack_envs) and float(np.mean([summary["pauc"][e] for e in attack_envs])) >= 0.75
                          and summary["pauc"].get("botsv1", 1.0) >= 0.65),
               "pauc": summary["pauc"],
               "macro": float(np.mean([summary["pauc"][e] for e in attack_envs])) if attack_envs else None},
        "C4": probe,
        "C5": {"passes": all((c5[e] or 0.0) <= (b2[e] or 0.0) + 0.2 for e in c5), "c5": c5, "b2": b2},
        "C6": {"passes": bool(ttd) and float(np.median(ttd)) <= 120.0,
               "median_of_environment_medians_s": float(np.median(ttd)) if ttd else None},
        "C7": {"passes": manifest["golden_max_abs_error"] <= 1e-9, "golden_max_abs_error": manifest["golden_max_abs_error"],
               "golden_vectors_with_nan": manifest["golden_vectors_with_nan"],
               "note": "bit-identical rebuild checked by rerunning this step into a second version"},
        "C8": {"passes": all(v["passes"] for v in robust.values()), "families": robust},
    }
    out["export"] = manifest
    return X.jsonable(out)
