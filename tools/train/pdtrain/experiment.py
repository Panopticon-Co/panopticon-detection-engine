"""Train and evaluate the process-start classifier; export the bundle.

Everything here follows docs/ml/training-plan.md (§5-§7). The integration
gate thresholds are fixed in :data:`GATES` *before* any test number exists.

Data roles
----------
* **pool** -- attack_data, OTRF compound, BOTSv1 servers. Training and
  out-of-fold (OOF) evaluation by group: a malicious group is one ATT&CK
  technique (or recording family), a benign group is one host. Malicious
  groups are capped at ``CAP_PER_GROUP`` rows so a few chatty techniques do
  not dominate.
* **E3 / leave-source-out** -- all OTRF atomic rows (another lab, other operators).
* **E4 / held-out host** -- BOTSv1 ``we8105desk``: a real desktop, its benign
  day plus the Cerber infection. False positives are counted on its *raw*
  event stream (duplicates included) per observed host-hour.
* **E5 / out-of-distribution** -- WinLOLBIN-GT samples (synthetic; never trained on).

Calibration (Platt) and thresholds are fitted on pool OOF scores only, then
frozen and applied to every test set.
"""

from __future__ import annotations

import collections
import csv
import hashlib
import json
import math
import platform
import random
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np
import sklearn
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.preprocessing import MaxAbsScaler

from panopticon_detection.factory import build_detection_run
from panopticon_detection.ml.scorer import TreeModel, platt
from pdtrain import featurizer_v3 as F  # legacy runs v1-v6 are pinned to featurizer v3
from pdtrain.label import (
    dedup_key,
    label_attack_recording,
    label_botsv1,
    leaf,
    read_labelled,
    technique_group,
)
from pdtrain.normalize import read_rows

SEED = 20261023
CAP_PER_GROUP = 300
N_FOLDS = 5
BOOTSTRAP = 1000
HOLDOUT_HOST = "we8105desk"
GAP_CAP_SECONDS = 3600.0
BUDGETS = {"alert": 1.0, "high": 0.1}  # false positives per observed host-hour

# Fixed before any test result was computed (training plan §7).
GATES = {
    "G1": "E2 recall at the alert budget: model beats rules-only and LR (paired bootstrap "
          "95% CI of the difference > 0); PR-AUC beats LR",
    "G2": "E4 FP/host-hour <= 1 at alert and <= 0.1 at high, on the held-out host; "
          "same budget on E6 (agent-recorded benign, held-out second half) -- E6 added 2026-10-23 before run 3; "
          "same budget on E7 (OpTC held-out host range, planned in the training plan) -- before run v4",
    "G3": "E3 recall at alert within 15 percentage points of E2",
    "G4": "no harness/lab tokens in the top-30 features; no train/test duplicates",
    "G5": "calibrated ECE <= 0.10 (OOF)",
    "G6": "rebuild gives a bit-identical model.json; golden vectors pass the pure-Python scorer",
    "E9": "final test (pdtrain.final_test, pre-registered 2026-10-23 before run v6): ATLASv2 scored once "
          "with the frozen bundle via the pure-Python scorer; pass = <= 1 FP/host-hour at alert (variant A)",
}
HARNESS_TOKENS = ("atomic", "invoke-atomictest", "pathtoatomics", "attackrange", "attack_range",
                  "splunk", "externalpayloads", "mordor", "theshire", "waynecorp", "ssm-")

PARAM_GRID = [{"num_leaves": nl, "min_data_in_leaf": md} for nl in (15, 31) for md in (20, 50)]
BASE_PARAMS = {
    "objective": "binary", "learning_rate": 0.05, "feature_fraction": 0.8,
    "bagging_fraction": 0.8, "bagging_freq": 1, "lambda_l2": 1.0, "verbose": -1,
    "deterministic": True, "num_threads": 1, "seed": SEED, "zero_as_missing": False,
    "force_col_wise": True,
}

LOLBINS = frozenset(
    """certutil.exe bitsadmin.exe mshta.exe rundll32.exe regsvr32.exe msbuild.exe installutil.exe
    regasm.exe regsvcs.exe cmstp.exe wmic.exe msiexec.exe odbcconf.exe forfiles.exe pcalua.exe
    schtasks.exe at.exe sc.exe reg.exe vssadmin.exe wbadmin.exe bcdedit.exe netsh.exe esentutl.exe
    expand.exe extrac32.exe hh.exe ieexec.exe infdefaultinstall.exe makecab.exe presentationhost.exe
    syncappvpublishingserver.exe control.exe csc.exe atbroker.exe mavinject.exe createdump.exe
    procdump.exe ntdsutil.exe nltest.exe dsquery.exe adfind.exe""".split()
)
MUTATIONS = ("caret", "case", "envvar", "whitespace", "argswap", "renamed_binary")


# ====================================================================== data


def labelled_raw(rows_dir: Path, sources: Sequence[str]) -> List[Dict[str, Any]]:
    """Every row with its label, *before* de-duplication (for FP-per-hour counts)."""
    out: List[Dict[str, Any]] = []
    for source in sources:
        grouped: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
        for row in read_rows(rows_dir, source):
            grouped[row["dataset"]].append(row)
        for _, rows in sorted(grouped.items()):
            if source == "botsv1":
                label_botsv1(rows)
            elif source in ("officer_vm", "optc", "atlasv2"):
                pass  # labelled by their readers (pdtrain.officer_vm, pdtrain.optc, pdtrain.atlasv2)
            else:
                label_attack_recording(rows, technique_group)
            out.extend(rows)
    for row in out:
        row["dedup_key"] = dedup_key(row)
    return out


# Agent-recorded benign data (pdtrain.officer_vm) is split by time: rows before
# OFFICER_SPLIT[0] may train (when OFFICER_SPLIT[1]), the rest are test E6.
OFFICER_SPLIT: List[Any] = [None, False]
# OpTC benign: one 25-host range trains (when enabled), the other is test E7.
OPTC_HOLDOUT = "AIA-201-225"
OPTC_TRAIN: List[bool] = [False]


def role(row: Dict[str, Any]) -> str:
    if row["source"] == "atlasv2":
        return "v7_only"  # legacy runs v1-v6 never read ATLASv2; v7 trains on it (pdtrain.loeo)
    if row["source"] == "optc":
        return "E7" if OPTC_HOLDOUT in row["dataset"] else ("pool" if OPTC_TRAIN[0] else "E7")
    if row["source"] == "officer_vm":
        cutoff, train = OFFICER_SPLIT
        return "pool" if train and cutoff is not None and row["utc"] < cutoff else "E6"
    if row["source"] == "otrf":
        return "E3"
    if row["source"] == "botsv1" and (row.get("host") or "").lower().startswith(HOLDOUT_HOST):
        return "E4"
    return "pool"


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", ""))


def observed_hours(rows: Sequence[Dict[str, Any]]) -> float:
    """Sum of inter-event gaps per (recording, host), each gap capped at an hour."""
    times: Dict[Tuple[str, str], List[datetime]] = collections.defaultdict(list)
    for row in rows:
        times[(row["dataset"], row.get("host") or "")].append(_ts(row["utc"]))
    total = 0.0
    for stamps in times.values():
        stamps.sort()
        total += sum(min((b - a).total_seconds(), GAP_CAP_SECONDS) for a, b in zip(stamps, stamps[1:]))
    return total / 3600.0


def cap_groups(rows: List[Dict[str, Any]], cap: int) -> List[Dict[str, Any]]:
    by_group: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        by_group[row["group"]].append(row)
    out: List[Dict[str, Any]] = []
    for _, members in sorted(by_group.items()):
        if members[0]["label"] == 1 and len(members) > cap:
            members = sorted(members, key=lambda r: hashlib.sha256(r["row_id"].encode()).hexdigest())[:cap]
        out.extend(members)
    return sorted(out, key=lambda r: r["row_id"])


# ================================================================== features


_INTEGRITY_COLS = frozenset(F.FEATURE_NAMES.index(n) for n in F.INTEGRITY_FEATURES)


# Harness and lab artefacts (training plan §4): test-harness paths, ATT&CK ids
# embedded in file names, lab domains and hostnames. Scrubbed from every row
# before featurizing -- train and test alike -- so the model cannot learn
# "came from the attack lab". A deployed agent never sees these strings, so
# serving needs no equivalent step.
_SCRUB = tuple(
    (re.compile(p, re.I), r)
    for p, r in (
        (r"[a-z]:\\atomicredteam\\atomics\\[^\s\"']*", r"c:\\tools\\payload"),
        (r"[a-z]:\\detectiontesting\\[^\s\"']*", r"c:\\tools\\payload"),
        (r"pathtoatomicsfolder|externalpayloads|atomicredteam|invoke-atomictest", "tool"),
        (r"\bt1\d{3}(?:\.\d{3})?\b", "item"),
        (r"\b[\w.-]*\.(?:attackrange\.local|theshire\.local|mordor\.local|waynecorpinc\.local|"
         r"pandalab\.com|azsentinel\.local|contoso\.lab|systemia\.com)\b", "host.example"),
        (r"\bwin-(?:dc|host)-[\w-]+\b", "host"),
    )
)


def scrub(row: Dict[str, Any]) -> Dict[str, Any]:
    event = json.loads(json.dumps(row["event"]))
    proc = event.get("process") or {}
    for key in ("command_line", "executable"):
        text = proc.get(key)
        if text:
            for pattern, replacement in _SCRUB:
                text = pattern.sub(replacement, text)
            proc[key] = text
    return {**row, "event": event}


def is_lab_infrastructure(row: Dict[str, Any]) -> bool:
    """Recording infrastructure (Splunk forwarder & helpers): kept out of training.

    It is benign, but it is a property of the lab, not of the endpoints the
    agent protects; the run-1 leakage probe found the model leaning on it.
    """
    paths = " ".join((row.get(k) or "") for k in ("image", "parent_image", "command_line")).lower()
    return "splunk" in paths or row.get("label_rule") == "benign/infrastructure"


def vector(row: Dict[str, Any], variant: str) -> Dict[int, float]:
    row = scrub(row)
    v = F.featurize(row["event"], row.get("integrity") if variant == "B" else None)
    if variant == "A":
        v = {i: x for i, x in v.items() if i not in _INTEGRITY_COLS}
    return v


def matrix(rows: Sequence[Dict[str, Any]], variant: str) -> sparse.csr_matrix:
    data: List[float] = []
    indices: List[int] = []
    indptr = [0]
    for row in rows:
        for i, v in vector(row, variant).items():
            indices.append(i)
            data.append(v)
        indptr.append(len(indices))
    return sparse.csr_matrix(
        (np.array(data, dtype=np.float64), np.array(indices, dtype=np.int64), np.array(indptr)),
        shape=(len(rows), len(F.FEATURE_NAMES)),
    )


# ================================================================== models


def train_lgb(x, y, params, rounds: int, valid=None):
    train_set = lgb.Dataset(x, label=y, feature_name=list(F.FEATURE_NAMES), free_raw_data=False)
    valid_sets, callbacks = [], []
    if valid is not None:
        valid_sets = [lgb.Dataset(valid[0], label=valid[1], reference=train_set)]
        callbacks = [lgb.early_stopping(50, verbose=False)]
    return lgb.train({**BASE_PARAMS, **params}, train_set, num_boost_round=rounds,
                     valid_sets=valid_sets, callbacks=callbacks)


def _inner_split(groups: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Hold ~15% of the training groups out for early stopping."""
    uniq = sorted(set(groups.tolist()))
    random.Random(SEED).shuffle(uniq)
    held = set(uniq[: max(2, len(uniq) * 15 // 100)])
    mask = np.array([g in held for g in groups])
    if len(set(y[mask].tolist())) < 2 or len(set(y[~mask].tolist())) < 2:
        mask = np.zeros(len(y), dtype=bool)
        mask[::7] = True
    return np.where(~mask)[0], np.where(mask)[0]


def oof_lgb(x, y, groups, params, folds) -> Tuple[np.ndarray, List[int]]:
    scores = np.zeros(len(y))
    best_iters: List[int] = []
    for train_idx, test_idx in folds:
        inner_tr, inner_va = _inner_split(groups[train_idx], y[train_idx])
        tr, va = train_idx[inner_tr], train_idx[inner_va]
        booster = train_lgb(x[tr], y[tr], params, 1000, valid=(x[va], y[va]))
        best = booster.best_iteration or booster.current_iteration()
        best_iters.append(int(best))
        scores[test_idx] = booster.predict(x[test_idx], raw_score=True, num_iteration=best)
    return scores, best_iters


def make_lr() -> Tuple[MaxAbsScaler, LogisticRegression]:
    return MaxAbsScaler(), LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, solver="liblinear")


def oof_lr(x, y, folds) -> np.ndarray:
    scores = np.zeros(len(y))
    for train_idx, test_idx in folds:
        scaler, lr = make_lr()
        lr.fit(scaler.fit_transform(x[train_idx]), y[train_idx])
        scores[test_idx] = lr.decision_function(scaler.transform(x[test_idx]))
    return scores


def heuristic_score(row: Dict[str, Any]) -> float:
    """LOLBin / suspicious-flag heuristic baseline (no learning)."""
    process = row["event"].get("process") or {}
    cmd = (process.get("command_line") or "").lower()
    name = (process.get("name") or "").lower()
    parent = ((row["event"].get("parent") or {}).get("name") or "").lower()
    v = F.featurize(row["event"])
    idx = F.FEATURE_NAMES.index
    score = 1.0 if name in LOLBINS else 0.0
    score += 1.0 if name in ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe") else 0.0
    score += 1.0 if parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe") else 0.0
    for flag in ("cmd_flag_encoded", "cmd_flag_hidden", "cmd_flag_bypass", "cmd_has_url", "cmd_has_base64_blob"):
        score += v.get(idx(flag), 0.0)
    score += 0.5 if "\\temp\\" in cmd or "\\appdata\\" in cmd else 0.0
    return score


def rules_scores(raw_rows: Sequence[Dict[str, Any]], rules_dir: Path) -> Dict[str, float]:
    """Highest rule level fired on each process start, replaying each recording in order.

    Only process starts are replayed, so rules that need other telemetry
    (file, network, registry) cannot fire: the baseline measures what the
    rules can do on the same input the model sees.
    """
    by_dataset: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in raw_rows:
        by_dataset[row["dataset"]].append(row)
    level: Dict[str, float] = {}
    for _, rows in sorted(by_dataset.items()):
        run, _ctx = build_detection_run(rules_dir)
        for row in sorted(rows, key=lambda r: (r["utc"], r["row_id"])):
            best = 0.0
            for alert in run.process_event(dict(row["event"])):
                if alert.rule_id == "PROV-CAMPAIGN" or alert.rule_id.startswith(("RISK", "CORR-RISK")):
                    continue
                best = max(best, float(alert.level))
            level[row["row_id"]] = best
    return level


# ================================================================== metrics


def _boot_index(groups: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    index: Dict[str, List[int]] = collections.defaultdict(list)
    for i, g in enumerate(groups.tolist()):
        index[g].append(i)
    uniq = sorted(index)
    picked = rng.choice(len(uniq), size=len(uniq), replace=True)
    return np.concatenate([np.array(index[uniq[p]]) for p in picked])


def _ci(values: List[float]) -> List[Optional[float]]:
    vals = [v for v in values if v is not None and not math.isnan(v)]
    if not vals:
        return [None, None]
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def pr_auc(y, s) -> float:
    return float(average_precision_score(y, s)) if 0 < y.sum() < len(y) else float("nan")


def roc(y, s) -> float:
    return float(roc_auc_score(y, s)) if 0 < y.sum() < len(y) else float("nan")


def recall_at(y, s, t) -> float:
    pos = y == 1
    return float((s[pos] >= t).mean()) if pos.any() else float("nan")


def precision_at(y, s, t) -> float:
    flagged = s >= t
    return float(y[flagged].mean()) if flagged.any() else float("nan")


def ece(y, p, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for lo, hi in zip(edges, edges[1:]):
        mask = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if mask.any():
            total += mask.mean() * abs(p[mask].mean() - y[mask].mean())
    return float(total)


def summarize(y, s, groups, thresholds: Dict[str, float]) -> Dict[str, Any]:
    rng = np.random.default_rng(SEED)
    point = {"pr_auc": pr_auc(y, s), "roc_auc": roc(y, s)}
    for name, t in thresholds.items():
        point[f"recall@{name}"] = recall_at(y, s, t)
        point[f"precision@{name}"] = precision_at(y, s, t)
    boots: Dict[str, List[float]] = collections.defaultdict(list)
    for _ in range(BOOTSTRAP):
        idx = _boot_index(groups, rng)
        yb, sb = y[idx], s[idx]
        boots["pr_auc"].append(pr_auc(yb, sb))
        boots["roc_auc"].append(roc(yb, sb))
        for name, t in thresholds.items():
            boots[f"recall@{name}"].append(recall_at(yb, sb, t))
            boots[f"precision@{name}"].append(precision_at(yb, sb, t))
    return {
        "n": int(len(y)), "positives": int(y.sum()), "groups": int(len(set(groups.tolist()))),
        "metrics": {k: {"value": v, "ci95": _ci(boots[k])} for k, v in point.items()},
    }


def paired_diff(y, s_model, s_base, groups, metric: Callable) -> Dict[str, Any]:
    rng = np.random.default_rng(SEED)
    diffs = []
    for _ in range(BOOTSTRAP):
        idx = _boot_index(groups, rng)
        diffs.append(metric(y[idx], s_model[idx]) - metric(y[idx], s_base[idx]))
    return {"diff": float(metric(y, s_model) - metric(y, s_base)), "ci95": _ci(diffs)}


def threshold_for_budget(scores: np.ndarray, weights: np.ndarray, hours: float, budget: float) -> float:
    """Lowest threshold whose weighted benign false positives stay within budget * hours."""
    # Walk distinct score values from the top: a threshold at value v flags
    # *every* benign row scoring >= v, so tied rows are admitted together or
    # not at all (a per-row walk let a tied block blow through the budget).
    allowed = budget * hours
    cumulative = 0.0
    threshold = float(scores.max()) + 1e-6
    by_value: Dict[float, float] = collections.defaultdict(float)
    for s, w in zip(scores.tolist(), weights.tolist()):
        by_value[s] += w
    for value in sorted(by_value, reverse=True):
        if cumulative + by_value[value] > allowed:
            break
        cumulative += by_value[value]
        threshold = value
    return threshold


# ================================================================== probes


def bucket_tokens(rows: Sequence[Dict[str, Any]]) -> Dict[int, collections.Counter]:
    """Which raw tokens land in each hashed bucket (to read hashed importances)."""
    out: Dict[int, collections.Counter] = collections.defaultdict(collections.Counter)
    for row in rows:
        event = row["event"]
        proc = event.get("process") or {}
        tokens = F._TOKEN.findall(F.normalize_text(proc.get("command_line")))
        for t in tokens:
            out[F._bucket("cmd", t)][t] += 1
        for a, b in zip(tokens, tokens[1:]):
            out[F._bucket("cmd", f"{a} {b}")][f"{a} {b}"] += 1
        for t in F._TOKEN.findall(F.normalize_text(proc.get("executable"))):
            out[F._bucket("path", t)][t] += 1
        name_n = F.normalize_text(proc.get("name"))
        parent_n = F.normalize_text((event.get("parent") or {}).get("name"))
        out[F._bucket("pair", f"{parent_n or '<none>'}->{name_n or '<none>'}")][f"{parent_n}->{name_n}"] += 1
        for g in F._char_bigrams(name_n) if name_n else []:
            out[F._bucket("name", g)][g] += 1
        for g in F._char_bigrams(parent_n) if parent_n else []:
            out[F._bucket("parent", g)][g] += 1
    return out


def top_features(booster, rows, k: int = 30) -> List[Dict[str, Any]]:
    gain = booster.feature_importance(importance_type="gain")
    tokens = bucket_tokens(rows)
    out = []
    for i in np.argsort(-gain)[:k]:
        if gain[i] <= 0:
            break
        name = F.FEATURE_NAMES[int(i)]
        top = [t for t, _ in tokens.get(int(i), collections.Counter()).most_common(4)] if "#" in name else []
        out.append({"feature": name, "gain": round(float(gain[i]), 2), "tokens": top,
                    "harness_token": any(h in " ".join(top).lower() for h in HARNESS_TOKENS)})
    return out


def mutate(row: Dict[str, Any], kind: str, rng: random.Random) -> Dict[str, Any]:
    event = json.loads(json.dumps(row["event"]))
    proc = event.setdefault("process", {})
    cmd = proc.get("command_line") or ""
    if kind == "caret":
        proc["command_line"] = "".join(c + ("^" if c.isalpha() and rng.random() < 0.3 else "") for c in cmd)
    elif kind == "case":
        proc["command_line"] = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in cmd)
    elif kind == "envvar":
        proc["command_line"] = cmd.replace("C:\\Windows", "%SystemRoot%").replace("c:\\windows", "%SystemRoot%")
    elif kind == "whitespace":
        proc["command_line"] = "  ".join(cmd.split(" "))
    elif kind == "argswap":
        parts = cmd.split(" ")
        if len(parts) > 2:
            parts[-1], parts[-2] = parts[-2], parts[-1]
        proc["command_line"] = " ".join(parts)
    elif kind == "renamed_binary":
        old = proc.get("name") or ""
        proc["name"] = "updater.exe"
        proc["executable"] = "C:\\Users\\Public\\AppData\\Local\\Temp\\updater.exe"
        proc["command_line"] = cmd.replace(old, "updater.exe") if old else cmd
    return {**row, "event": event}


# ================================================================== E5 (WinLOLBIN)


def winlolbin_rows(raw: Path) -> List[Dict[str, Any]]:
    rows = []
    for label, name in ((0, "benign"), (1, "malicious")):
        path = raw / "winlolbin" / f"winlolbin_gt_sample_unprocessed_{name}_500_lines.csv"
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            for rec in csv.DictReader(handle):
                user = rec.get("username") or ""
                domain, _, uname = user.partition("\\") if "\\" in user else ("", "", user)
                rows.append({
                    "row_id": f"winlolbin:{rec.get('event_id')}", "label": label,
                    "group": f"winlolbin:{rec.get('mitre_technique') or name}",
                    "integrity": rec.get("integrity_level"),
                    "event": {
                        "event_type": "process_create",
                        "process": {"name": rec.get("process_name"), "executable": rec.get("process_path"),
                                    "command_line": rec.get("command_line")},
                        "parent": {"name": rec.get("parent_process")},
                        "user": {"name": uname or None, "domain": domain or None},
                    },
                })
    return rows


# ================================================================== driver


def git_sha(repo: Path) -> str:
    """HEAD, with ``+dirty`` when tracked files differ from it (the bundle is then not reproducible from the SHA)."""
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True,
                             check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo,
                               capture_output=True, text=True, check=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


OFFICER_IMAGE_CAP = 50  # per process image, training rows only (kit issue 6: git.exe dominates)


def _cap_officer(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_image: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        by_image[leaf(row["image"])].append(row)
    out: List[Dict[str, Any]] = []
    for _, members in sorted(by_image.items()):
        out.extend(sorted(members, key=lambda r: hashlib.sha256(r["row_id"].encode()).hexdigest())[:OFFICER_IMAGE_CAP])
    return out


def run(data: Path, repo: Path, export_dir: Optional[Path] = None, officer_train: bool = False,
        optc_train: bool = False) -> Dict[str, Any]:
    sources = ["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm"]
    if (data / "rows" / "optc.jsonl.gz").exists():
        sources.append("optc")
    OPTC_TRAIN[0] = optc_train
    rows = read_labelled(data / "labelled")
    raw = labelled_raw(data / "rows", sources)

    officer_times = sorted(_ts(r["utc"]) for r in raw if r["source"] == "officer_vm")
    cutoff = None
    if officer_times:
        mid = officer_times[0] + (officer_times[-1] - officer_times[0]) / 2
        cutoff = mid.strftime("%Y-%m-%dT%H:%M:%S.") + f"{mid.microsecond // 1000:03d}Z"
    OFFICER_SPLIT[:] = [cutoff, officer_train]

    excluded_infra = sum(1 for r in rows if role(r) == "pool" and is_lab_infrastructure(r))
    pool_rows = [r for r in rows if role(r) == "pool" and not is_lab_infrastructure(r)]
    officer_pool = _cap_officer([r for r in pool_rows if r["source"] == "officer_vm"])
    optc_pool = _cap_officer([r for r in pool_rows if r["source"] == "optc"])
    pool = cap_groups([r for r in pool_rows if r["source"] not in ("officer_vm", "optc")], CAP_PER_GROUP)
    pool += officer_pool + optc_pool
    pool.sort(key=lambda r: r["row_id"])
    e3 = [r for r in rows if role(r) == "E3"]
    e4 = [r for r in rows if role(r) == "E4"]
    e5 = winlolbin_rows(data / "raw")
    e6_keys = {r["dedup_key"] for r in rows if role(r) in ("E6", "E7")}
    duplicates_across = len({r["dedup_key"] for r in pool} & ({r["dedup_key"] for r in e3 + e4} | e6_keys))

    y = np.array([r["label"] for r in pool])
    groups = np.array([r["group"] for r in pool])
    folds = list(GroupKFold(n_splits=N_FOLDS).split(np.zeros(len(y)), y, groups))

    raw_pool_benign = [r for r in raw if r.get("label") == 0 and role(r) == "pool"]
    raw_e4 = [r for r in raw if role(r) == "E4" and r.get("label") is not None]
    pool_hours = observed_hours([r for r in raw if role(r) == "pool"])
    e4_hours = observed_hours([r for r in raw if role(r) == "E4"])
    benign_weight = collections.Counter(r["dedup_key"] for r in raw_pool_benign)
    benign_idx = np.where(y == 0)[0]
    weights = np.array([benign_weight.get(pool[i]["dedup_key"], 1) for i in benign_idx], dtype=float)

    def budget_thresholds(scores: np.ndarray) -> Dict[str, float]:
        return {n: threshold_for_budget(scores[benign_idx], weights, pool_hours, b) for n, b in BUDGETS.items()}

    def fp_rate(scores: np.ndarray, t: float) -> float:
        return float(weights[scores[benign_idx] >= t].sum() / pool_hours)

    results: Dict[str, Any] = {
        "seed": SEED, "gates": GATES, "budgets_fp_per_host_hour": BUDGETS,
        "data": {
            "pool": {"rows": len(pool), "malicious": int(y.sum()), "benign": int((y == 0).sum()),
                     "groups": int(len(set(groups.tolist()))), "observed_host_hours": pool_hours,
                     "benign_raw_events": len(raw_pool_benign)},
            "E3_otrf": {"rows": len(e3), "malicious": sum(r["label"] for r in e3)},
            "E4_holdout_host": {"rows": len(e4), "malicious": sum(r["label"] for r in e4),
                                "raw_events": len(raw_e4), "observed_host_hours": e4_hours},
            "E5_winlolbin": {"rows": len(e5), "malicious": sum(r["label"] for r in e5)},
            "officer_vm": {"split_cutoff_utc": cutoff, "first_half_in_training": officer_train,
                           "training_rows_after_image_cap": len(officer_pool)},
            "optc": {"first_range_in_training": optc_train, "held_out_range": OPTC_HOLDOUT,
                     "training_rows_after_image_cap": len(optc_pool)},
            "train_test_duplicate_keys": duplicates_across,
            "pool_lab_infrastructure_rows_excluded": excluded_infra,
            "run": 2,
        },
    }

    # -------------------------------------------------- tuning on variant A (OOF PR-AUC)
    xa, xb = matrix(pool, "A"), matrix(pool, "B")
    tuning = []
    for params in PARAM_GRID:
        s, iters = oof_lgb(xa, y, groups, params, folds)
        tuning.append({"params": params, "oof_pr_auc": pr_auc(y, s), "best_iterations": iters})
    params = max(tuning, key=lambda t: t["oof_pr_auc"])["params"]
    results["tuning"] = {"grid": tuning, "chosen": params,
                         "note": "selected on the same OOF folds used for E2 (4 configs): slightly optimistic"}

    variants: Dict[str, Dict[str, Any]] = {}
    for variant, x in (("A", xa), ("B", xb)):
        oof, iters = oof_lgb(x, y, groups, params, folds)
        calib = LogisticRegression(C=1e6, max_iter=1000).fit(oof.reshape(-1, 1), y)
        a, b = float(calib.coef_[0][0]), float(calib.intercept_[0])
        variants[variant] = {
            "oof": oof, "a": a, "b": b, "rounds": int(np.median(iters)),
            "prob": np.array([platt(v, a, b) for v in oof]),
            "thresholds": budget_thresholds(oof),
        }
        variants[variant]["booster"] = train_lgb(x, y, params, variants[variant]["rounds"])

    # -------------------------------------------------- baselines (OOF on pool)
    lr_oof = oof_lr(xa, y, folds)
    heur = np.array([heuristic_score(r) for r in pool])
    rules = rules_scores([r for r in raw if r.get("label") is not None], repo / "rules")
    rules_pool = np.array([rules.get(r["row_id"], 0.0) for r in pool])
    base_t = {"lr": budget_thresholds(lr_oof), "heuristic": budget_thresholds(heur),
              "rules": budget_thresholds(rules_pool)}

    # -------------------------------------------------- E1 ceiling and E2 group OOF
    strat = list(StratifiedKFold(N_FOLDS, shuffle=True, random_state=SEED % 2**31).split(np.zeros(len(y)), y))
    e1_scores, _ = oof_lgb(xa, y, np.array([str(i) for i in range(len(y))]), params, strat)
    results["E1_random_split_ceiling"] = summarize(y, e1_scores, groups, variants["A"]["thresholds"])

    e2: Dict[str, Any] = {}
    for variant in ("A", "B"):
        v = variants[variant]
        e2[f"model_{variant}"] = summarize(y, v["oof"], groups, v["thresholds"])
        e2[f"model_{variant}"].update(
            thresholds_raw=v["thresholds"], ece_oof=ece(y, v["prob"]),
            brier_oof=float(np.mean((v["prob"] - y) ** 2)), calibration={"a": v["a"], "b": v["b"]},
            fp_per_host_hour_oof={n: fp_rate(v["oof"], t) for n, t in v["thresholds"].items()},
        )
    for name, scores in (("logistic_regression", lr_oof), ("heuristic", heur), ("rules_only", rules_pool)):
        key = {"logistic_regression": "lr", "heuristic": "heuristic", "rules_only": "rules"}[name]
        e2[name] = summarize(y, scores, groups, base_t[key])
        e2[name]["fp_per_host_hour_oof"] = {n: fp_rate(scores, t) for n, t in base_t[key].items()}
    e2["rules_only"]["any_rule_fired"] = {
        "recall": float((rules_pool[y == 1] > 0).mean()),
        "fp_per_host_hour": fp_rate(rules_pool, 1e-9),
    }
    flag = lambda s, t: (s >= t).astype(float)  # noqa: E731
    recall_flag = lambda yy, ss: recall_at(yy, ss, 0.5)  # noqa: E731
    ta = variants["A"]["thresholds"]["alert"]
    e2["paired"] = {
        "A_vs_lr_pr_auc": paired_diff(y, variants["A"]["oof"], lr_oof, groups, pr_auc),
        "A_vs_lr_recall_alert": paired_diff(y, flag(variants["A"]["oof"], ta), flag(lr_oof, base_t["lr"]["alert"]),
                                            groups, recall_flag),
        "A_vs_rules_recall_alert": paired_diff(y, flag(variants["A"]["oof"], ta),
                                               flag(rules_pool, base_t["rules"]["alert"]), groups, recall_flag),
        "A_vs_heuristic_recall_alert": paired_diff(y, flag(variants["A"]["oof"], ta),
                                                   flag(heur, base_t["heuristic"]["alert"]), groups, recall_flag),
        "B_vs_A_pr_auc": paired_diff(y, variants["B"]["oof"], variants["A"]["oof"], groups, pr_auc),
    }
    per_group: Dict[str, List[int]] = collections.defaultdict(lambda: [0, 0])
    for r, sc in zip(pool, variants["A"]["oof"]):
        if r["label"] == 1:
            per_group[r["group"]][0] += int(sc >= ta)
            per_group[r["group"]][1] += 1
    e2["per_group_recall_A_alert"] = {g: {"detected": d, "total": n} for g, (d, n) in sorted(per_group.items())}
    results["E2_group_oof"] = e2

    # -------------------------------------------------- held-out tests
    def score(variant: str, rows_: Sequence[Dict[str, Any]]) -> np.ndarray:
        return variants[variant]["booster"].predict(matrix(rows_, variant), raw_score=True)

    tests: Dict[str, Any] = {}
    scaler, final_lr = make_lr()
    final_lr.fit(scaler.fit_transform(xa), y)
    for name, rows_ in (("E3_otrf_leave_source_out", e3), ("E5_winlolbin_ood", e5)):
        yt = np.array([r["label"] for r in rows_])
        gt = np.array([r["group"] for r in rows_])
        tests[name] = {f"model_{v}": summarize(yt, score(v, rows_), gt, variants[v]["thresholds"]) for v in ("A", "B")}
        tests[name]["logistic_regression"] = summarize(
            yt, final_lr.decision_function(scaler.transform(matrix(rows_, "A"))), gt, base_t["lr"])
        tests[name]["heuristic"] = summarize(yt, np.array([heuristic_score(r) for r in rows_]), gt, base_t["heuristic"])
        if name.startswith("E3"):
            tests[name]["rules_only"] = summarize(
                yt, np.array([rules.get(r["row_id"], 0.0) for r in rows_]), gt, base_t["rules"])

    e4_y = np.array([r["label"] for r in raw_e4])
    e4_res: Dict[str, Any] = {"observed_host_hours": e4_hours, "raw_events": len(raw_e4),
                              "raw_malicious": int(e4_y.sum())}
    for v in ("A", "B"):
        s = score(v, raw_e4)
        e4_res[f"model_{v}"] = {
            n: {"threshold": t, "fp_events": int(((s >= t) & (e4_y == 0)).sum()),
                "fp_per_host_hour": float(((s >= t) & (e4_y == 0)).sum() / e4_hours),
                "recall_malicious_events": recall_at(e4_y, s, t)}
            for n, t in variants[v]["thresholds"].items()
        }
        e4_res[f"model_{v}"]["top_benign_scores"] = [
            {"score": round(float(s[i]), 3), "parent": leaf(raw_e4[i]["parent_image"]),
             "image": leaf(raw_e4[i]["image"]), "command_line": (raw_e4[i]["command_line"] or "")[:160]}
            for i in np.argsort(-s) if e4_y[i] == 0
        ][:15]
    for name, s, t in (
        ("logistic_regression", final_lr.decision_function(scaler.transform(matrix(raw_e4, "A"))), base_t["lr"]),
        ("heuristic", np.array([heuristic_score(r) for r in raw_e4]), base_t["heuristic"]),
    ):
        e4_res[name] = {
            n: {"fp_events": int(((s >= th) & (e4_y == 0)).sum()),
                "fp_per_host_hour": float(((s >= th) & (e4_y == 0)).sum() / e4_hours),
                "recall_malicious_events": recall_at(e4_y, s, th)}
            for n, th in t.items()
        }
    rs = np.array([rules.get(r["row_id"], 0.0) for r in raw_e4])
    e4_res["rules_only_any_fired"] = {
        "fp_events": int(((rs > 0) & (e4_y == 0)).sum()),
        "fp_per_host_hour": float(((rs > 0) & (e4_y == 0)).sum() / e4_hours),
        "recall_malicious_events": float((rs[e4_y == 1] > 0).mean()) if (e4_y == 1).any() else None,
    }
    tests["E4_holdout_host_raw_stream"] = e4_res

    for test_role, test_name in (("E6", "E6_agent_benign_raw_stream"), ("E7", "E7_optc_benign_raw_stream")):
        stream = [r for r in raw if role(r) == test_role]
        if not stream:
            continue
        hours = observed_hours(stream)
        res: Dict[str, Any] = {"observed_host_hours": hours, "raw_events": len(stream),
                               "hosts": len({r["host"] for r in stream})}
        lr_s = final_lr.decision_function(scaler.transform(matrix(stream, "A")))
        for name, s, t in (
            ("model_A", score("A", stream), variants["A"]["thresholds"]),
            ("logistic_regression", lr_s, base_t["lr"]),
            ("heuristic", np.array([heuristic_score(r) for r in stream]), base_t["heuristic"]),
        ):
            res[name] = {n: {"fp_events": int((s >= th).sum()), "fp_per_host_hour": float((s >= th).sum() / hours)}
                         for n, th in t.items()}
            if name == "model_A":
                res[name]["top_scores"] = [
                    {"score": round(float(s[i]), 3), "parent": leaf(stream[i]["parent_image"]),
                     "image": leaf(stream[i]["image"]), "command_line": (stream[i]["command_line"] or "")[:160]}
                    for i in np.argsort(-s)[:20]]
        fired = sum(1 for r in stream if rules.get(r["row_id"], 0.0) > 0)
        res["rules_only_any_fired"] = {"fp_events": fired, "fp_per_host_hour": fired / hours}
        tests[test_name] = res
    results["tests"] = tests

    # -------------------------------------------------- robustness (E3 positives, variant A)
    rng = random.Random(SEED)
    positives = [r for r in e3 if r["label"] == 1]
    base = score("A", positives)
    robust: Dict[str, Any] = {"n": len(positives), "baseline_recall_alert": float((base >= ta).mean())}
    for kind in MUTATIONS:
        mutated = score("A", [mutate(r, kind, rng) for r in positives])
        robust[kind] = {"recall_alert": float((mutated >= ta).mean()),
                        "mean_raw_score_change": float((mutated - base).mean())}
    results["robustness_E3_variant_A"] = robust

    # -------------------------------------------------- ablations (OOF PR-AUC)
    def masked(keep: Sequence[int]) -> sparse.csr_matrix:
        mask = np.zeros(len(F.FEATURE_NAMES))
        mask[list(keep)] = 1.0
        return sparse.csr_matrix(xa @ sparse.diags(mask))

    cmd_cols = {i for i, n in enumerate(F.FEATURE_NAMES) if n.startswith("cmd#")}
    names_cols = [i for i, n in enumerate(F.FEATURE_NAMES) if n.startswith(("name", "parent", "pair"))]
    ablations = {"full_A": pr_auc(y, variants["A"]["oof"]), "full_B": pr_auc(y, variants["B"]["oof"])}
    for label, keep in (("no_cmdline_ngrams", [i for i in range(len(F.FEATURE_NAMES)) if i not in cmd_cols]),
                        ("names_only", names_cols)):
        s, _ = oof_lgb(masked(keep), y, groups, params, folds)
        ablations[label] = pr_auc(y, s)
    results["ablations_oof_pr_auc"] = ablations

    # -------------------------------------------------- leakage probes
    sources_arr = np.array([r["source"] for r in pool])
    source_auc = {}
    for target in sorted(set(sources_arr.tolist())):
        yy = (sources_arr == target).astype(int)
        if 0 < yy.sum() < len(yy):
            s, _ = oof_lgb(xa, yy, groups, params, folds)
            source_auc[target] = roc(yy, s)
    results["leakage"] = {
        "source_predictability_auc": source_auc,
        "top_features_A": top_features(variants["A"]["booster"], pool),
        "top_features_B": top_features(variants["B"]["booster"], pool),
        "train_test_duplicate_keys": duplicates_across,
    }

    if export_dir is not None:
        results["export"] = export(export_dir, variants, params, pool, repo, data)
    return jsonable(results)


def jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items() if k not in ("booster", "oof", "prob")}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, (np.floating, float)):
        return None if math.isnan(float(obj)) else round(float(obj), 6)
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    return obj


def export(out: Path, variants, params, pool, repo: Path, data: Path) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    files: Dict[str, Any] = {}
    golden_rows = sorted(pool, key=lambda r: hashlib.sha256(r["row_id"].encode()).hexdigest())[:50]
    for variant, v in variants.items():
        folder = out / f"variant_{variant}"
        folder.mkdir(exist_ok=True)
        dump = v["booster"].dump_model()
        (folder / "model.json").write_text(json.dumps(dump, sort_keys=True) + "\n", encoding="utf-8")
        (folder / "features.json").write_text(json.dumps(
            {**F.feature_spec(), "variant": variant, "uses_integrity": variant == "B",
             "feature_names_sha256": hashlib.sha256("\n".join(F.FEATURE_NAMES).encode()).hexdigest()},
            indent=2) + "\n", encoding="utf-8")
        (folder / "calibration.json").write_text(
            json.dumps({"method": "platt", "a": v["a"], "b": v["b"]}, indent=2) + "\n", encoding="utf-8")
        (folder / "thresholds.json").write_text(json.dumps(
            {"raw_score": v["thresholds"], "budgets_fp_per_host_hour": BUDGETS}, indent=2) + "\n", encoding="utf-8")
        vectors = [vector(r, variant) for r in golden_rows]
        raw_scores = v["booster"].predict(matrix(golden_rows, variant), raw_score=True)
        golden = [{"row_id": r["row_id"], "vector": {str(k): x for k, x in vec.items()}, "raw_score": float(s)}
                  for r, vec, s in zip(golden_rows, vectors, raw_scores)]
        (folder / "golden.json").write_text(json.dumps(golden, indent=1) + "\n", encoding="utf-8")
        model = TreeModel.from_dump(dump)
        worst = max(abs(model.raw_score(vec) - s) for vec, s in zip(vectors, raw_scores))
        files[variant] = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
                          for name in ("model.json", "features.json", "calibration.json", "thresholds.json", "golden.json")}
        files[variant].update(golden_max_abs_error=float(worst), rounds=v["rounds"])
    pins = repo / "tools" / "train" / "pins.json"
    manifest = {
        "model_id": "panopticon-process-start-lgbm",
        "featurizer_version": F.FEATURIZER_VERSION,
        "params": {**BASE_PARAMS, **params},
        "engine_git_sha": git_sha(repo),
        "versions": {"lightgbm": lgb.__version__, "scikit_learn": sklearn.__version__,
                     "numpy": np.__version__, "python": platform.python_version()},
        "pins_sha256": hashlib.sha256(pins.read_bytes()).hexdigest() if pins.exists() else None,
        "labels_sha256": json.loads((data / "labelled" / "labels_manifest.json").read_text())["sha256"],
        "pool_rows": len(pool),
        "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
