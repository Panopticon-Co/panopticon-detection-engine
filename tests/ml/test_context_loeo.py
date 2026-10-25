"""Context-model decision run (pdtrain.context_loeo): admission, masking, fold smoke test."""

from __future__ import annotations

import math

import numpy as np
import pytest

pytest.importorskip("lightgbm")

from pdtrain import context_loeo as K  # noqa: E402

from panopticon_detection.features import FEATURE_SCHEMA_VERSION  # noqa: E402
from panopticon_detection.ml import context_featurizer as CF  # noqa: E402


def _features(bits=(), parent="explorer.exe", minute=0):
    return dict(
        feature_schema_version=FEATURE_SCHEMA_VERSION, host_id="h", node_id="n", pid=1, parent_pid=2,
        name="x.exe", executable=r"C:\Windows\System32\x.exe", path_class="system",
        start_time="2026-01-01T10:00:00", user="u", inferred=False, parent_name=parent, grandparent_name=None,
        tree_root_name=None, depth=1, parent_child=None, cmdline_length=1, cmdline_token_count=1,
        cmdline_entropy=0.0, cmdline_obfuscated=False, cmdline_evasion_count=0, image_writer_name=None,
        image_age_seconds=None, child_count=0, file_write_count=0, executable_write_count=0,
        registry_write_count=0, network_connect_count=0, public_connect_count=0, module_load_count=0,
        lifetime_seconds=None, dns_query_count=0, distinct_domain_count=0, failed_dns_query_count=0,
        process_access_count=0, lsass_access_count=0, remote_thread_count=0, injected_thread_count=0,
        access_targets=[], remote_thread_targets=[], script_block_count=0, script_block_bytes=0,
        obfuscated_script_block_count=0, as_of=f"2026-01-01T10:{minute:02d}:30", ancestor_names=[parent],
        behavior_bits=list(bits), behavior_bit_objects=[[b, 1] for b in bits])


def _proc(i, env, label, families, bits=(), group=None, host="h"):
    return K.Proc(uid=f"{env}-{i}", env=env, unit=env, host=host, label=label,
                  row={"image": r"C:\Windows\System32\x.exe", "parent_image": r"C:\Windows\explorer.exe",
                       "command_line": "x", "event": {"process": {"executable": r"C:\Windows\System32\x.exe"}}},
                  start_ts="2026-01-01T10:00:00.000Z", start_vector={},
                  families=frozenset(families), checkpoints=[("start", "2026-01-01T10:00:00", _features()),
                                                             ("bit", "2026-01-01T10:00:30", _features(bits))],
                  group=group or f"{env}:{host}" if label == 0 else group or f"T:{i % 9}")


def test_admission_rule_reads_the_census_only():
    cen = {
        "optc": {"host_hours": 200.0, "hours_with_family": {"network": 200.0, "registry": 190.0}},
        "officer_vm": {"host_hours": 4.0, "hours_with_family": {}},
        "attack_range": {"host_hours": 100.0, "hours_with_family": {"network": 40.0, "registry": 70.0}},
        "mordor": {"host_hours": 30.0, "hours_with_family": {"network": 30.0, "registry": 30.0, "dns": 30.0}},
        "botsv1": {"host_hours": 18.0, "hours_with_family": {"network": 18.0}},
    }
    groups, decision = K.admitted_groups(cen)
    assert "network" in groups and "registry" in groups  # network: mordor + botsv1; registry: attack_range + mordor
    assert "dns" not in groups  # no benign-only environment collects it
    assert set(K.CF.CORE_GROUPS) <= set(groups)
    assert decision["network"]["attack_envs"] == ["mordor", "botsv1"]


def test_masked_copies_keep_each_process_weight_and_carry_nan():
    procs = [_proc(1, "optc", 0, {"network", "registry"}), _proc(2, "attack_range", 1, {"network", "registry"},
                                                                 bits=("network:public_destination",))]
    groups = ["start", "lineage", "children", "network", "registry"]
    matrix = K.Matrix(procs, groups)
    x, y, w, g = K.training_set(procs, groups, (0.5, {"network": 0.1, "registry": 0.1}), matrix)
    assert x.shape[0] == 2 * 2 * 4  # 2 processes x 2 checkpoints x (base + all-masked + 2 single masks)
    for label in (0, 1):
        assert math.isclose(w[y == label].sum(), 1.0)  # one process per class, balanced weights of 1
    dense = x.toarray()
    net = CF.FEATURE_NAMES.index("network:public_destination")
    assert np.isnan(dense[:, net]).any() and not np.isnan(dense[:4, net]).any()


def test_fold_smoke_run_scores_every_environment():
    procs = []
    for env, label, n, fams in (("attack_range", 1, 120, {"network"}), ("mordor", 1, 60, {"network"}),
                                ("optc", 0, 200, {"network"}), ("officer_vm", 0, 60, set()),
                                ("attack_range", 0, 40, {"network"}), ("mordor", 0, 40, {"network"})):
        for i in range(n):
            bits = ("network:public_destination",) if label == 1 and i % 3 else ()
            procs.append(_proc(f"{label}{i}", env, label, fams, bits=bits, host=f"{env}{i % 4}",
                               group=f"T:{i % 9}" if label else None))
    hours = {"attack_range": 10.0, "mordor": 10.0, "optc": 100.0, "officer_vm": 4.0}
    hours_of_host = {(p.env, p.host): 1.0 for p in procs}
    groups = ["start", "lineage", "children", "network"]
    matrix = K.Matrix(procs, groups)
    result, models = K.run_model(procs, hours, hours_of_host, K.CANDIDATES["ctx_lgb"], matrix,
                                 ["attack_range", "mordor", "optc", "officer_vm"], details=True)
    assert set(result["folds"]) == {"attack_range", "mordor", "optc", "officer_vm"}
    assert result["summary"]["recall_alert"]["attack_range"] is not None
    assert all(set(r["thresholds_per_training_environment"]) <= set(hours) for r in result["folds"].values())
