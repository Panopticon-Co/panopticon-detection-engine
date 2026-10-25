"""Leave-one-environment-out harness (pdtrain.loeo): units, splits, thresholds, mutations, a smoke run."""

from __future__ import annotations

import pytest

pytest.importorskip("lightgbm")

import numpy as np  # noqa: E402
from pdtrain import loeo as L  # noqa: E402
from pdtrain.label import dedup_key  # noqa: E402


def _row(source, i, label, cmd, image="C:\\Windows\\System32\\cmd.exe", parent="explorer.exe", host="h1",
         group=None, dataset=None, minute=0, tool=None):
    name = image.rsplit("\\", 1)[-1]
    row = {
        "row_id": f"{source}:{host}:{i}:{minute}", "source": source, "dataset": dataset or f"{source}:rec",
        "host": host, "utc": f"2026-01-01T{10 + minute // 60:02d}:{minute % 60:02d}:00.000Z", "label": label,
        "label_rule": "x", "group": group or (f"{source}:{host}" if label == 0 else f"T:{i % 7}"),
        "tool": tool, "image": image, "parent_image": f"C:\\Windows\\{parent}", "command_line": cmd,
        "integrity": None,
        "event": {"event_type": "process_create",
                  "process": {"name": name, "executable": image, "command_line": cmd},
                  "parent": {"name": parent}, "user": {"name": "u", "domain": "d"}},
    }
    row["dedup_key"] = dedup_key(row)
    return row


def test_units_dedup_within_environment_and_flag_conflicts():
    raw = [
        _row("optc", 1, 0, "cmd /c dir", minute=1), _row("optc", 2, 0, "cmd /c dir", minute=2),
        _row("officer_vm", 3, 0, "cmd /c dir"),                       # same key, another environment
        _row("attack_data", 4, 1, "cmd /c dir"),                      # same key, malicious -> conflict
        _row("atlasv2", 5, 1, "payload.exe", dataset="atlasv2:attack/h1/sysmon-h1-m1.xml", host="h1"),
        _row("atlasv2", 6, 1, "payload.exe -x", dataset="atlasv2:attack/h2/sysmon-h2-m1.xml", host="h2"),
    ]
    units, info = L.build_units(raw)
    by = {(u.env, u.label, u.row["command_line"]): u for u in units}
    optc = by[("optc", 0, "cmd /c dir")]
    assert optc.count == 2 and optc.conflict and by[("officer_vm", 0, "cmd /c dir")].count == 1
    assert info["conflict_keys"] == 1
    m1, m1b = by[("atlasv2", 1, "payload.exe")], by[("atlasv2", 1, "payload.exe -x")]
    assert m1.group == m1b.group  # h1-m1 and h2-m1 are one attack scenario


def test_templates_merge_near_duplicate_attack_groups():
    raw = [_row("attack_data", 1, 1, "cmd /c ping 10.0.0.1", group="T:1"),
           _row("attack_data", 2, 1, "cmd /c ping 10.0.0.2", group="T:2"),
           _row("attack_data", 3, 1, "cmd /c whoami", group="T:3")]
    units, info = L.build_units(raw)
    groups = {u.row["command_line"]: u.group for u in units}
    assert groups["cmd /c ping 10.0.0.1"] == groups["cmd /c ping 10.0.0.2"] != groups["cmd /c whoami"]
    assert info["malicious_groups_merged_by_template"] == 1


def test_training_units_exclude_held_out_conflicts_and_infrastructure():
    raw = [_row("optc", i, 0, f"a{i}.exe run", minute=i) for i in range(5)]
    raw += [_row("attack_data", 9, 0, "C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunkd.exe x")]
    raw += [_row("attack_data", 10 + i, 1, f"evil{i}.exe go") for i in range(3)]
    units, _ = L.build_units(raw)
    train = L.training_units(units, L.RECIPES["v7_lgb"], held_out="optc")
    assert {u.env for u in train} == {"attack_range"} and not any(u.infra for u in train)
    assert len(L.training_units(units, L.RECIPES["v7_lgb"], held_out=None)) == 8


def test_minimax_threshold_meets_the_budget_in_every_environment():
    units, _ = L.build_units(
        [_row("optc", i, 0, f"x{i}", minute=i) for i in range(60)]
        + [_row("officer_vm", i, 0, f"y{i}", minute=i) for i in range(60)])
    rng = np.random.default_rng(0)
    scores = {u.uid: float(rng.normal(3.0 if u.env == "officer_vm" else 0.0, 1.0)) for u in units}
    hours = {"optc": 10.0, "officer_vm": 1.0}
    minimax, per_env = L._thresholds("minimax", units, scores, hours)
    pooled, _ = L._thresholds("pooled", units, scores, hours)
    for env, h in hours.items():
        fp = sum(u.count for u in units if u.env == env and scores[u.uid] >= minimax["alert"])
        assert fp <= h * L.BUDGETS["alert"]
        assert minimax["alert"] >= per_env[env]["alert"]
    assert pooled["alert"] <= minimax["alert"]


@pytest.mark.parametrize("kind,expect", [
    ("quote_split", 'po""wershell'),
    ("envvar_substring", "po%LOCALAPPDATA:~0,0%wershell"),
    ("unicode_dash", "\u2013enc"),
    ("flag_prefix", "-encodedcomm"),
])
def test_mutations_change_the_command_line(kind, expect):
    row = _row("attack_data", 1, 1, "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
               image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert expect in L.mutate(row, kind)["event"]["process"]["command_line"]


def test_framework_mapping():
    assert L.framework({"source": "otrf", "tool": "otrf", "dataset": "x/empire_wmic_add_user.zip"}) == "empire"
    assert L.framework({"source": "attack_data", "tool": "atomic_red_team", "dataset": "a"}) == "atomic_red_team"
    assert L.framework({"source": "otrf_compound", "tool": "LSASS_campaign_01", "dataset": "a"}) == "metasploit"


def test_smoke_run_recipe_end_to_end():
    raw = []
    for env_source, host_count in (("optc", 3), ("officer_vm", 1), ("botsv1", 2)):
        for h in range(host_count):
            raw += [_row(env_source, i, 0, f"C:\\Program Files\\app{i % 9}\\app.exe --run {i}",
                         image=f"C:\\Program Files\\app{i % 9}\\app.exe", host=f"{env_source}{h}", minute=i)
                    for i in range(40)]
    for src in ("attack_data", "otrf"):
        raw += [_row(src, i, 1, f"powershell -nop -w hidden -enc {'QUFB' * (5 + i)}",
                     image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     parent="winword.exe", group=f"T:{i}") for i in range(12)]
        raw += [_row(src, 100 + i, 0, f"C:\\Windows\\System32\\svchost.exe -k svc{i}",
                     image="C:\\Windows\\System32\\svchost.exe", parent="services.exe", host=f"{src}h",
                     minute=i) for i in range(15)]
    units, _ = L.build_units(raw)
    hours = L.hours_by_environment(raw)
    result, fits = L.run_recipe(units, hours, L.RECIPES["v7_lgb"], fired={})
    assert set(result["folds"]) == {"attack_range", "mordor", "botsv1", "officer_vm", "optc"}
    for env, res in result["folds"].items():
        assert set(res["thresholds_per_training_environment"]) <= set(L.ENVIRONMENTS) - {env}
        assert res["alert"]["fp_per_host_hour"] is not None
    assert result["summary"]["recall_unique_alert"]["attack_range"] is not None
    assert L.robustness(units, fits)["flag_prefix"]["changed_rows"] > 0


@pytest.mark.parametrize("recipe", ["v7_lgb", "v7_lr", "v7_tokens"])
def test_export_bundle_matches_the_pure_python_scorer(tmp_path, recipe):
    raw = [_row("optc", i, 0, f"C:\\Program Files\\app{i % 7}\\app.exe --run {i}",
                image=f"C:\\Program Files\\app{i % 7}\\app.exe", host=f"o{i % 4}", minute=i) for i in range(80)]
    raw += [_row("officer_vm", i, 0, f"git status {i}", image="C:\\Program Files\\Git\\git.exe", minute=i)
            for i in range(30)]
    verbs = ("whoami", "certutil -urlcache -f", "vssadmin delete shadows", "net user x /add", "wevtutil cl",
             "schtasks /create /tn", "reg save hklm\\sam", "mshta", "regsvr32 /i:http", "bitsadmin /transfer")
    raw += [_row(src, i, 1, f"cmd /c {verbs[i % 10]} {'abcdefghij'[i // 10]}{src}",
                 parent="winword.exe", group=f"T:{i}") for src in ("attack_data", "otrf") for i in range(20)]
    units, _ = L.build_units(raw)
    hours = L.hours_by_environment(raw)
    fit = L.fit(units, hours, L.RECIPES[recipe])
    manifest = L.export(tmp_path / "bundle", fit, units, tmp_path, tmp_path, hours)
    assert manifest["golden_max_abs_error"] < 1e-9
    assert {p.name for p in (tmp_path / "bundle").iterdir()} == {
        "model.json", "features.json", "thresholds.json", "calibration.json", "golden.json", "manifest.json"}
    probe = L.environment_probe(units, L.RECIPES[recipe], fit)
    assert set(probe["benign_environment_auc"]) == {"optc", "officer_vm"}
