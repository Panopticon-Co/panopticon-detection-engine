"""The process-start featurizer (v4): layout, normalisation, determinism and golden vectors.

Golden vectors pin the exact output for fixed inputs. If one of these fails
after an intentional change, bump FEATURIZER_VERSION and regenerate with
``python -m tests.ml.test_featurizer --regenerate`` -- every model trained on
the old version is then invalid, which is the point.
"""

from __future__ import annotations

import ast
import json
import math
import os
import subprocess
import sys
from pathlib import Path

import pytest

from panopticon_detection.ml import featurizer as F

GOLDEN = Path(__file__).with_name("golden_featurizer.json")
REPO = Path(__file__).resolve().parents[2]

CASES = [
    (
        "office_spawns_encoded_powershell",
        {
            "process": {
                "name": "powershell.exe",
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            },
            "parent": {"name": "WINWORD.EXE"},
            "user": {"name": "alice", "domain": "CORP"},
        },
        "Medium",
    ),
    (
        "rundll32_comsvcs_minidump",
        {
            "process": {
                "name": "rundll32.exe",
                "executable": r"C:\Windows\System32\rundll32.exe",
                "command_line": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\bob\AppData\Local\Temp\l.dmp full",
            },
            "parent": {"name": "cmd.exe"},
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
        },
        "System",
    ),
    (
        "benign_chrome_child",
        {
            "process": {
                "name": "chrome.exe",
                "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "command_line": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --lang=en-US',
            },
            "parent": {"name": "chrome.exe"},
            "user": {"name": "carol", "domain": "CORP"},
        },
        "Low",
    ),
    (
        "service_host",
        {
            "process": {
                "name": "svchost.exe",
                "executable": r"C:\Windows\System32\svchost.exe",
                "command_line": r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule",
            },
            "parent": {"name": "services.exe"},
            "user": {"name": "LOCAL SERVICE", "domain": "NT AUTHORITY"},
        },
        None,
    ),
    ("everything_missing", {"process": {}, "parent": {}, "user": {}}, None),
]


def _compute():
    return [
        {
            "id": cid,
            "event": event,
            "integrity": integrity,
            "vector": {str(k): v for k, v in F.featurize(event).items()},
        }
        for cid, event, integrity in CASES
    ]


def test_golden_vectors_are_unchanged():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["featurizer_version"] == F.FEATURIZER_VERSION
    assert golden["feature_count"] == len(F.FEATURE_NAMES)
    assert _compute() == golden["cases"]


def test_vectors_do_not_depend_on_pythonhashseed():
    code = (
        "import json;from panopticon_detection.ml import featurizer as F;"
        "from tests.ml.test_featurizer import CASES;"
        "print(json.dumps([F.featurize(e) for _,e,_i in CASES],sort_keys=True))"
    )
    outputs = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True, check=True
        )
        outputs.add(result.stdout)
    assert len(outputs) == 1


def test_every_value_is_finite_and_indexed():
    for _, event, _integrity in CASES:
        vector = F.featurize(event)
        assert all(0 <= i < len(F.FEATURE_NAMES) for i in vector)
        assert all(math.isfinite(v) and v != 0.0 for v in vector.values())


def test_user_identity_never_reaches_features():
    base = CASES[0][1]
    renamed = json.loads(json.dumps(base))
    renamed["user"] = {"name": "zed", "domain": "OTHERLAB"}
    assert F.featurize(base) == F.featurize(renamed)


def test_profile_paths_are_normalised_per_user():
    a = {
        "process": {
            "name": "x.exe",
            "executable": r"C:\Users\alice\AppData\Local\Temp\x.exe",
            "command_line": r"C:\Users\alice\AppData\Local\Temp\x.exe",
        },
        "parent": {"name": "explorer.exe"},
        "user": {"name": "alice"},
    }
    b = json.loads(json.dumps(a).replace("alice", "bob"))
    assert F.featurize(a) == F.featurize(b)
    assert (
        F.normalize_text(r"C:\Users\alice\x {0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0} 123456")
        == r"c:\users\<user>\x <guid> <n>"
    )


def test_carets_change_only_the_obfuscation_features():
    blob = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    plain = {"process": {"name": "cmd.exe", "executable": r"C:\Windows\System32\cmd.exe",
                         "command_line": f"cmd /c powershell -w hidden -enc {blob}"}, "parent": {"name": "winword.exe"}}
    caret = json.loads(json.dumps(plain))
    caret["process"]["command_line"] = f"cmd /c p^o^w^e^r^s^h^e^l^l -w h^idden -e^n^c {blob}"
    assert F.normalize_text("p^o^w^e^r^s^h^e^l^l -e^n^c AAA") == "powershell -enc aaa"
    obfuscation = {F.FEATURE_NAMES.index("cmd_obfuscated"), F.FEATURE_NAMES.index("cmd_evasion_count")}
    strip = lambda v: {i: x for i, x in v.items() if i not in obfuscation}  # noqa: E731
    assert strip(F.featurize(plain)) == strip(F.featurize(caret))
    assert F.featurize(plain)[F.FEATURE_NAMES.index("ind_ps_encoded")] == 1.0


@pytest.mark.parametrize(
    "name,domain,expected",
    [
        ("SYSTEM", "NT AUTHORITY", "system"),
        ("WS01$", "CORP", "system"),
        ("NETWORK SERVICE", "NT AUTHORITY", "service"),
        ("SERVICIO DE RED", None, "service"),
        ("alice", "CORP", "user"),
        (None, None, "unknown"),
    ],
)
def test_user_category(name, domain, expected):
    assert F.user_category(name, domain) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [("Medium", "medium"), ("High", "high"), ("System", "system"), ("Low", "low"),
     (None, "missing"), ("", "missing"), ("weird", "missing")],
)
def test_integrity_category(raw, expected):
    assert F.integrity_category(raw) == expected


def test_featurizer_is_stdlib_only_and_never_calls_hash():
    tree = ast.parse(Path(F.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "hash", "built-in hash() is seeded per process"
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            root = (module or "").split(".")[0]
            assert root in sys.stdlib_module_names or root in ("panopticon_detection", "__future__")


if __name__ == "__main__" and "--regenerate" in sys.argv:
    GOLDEN.write_text(
        json.dumps(
            {"featurizer_version": F.FEATURIZER_VERSION, "feature_count": len(F.FEATURE_NAMES), "cases": _compute()},
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {GOLDEN}")
