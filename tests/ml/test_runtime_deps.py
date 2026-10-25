"""The runtime-dependency gate passes on the tree and catches a leaked import."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_runtime_deps.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_runtime_deps", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tree_passes():
    assert _load().check() == []


def test_a_leaked_ml_import_fails(tmp_path, monkeypatch):
    gate = _load()
    package = tmp_path / "panopticon_detection"
    package.mkdir()
    (package / "leak.py").write_text("import lightgbm\nfrom numpy import array\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies = ["pyyaml>=6", "pydantic>=2", "numpy"]\n', encoding="utf-8"
    )
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    problems = gate.check()
    assert any("numpy" in p and "pyproject" in p for p in problems)
    assert any("'lightgbm'" in p for p in problems)
    assert any("'numpy'" in p and "leak.py" in p for p in problems)
