#!/usr/bin/env python3
"""CI gate: the engine's runtime dependencies stay exactly pyyaml + pydantic.

Two checks, both must pass:

1. ``[project].dependencies`` in pyproject.toml names only ``pyyaml`` and
   ``pydantic``. Training and test tooling belong in optional extras.
2. Every import under ``panopticon_detection/`` resolves to the standard
   library, ``yaml``, ``pydantic`` or the package itself -- so an ML library
   (lightgbm, sklearn, numpy, ...) can never leak into the runtime, even
   through an import that happens to work on a developer's machine.

Usage: python scripts/check_runtime_deps.py   (exit 1 on any violation)
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import List

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_DISTRIBUTIONS = {"pyyaml", "pydantic"}
ALLOWED_IMPORT_ROOTS = {"yaml", "pydantic", "panopticon_detection", "__future__"}


def _dependencies() -> List[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if tomllib is not None:
        return list(tomllib.loads(text)["project"]["dependencies"])
    match = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
    return re.findall(r"\"([^\"]+)\"", match.group(1)) if match else []


def check() -> List[str]:
    problems: List[str] = []
    for requirement in _dependencies():
        name = re.split(r"[<>=!~\[; ]", requirement, maxsplit=1)[0].strip().lower()
        if name not in ALLOWED_DISTRIBUTIONS:
            problems.append(f"pyproject.toml: runtime dependency {requirement!r} is not allowed")

    for path in sorted((ROOT / "panopticon_detection").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = [node.module.split(".")[0]]
            else:
                continue
            for root in roots:
                if root not in sys.stdlib_module_names and root not in ALLOWED_IMPORT_ROOTS:
                    rel = path.relative_to(ROOT)
                    problems.append(f"{rel}:{node.lineno}: imports {root!r}, which is not a runtime dependency")
    return problems


def main() -> int:
    problems = check()
    for problem in problems:
        print(f"[FAIL] {problem}")
    if problems:
        return 1
    print("OK: runtime dependencies are pyyaml + pydantic; panopticon_detection imports nothing else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
