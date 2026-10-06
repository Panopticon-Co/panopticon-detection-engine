"""Discovers, resolves and validates YAML detection rules.

Rules may reference named value lists as ``$name``. A list lives in
``<rules_dir>/lists/<name>.yaml`` as ``values: [...]``; a condition value of
``"$office"`` becomes that list, and a ``"$office"`` item inside a list is
spliced in place. Keeping LOLBin / Office / script-host names in one file
means a correction lands in every rule that uses them.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from panopticon_detection.rules.schema import RULE_TYPES, AnyRule, RuleStatus
from panopticon_detection.rules.validator import RuleValidationError, RuleValidator

LISTS_DIR = "lists"


def load_lists(lists_dir: Union[str, Path]) -> Dict[str, List[Any]]:
    """Read every ``<name>.yaml`` under ``lists_dir`` into ``{name: values}``."""
    path = Path(lists_dir)
    lists: Dict[str, List[Any]] = {}
    if not path.is_dir():
        return lists
    for file_path in sorted(path.glob("*.y*ml")):
        data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        values = data.get("values") if isinstance(data, dict) else None
        if not isinstance(values, list) or not values:
            raise RuleValidationError(f"List {file_path} must define a non-empty 'values' list")
        lists[file_path.stem] = values
    return lists


def _resolve_refs(node: Any, lists: Dict[str, List[Any]], where: str) -> Any:
    """Replace ``$name`` references to named lists, recursively."""
    if isinstance(node, dict):
        return {k: _resolve_refs(v, lists, where) for k, v in node.items()}
    if isinstance(node, list):
        out: List[Any] = []
        for item in node:
            if isinstance(item, str) and item.startswith("$"):
                out.extend(_lookup(item, lists, where))
            else:
                out.append(_resolve_refs(item, lists, where))
        return out
    if isinstance(node, str) and node.startswith("$"):
        return list(_lookup(node, lists, where))
    return node


def _lookup(ref: str, lists: Dict[str, List[Any]], where: str) -> List[Any]:
    name = ref[1:]
    if name not in lists:
        raise RuleValidationError(f"{where} references unknown list '{ref}'")
    return lists[name]


class RuleLoader:
    """Discovers, parses, validates, and indexes detection rules."""

    def __init__(
        self,
        validator: Optional[RuleValidator] = None,
        lists: Optional[Dict[str, List[Any]]] = None,
    ):
        self.validator = validator or RuleValidator()
        self.lists: Dict[str, List[Any]] = dict(lists or {})

    def load_file(self, file_path: Union[str, Path]) -> AnyRule:
        """Load and validate a single YAML rule file of any type."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Rule file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
        if not isinstance(raw_data, dict):
            raise RuleValidationError(f"File {path} does not contain a valid YAML dictionary")

        rule_type = raw_data.get("type", "single")
        model = RULE_TYPES.get(rule_type)
        if model is None:
            raise RuleValidationError(
                f"File {path} has unknown rule type '{rule_type}'; "
                f"expected one of {sorted(RULE_TYPES)}"
            )
        rule = model(**_resolve_refs(raw_data, self.lists, str(path)))
        self.validator.validate_rule(rule)
        return rule

    def load_directory(self, dir_path: Union[str, Path], recursive: bool = True) -> List[AnyRule]:
        """Load every enabled rule under ``dir_path`` (lists are not rules).

        Every rule is expected to read telemetry a Panopticon agent can
        actually emit; ``scripts/check_rule_sourcing.py`` enforces that in CI.
        """
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Rules directory not found: {path}")

        self.lists.update(load_lists(path / LISTS_DIR))
        lists_root = (path / LISTS_DIR).resolve()

        pattern = "**/*.y*ml" if recursive else "*.y*ml"
        rules: List[AnyRule] = []
        for file_path in sorted(path.glob(pattern)):
            if lists_root in file_path.resolve().parents:
                continue
            try:
                rule = self.load_file(file_path)
            except Exception as e:
                raise RuleValidationError(f"Failed loading rule {file_path}: {e}") from e
            if rule.status == RuleStatus.ENABLED:
                rules.append(rule)
        return rules
