"""Structural validation for detection rules (all four rule types)."""

import re
from typing import Set

from panopticon_detection.rules.schema import (
    KEY_KINDS,
    AnyRule,
    Condition,
    LogicNode,
    ValueCountRule,
    logic_blocks_of,
)

VALID_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "starts_with",
    "ends_with",
    "regex",
    "greater_than",
    "less_than",
    "exists",
    "has_ancestor",
    "in_threat_intel",
    "entropy_greater_than",
    "cidr",
    "windash",
}

_FIELD_PATH = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$")


class RuleValidationError(Exception):
    """Raised when a detection rule fails validation."""


class RuleValidator:
    """Validates rule integrity, logical structure, and operator correctness."""

    def __init__(self):
        self.seen_rule_ids: Set[str] = set()

    def validate_rule(self, rule: AnyRule) -> None:
        if not rule.id or not rule.id.strip():
            raise RuleValidationError("Rule must have a non-empty 'id'")
        if rule.id in self.seen_rule_ids:
            raise RuleValidationError(f"Duplicate rule ID detected: '{rule.id}'")
        if not rule.name or not rule.name.strip():
            raise RuleValidationError(f"Rule '{rule.id}' must have a non-empty 'name'")

        for event_type, logic in logic_blocks_of(rule):
            if not event_type or not event_type.strip():
                raise RuleValidationError(f"Rule '{rule.id}' must specify an 'event_type'")
            self._validate_logic_node(rule.id, logic)

        for key in getattr(rule, "by", []) or []:
            if key not in KEY_KINDS and not _FIELD_PATH.match(key):
                raise RuleValidationError(
                    f"Rule '{rule.id}' keys on '{key}', which is neither an entity kind "
                    f"({sorted(KEY_KINDS)}) nor a dotted event field"
                )
        if isinstance(rule, ValueCountRule) and not _FIELD_PATH.match(rule.field):
            raise RuleValidationError(f"Rule '{rule.id}' counts an invalid field '{rule.field}'")

        self.seen_rule_ids.add(rule.id)

    def _validate_logic_node(self, rule_id: str, node: LogicNode) -> None:
        has_condition = False
        for branch, items in [("all", node.all), ("any", node.any), ("none", node.none)]:
            if items is None:
                continue
            if len(items) == 0:
                raise RuleValidationError(f"Rule '{rule_id}' has an empty '{branch}' block")
            has_condition = True
            for item in items:
                if isinstance(item, Condition):
                    self._validate_condition(rule_id, item)
                elif isinstance(item, LogicNode):
                    self._validate_logic_node(rule_id, item)
        if not has_condition:
            raise RuleValidationError(
                f"Rule '{rule_id}' has an empty logic block without conditions"
            )

    def _validate_condition(self, rule_id: str, condition: Condition) -> None:
        if condition.operator not in VALID_OPERATORS:
            raise RuleValidationError(
                f"Rule '{rule_id}' uses unknown operator '{condition.operator}'. "
                f"Valid operators: {sorted(VALID_OPERATORS)}"
            )
        if not condition.field or not condition.field.strip():
            raise RuleValidationError(f"Rule '{rule_id}' has a condition with an empty 'field'")
        if condition.operator == "regex":
            try:
                re.compile(str(condition.value))
            except re.error as e:
                raise RuleValidationError(
                    f"Rule '{rule_id}' has invalid regex '{condition.value}': {e}"
                )
        if condition.operator in ("in", "not_in") and not isinstance(
            condition.value, (list, set, tuple)
        ):
            raise RuleValidationError(
                f"Rule '{rule_id}' operator '{condition.operator}' requires a list/array value"
            )
        if condition.operator == "exists" and not isinstance(condition.value, bool):
            raise RuleValidationError(
                f"Rule '{rule_id}' operator 'exists' takes true or false"
            )
