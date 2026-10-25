"""Field extraction, condition matching, and condition-tree evaluation.

``evaluate_logic`` is the single implementation of the rule condition tree
(``all`` / ``any`` / ``none``); single-event and stateful rules both use it. It
optionally records which conditions matched and with what value, which is what
lets an alert explain itself instead of only naming the rule that fired.
"""

from typing import Any, Dict, List, Optional

from panopticon_detection import enrichment
from panopticon_detection.enrichment import MatchContext
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator
from panopticon_detection.evaluator.operators import NEGATED_OPERATORS, OPERATOR_MAP
from panopticon_detection.rules.schema import Condition, LogicNode


def extract_field(
    event: Dict[str, Any],
    field_path: str,
    registry=None,
    threat_intel=None,
    graph=None,
    ctx: Optional[MatchContext] = None,
) -> Any:
    """A dotted field from the event, or a derived one from the enrichment layer."""
    if field_path in enrichment.DERIVED_FIELDS:
        context = ctx or MatchContext(registry=registry, graph=graph, threat_intel=threat_intel)
        return enrichment.derive(event, field_path, context)

    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def match_condition(condition: Condition, event: Dict[str, Any], ctx: MatchContext) -> tuple:
    """``(matched, actual_value)`` for one condition."""
    if condition.operator == "has_ancestor":
        # The declared field is documentation only: ancestry is a property of
        # the process that emitted the event, resolved through the registry, so
        # it works on a process_create and on that process's later telemetry.
        if ctx.registry is None:
            return False, None
        actor = ctx.registry.resolve_event(event)
        if actor is None:
            return False, None
        targets = condition.value if isinstance(condition.value, list) else [condition.value]
        wanted = {str(t).lower() for t in targets}
        names = [a.name for a in ctx.registry.ancestors(actor.node_id)]
        hit = next((n for n in names if n in wanted), None)
        return hit is not None, hit

    actual = extract_field(event, condition.field, ctx=ctx)

    if condition.operator == "in_threat_intel":
        if ctx.threat_intel is None:
            return False, actual
        kind = str(condition.value).lower()
        if kind in ("hash", "file_hash", "sha256", "md5"):
            return ctx.threat_intel.check_hash(actual) is not None, actual
        if kind in ("ip", "ip_address", "c2"):
            return ctx.threat_intel.check_ip(actual) is not None, actual
        return False, actual

    if condition.operator == "entropy_greater_than":
        entropy = ShannonEntropyCalculator.calculate_entropy(str(actual or ""))
        try:
            return entropy >= float(condition.value), round(entropy, 3)
        except (ValueError, TypeError):
            return False, entropy

    op = OPERATOR_MAP.get(condition.operator)
    if op is None:
        return False, actual
    matched = op(actual, condition.value, case_sensitive=condition.case_sensitive)

    # A command line that does not match as written is re-checked in its
    # deobfuscated form (carets, backticks, concatenation, -enc payloads).
    # Only for positive operators: re-running a negation against a different
    # string could turn "does not contain X" into a match it never earned.
    if (
        not matched
        and condition.field == "process.command_line"
        and condition.operator not in NEGATED_OPERATORS
    ):
        decoded = extract_field(event, "process.deobfuscated_command", ctx=ctx)
        if decoded and decoded != actual:
            matched = op(decoded, condition.value, case_sensitive=condition.case_sensitive)
            if matched:
                actual = decoded
    return matched, actual


class ConditionMatcher:
    """Kept for callers that match one condition at a time."""

    @staticmethod
    def evaluate(condition, event, registry=None, threat_intel=None, graph=None) -> bool:
        ctx = MatchContext(registry=registry, graph=graph, threat_intel=threat_intel)
        return match_condition(condition, event, ctx)[0]


def evaluate_logic(
    node: LogicNode,
    event: Dict[str, Any],
    ctx: MatchContext,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """Evaluate a condition tree with short-circuiting.

    When ``trace`` is given, the conditions that made the tree true are
    appended to it; conditions from branches that ultimately failed are not.
    """
    local: List[Dict[str, Any]] = []

    def check(item) -> bool:
        if isinstance(item, Condition):
            matched, actual = match_condition(item, event, ctx)
            if matched:
                local.append(_describe(item, actual))
            return matched
        sub: List[Dict[str, Any]] = []
        ok = evaluate_logic(item, event, ctx, sub)
        if ok:
            local.extend(sub)
        return ok

    if node.all is not None and not all(check(item) for item in node.all):
        return False

    if node.any is not None and not any(check(item) for item in node.any):
        return False

    if node.none is not None:
        for item in node.none:
            if isinstance(item, Condition):
                if match_condition(item, event, ctx)[0]:
                    return False
            elif evaluate_logic(item, event, ctx):
                return False

    if trace is not None:
        trace.extend(local)
    return True


def _describe(condition: Condition, actual: Any) -> Dict[str, Any]:
    shown = actual
    if isinstance(shown, str) and len(shown) > 160:
        shown = shown[:157] + "..."
    return {
        "field": condition.field,
        "operator": condition.operator,
        "value": condition.value,
        "actual": shown,
    }


def format_trace(trace: List[Dict[str, Any]]) -> List[str]:
    """Human-readable matched conditions for alert evidence."""
    lines = []
    for entry in trace:
        value = entry["value"]
        if isinstance(value, list) and len(value) > 6:
            value = value[:6] + ["..."]
        lines.append(f"{entry['field']} {entry['operator']} {value!r} (saw {entry['actual']!r})")
    return lines
