#!/usr/bin/env python3
"""CI gate: every rule must read telemetry a Panopticon agent can actually emit.

A rule that can never fire is not coverage, it is a claim. Two ways a rule
silently never fires, both checked here for every rule type (single, sequence,
threshold, value_count):

1. Its ``event_type`` is one the normalizer never produces. 38 such rules once
   shipped unnoticed.
2. A field it reads -- in a condition, a ``by`` key, a counted ``field`` or its
   ``evidence`` list -- is one the normalizer never emits for that event type
   and no enrichment derives. Three rules once depended solely on fields like
   ``process.ppid_spoofed`` that nothing produced; their tests injected the
   field by hand, so the suite passed while the rules were dead.

The producible vocabulary is derived, not hand-kept: ``ingestion.telemetry``
builds ``FIELD_REGISTRY`` by running every normalizer on a fully populated
agent event, and ``enrichment.DERIVED_FIELDS`` declares which event types each
derived field applies to.

There is no exemption list. Exits non-zero and names every offender.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from panopticon_detection.enrichment import derived_available  # noqa: E402
from panopticon_detection.ingestion.telemetry import FIELD_REGISTRY  # noqa: E402
from panopticon_detection.rules.loader import RuleLoader  # noqa: E402
from panopticon_detection.rules.schema import (  # noqa: E402
    KEY_KINDS,
    Condition,
    LogicNode,
    ValueCountRule,
    logic_blocks_of,
)

# ``has_ancestor`` resolves ancestry through the provenance registry; its field
# is documentation only.
_FIELD_IGNORED_OPERATORS = {"has_ancestor"}


def _producible(field: str, event_type: str) -> bool:
    return field in FIELD_REGISTRY.get(event_type, ()) or derived_available(field, event_type)


def _conditions(node: LogicNode):
    for branch in (node.all, node.any, node.none):
        for item in branch or []:
            if isinstance(item, Condition):
                yield item
            else:
                yield from _conditions(item)


def check(rules_dir: Path) -> List[str]:
    problems: List[str] = []
    for rule in RuleLoader().load_directory(rules_dir):
        blocks = logic_blocks_of(rule)
        event_types = [event_type for event_type, _ in blocks]
        for event_type, logic in blocks:
            if event_type not in FIELD_REGISTRY:
                problems.append(f"{rule.id}: event_type '{event_type}' is never produced")
                continue
            for cond in _conditions(logic):
                if cond.operator in _FIELD_IGNORED_OPERATORS:
                    continue
                if not _producible(cond.field, event_type):
                    problems.append(
                        f"{rule.id}: condition field '{cond.field}' is never produced "
                        f"for {event_type}"
                    )

        # A 'by' field keys every event the rule sees; evidence is read from
        # the event that completes the rule (a sequence's final step).
        for key in getattr(rule, "by", []) or []:
            if key in KEY_KINDS:
                continue
            for event_type in event_types:
                if not _producible(key, event_type):
                    problems.append(f"{rule.id}: 'by' field '{key}' is never produced for {event_type}")
        if isinstance(rule, ValueCountRule) and not _producible(rule.field, rule.event_type):
            problems.append(
                f"{rule.id}: counted field '{rule.field}' is never produced for {rule.event_type}"
            )
        for field in rule.evidence:
            if not _producible(field, event_types[-1]):
                problems.append(
                    f"{rule.id}: evidence field '{field}' is never produced for {event_types[-1]}"
                )
    return problems


def main() -> int:
    rules_dir = REPO_ROOT / "rules"
    problems = check(rules_dir)
    if problems:
        print("Rules reading telemetry no Panopticon agent emits:\n")
        for problem in problems:
            print(f"  {problem}")
        print(
            f"\n{len(problems)} problem(s). Correct the rule to read fields the normalizer "
            "or enrichment layer produces, or delete it -- do not ship a rule that can "
            "never fire."
        )
        return 1
    count = len(RuleLoader().load_directory(rules_dir))
    print(f"OK: all {count} rule(s) read only producible telemetry, field by field.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
