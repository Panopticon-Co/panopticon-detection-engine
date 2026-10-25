"""Single-event rule evaluation.

Stateful rules (sequence / threshold / value_count) are evaluated by
:mod:`panopticon_detection.evaluator.stateful`; this evaluator ignores them, so a
mixed rule list from ``RuleLoader.load_directory`` can be handed to either.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from panopticon_detection.enrichment import MatchContext
from panopticon_detection.evaluator.matcher import evaluate_logic, extract_field, format_trace
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.rules.schema import Rule
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine

_log = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """A rule match with the evidence that supports it."""

    rule: Any
    event: Dict[str, Any]
    matched_evidence: Dict[str, Any] = field(default_factory=dict)
    # The conditions that made the rule true and the values they saw.
    matched_conditions: List[str] = field(default_factory=list)


def collect_evidence(rule, event: Dict[str, Any], ctx: MatchContext) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {}
    for field_path in rule.evidence:
        value = extract_field(event, field_path, ctx=ctx)
        if value is not None:
            evidence[field_path] = value
    return evidence


class RuleEvaluator:
    """Evaluates telemetry events against single-event rules."""

    def __init__(
        self,
        rules: Optional[List[Any]] = None,
        registry: Optional[ProcessRegistry] = None,
        threat_intel: Optional[ThreatIntelEngine] = None,
        graph=None,
    ):
        self.registry = registry
        self.threat_intel = threat_intel or ThreatIntelEngine()
        self.ctx = MatchContext(registry=registry, graph=graph, threat_intel=self.threat_intel)
        self._rules_by_type: Dict[str, List[Rule]] = {}
        # Per-rule exception counts -- observable evidence that a specific rule
        # is broken, without letting it silently disable unrelated rules.
        self.rule_errors: Dict[str, int] = {}
        self.rules: List[Rule] = []
        self.set_rules(rules or [])

    def set_rules(self, rules: List[Any]) -> None:
        self.rules = [r for r in rules if isinstance(r, Rule)]
        self._rules_by_type.clear()
        for rule in self.rules:
            self._rules_by_type.setdefault(rule.event_type, []).append(rule)

    def evaluate_event(self, event: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluate one event against the rules for its event_type."""
        event_type = event.get("event_type")
        if not event_type:
            return []

        matches: List[DetectionResult] = []
        for rule in self._rules_by_type.get(event_type, []):
            # Isolated per rule: one rule raising on an unexpected event shape
            # must not withhold every other rule's verdict on this event.
            try:
                trace: List[Dict[str, Any]] = []
                if evaluate_logic(rule.logic, event, self.ctx, trace):
                    matches.append(
                        DetectionResult(
                            rule=rule,
                            event=event,
                            matched_evidence=collect_evidence(rule, event, self.ctx),
                            matched_conditions=format_trace(trace),
                        )
                    )
            except Exception:
                self.rule_errors[rule.id] = self.rule_errors.get(rule.id, 0) + 1
                _log.exception("rule %s raised while evaluating event_type=%s", rule.id, event_type)
        return matches
