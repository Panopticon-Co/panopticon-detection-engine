"""Evaluation engine orchestrating rule logic matching, threat intel lookups, and rule inheritance."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from panopticon_detection.evaluator.matcher import ConditionMatcher, extract_field
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.rules.schema import Condition, LogicNode, Rule
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


@dataclass
class DetectionResult:
    """Represents a successful atomic rule match with extracted evidence."""
    rule: Rule
    event: Dict[str, Any]
    matched_evidence: Dict[str, Any] = field(default_factory=dict)


class RuleEvaluator:
    """Evaluates telemetry events against active detection rules."""

    def __init__(
        self,
        rules: List[Rule] = None,
        registry: Optional[ProcessRegistry] = None,
        threat_intel: Optional[ThreatIntelEngine] = None,
    ):
        self.rules = rules or []
        self.registry = registry
        self.threat_intel = threat_intel or ThreatIntelEngine()
        self._rules_by_type: Dict[str, List[Rule]] = {}
        # Tracks matched rule IDs per host for `depends_on_rule` (Wazuh <if_sid>)
        self._matched_rules_history: Dict[str, Set[str]] = {}
        self.set_rules(self.rules)

    def set_rules(self, rules: List[Rule]) -> None:
        self.rules = rules
        self._rules_by_type.clear()
        for r in self.rules:
            self._rules_by_type.setdefault(r.event_type, []).append(r)

    def evaluate_event(self, event: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluates a single telemetry event against all candidate rules for its event_type."""
        # Process-identity state is maintained by EventGraphBuilder, which runs
        # once per event before evaluation (see detection_run.DetectionRun). The
        # evaluator only reads the registry, so ancestry conditions see the
        # current event's own process already indexed.
        event_type = event.get("event_type")
        if not event_type:
            return []

        host_id = event.get("host_id", "UNKNOWN_HOST")
        candidate_rules = self._rules_by_type.get(event_type, [])
        matches: List[DetectionResult] = []

        for rule in candidate_rules:
            # 1. Rule Inheritance Check (Wazuh <if_sid>)
            if rule.depends_on_rule:
                host_history = self._matched_rules_history.get(host_id, set())
                if rule.depends_on_rule not in host_history:
                    continue  # Parent rule hasn't triggered yet!

            # 2. Logic condition check
            if self._evaluate_logic_node(rule.logic, event):
                evidence = self._extract_evidence(rule, event)
                matches.append(DetectionResult(rule=rule, event=event, matched_evidence=evidence))
                self._matched_rules_history.setdefault(host_id, set()).add(rule.id)

        return matches

    def _evaluate_logic_node(self, node: LogicNode, event: Dict[str, Any]) -> bool:
        """Recursively evaluates boolean logic tree with short-circuiting."""
        # 1. Evaluate 'all' (AND)
        if node.all is not None:
            for item in node.all:
                if isinstance(item, Condition):
                    if not ConditionMatcher.evaluate(
                        item, event, registry=self.registry, threat_intel=self.threat_intel
                    ):
                        return False
                elif isinstance(item, LogicNode):
                    if not self._evaluate_logic_node(item, event):
                        return False

        # 2. Evaluate 'any' (OR)
        if node.any is not None:
            any_matched = False
            for item in node.any:
                if isinstance(item, Condition):
                    if ConditionMatcher.evaluate(
                        item, event, registry=self.registry, threat_intel=self.threat_intel
                    ):
                        any_matched = True
                        break
                elif isinstance(item, LogicNode):
                    if self._evaluate_logic_node(item, event):
                        any_matched = True
                        break
            if not any_matched:
                return False

        # 3. Evaluate 'none' (NOT)
        if node.none is not None:
            for item in node.none:
                if isinstance(item, Condition):
                    if ConditionMatcher.evaluate(
                        item, event, registry=self.registry, threat_intel=self.threat_intel
                    ):
                        return False
                elif isinstance(item, LogicNode):
                    if self._evaluate_logic_node(item, event):
                        return False

        return True

    def _extract_evidence(self, rule: Rule, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts specified evidence fields from the event or dynamic process tree."""
        evidence_dict: Dict[str, Any] = {}
        for field_path in rule.evidence:
            val = extract_field(
                event, field_path, registry=self.registry, threat_intel=self.threat_intel
            )
            if val is not None:
                evidence_dict[field_path] = val
        return evidence_dict
