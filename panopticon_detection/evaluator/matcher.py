"""Extracts fields from events and matches atomic rule conditions with process tree, threat intel, and deobfuscation awareness."""

from typing import Any, Dict, Optional

from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator
from panopticon_detection.evaluator.operators import OPERATOR_MAP
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.rules.schema import Condition
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


def extract_field(
    event: Dict[str, Any],
    field_path: str,
    registry: Optional[ProcessRegistry] = None,
    threat_intel: Optional[ThreatIntelEngine] = None,
) -> Any:
    """Extracts a nested field value from a dictionary using dot notation or dynamic analyzers."""
    proc = event.get("process", {})
    raw_cmd = proc.get("command_line", "")

    # Dynamic Deobfuscation fields
    if field_path in ("process.deobfuscated_command", "process.normalized_command"):
        return CommandDeobfuscator.deobfuscate(raw_cmd)["full_deobfuscated"]

    if field_path == "process.is_obfuscated":
        return CommandDeobfuscator.deobfuscate(raw_cmd)["is_obfuscated"]

    if field_path == "process.evasion_techniques":
        return CommandDeobfuscator.deobfuscate(raw_cmd)["evasion_techniques"]

    # Dynamic Shannon Entropy fields
    if field_path == "process.entropy":
        return ShannonEntropyCalculator.calculate_entropy(raw_cmd)

    if field_path == "process.is_high_entropy":
        return ShannonEntropyCalculator.analyze_tokens(raw_cmd)["is_anomaly"]

    # Dynamic provenance fields.
    #
    # Resolved from the *event* rather than from process.entity_id/process_guid.
    # The agent derives entity_id with a different formula for process-create
    # than for network/file/registry/image_load telemetry (see
    # provenance/identity.py), so a guid lookup silently missed on four of the
    # five families and every ancestry check quietly returned nothing. The
    # registry joins on (host_id, pid, timestamp) instead, which the agent's
    # own contract guarantees.
    if field_path in ("process.lineage", "process.ancestry") and registry:
        actor = registry.resolve_event(event)
        if actor:
            return registry.lineage(actor.node_id)

    if field_path == "process.ancestor_names" and registry:
        actor = registry.resolve_event(event)
        if actor:
            return [a.name for a in registry.ancestors(actor.node_id)]

    # Dynamic DNS & DGA fields
    if field_path.startswith("network.is_dga") or field_path.startswith("network.is_dns_tunneling") or field_path.startswith("network.domain_entropy"):
        from panopticon_detection.behavioral.dns import DnsAnalyzer
        domain = event.get("network", {}).get("dns_query") or event.get("network", {}).get("destination_domain") or event.get("dns", {}).get("query")
        dns_res = DnsAnalyzer.analyze_domain(domain)
        if field_path == "network.is_dga":
            return dns_res["is_dga"]
        if field_path == "network.is_dns_tunneling":
            return dns_res["is_tunneling"]
        if field_path == "network.domain_entropy":
            return dns_res["entropy"]

    # Dynamic ThreatIntel fields
    if field_path == "threat_intel.hash_match" and threat_intel:
        file_hash = proc.get("file_hash") or event.get("file", {}).get("hash")
        return threat_intel.check_hash(file_hash)

    if field_path == "threat_intel.ip_match" and threat_intel:
        dest_ip = event.get("network", {}).get("destination_ip")
        return threat_intel.check_ip(dest_ip)

    # Dotted nested path lookup (e.g. process.name)
    parts = field_path.split(".")
    current = event
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


class ConditionMatcher:
    """Evaluates a single rule Condition against an event."""

    @staticmethod
    def evaluate(
        condition: Condition,
        event: Dict[str, Any],
        registry: Optional[ProcessRegistry] = None,
        threat_intel: Optional[ThreatIntelEngine] = None,
    ) -> bool:
        # 1. Special operator: has_ancestor
        #
        # The rule's declared `field` is documentation only -- ancestry is a
        # property of the process that emitted the event, resolved through the
        # registry, so this works identically on a process_create and on a
        # later network/file/registry event from the same process.
        if condition.operator == "has_ancestor" and registry:
            actor = registry.resolve_event(event)
            if actor is None:
                return False
            targets = condition.value if isinstance(condition.value, list) else [condition.value]
            wanted = {str(t).lower() for t in targets}
            return any(a.name in wanted for a in registry.ancestors(actor.node_id))

        # 2. Special operator: in_threat_intel (IOC Blacklist Check)
        if condition.operator == "in_threat_intel" and threat_intel:
            actual_val = extract_field(event, condition.field, registry=registry, threat_intel=threat_intel)
            target_type = str(condition.value).lower()
            if target_type in ("hash", "file_hash", "sha256", "md5"):
                return threat_intel.check_hash(actual_val) is not None
            elif target_type in ("ip", "ip_address", "c2"):
                return threat_intel.check_ip(actual_val) is not None

        # 3. Special operator: entropy_greater_than
        if condition.operator == "entropy_greater_than":
            raw_text = extract_field(event, condition.field, registry=registry, threat_intel=threat_intel)
            actual_entropy = ShannonEntropyCalculator.calculate_entropy(str(raw_text or ""))
            try:
                return actual_entropy >= float(condition.value)
            except (ValueError, TypeError):
                return False

        # Standard field extraction & comparison
        actual_val = extract_field(event, condition.field, registry=registry, threat_intel=threat_intel)

        # If matching against process.command_line and normal match fails, fallback to deobfuscated view!
        op_func = OPERATOR_MAP.get(condition.operator)
        if not op_func:
            return False

        match_result = op_func(actual_val, condition.value, case_sensitive=condition.case_sensitive)
        if not match_result and condition.field == "process.command_line":
            # Transparent fallback to deobfuscated / decoded command line!
            deobf_val = extract_field(event, "process.deobfuscated_command", registry=registry, threat_intel=threat_intel)
            match_result = op_func(deobf_val, condition.value, case_sensitive=condition.case_sensitive)

        return match_result
