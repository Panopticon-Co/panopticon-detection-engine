"""Active Response and Automated Incident Containment Engine.

Inspired by Wazuh Active Response (<active-response>).
Generates structured remediation actions for high-severity alerts (Level 12+).
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class ActiveResponseAction:
    """Action payload for automated endpoint containment."""
    action: str  # e.g., "TERMINATE_PROCESS", "ISOLATE_HOST", "BLOCK_FIREWALL_IP", "QUARANTINE_FILE"
    host_id: str
    target_pid: Optional[int] = None
    target_guid: Optional[str] = None
    target_ip: Optional[str] = None
    target_file: Optional[str] = None
    # Opaque, OS-native process-creation value from Schema 0.4's
    # process.start_time_ticks (never a duration or wall-clock time -- see
    # panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md).
    # response_engine.translate_recommendation requires this to turn a
    # TERMINATE_PROCESS recommendation into an executable KILL_PROCESS
    # command; without it the recommendation is still surfaced on the alert
    # for analyst visibility, but no command can safely be produced.
    target_start_time_ticks: Optional[int] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class ActiveResponseEngine:
    """Evaluates alerts and attaches automated mitigation instructions."""

    @staticmethod
    def resolve_action(
        level: int,
        event: Dict[str, Any],
        custom_action: Optional[str] = None,
        reason: str = "",
    ) -> Optional[ActiveResponseAction]:
        host_id = event.get("host_id", "UNKNOWN_HOST")
        proc = event.get("process", {})
        net = event.get("network", {})
        file_info = event.get("file", {})

        pid = proc.get("pid")
        guid = proc.get("process_guid")
        dest_ip = net.get("destination_ip")
        file_path = file_info.get("path")
        # Schema 0.4's process.start_time_ticks, read straight off the
        # triggering event exactly like pid/guid above -- resolve_action only
        # ever sees the raw event dict, not a ProcessTree, so this is only
        # populated when the event that fired the rule is itself the
        # process's own process_create/snapshot event (the common case for
        # rules that trigger directly on process creation). A correlation
        # rule that fires on some other, later event referencing the same
        # process only by pid/guid will not have it here, and
        # response_engine.translate_recommendation correctly fails closed in
        # that case rather than mistargeting a since-recycled pid.
        start_time_ticks = proc.get("start_time_ticks")

        # 1. Custom rule-specified action takes first precedence
        if custom_action == "TERMINATE_PROCESS" or (custom_action is None and pid and level in (12, 13)):
            return ActiveResponseAction(
                action="TERMINATE_PROCESS",
                host_id=host_id,
                target_pid=pid,
                target_guid=guid,
                target_start_time_ticks=start_time_ticks,
                reason=reason or f"Automated malicious process termination for Level {level} threat",
            )
        elif custom_action == "BLOCK_FIREWALL_IP" or (custom_action is None and dest_ip and level >= 12):
            return ActiveResponseAction(
                action="BLOCK_FIREWALL_IP",
                host_id=host_id,
                target_ip=dest_ip,
                target_pid=pid,
                reason=reason or f"Automated C2 egress block for Level {level} threat",
            )
        elif custom_action == "ISOLATE_HOST" or level >= 14:
            return ActiveResponseAction(
                action="ISOLATE_HOST",
                host_id=host_id,
                target_pid=pid,
                target_guid=guid,
                reason=reason or f"Emergency containment triggered for critical Level {level} event",
            )
        # COLLECT_PROCESS_INFO/COLLECT_NETWORK_CONNECTIONS are read-only,
        # AUTO_SAFE actions in the closed 7-action contract (see
        # panopticon-contracts/docs/CONTRACT.md) -- unlike the branches above,
        # no severity level auto-fires them here: only a rule that explicitly
        # opts in via its own YAML `active_response:` field (the same
        # custom_action mechanism TERMINATE_PROCESS/BLOCK_FIREWALL_IP already
        # use) produces one, since inventing a new severity heuristic for an
        # evidence-collection action is a rule-authoring decision, not
        # something this engine should default on its own.
        elif custom_action == "COLLECT_PROCESS_INFO":
            return ActiveResponseAction(
                action="COLLECT_PROCESS_INFO",
                host_id=host_id,
                target_pid=pid,
                target_guid=guid,
                target_start_time_ticks=start_time_ticks,
                reason=reason or f"Automated process evidence collection for Level {level} event",
            )
        elif custom_action == "COLLECT_NETWORK_CONNECTIONS":
            return ActiveResponseAction(
                action="COLLECT_NETWORK_CONNECTIONS",
                host_id=host_id,
                reason=reason or f"Automated network connection snapshot for Level {level} event",
            )

        return None
