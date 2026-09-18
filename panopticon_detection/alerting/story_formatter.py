"""Plain-English rendering of what the engine observed.

Replaces a hand-maintained table that mapped each rule id to a fixed narrative.
That table had two problems. Six of its entries described rules that no longer
exist, because nothing kept it in step with ``rules/``. And every entry carried
a ``what_system_did`` line asserting the engine had *acted* -- "terminated the
virus process", "moved the file into an isolated AES-256 encrypted vault",
"blocked the hacker's IP address on the firewall", "revoked active session
tokens" -- closing with "100% OF THREATS WERE INTERCEPTED & NEUTRALIZED".

The engine does none of that. It detects, and it recommends. Execution belongs
to panopticon-response-engine and panopticon-manager, and every destructive
action in the closed seven-action set requires analyst approval before it runs.

So this renders from the alert itself: what was seen, and what was recommended
for a human to decide on. Nothing to keep in sync, and nothing claimed that did
not happen.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Actions an analyst must approve before anything runs. Mirrors
# response_engine.policy's tier table; duplicated as display text only, never
# as an authorization decision.
_APPROVAL_REQUIRED = {
    "TERMINATE_PROCESS",
    "ISOLATE_HOST",
    "QUARANTINE_FILE",
    "RELEASE_HOST_ISOLATION",
}

_SEVERITY_MARK = {
    "critical": "!!",
    "high": "! ",
    "medium": "  ",
    "low": "  ",
}


class StoryModeFormatter:
    """Renders an alert sequence as a readable incident narrative."""

    @classmethod
    def render_story_timeline(
        cls, alerts: List[Any], remediations: Optional[List[Any]] = None
    ) -> str:
        sep = "=" * 78
        lines = [sep, "INCIDENT NARRATIVE", sep, ""]

        if not alerts:
            lines.append("  No detections in this run.")
            lines.append("")
            lines.append(sep)
            return "\n".join(lines)

        for step, alert in enumerate(alerts, start=1):
            mark = _SEVERITY_MARK.get(str(alert.severity).lower(), "  ")
            lines.append(f"  {mark} STEP {step:02d}  {_clean_title(alert.title)}")
            lines.append(f"        host      : {alert.host_id}")
            lines.append(f"        observed  : {alert.description}")

            if getattr(alert, "mitre_tactic", None):
                technique = getattr(alert, "mitre_technique", None) or "-"
                lines.append(f"        technique : {alert.mitre_tactic} / {technique}")

            for extra in _campaign_detail(alert):
                lines.append(f"        {extra}")

            lines.append(f"        recommend : {_recommendation_text(alert)}")
            lines.append("")

        lines.append(sep)
        lines.append(_closing_summary(alerts))
        lines.append(sep)
        return "\n".join(lines)


def _clean_title(title: str) -> str:
    """Strip the ``[CATEGORY]`` prefix the alert titles carry."""
    text = str(title)
    if text.startswith("[") and "]" in text:
        return text.split("]", 1)[1].strip()
    return text


def _campaign_detail(alert: Any) -> List[str]:
    """Extra lines for a multi-stage campaign alert."""
    evidence: Dict[str, Any] = getattr(alert, "evidence", None) or {}
    out: List[str] = []
    if evidence.get("attack_chain"):
        out.append(f"chain     : {evidence['attack_chain']}")
    if evidence.get("process_lineage"):
        out.append(f"lineage   : {evidence['process_lineage']}")
    return out


def _recommendation_text(alert: Any) -> str:
    """Describe the recommendation, and who has to approve it.

    A recommendation is a proposal for an analyst. Saying so is the whole point
    of this rewrite.
    """
    recommendation = getattr(alert, "active_response", None)
    if not recommendation:
        return "no action recommended -- detection only"

    action = recommendation.get("action", "UNKNOWN")
    target_bits = []
    if recommendation.get("target_pid") is not None:
        target_bits.append(f"pid {recommendation['target_pid']}")
    if recommendation.get("target_file"):
        target_bits.append(str(recommendation["target_file"]))
    target = f" ({', '.join(target_bits)})" if target_bits else ""

    if action in _APPROVAL_REQUIRED:
        return f"{action}{target} -- requires analyst approval before it runs"
    return f"{action}{target} -- read-only, may run automatically"


def _closing_summary(alerts: List[Any]) -> str:
    """Counts only. The engine executed nothing, so it claims nothing."""
    campaigns = sum(1 for a in alerts if getattr(a, "rule_id", "") == "PROV-CAMPAIGN")
    recommended = sum(1 for a in alerts if getattr(a, "active_response", None))
    hosts = len({a.host_id for a in alerts if getattr(a, "host_id", None)})

    parts = [
        f"{len(alerts)} detection(s) across {hosts} host(s)",
        f"{campaigns} multi-stage campaign(s)",
        f"{recommended} response action(s) recommended for analyst review",
    ]
    return "  " + " | ".join(parts)
