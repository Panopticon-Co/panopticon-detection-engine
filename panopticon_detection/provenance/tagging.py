"""L3 -- technique tags, and which of them anchor a campaign search.

A rule match does not become an alert and then get re-correlated later. It
becomes a **tag on the graph edge the event created**, so the detection is part
of the structure and any traversal that crosses that edge picks it up for free.

Only some tags are worth searching from. A campaign search runs on an *anchor*
-- a technique from a tactic that represents an attacker achieving something,
not merely preparing. Anchoring on terminal tactics is the cost control: the
replaced correlation engine re-evaluated every rule against every buffer on
every single detection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ATT&CK tactics that mean damage, theft, or attacker control -- the points a
# defender actually cares about reconstructing backwards from. Matching is
# case- and separator-insensitive (``Command and Control``, ``command_and_control``).
TERMINAL_TACTICS = frozenset(
    {
        "impact",
        "exfiltration",
        "commandandcontrol",
        "credentialaccess",
        "lateralmovement",
    }
)

# Below this, a match is treated as context for a campaign rather than a reason
# to start searching for one. Level is the engine's existing 0-16 Wazuh-style
# scale, so this stays consistent with how rules already express severity.
DEFAULT_ANCHOR_MIN_LEVEL = 10


def normalise_tactic(tactic: Optional[str]) -> str:
    """``"Command and Control"`` -> ``"commandandcontrol"``."""
    if not tactic:
        return ""
    return "".join(ch for ch in tactic.lower() if ch.isalnum())


@dataclass(frozen=True)
class Tag:
    """One rule match, recorded against a graph edge.

    Frozen because a tag is a historical fact about an observation: if the same
    rule fires again it is a new tag on a new edge, never a mutation of this one.
    """

    rule_id: str
    rule_name: str
    tactic: str
    technique: str
    level: int
    severity: str
    confidence: float
    # Carried so a campaign can hand the response layer the recommendation the
    # rule itself asked for, rather than re-deriving one from severity.
    active_response: Optional[str] = None

    @property
    def tactic_key(self) -> str:
        return normalise_tactic(self.tactic)

    def is_anchor(self, min_level: int = DEFAULT_ANCHOR_MIN_LEVEL) -> bool:
        """Whether this tag should trigger a backward campaign search."""
        return self.level >= min_level and self.tactic_key in TERMINAL_TACTICS


def tag_from_detection(result) -> Tag:
    """Build a :class:`Tag` from an evaluator ``DetectionResult``.

    Takes the result rather than the rule so that this stays the single place
    that knows how a match maps onto a tag.
    """
    rule = result.rule
    mitre = getattr(rule, "mitre", None)
    severity = getattr(rule, "severity", "medium")
    return Tag(
        rule_id=rule.id,
        rule_name=rule.name,
        tactic=(getattr(mitre, "tactic", None) or "") if mitre else "",
        technique=(getattr(mitre, "technique", None) or "") if mitre else "",
        level=getattr(rule, "level", 0) or 0,
        # SeverityLevel is a str-Enum; take its value so a Tag stays plain data.
        severity=getattr(severity, "value", severity) or "medium",
        confidence=getattr(rule, "confidence", 0.0) or 0.0,
        active_response=getattr(rule, "active_response", None),
    )
