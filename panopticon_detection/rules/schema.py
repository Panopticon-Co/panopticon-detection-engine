"""Data models for detection rules.

Four rule types share one metadata block (id, level, severity, ATT&CK ...):

* ``single``      -- a boolean condition tree over one event (the original form)
* ``sequence``    -- ordered steps, each its own event type and conditions, that
                     must occur for the same entity within ``maxspan``
* ``threshold``   -- at least ``count`` matching events for the same entity
                     within ``window``
* ``value_count`` -- at least ``count`` *distinct* values of ``field`` among
                     matching events for the same entity within ``window``

The stateful types are keyed by ``by``: an entity kind resolved through the
provenance registry (``process``, ``parent``, ``process_tree``, ``host``,
``user``) or a dotted event field. Keying on the registry rather than the
agent's ``entity_id`` is what lets a sequence span telemetry families -- the
agent derives that id differently for process events than for everything else.

Unknown keys are rejected: a silently ignored typo (``levle:``) is a rule that
does not do what its author thinks.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    EXPERIMENTAL = "experimental"


# Entity kinds a stateful rule can key on. Anything else in ``by`` is read as a
# dotted event field (e.g. ``network.destination_ip``).
KEY_KINDS = frozenset({"process", "parent", "process_tree", "host", "user"})

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$")
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: Any) -> float:
    """``90`` / ``"90s"`` / ``"5m"`` / ``"1h"`` -> seconds."""
    if isinstance(value, bool):
        raise ValueError("duration must be a number or a string like '90s'")
    if isinstance(value, (int, float)):
        seconds = float(value)
    else:
        match = _DURATION.match(str(value))
        if not match:
            raise ValueError(f"invalid duration {value!r}; use e.g. 90, '90s', '5m', '1h'")
        seconds = float(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    if seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class Condition(_Strict):
    field: str
    operator: str
    value: Any = None
    case_sensitive: bool = False


class LogicNode(_Strict):
    all: Optional[List[Union[Condition, "LogicNode"]]] = None
    any: Optional[List[Union[Condition, "LogicNode"]]] = None
    none: Optional[List[Union[Condition, "LogicNode"]]] = None


LogicNode.model_rebuild()


class MitreMapping(_Strict):
    tactic: Optional[str] = None
    technique: Optional[str] = None
    name: Optional[str] = None


class RuleMeta(_Strict):
    """Metadata every rule type carries."""

    id: str
    name: str
    description: str = ""
    version: int = 1
    status: RuleStatus = RuleStatus.ENABLED

    # Wazuh-style level (0-16). Required: a silent default once left 20 rules
    # at 7, below the campaign anchor threshold, including critical ones.
    level: int = Field(ge=0, le=16)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)

    # A recommendation for an analyst, never an action this engine takes.
    active_response: Optional[str] = None

    evidence: List[str] = Field(default_factory=list)
    mitre: Optional[MitreMapping] = None
    compliance: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class Rule(RuleMeta):
    """A single-event rule."""

    type: Literal["single"] = "single"
    event_type: str
    logic: LogicNode


def _as_key_list(value: Any) -> List[str]:
    keys = [value] if isinstance(value, str) else list(value or [])
    if not keys or not all(isinstance(k, str) and k.strip() for k in keys):
        raise ValueError("'by' needs at least one entity kind or event field")
    return [k.strip() for k in keys]


class _StatefulRule(RuleMeta):
    by: List[str]

    @field_validator("by", mode="before")
    @classmethod
    def _by(cls, value: Any) -> List[str]:
        return _as_key_list(value)


class SequenceStep(_Strict):
    event_type: str
    logic: LogicNode
    # Optional human label used in evidence ("office spawns script host").
    name: Optional[str] = None


class SequenceRule(_StatefulRule):
    type: Literal["sequence"]
    maxspan: float
    steps: List[SequenceStep] = Field(min_length=2, max_length=8)

    @field_validator("maxspan", mode="before")
    @classmethod
    def _span(cls, value: Any) -> float:
        return parse_duration(value)


class _WindowedRule(_StatefulRule):
    event_type: str
    logic: LogicNode
    window: float
    count: int = Field(ge=2)

    @field_validator("window", mode="before")
    @classmethod
    def _window(cls, value: Any) -> float:
        return parse_duration(value)


class ThresholdRule(_WindowedRule):
    type: Literal["threshold"]


class ValueCountRule(_WindowedRule):
    type: Literal["value_count"]
    field: str


StatefulRule = Union[SequenceRule, ThresholdRule, ValueCountRule]
AnyRule = Union[Rule, SequenceRule, ThresholdRule, ValueCountRule]

RULE_TYPES = {
    "single": Rule,
    "sequence": SequenceRule,
    "threshold": ThresholdRule,
    "value_count": ValueCountRule,
}


def event_types_of(rule: AnyRule) -> List[str]:
    """Every event type a rule reads, in step order for sequences."""
    if isinstance(rule, SequenceRule):
        return [step.event_type for step in rule.steps]
    return [rule.event_type]


def logic_blocks_of(rule: AnyRule) -> List[tuple]:
    """``(event_type, LogicNode)`` pairs -- one per step for sequences."""
    if isinstance(rule, SequenceRule):
        return [(step.event_type, step.logic) for step in rule.steps]
    return [(rule.event_type, rule.logic)]
