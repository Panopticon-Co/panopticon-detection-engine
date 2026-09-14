"""Data models and schema definitions for detection rules.

Incorporates Wazuh-grade 0-16 Alert Levels, Rule Inheritance (depends_on_rule),
Active Response actions, and Compliance framework mappings.
"""

from enum import Enum
from typing import Any, List, Optional, Union

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    EXPERIMENTAL = "experimental"


class Condition(BaseModel):
    field: str
    operator: str
    value: Any
    case_sensitive: bool = False


class LogicNode(BaseModel):
    all: Optional[List[Union[Condition, "LogicNode"]]] = None
    any: Optional[List[Union[Condition, "LogicNode"]]] = None
    none: Optional[List[Union[Condition, "LogicNode"]]] = None


# Allow recursive definitions
LogicNode.update_forward_refs()


class MitreMapping(BaseModel):
    tactic: Optional[str] = None
    technique: Optional[str] = None
    name: Optional[str] = None


class Rule(BaseModel):
    id: str
    name: str
    description: str = ""
    version: int = 1
    status: RuleStatus = RuleStatus.ENABLED
    event_type: str
    logic: LogicNode
    
    # Wazuh-grade Level (0 to 16)
    level: int = Field(default=7, ge=0, le=16)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    
    # Rule Inheritance (Wazuh <if_sid>)
    depends_on_rule: Optional[str] = None
    
    # Automated Active Response
    active_response: Optional[str] = None
    
    evidence: List[str] = Field(default_factory=list)
    mitre: Optional[MitreMapping] = None
    compliance: List[str] = Field(default_factory=list)  # e.g., ["PCI-DSS_10.6", "NIST_800-53_SI-4"]
    tags: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
