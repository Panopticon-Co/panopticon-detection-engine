"""What every behavioral detector emits, and how it joins the existing pipeline.

A behavioral detector -- the rarity baseline today; a command-line classifier,
an anomaly detector or a sequence model later -- reports a
:class:`BehavioralSignal`: *what* was unusual, *which* process and event, *by
how much* (the detector's own measurement, never a probability of malice),
*which* detector and model version said so, and a sentence an analyst can read.

A signal becomes an ordinary :class:`~panopticon_detection.alerting.alert.Alert`
through :meth:`BehavioralSignal.to_alert`, and from there takes the same path
as every other detection: dedup, emit, ``tag_from_alert`` onto the event's
graph edge, and ``IncidentTracker.on_tag``. Nothing downstream needs to know
which detector produced it, so adding a detector never touches the graph or the
incident engine.

A signal is evidence, not a verdict:

* it carries no ATT&CK tactic -- unusual is not a technique -- so it can join
  an incident but never open one (only terminal-tactic tags anchor);
* it never carries a response recommendation;
* ``DetectionRun`` keeps it out of the host risk meter.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from panopticon_detection.alerting.alert import Alert

# Fixed, and documented as meaningless statistically: Alert requires a
# confidence, but a behavioral signal measures unusualness, not maliciousness.
# The measurement lives in ``measurement``; this only keeps signals visibly
# weaker than rule detections wherever confidence is displayed.
SIGNAL_CONFIDENCE = 0.3


@dataclass(frozen=True)
class BehavioralSignal:
    """One explainable observation from a behavioral detector."""

    # which detector, and which learned artefact it used
    detector: str
    detector_version: str
    model_version: str

    # what kind of observation, and the rule id it is reported under
    signal_type: str
    rule_id: str
    title: str

    # the decision and the numbers behind it
    category: str
    measurement: Dict[str, Any]
    explanation: str

    # where it happened
    host_id: str
    event_id: Optional[str]
    timestamp: str
    node_id: Optional[str]
    pid: Optional[int]
    process_name: str

    level: int
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def signal_id(self) -> str:
        """Stable id: the same observation of the same event by the same model."""
        key = "|".join(
            str(part)
            for part in (
                self.detector,
                self.model_version,
                self.rule_id,
                self.host_id,
                self.event_id,
                self.timestamp,
                self.node_id,
            )
        )
        return "BHV-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10].upper()

    def to_dict(self) -> Dict[str, Any]:
        return {"signal_id": self.signal_id, **asdict(self)}

    def to_alert(self) -> Alert:
        """The existing alert representation, ready for tagging and correlation."""
        return Alert(
            alert_id=self.signal_id,
            rule_id=self.rule_id,
            title=self.title,
            description=self.explanation,
            level=self.level,
            severity="low",
            confidence=SIGNAL_CONFIDENCE,
            host_id=self.host_id,
            timestamp=self.timestamp,
            event_id=self.event_id,
            # A plain-JSON copy, so the alert serialises whatever the detector
            # put in its evidence.
            evidence=json.loads(json.dumps(self.to_dict(), default=str)),
            active_response=None,
            mitre_tactic=None,
            mitre_technique=None,
            tags=["behavioral", self.detector],
        )
