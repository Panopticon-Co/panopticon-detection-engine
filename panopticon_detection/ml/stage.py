"""ML scoring stage: a supervised process-start model as bounded, explainable evidence.

``MLStage`` scores each Sysmon-style ``process_create`` (one that carries a
command line, as the training data did) with the pure-Python tree scorer. What
the score may do is deliberately narrow (docs/adr/002):

* ``shadow`` mode annotates the rule alerts of the same event with an ``ml``
  block and emits nothing of its own;
* ``active`` mode also emits ``ML-PROC-001`` (level 7, over the ``alert``
  threshold) or ``ML-PROC-002`` (level 9, over ``high``). They carry no ATT&CK
  tactic -- so they can join an incident but never open one -- and no response
  recommendation, and they are kept out of the host risk meter. ``ML-PROC-002``
  adds one bounded, itemised factor to an incident that rules already anchored.

The model is never an authority: it cannot re-level a rule hit, cannot create a
TERMINATE / QUARANTINE / ISOLATE recommendation, and its probability is not
presented as calibrated for deployment (``calibration.json`` says it was fitted
at training prevalence). Stateless, event time only, so ``prune`` frees nothing.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from panopticon_detection.alerting.alert import Alert
from panopticon_detection.ml.artifact import Bundle
from panopticon_detection.ml.featurizer import featurize
from panopticon_detection.ml.scorer import platt

log = logging.getLogger(__name__)

MODES = ("shadow", "active")
RULE_ALERT = "ML-PROC-001"
RULE_HIGH = "ML-PROC-002"
#: Alert requires a confidence; like rarity signals this is a fixed marker of a
#: weak, uncalibrated signal, not a probability.
ML_CONFIDENCE = 0.3
_LEVEL = {"alert": 7, "high": 9}
_RULE = {"alert": RULE_ALERT, "high": RULE_HIGH}
_ERROR_LOG_EVERY = 1000


@dataclass(frozen=True)
class MLResult:
    raw_score: float
    probability: float
    band: Optional[str]          # None, "alert" or "high"


class MLStage:
    def __init__(self, bundle: Bundle, mode: str = "shadow") -> None:
        if mode not in MODES:
            raise ValueError(f"ml mode must be one of {MODES}, not {mode!r}")
        self.bundle = bundle
        self.mode = mode
        self.scored = 0
        self.skipped = 0
        self.errors = 0
        self.alerts = 0
        self.latency_total_s = 0.0
        self.latency_max_s = 0.0

    # ------------------------------------------------------------------
    def score(self, event: Dict[str, Any]) -> Optional[MLResult]:
        """Score a process start; ``None`` when this event is not scoreable.

        Never raises: a malformed event or a scorer fault is counted in
        ``ml_errors`` and the event goes on to the rules unscored.
        """
        try:
            if event.get("event_type") != "process_create":
                return None
            proc = event.get("process")
            if not (isinstance(proc, dict) and proc.get("command_line")):
                self.skipped += 1  # the model was trained on starts that carry a command line
                return None
            if not isinstance(proc["command_line"], str):
                raise TypeError(f"command_line is {type(proc['command_line']).__name__}, not str")
            started = time.perf_counter()
            raw = self.bundle.model.raw_score(featurize(event))
            elapsed = time.perf_counter() - started
        except Exception as exc:  # a bad event must never take detection down
            self.errors += 1
            if self.errors == 1 or self.errors % _ERROR_LOG_EVERY == 0:
                log.error("ML scoring failed (%d so far): %r", self.errors, exc)
            return None
        self.scored += 1
        self.latency_total_s += elapsed
        self.latency_max_s = max(self.latency_max_s, elapsed)
        band = "high" if raw >= self.bundle.high_raw else "alert" if raw >= self.bundle.alert_raw else None
        return MLResult(round(raw, 6), round(platt(raw, self.bundle.platt_a, self.bundle.platt_b), 6), band)

    def annotation(self, result: MLResult) -> Dict[str, Any]:
        b = self.bundle
        return {
            "model_id": b.model_id, "model_version": b.model_version, "artifact_sha256": b.artifact_sha256,
            "featurizer_version": b.featurizer_version, "mode": self.mode,
            "raw_score": result.raw_score, "band": result.band,
            "thresholds": {"alert": round(b.alert_raw, 6), "high": round(b.high_raw, 6)},
            # Fitted at training prevalence: a ranking aid, not a deployment probability.
            "training_prevalence_probability": result.probability,
        }

    def to_alert(self, result: MLResult, event: Dict[str, Any], node_id: Optional[str]) -> Alert:
        assert result.band is not None
        b = self.bundle
        proc = event.get("process") or {}
        parent = event.get("parent") or {}
        level = _LEVEL[result.band]
        key = "|".join(str(p) for p in (b.model_version, event.get("host_id"), event.get("event_id"),
                                         event.get("timestamp"), node_id))
        self.alerts += 1
        return Alert(
            alert_id="ML-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10].upper(),
            rule_id=_RULE[result.band],
            title="ML triage: process start resembles abuse seen in training",
            description=(
                f"{proc.get('name') or 'process'} (PID {proc.get('pid')}) started by "
                f"{parent.get('name') or 'unknown parent'} scored {result.raw_score:.2f} "
                f"against the {result.band} threshold "
                f"({b.alert_raw if result.band == 'alert' else b.high_raw:.2f}). "
                "A triage signal from a supervised model, not a verdict."),
            level=level,
            severity="high" if result.band == "high" else "medium",
            confidence=ML_CONFIDENCE,
            host_id=event.get("host_id", "UNKNOWN_HOST"),
            timestamp=event.get("timestamp") or "",
            event_id=event.get("event_id"),
            evidence={
                "process.name": proc.get("name"), "process.command_line": proc.get("command_line"),
                "process.parent.name": parent.get("name"), "ml.raw_score": result.raw_score,
                "ml.band": result.band, "ml.model_version": b.model_version,
            },
            active_response=None,
            mitre_tactic=None,
            mitre_technique=None,
            tags=["ml", "process"],
            ml=self.annotation(result),
        )

    def prune(self, before: Any) -> int:
        return 0  # stateless

    def stats(self) -> Dict[str, Any]:
        return {"ml_state": "enabled", "ml_mode": self.mode, "ml_model_version": self.bundle.model_version,
                "ml_scored": self.scored, "ml_skipped_no_command_line": self.skipped,
                "ml_errors": self.errors, "ml_alerts": self.alerts,
                "ml_latency_mean_ms": round(1000 * self.latency_total_s / self.scored, 4) if self.scored else None,
                "ml_latency_max_ms": round(1000 * self.latency_max_s, 4)}
