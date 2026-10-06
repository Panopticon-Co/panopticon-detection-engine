"""Per-event detection dispatch.

One event flows through here exactly once, in a fixed order:

1. **Record it.** :class:`EventGraphBuilder` turns the event into a provenance
   edge and keeps the process registry current -- before evaluation, so rules
   asking about this process's ancestry or image see it.
2. **Detect.** Single-event rules, stateful rules (sequence / threshold /
   value_count) and the beacon detector each run on the event.
3. **Deduplicate.** The same rule on the same process within ``dedup_ttl`` is
   one alert; repeats are counted, not re-emitted.
4. **Tag.** Every detection -- including suppressed repeats -- is written onto
   the edge the event created, so the graph holds the full picture.
5. **Correlate.** Each tag is handed to the incident tracker, which attaches it
   to the causal incident it belongs to or opens one; an incident alert is
   emitted only when an incident opens or changes materially.

Both the CLI and the manager's detection worker drive :meth:`process_event`,
so their behaviour cannot drift apart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from panopticon_detection import enrichment
from panopticon_detection.alerting.alert import Alert
from panopticon_detection.alerting.formatter import AlertFormatter
from panopticon_detection.provenance.graph import actor_of
from panopticon_detection.provenance.identity import event_epoch, naive_utc_epoch
from panopticon_detection.provenance.tagging import Tag, tag_from_alert, tag_from_detection


def _print_alert(alert: Alert, fmt: str, story_mode: bool = False) -> None:
    if story_mode:
        return
    if fmt == "console":
        print(AlertFormatter.to_console(alert))
    elif fmt == "json":
        print(AlertFormatter.to_json(alert))
    elif fmt == "ndjson":
        print(AlertFormatter.to_ndjson(alert))


class DetectionRun:
    """Stateful driver that evaluates one event at a time against every engine."""

    def __init__(
        self,
        *,
        graph_builder,
        evaluator,
        stateful,
        incidents,
        risk_scorer,
        beacon_detector,
        emit: Optional[Callable[[Alert], None]] = None,
        dedup_ttl_seconds: float = 600.0,
    ) -> None:
        self.graph_builder = graph_builder
        self.evaluator = evaluator
        self.stateful = stateful
        self.incidents = incidents
        self.risk_scorer = risk_scorer
        self.beacon_detector = beacon_detector
        self.dedup_ttl_seconds = dedup_ttl_seconds

        self._emit_cb = emit or (lambda _alert: None)
        # (rule, host, actor) -> event time of the last emitted alert.
        self._last_emitted: Dict[Tuple[str, str, str], float] = {}

        # Kept for story mode and the end-of-run summary.
        self.all_alerts: List[Alert] = []

        self.events_count = 0
        self.rule_alerts_count = 0
        self.stateful_alerts_count = 0
        self.beacon_alerts_count = 0
        self.incident_alerts_count = 0
        self.risk_breach_alerts_count = 0
        self.suppressed_duplicates = 0
        self.active_responses_count = 0

    # ------------------------------------------------------------------
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Run every detector against one event; return the alerts produced."""
        produced: List[Alert] = []
        self.events_count += 1
        enrichment.reset(event)

        edge = self.graph_builder.apply(event)

        detections: List[Tuple[Alert, Tag, str]] = []
        for result in self.evaluator.evaluate_event(event):
            detections.append((Alert.from_detection_result(result), tag_from_detection(result), "rule"))
        for result in self.stateful.evaluate_event(event):
            detections.append(
                (Alert.from_detection_result(result), tag_from_detection(result), "stateful")
            )
        beacon = self.beacon_detector.ingest_connection(event)
        if beacon is not None:
            alert = self._beacon_alert(beacon, event)
            detections.append((alert, tag_from_alert(alert), "beacon"))

        # Emit (or suppress) each detection, then tag them all onto the edge
        # before correlating, so an incident opened by one detection on this
        # event already includes the others.
        emitted: List[Alert] = []
        for alert, _tag, kind in detections:
            if self._is_duplicate(alert, event, edge):
                self.suppressed_duplicates += 1
                continue
            self._count(kind)
            self._emit(alert, produced)
            emitted.append(alert)

        # One event is one piece of evidence toward a host's risk, however many
        # overlapping rules describe it: feed the meter once, with the event's
        # strongest detection.
        if emitted:
            strongest = max(emitted, key=lambda a: (a.level, a.rule_id))
            risk = self.risk_scorer.record_detection(
                host_id=strongest.host_id,
                rule_id=strongest.rule_id,
                rule_name=strongest.title,
                level=strongest.level,
                timestamp=strongest.timestamp,
                summary=strongest.description,
                confidence=strongest.confidence,
            )
            if risk is not None:
                self.risk_breach_alerts_count += 1
                self._emit(risk, produced)

        if edge is not None:
            for _alert, tag, _kind in detections:
                edge.tags.append(tag)
            for _alert, tag, _kind in detections:
                incident_alert = self.incidents.on_tag(edge, tag)
                if incident_alert is not None:
                    self.incident_alerts_count += 1
                    self._emit(incident_alert, produced)

        return produced

    # ------------------------------------------------------------------
    def _is_duplicate(self, alert: Alert, event: Dict[str, Any], edge) -> bool:
        ts = event_epoch(event.get("timestamp"))
        if ts is None:
            return False
        actor = actor_of(edge) if edge is not None else f"pid:{(event.get('process') or {}).get('pid')}"
        key = (alert.rule_id, alert.host_id, actor)
        last = self._last_emitted.get(key)
        if last is not None and 0 <= ts - last < self.dedup_ttl_seconds:
            return True
        self._last_emitted[key] = ts
        return False

    def _count(self, kind: str) -> None:
        if kind == "rule":
            self.rule_alerts_count += 1
        elif kind == "stateful":
            self.stateful_alerts_count += 1
        elif kind == "beacon":
            self.beacon_alerts_count += 1

    def _emit(self, alert: Alert, produced: List[Alert]) -> None:
        produced.append(alert)
        self.all_alerts.append(alert)
        if alert.active_response:
            self.active_responses_count += 1
        self._emit_cb(alert)

    @staticmethod
    def _beacon_alert(match, event: Dict[str, Any]) -> Alert:
        # No active_response: the closed action set has no per-destination
        # block, and substituting whole-host isolation for a narrow egress
        # block is exactly the mapping the response contract forbids.
        return Alert(
            alert_id=f"ALT-BCN-{match.host_id}-{match.pid}-{match.destination_ip}-"
            f"{match.destination_port}-{event.get('event_id')}",
            rule_id="DET-NET-004",
            title="Periodic outbound connections (possible C2 beacon)",
            description=(
                f"{match.process_name} (PID {match.pid}) connected to "
                f"{match.destination_ip}:{match.destination_port} {match.connections} times "
                f"at a regular ~{match.median_interval_seconds}s interval "
                f"(dispersion {match.dispersion})."
            ),
            level=13,
            severity="high",
            confidence=match.confidence,
            host_id=match.host_id,
            timestamp=event.get("timestamp") or "",
            event_id=event.get("event_id"),
            evidence=match.evidence,
            active_response=None,
            mitre_tactic="Command and Control",
            mitre_technique="T1071.001",
            tags=["attack.command_and_control", "c2_beaconing"],
        )

    def prune(self, before: datetime) -> int:
        """Forget dedup entries older than ``before``."""
        cutoff = naive_utc_epoch(before)
        stale = [k for k, ts in self._last_emitted.items() if ts < cutoff]
        for k in stale:
            del self._last_emitted[k]
        return len(stale)
