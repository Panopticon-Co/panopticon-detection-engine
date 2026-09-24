"""Stateful rule evaluation: sequences, thresholds and distinct-value counts.

Each rule keeps per-entity state keyed by its ``by`` list, always scoped to the
host. Entity kinds resolve through the provenance registry:

* ``process``      -- the acting process incarnation (PID-reuse safe)
* ``parent``       -- that process's parent incarnation
* ``process_tree`` -- the tree's entry point (topmost non-boundary ancestor), so
                      ``winword -> powershell -> payload`` shares one key
* ``host`` / ``user``
* anything else    -- a dotted event field, e.g. ``network.destination_ip``

Time is event time only, so replaying a stream reproduces the same matches.
State is bounded per key (``max_partials_per_key`` open sequence matches,
``max_window_events`` window entries) and :meth:`prune` evicts keys with no
activity since a cutoff. Windows assume near-ordered arrival: an event older
than the head of a window is counted but never evicts newer entries.

A sequence advances each open partial match at most one step per event, and an
event that completes a sequence can also start a new one. Once a sequence
completes for a key its partial is consumed, so a process making fifty
connections after a suspicious start fires once, not fifty times. A window
rule clears its window when it fires for the same reason.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

from panopticon_detection.enrichment import MatchContext, tree_root
from panopticon_detection.evaluator.engine import DetectionResult, collect_evidence
from panopticon_detection.evaluator.matcher import evaluate_logic, extract_field, format_trace
from panopticon_detection.provenance.identity import event_epoch, naive_utc_epoch
from panopticon_detection.rules.schema import (
    SequenceRule,
    ThresholdRule,
    ValueCountRule,
)

_log = logging.getLogger(__name__)


@dataclass
class _Partial:
    start: float
    last: float
    next_step: int
    steps: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)


def _describe_event(event: Dict[str, Any]) -> str:
    proc = event.get("process") or {}
    event_type = event.get("event_type") or ""
    bits = [event_type, f"{proc.get('name') or '?'}[{proc.get('pid')}]"]
    net = event.get("network") or {}
    if net.get("destination_ip"):
        bits.append(f"-> {net['destination_ip']}:{net.get('destination_port')}")
    elif event_type.startswith("file_") and (event.get("file") or {}).get("path"):
        bits.append(str(event["file"]["path"]))
    elif event_type.startswith("registry_") and (event.get("registry") or {}).get("key_path"):
        bits.append(str(event["registry"]["key_path"]))
    elif event_type == "image_load" and (event.get("image") or {}).get("path"):
        bits.append(str(event["image"]["path"]))
    bits.append(f"@ {event.get('timestamp')}")
    return " ".join(bits)


class StatefulEvaluator:
    """Evaluates sequence / threshold / value_count rules over an event stream."""

    def __init__(
        self,
        rules: List[Any],
        registry=None,
        graph=None,
        threat_intel=None,
        *,
        max_partials_per_key: int = 16,
        max_window_events: int = 10_000,
    ):
        self.ctx = MatchContext(registry=registry, graph=graph, threat_intel=threat_intel)
        self.registry = registry
        self.max_partials_per_key = max_partials_per_key
        self.max_window_events = max_window_events

        self.rules = [r for r in rules if isinstance(r, (SequenceRule, ThresholdRule, ValueCountRule))]
        self._sequences: Dict[str, List[SequenceRule]] = {}
        self._windowed: Dict[str, List[Any]] = {}
        for rule in self.rules:
            if isinstance(rule, SequenceRule):
                for event_type in sorted({s.event_type for s in rule.steps}):
                    self._sequences.setdefault(event_type, []).append(rule)
            else:
                self._windowed.setdefault(rule.event_type, []).append(rule)

        self._partials: Dict[Tuple[str, str], List[_Partial]] = {}
        self._windows: Dict[Tuple[str, str], Deque[Tuple[float, Any, Optional[str]]]] = {}
        self.rule_errors: Dict[str, int] = {}

    # ------------------------------------------------------------------
    def evaluate_event(self, event: Dict[str, Any]) -> List[DetectionResult]:
        event_type = event.get("event_type")
        ts = event_epoch(event.get("timestamp"))
        if not event_type or ts is None:
            return []

        results: List[DetectionResult] = []
        for rule in self._sequences.get(event_type, []):
            self._guard(rule, results, self._sequence, event, ts)
        for rule in self._windowed.get(event_type, []):
            self._guard(rule, results, self._window, event, ts)
        return results

    def _guard(self, rule, results, fn, event, ts) -> None:
        try:
            result = fn(rule, event, ts)
        except Exception:
            self.rule_errors[rule.id] = self.rule_errors.get(rule.id, 0) + 1
            _log.exception("stateful rule %s raised", rule.id)
            return
        if result is not None:
            results.append(result)

    # ------------------------------------------------------------------
    def _key(self, rule, event: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """``(state key, human label)`` or ``None`` when the event cannot be keyed."""
        host = event.get("host_id") or "UNKNOWN_HOST"
        parts: List[str] = []
        labels: List[str] = []
        actor = None
        for kind in rule.by:
            if kind == "host":
                parts.append(f"host={host}")
                labels.append(f"host {host}")
                continue
            if kind == "user":
                user = (event.get("user") or {}).get("full") or (event.get("process") or {}).get("user")
                if not user:
                    return None
                parts.append(f"user={user}")
                labels.append(f"user {user}")
                continue
            if kind in ("process", "parent", "process_tree"):
                if self.registry is None:
                    return None
                if actor is None:
                    actor = self.registry.resolve_event(event)
                if actor is None:
                    return None
                if kind == "process":
                    target = actor
                elif kind == "parent":
                    target = self.registry.get(actor.parent_node_id) if actor.parent_node_id else None
                else:
                    target = tree_root(self.registry, actor)
                if target is None:
                    return None
                parts.append(f"{kind}={target.node_id}")
                labels.append(f"{kind} {target.name}[{target.pid}]")
                continue
            value = extract_field(event, kind, ctx=self.ctx)
            if value is None:
                return None
            parts.append(f"{kind}={value}")
            labels.append(f"{kind}={value}")
        return f"{host}|" + "|".join(parts), ", ".join(labels)

    # ------------------------------------------------------------------
    def _sequence(self, rule: SequenceRule, event: Dict[str, Any], ts: float):
        event_type = event.get("event_type")
        matched: Dict[int, List[Dict[str, Any]]] = {}
        for index, step in enumerate(rule.steps):
            if step.event_type != event_type:
                continue
            trace: List[Dict[str, Any]] = []
            if evaluate_logic(step.logic, event, self.ctx, trace):
                matched[index] = trace
        if not matched:
            return None

        keyed = self._key(rule, event)
        if keyed is None:
            return None
        key, label = keyed
        slot = (rule.id, key)
        partials = [p for p in self._partials.get(slot, []) if ts - p.start <= rule.maxspan]

        completed: Optional[_Partial] = None
        # Highest step first, so one event advances existing matches before it
        # is also considered as the start of a new one.
        for index in sorted((i for i in matched if i > 0), reverse=True):
            for partial in partials:
                if partial.next_step != index or ts < partial.last:
                    continue
                partial.next_step += 1
                partial.last = ts
                partial.steps.append(self._step_line(rule, index, event))
                partial.conditions += [f"step {index + 1}: {c}" for c in format_trace(matched[index])]
                if partial.next_step == len(rule.steps):
                    completed = partial
                break
            if completed is not None:
                break

        if completed is not None:
            partials.remove(completed)
        if 0 in matched:
            partials.append(
                _Partial(
                    start=ts,
                    last=ts,
                    next_step=1,
                    steps=[self._step_line(rule, 0, event)],
                    conditions=[f"step 1: {c}" for c in format_trace(matched[0])],
                )
            )
        if len(partials) > self.max_partials_per_key:
            partials = partials[-self.max_partials_per_key:]
        if partials:
            self._partials[slot] = partials
        else:
            self._partials.pop(slot, None)

        if completed is None:
            return None
        evidence = collect_evidence(rule, event, self.ctx)
        evidence.update(
            {
                "sequence": completed.steps,
                "sequence_key": label,
                "span_seconds": round(completed.last - completed.start, 3),
                "maxspan_seconds": rule.maxspan,
            }
        )
        return DetectionResult(
            rule=rule, event=event, matched_evidence=evidence, matched_conditions=completed.conditions
        )

    @staticmethod
    def _step_line(rule: SequenceRule, index: int, event: Dict[str, Any]) -> str:
        name = rule.steps[index].name
        label = f"step {index + 1}" + (f" ({name})" if name else "")
        return f"{label}: {_describe_event(event)}"

    # ------------------------------------------------------------------
    def _window(self, rule, event: Dict[str, Any], ts: float):
        trace: List[Dict[str, Any]] = []
        if not evaluate_logic(rule.logic, event, self.ctx, trace):
            return None
        keyed = self._key(rule, event)
        if keyed is None:
            return None
        key, label = keyed

        if isinstance(rule, ValueCountRule):
            value = extract_field(event, rule.field, ctx=self.ctx)
            if value is None:
                return None
        else:
            value = event.get("event_id")

        slot = (rule.id, key)
        window = self._windows.setdefault(slot, deque())
        window.append((ts, value, event.get("event_id")))
        while window and window[0][0] < ts - rule.window:
            window.popleft()
        while len(window) > self.max_window_events:
            window.popleft()

        if isinstance(rule, ValueCountRule):
            distinct = sorted({str(v) for _, v, _ in window})
            observed = len(distinct)
        else:
            distinct = []
            observed = len(window)
        if observed < rule.count:
            return None

        first_ts = window[0][0]
        event_ids = [eid for _, _, eid in window if eid][:20]
        window.clear()

        evidence = collect_evidence(rule, event, self.ctx)
        evidence.update(
            {
                "window_key": label,
                "window_seconds": rule.window,
                "observed": observed,
                "required": rule.count,
                "span_seconds": round(ts - first_ts, 3),
                "contributing_event_ids": event_ids,
            }
        )
        if isinstance(rule, ValueCountRule):
            evidence["counted_field"] = rule.field
            evidence["distinct_values"] = distinct[:20]
        what = f"distinct {rule.field}" if isinstance(rule, ValueCountRule) else "matching events"
        conditions = format_trace(trace) + [
            f"{what} reached {observed} >= {rule.count} within {rule.window:g}s for {label}"
        ]
        return DetectionResult(
            rule=rule, event=event, matched_evidence=evidence, matched_conditions=conditions
        )

    # ------------------------------------------------------------------
    def prune(self, before: datetime) -> int:
        """Drop sequence and window state with no activity since ``before``."""
        cutoff = naive_utc_epoch(before)
        removed = 0
        for slot, partials in list(self._partials.items()):
            kept = [p for p in partials if p.last >= cutoff]
            removed += len(partials) - len(kept)
            if kept:
                self._partials[slot] = kept
            else:
                del self._partials[slot]
        for slot, window in list(self._windows.items()):
            if not window or window[-1][0] < cutoff:
                removed += 1
                del self._windows[slot]
        return removed

    def state_size(self) -> Dict[str, int]:
        return {
            "sequence_keys": len(self._partials),
            "open_sequence_matches": sum(len(p) for p in self._partials.values()),
            "window_keys": len(self._windows),
            "window_events": sum(len(w) for w in self._windows.values()),
        }
