"""Storyline risk index (L3): risk-based correlation over a process tree.

Rules, the context model and rarity each produce *risk events* about a storyline:
the process tree rooted at ``enrichment.tree_root`` (the first process below a
boundary hub, Cortex XDR's "causality group owner"). No single risk event is an
alert. A storyline alerts when its accumulated risk crosses a threshold, or when
enough independent rules covering enough tactics agree -- the design of Splunk's
risk-based alerting, with Google SecOps' ``max + 0.2 * sum(rest)`` aggregation so
many weak hits cannot add up to an alert, and a bonus when tactics appear in
kill-chain order (HOLMES / RapSheet).

Contract, from ADR 002 and the project owner's response policy:

* a storyline alert (``CORR-STORY-001``) is at most level 11 -- level 12 would
  trigger the default TERMINATE recommendation -- carries no tactic, and may only
  recommend read-only collection;
* ML and rarity together may add at most :attr:`ml_cap_fraction` of the
  threshold on top of what the rules alone score, so they can raise but never
  alone decide an alert;
* event time only; :meth:`prune` drops storylines idle before a cut-off.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: ATT&CK enterprise tactics in kill-chain order.
TACTIC_ORDER: Tuple[str, ...] = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)
_PHASE = {t.lower(): i for i, t in enumerate(TACTIC_ORDER)}
_SOFT_SOURCES = ("ml", "rarity")


@dataclass
class RiskEvent:
    source: str            # "rule:<rule_id>", "ml:<model>", "rarity:<dimension>"
    score: float
    ts: datetime
    tactic: Optional[str] = None
    threat_object: str = ""

    @property
    def soft(self) -> bool:
        return self.source.split(":", 1)[0] in _SOFT_SOURCES


@dataclass
class Storyline:
    key: Tuple[str, str]
    events: Dict[Tuple[str, str], RiskEvent] = field(default_factory=dict)
    last_seen: Optional[datetime] = None
    alerted: bool = False


def kill_chain_run(events: Sequence[RiskEvent]) -> int:
    """Length of the longest run of distinct tactics ordered in both time and kill-chain phase."""
    phases = [_PHASE[e.tactic.lower()] for e in sorted(events, key=lambda e: e.ts)
              if e.tactic and e.tactic.lower() in _PHASE]
    best: Dict[int, int] = {}  # phase -> longest strictly increasing run ending at it
    for phase in phases:
        length = 1 + max((n for p, n in best.items() if p < phase), default=0)
        best[phase] = max(best.get(phase, 0), length)
    return max(best.values(), default=0)


def _aggregate(scores: List[float]) -> float:
    values = sorted(scores, reverse=True)
    return (values[0] + 0.2 * sum(values[1:])) if values else 0.0


class StorylineRiskIndex:
    """Accumulates risk per (host, storyline root) and reports breaches."""

    def __init__(self, threshold: float = 100.0, window: timedelta = timedelta(hours=24),
                 ml_cap_fraction: float = 0.4, chain_bonus: float = 10.0, chain_cap: float = 30.0,
                 min_tactics: int = 3, min_rule_sources: int = 3) -> None:
        self.threshold = threshold
        self.window = window
        self.ml_cap_fraction = ml_cap_fraction
        self.chain_bonus = chain_bonus
        self.chain_cap = chain_cap
        self.min_tactics = min_tactics
        self.min_rule_sources = min_rule_sources
        self.storylines: Dict[Tuple[str, str], Storyline] = {}

    # ------------------------------------------------------------------
    def add(self, host: str, root: str, event: RiskEvent) -> Optional[Dict[str, Any]]:
        """Record one risk event; returns the breach (once per storyline) when it fires."""
        key = (host, root)
        story = self.storylines.setdefault(key, Storyline(key))
        dedup = (event.source, event.threat_object)
        held = story.events.get(dedup)
        if held is None or event.score > held.score:
            story.events[dedup] = event
        story.last_seen = event.ts if story.last_seen is None else max(story.last_seen, event.ts)
        self._expire(story, event.ts)
        if story.alerted:
            return None
        breakdown = self.score(story)
        if breakdown["fires"]:
            story.alerted = True
            return {"host": host, "root": root, "ts": event.ts, **breakdown}
        return None

    def score(self, story: Storyline) -> Dict[str, Any]:
        events = list(story.events.values())
        hard = _aggregate([e.score for e in events if not e.soft])
        full = _aggregate([e.score for e in events])
        soft_added = min(max(0.0, full - hard), self.ml_cap_fraction * self.threshold)
        run = kill_chain_run([e for e in events if not e.soft])
        bonus = min(self.chain_cap, self.chain_bonus * max(0, run - 1))
        total = hard + soft_added + bonus
        tactics = {e.tactic for e in events if e.tactic and not e.soft}
        rule_sources = {e.source for e in events if not e.soft}
        fires = total >= self.threshold or (
            len(tactics) >= self.min_tactics and len(rule_sources) >= self.min_rule_sources)
        return {"score": round(total, 3), "rules": round(hard, 3), "ml_and_rarity": round(soft_added, 3),
                "chain_bonus": round(bonus, 3), "kill_chain_run": run, "tactics": sorted(tactics),
                "rule_sources": len(rule_sources), "fires": fires,
                "events": sorted(((e.source, round(e.score, 2), e.tactic) for e in events),
                                 key=lambda x: -x[1])[:20]}

    def _expire(self, story: Storyline, now: datetime) -> None:
        cutoff = now - self.window
        for key in [k for k, e in story.events.items() if e.ts < cutoff]:
            del story.events[key]

    def prune(self, before: datetime) -> int:
        stale = [k for k, s in self.storylines.items() if s.last_seen is not None and s.last_seen < before]
        for key in stale:
            del self.storylines[key]
        return len(stale)


def rule_points(level: int, confidence: Optional[float]) -> float:
    """Splunk RBA style: impact (level / 16 * 100) x confidence."""
    return max(0, min(16, int(level))) / 16.0 * 100.0 * (confidence if confidence is not None else 0.7)
