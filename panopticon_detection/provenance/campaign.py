"""L4 -- anchored backward traversal: multi-stage detection as a graph query.

Replaces the enumerated ``CorrelationEngine``. That design bucketed detections
under ``f"{host_id}:{pid}"`` and looked for a hardcoded ordered subsequence of
rule ids, which meant it could only ever correlate a process with *itself* --
every genuinely multi-stage intrusion (dropper spawns loader spawns beacon) was
invisible to it, and its own ``CORR-002`` (recon then shadow-copy deletion,
necessarily two PIDs) could not fire at all.

Here a campaign is not enumerated, it is *found*:

1. A rule match tags the graph edge its event created (L3).
2. If that tag is an **anchor** -- a terminal tactic at sufficient severity --
   walk backwards from the edge under the causality constraint (L2).
3. Every other tagged edge on that subgraph is a stage of the same campaign,
   regardless of which process it happened in.
4. Score by tactic breadth and path rareness; emit once per distinct stage set.

Scoring weights
---------------
``breadth`` is principled -- it counts distinct ATT&CK tactics. ``rareness`` is
deliberately a *placeholder*: it uses a static prior over edge kinds because no
baseline has been collected yet. The real version learns frequencies from a
rolling window per host cohort, and the weights need real telemetry to tune.
Stated here rather than presented as settled.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set

from panopticon_detection.alerting.alert import Alert
from panopticon_detection.provenance.graph import (
    Edge,
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
)
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.tagging import DEFAULT_ANCHOR_MIN_LEVEL, Tag

# Kill-chain depth used to normalise tactic breadth into 0..1. Seven is the
# count of distinct tactics this rule set can realistically express against
# endpoint-only telemetry, not the full ATT&CK matrix.
KILL_CHAIN_DEPTH = 7

# Static prior standing in for a learned baseline: how routine each relation is
# on a normal endpoint. Lower value == rarer == more signal. A real deployment
# replaces this with observed frequencies; see the module docstring.
_EDGE_PRIOR: Dict[EdgeKind, float] = {
    EdgeKind.FORKED: 0.50,
    EdgeKind.EXECUTED: 0.50,
    EdgeKind.LOADED: 0.40,
    EdgeKind.WROTE: 0.30,
    EdgeKind.CONNECTED_TO: 0.20,
    EdgeKind.SET_VALUE: 0.10,
    EdgeKind.CREATED_KEY: 0.10,
    EdgeKind.RENAMED: 0.08,
    EdgeKind.DELETED: 0.05,
    EdgeKind.DELETED_KEY: 0.05,
    EdgeKind.RAN_AS: 0.60,
}
_DEFAULT_PRIOR = 0.25

_WEIGHT_BREADTH = 0.5
_WEIGHT_RARENESS = 0.3
_WEIGHT_SEVERITY = 0.2


@dataclass
class Campaign:
    """A multi-stage attack reconstructed from the provenance graph."""

    campaign_id: str
    host_id: str
    anchor_edge_id: str
    timestamp: str
    score: float
    tactics: List[str]
    stages: List[Tag]
    edges: List[Edge]
    # The most upstream process still resolvable on the path -- the thing worth
    # acting on, rather than whichever process happened to fire the last rule.
    root_process_id: Optional[str] = None
    root_process_name: str = ""
    root_pid: Optional[int] = None
    root_start_time_ticks: Optional[int] = None
    lineage: str = ""

    @property
    def severity(self) -> str:
        if self.score >= 0.75:
            return "critical"
        return "high" if self.score >= 0.5 else "medium"

    @property
    def level(self) -> int:
        return 15 if self.score >= 0.75 else (13 if self.score >= 0.5 else 11)

    @property
    def anchor_stage(self) -> Optional[Tag]:
        """The stage that triggered the search -- the chronologically last one."""
        return self.stages[-1] if self.stages else None

    def to_alert(self) -> Alert:
        anchor = self.anchor_stage
        evidence: Dict[str, Any] = {
            "attack_chain": " -> ".join(f"{t.rule_id} ({t.tactic})" for t in self.stages),
            "stage_count": len(self.stages),
            "tactics_covered": self.tactics,
            "campaign_score": round(self.score, 3),
            "provenance_edges": len(self.edges),
            "root_cause_process": self.root_process_name or "unknown",
            "process_lineage": self.lineage or "unknown",
        }
        for i, tag in enumerate(self.stages, start=1):
            evidence[f"stage_{i}"] = (
                f"{tag.rule_id} | {tag.rule_name} | {tag.tactic}/{tag.technique}"
            )

        return Alert(
            alert_id=self.campaign_id,
            rule_id="PROV-CAMPAIGN",
            title=(
                f"[CAMPAIGN] {len(self.tactics)}-tactic attack chain rooted at "
                f"{self.root_process_name or 'unknown process'}"
            ),
            description=(
                f"Provenance traversal linked {len(self.stages)} detections across "
                f"{len(self.tactics)} ATT&CK tactics into one causally-connected "
                f"campaign on {self.host_id}."
            ),
            level=self.level,
            severity=self.severity,
            # Confidence is the weakest link in the chain, not an invented
            # constant: a campaign is only as trustworthy as its least certain
            # stage. The replaced engine hardcoded 0.95-0.98 on every incident.
            confidence=round(min((t.confidence for t in self.stages), default=0.5), 3),
            host_id=self.host_id,
            timestamp=self.timestamp,
            event_id=None,
            evidence=evidence,
            active_response=self._recommendation(),
            # Both from the anchor stage -- the detection that triggered the
            # search. Taking the tactic from `tactics[-1]` and the technique
            # from `stages[-1]` could name two different stages.
            mitre_tactic=anchor.tactic or None,
            mitre_technique=anchor.technique or None,
            tags=["attack.campaign", "provenance", "multi_stage"],
        )

    def _recommendation(self) -> Optional[Dict[str, Any]]:
        """Recommend terminating the campaign's root process.

        This is the concrete payoff of the provenance layer. Previously a
        recommendation raised from anything other than a process's own creation
        event carried no ``start_time_ticks``, so
        ``response_engine.translate_recommendation`` failed closed every time
        and no command was ever produced. The root process node still holds the
        token the agent observed, so this recommendation is actionable.

        Still fails closed when the token is genuinely absent -- it is never
        defaulted or derived, per the response contract.
        """
        if self.root_pid is None or self.root_start_time_ticks is None:
            return None
        return {
            "action": "TERMINATE_PROCESS",
            "host_id": self.host_id,
            "target_pid": self.root_pid,
            "target_guid": self.root_process_id,
            "target_start_time_ticks": self.root_start_time_ticks,
            "reason": (
                f"Root process of a {len(self.tactics)}-tactic campaign "
                f"({', '.join(self.tactics)})"
            ),
        }


@dataclass
class CampaignDetector:
    """Finds campaigns by walking backwards from anchor tags."""

    graph: ProvenanceGraph
    registry: ProcessRegistry

    min_tactics: int = 2
    min_stages: int = 2
    anchor_min_level: int = DEFAULT_ANCHOR_MIN_LEVEL
    horizon: timedelta = timedelta(hours=6)
    max_depth: int = 12

    # Stage sets already reported, so a campaign is not re-emitted every time
    # the graph grows another edge around it.
    _reported: Set[FrozenSet[str]] = field(default_factory=set, repr=False)

    def on_tagged_edge(self, edge: Edge, tag: Tag) -> Optional[Campaign]:
        """Called after ``tag`` is attached to ``edge``. Returns a campaign when
        this tag anchors one, otherwise ``None``."""
        if not tag.is_anchor(self.anchor_min_level):
            return None

        subgraph = self.graph.backward(
            edge.src,
            edge.ts,
            horizon=self.horizon,
            max_depth=self.max_depth,
        )

        # The anchor edge is itself a stage; backward() starts from its source
        # node, so it only appears in the walk if re-crossed.
        stage_edges: List[Edge] = [e for e in subgraph.tagged_edges if e is not edge]
        stage_edges.append(edge)
        stage_edges.sort(key=lambda e: e.ts)

        stages: List[Tag] = []
        for staged in stage_edges:
            stages.extend(staged.tags)
        if len(stages) < self.min_stages:
            return None

        tactics = _ordered_unique(t.tactic for t in stages if t.tactic)
        if len(tactics) < self.min_tactics:
            return None

        identity = frozenset(e.edge_id for e in stage_edges)
        if identity in self._reported:
            return None
        self._reported.add(identity)

        campaign = Campaign(
            campaign_id="CMP-"
            + hashlib.sha1("|".join(sorted(identity)).encode("utf-8")).hexdigest()[
                :10
            ].upper(),
            host_id=edge.host_id,
            anchor_edge_id=edge.edge_id,
            timestamp=edge.ts.isoformat(),
            score=self._score(stages, stage_edges, tactics),
            tactics=tactics,
            stages=stages,
            edges=stage_edges,
        )

        root = self._root_process(subgraph.nodes, edge)
        if root is not None:
            campaign.root_process_id = root.node_id
            campaign.root_process_name = root.name or root.executable
            campaign.root_pid = root.pid
            campaign.root_start_time_ticks = root.start_time_ticks
            campaign.lineage = self.registry.lineage(root.node_id)

        return campaign

    # ------------------------------------------------------------------
    def _root_process(self, nodes: Dict[str, Any], anchor: Edge):
        """The earliest process incarnation on the traversed subgraph.

        Falls back to the anchor's own source process when the walk found no
        earlier one, so a single-process campaign still yields a target.
        """
        candidates = [
            inc
            for node_id, node in nodes.items()
            if node.kind == NodeKind.PROCESS
            for inc in (self.registry.get(node_id),)
            if inc is not None
        ]
        if not candidates:
            return self.registry.get(anchor.src)
        return min(candidates, key=lambda inc: inc.start_time)

    def _score(self, stages: List[Tag], edges: List[Edge], tactics: List[str]) -> float:
        """Combine kill-chain breadth, path rareness and stage severity into 0..1."""
        breadth = min(len(tactics) / KILL_CHAIN_DEPTH, 1.0)

        # Surprisal of the path: rare relations carry signal, routine ones
        # (a process forking a child) carry almost none.
        surprisal = sum(
            -math.log2(_EDGE_PRIOR.get(e.kind, _DEFAULT_PRIOR)) for e in edges
        )
        # Normalise against a chain of ~6 moderately rare edges so a long noisy
        # path cannot dominate the score outright.
        rareness = min(surprisal / (6 * -math.log2(_DEFAULT_PRIOR)), 1.0)

        severity = min(max(t.level for t in stages) / 16.0, 1.0)

        return round(
            _WEIGHT_BREADTH * breadth
            + _WEIGHT_RARENESS * rareness
            + _WEIGHT_SEVERITY * severity,
            4,
        )


def _ordered_unique(values: Iterable[str]) -> List[str]:
    """Deduplicate while preserving first-seen order (chronological here)."""
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
