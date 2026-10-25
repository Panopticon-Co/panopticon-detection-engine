"""L4 -- incidents: causally-connected detections, aggregated and explained.

A detection becomes a tag on the graph edge its event created (L3). This module
turns tags into incidents:

1. **Scope.** For each tag, walk backwards from the acting process along
   information flow (L2), stopping at boundary processes -- everything that led
   to it -- and forwards from its tree's entry point -- everything that entry
   point went on to cause (its children, and processes that ran files it
   wrote). Together these are the tag's *causal scope*. Both halves stop at
   boundary processes, so two programs a user launched from ``explorer.exe``
   never share a scope, while a malicious process's own children always do.
2. **Attach.** If that scope touches a process already in an open incident on
   the host, the tag joins that incident and the incident's scope grows. This
   is how later stages -- persistence, a C2 connection from a dropped payload
   -- attach to the chain that produced them, even when their tactic would
   never open an incident on its own.
3. **Open.** Otherwise, a tag on a terminal tactic (Impact, Exfiltration, C2,
   Credential Access, Lateral Movement) at sufficient level opens an incident,
   provided its scope already holds at least ``min_stages`` detections across
   ``min_tactics`` tactics. A lone detection stays an ordinary alert.
4. **Emit on material change.** An incident alert is emitted when the incident
   opens and again only when it gains a tactic or its severity band rises; new
   stages that change neither are recorded without a new alert. The alert id
   carries a revision (``INC-...-R2``), so every emission is distinct while
   ``incident_id`` stays stable.

The incident's stages are recomputed from the graph on every update -- every
tagged edge whose acting process is in scope -- so the graph stays the single
source of truth and replaying a stream rebuilds identical incidents.

Root: the *entry point* -- the topmost non-boundary ancestor of the earliest
detection's process. ``explorer.exe -> winword.exe -> powershell.exe`` roots at
``winword.exe``, never at the ``explorer.exe`` hub every program descends from.

Score: explainable by construction. Every component and context factor that
contributed is listed in the alert with its weight; nothing is a learned or
hidden number.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from panopticon_detection.alerting.alert import Alert
from panopticon_detection.enrichment import classify_path, destination_scope, tree_root
from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.provenance.boundary import DEFAULT_BOUNDARY_PROCESSES
from panopticon_detection.provenance.graph import (
    Edge,
    EdgeKind,
    Node,
    NodeKind,
    ProvenanceGraph,
    actor_of,
)
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.tagging import DEFAULT_ANCHOR_MIN_LEVEL, Tag

INCIDENT_RULE_ID = "PROV-CAMPAIGN"

# Applications through which an attacker most often first executes. An incident
# rooted at one is more likely a genuine intrusion than one rooted at, say, an
# administrator's shell.
INITIAL_ACCESS_APPS = frozenset(
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
        "msaccess.exe", "mspub.exe", "visio.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe",
        "thunderbird.exe", "acrord32.exe", "acrobat.exe",
    }
)

# Score components. Severity and breadth carry the weight; context factors add
# at most _CONTEXT_CAP between them.
_W_SEVERITY = 0.45
_W_BREADTH = 0.30
_BREADTH_SATURATION = 5
_CONTEXT = {
    "initial_access_vector": (0.10, "entry process is an Office, browser, mail or PDF application"),
    "user_writable_execution": (0.08, "a process in the chain ran from a user-writable or temp path"),
    "external_network": (0.07, "a process in the chain connected to a public address"),
    "obfuscated_command": (0.05, "a process in the chain ran an obfuscated command line"),
}
_CONTEXT_CAP = 0.25

_BANDS = ((0.75, "critical", 15), (0.55, "high", 13), (0.0, "medium", 11))
_BAND_RANK = {"medium": 0, "high": 1, "critical": 2}


@dataclass(frozen=True)
class Stage:
    """One detection within an incident."""

    edge_id: str
    ts: datetime
    event_id: Optional[str]
    rule_id: str
    rule_name: str
    tactic: str
    technique: str
    level: int
    confidence: float
    actor_node_id: str
    actor_name: str
    actor_pid: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.ts.isoformat(),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "tactic": self.tactic,
            "technique": self.technique,
            "process": self.actor_name,
            "pid": self.actor_pid,
            "event_id": self.event_id,
        }


@dataclass
class Incident:
    incident_id: str
    host_id: str
    opened_at: datetime
    last_activity: datetime
    scope: Set[str] = field(default_factory=set)
    path_edges: Dict[str, Edge] = field(default_factory=dict)
    stages: List[Stage] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    root_node_id: Optional[str] = None
    origin_node_id: Optional[str] = None
    score: float = 0.0
    breakdown: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    revision: int = 0
    # What the last emitted alert reported, to decide whether a change is
    # material enough to emit again.
    emitted_tactics: FrozenSet[str] = frozenset()
    emitted_band: Optional[str] = None
    # Stages added since the last emission without a material change.
    quiet_updates: int = 0

    @property
    def band(self) -> Tuple[str, int]:
        for threshold, name, level in _BANDS:
            if self.score >= threshold:
                return name, level
        return "medium", 11


@dataclass
class IncidentTracker:
    """Builds and maintains incidents from tagged graph edges."""

    graph: ProvenanceGraph
    registry: ProcessRegistry
    horizon: timedelta = timedelta(hours=6)
    max_depth: int = 12
    min_stages: int = 2
    min_tactics: int = 2
    anchor_min_level: int = DEFAULT_ANCHOR_MIN_LEVEL
    boundary: FrozenSet[str] = DEFAULT_BOUNDARY_PROCESSES

    incidents: Dict[str, Incident] = field(default_factory=dict, repr=False)
    _by_node: Dict[str, str] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    def on_tag(self, edge: Edge, tag: Tag) -> Optional[Alert]:
        """Called after ``tag`` is attached to ``edge``. Returns an incident
        alert when an incident opens or changes materially, else ``None``."""
        actor = actor_of(edge)
        walk = self.graph.backward(
            actor,
            edge.ts,
            horizon=self.horizon,
            max_depth=self.max_depth,
            boundary=self._is_boundary,
        )
        scope = {
            node_id
            for node_id, node in walk.nodes.items()
            if node.kind == NodeKind.PROCESS and node_id not in walk.boundary_nodes
        }
        scope.add(actor)
        # Everything downstream of the tree's entry point belongs too: a
        # malicious process's other children (it cleared the logs *and*
        # deleted the shadow copies) are one story. The backward walk alone
        # sees only ancestors; this is the forward half, and it stops at
        # boundary processes just as the backward half does.
        entry = tree_root(self.registry, self.registry.get(actor))
        if entry is not None and not self._is_boundary_name(entry.name):
            scope |= self.graph.forward_processes(
                entry.node_id,
                edge.ts - self.horizon,
                max_depth=self.max_depth,
                boundary=self._is_boundary,
            )

        existing = self._touching(scope, edge.host_id)
        if existing:
            incident = self._merge(existing)
            self._absorb(incident, scope, walk.edges, edge.ts)
            return self._refresh(incident, edge, tag)

        if not tag.is_anchor(self.anchor_min_level):
            return None

        floor = edge.ts - self.horizon
        stages = self._collect_stages(scope, floor, edge.ts)
        if len(stages) < self.min_stages:
            return None
        if len({s.tactic for s in stages if s.tactic}) < self.min_tactics:
            return None

        incident = Incident(
            incident_id="INC-"
            + hashlib.sha1(f"{edge.host_id}|{edge.edge_id}|{tag.rule_id}".encode("utf-8"))
            .hexdigest()[:10]
            .upper(),
            host_id=edge.host_id,
            opened_at=edge.ts,
            last_activity=edge.ts,
        )
        self.incidents[incident.incident_id] = incident
        self._absorb(incident, scope, walk.edges, edge.ts)
        return self._refresh(incident, edge, tag)

    def open_incidents(self) -> List[Incident]:
        return sorted(self.incidents.values(), key=lambda i: (i.opened_at, i.incident_id))

    def prune(self, before: datetime) -> int:
        """Close and forget incidents with no activity since ``before``."""
        stale = [iid for iid, inc in self.incidents.items() if inc.last_activity < before]
        for iid in stale:
            del self.incidents[iid]
        if stale:
            gone = set(stale)
            self._by_node = {n: i for n, i in self._by_node.items() if i not in gone}
        return len(stale)

    # ------------------------------------------------------------------
    def _is_boundary(self, node: Node) -> bool:
        return node.kind == NodeKind.PROCESS and self._is_boundary_name(node.label)

    def _is_boundary_name(self, name: Optional[str]) -> bool:
        return bool(name) and name.lower() in self.boundary

    def _touching(self, scope: Iterable[str], host_id: str) -> List[Incident]:
        found: Dict[str, Incident] = {}
        for node_id in scope:
            iid = self._by_node.get(node_id)
            if iid is None:
                continue
            incident = self.incidents.get(iid)
            if incident is not None and incident.host_id == host_id:
                found[iid] = incident
        return sorted(found.values(), key=lambda i: (i.opened_at, i.incident_id))

    def _merge(self, incidents: List[Incident]) -> Incident:
        """Fold incidents that one detection proves connected into the oldest."""
        keep = incidents[0]
        for other in incidents[1:]:
            keep.scope |= other.scope
            keep.path_edges.update(other.path_edges)
            keep.opened_at = min(keep.opened_at, other.opened_at)
            del self.incidents[other.incident_id]
        for node_id in keep.scope:
            self._by_node[node_id] = keep.incident_id
        return keep

    def _absorb(self, incident: Incident, scope: Set[str], edges: List[Edge], ts: datetime) -> None:
        incident.scope |= scope
        for e in edges:
            incident.path_edges[e.edge_id] = e
        for node_id in scope:
            self._by_node[node_id] = incident.incident_id
        if ts > incident.last_activity:
            incident.last_activity = ts

    def _collect_stages(self, scope: Set[str], floor: datetime, bound: datetime) -> List[Stage]:
        """Every detection performed by a process in scope, within the window.

        Keyed by (rule, process): the same rule firing repeatedly on the same
        process is one stage, at its first occurrence.
        """
        stages: Dict[Tuple[str, str], Stage] = {}
        for node_id in scope:
            for e in self.graph.incident_edges(node_id):
                if not e.tags or actor_of(e) != node_id or e.ts < floor or e.ts > bound:
                    continue
                proc = self.registry.get(node_id)
                for t in e.tags:
                    key = (t.rule_id, node_id)
                    if key in stages and stages[key].ts <= e.ts:
                        continue
                    stages[key] = Stage(
                        edge_id=e.edge_id,
                        ts=e.ts,
                        event_id=e.event_id,
                        rule_id=t.rule_id,
                        rule_name=t.rule_name,
                        tactic=t.tactic,
                        technique=t.technique,
                        level=t.level,
                        confidence=t.confidence,
                        actor_node_id=node_id,
                        actor_name=(proc.name if proc else "") or "unknown",
                        actor_pid=proc.pid if proc else None,
                    )
        return sorted(stages.values(), key=lambda s: (s.ts, s.rule_id, s.actor_node_id))

    def _refresh(self, incident: Incident, edge: Edge, tag: Tag) -> Optional[Alert]:
        incident.stages = self._collect_stages(
            incident.scope, incident.opened_at - self.horizon, incident.last_activity
        )
        incident.tactics = _ordered_unique(s.tactic for s in incident.stages if s.tactic)
        self._place_root(incident)
        self._score(incident)

        band, _ = incident.band
        tactics = frozenset(incident.tactics)
        material = (
            incident.revision == 0
            or not tactics <= incident.emitted_tactics
            or _BAND_RANK[band] > _BAND_RANK.get(incident.emitted_band or "medium", 0)
        )
        if not material:
            incident.quiet_updates += 1
            return None

        incident.revision += 1
        incident.emitted_tactics = tactics
        incident.emitted_band = band
        return self._to_alert(incident, edge, tag)

    # ------------------------------------------------------------------
    def _place_root(self, incident: Incident) -> None:
        processes = [self.registry.get(n) for n in incident.scope]
        processes = [p for p in processes if p is not None]
        if not incident.stages:
            return
        earliest = self.registry.get(incident.stages[0].actor_node_id)
        root = tree_root(self.registry, earliest) if earliest else None
        incident.root_node_id = root.node_id if root else incident.stages[0].actor_node_id
        non_boundary = [p for p in processes if (p.name or "").lower() not in self.boundary]
        origin = min(non_boundary, key=lambda p: (p.start_time, p.node_id), default=None)
        incident.origin_node_id = origin.node_id if origin else incident.root_node_id

    def _score(self, incident: Incident) -> None:
        max_level = max((s.level for s in incident.stages), default=0)
        severity = round(_W_SEVERITY * min(max_level / 16.0, 1.0), 3)
        breadth = round(
            _W_BREADTH * min(len(incident.tactics), _BREADTH_SATURATION) / _BREADTH_SATURATION, 3
        )

        factors: Dict[str, float] = {}
        root = self.registry.get(incident.root_node_id) if incident.root_node_id else None
        if root is not None and (root.name or "").lower() in INITIAL_ACCESS_APPS:
            factors["initial_access_vector"] = _CONTEXT["initial_access_vector"][0]
        in_scope = [self.registry.get(n) for n in incident.scope]
        in_scope = [p for p in in_scope if p is not None]
        if any(classify_path(p.executable) in ("temp", "user_writable") for p in in_scope):
            factors["user_writable_execution"] = _CONTEXT["user_writable_execution"][0]
        if self._external_connection(incident.scope):
            factors["external_network"] = _CONTEXT["external_network"][0]
        if any(CommandDeobfuscator.deobfuscate(p.command_line)["is_obfuscated"] for p in in_scope):
            factors["obfuscated_command"] = _CONTEXT["obfuscated_command"][0]

        context = round(min(sum(factors.values()), _CONTEXT_CAP), 3)
        incident.score = round(severity + breadth + context, 3)
        incident.breakdown = {
            "stage_severity": {"weight": severity, "max_stage_level": max_level},
            "tactic_breadth": {"weight": breadth, "tactics": len(incident.tactics)},
            "context": {"weight": context, "factors": factors},
            "total": incident.score,
        }
        incident.reasons = [
            f"highest stage level {max_level}/16",
            f"{len(incident.tactics)} ATT&CK tactic(s): {', '.join(incident.tactics)}",
        ] + [_CONTEXT[name][1] for name in factors]

    def _external_connection(self, scope: Set[str]) -> bool:
        for node_id in scope:
            for e in self.graph.incident_edges(node_id):
                if e.kind != EdgeKind.CONNECTED_TO or e.src != node_id:
                    continue
                socket = self.graph.nodes.get(e.dst)
                if socket is not None and destination_scope(socket.attrs.get("ip")) == "public":
                    return True
        return False

    def _causal_path(self, incident: Incident) -> List[str]:
        lines = []
        for e in sorted(incident.path_edges.values(), key=lambda x: (x.ts, x.edge_id))[:25]:
            src = self.graph.nodes.get(e.src)
            dst = self.graph.nodes.get(e.dst)
            lines.append(
                f"{e.ts.isoformat()} {_label(src)} -[{e.kind.value}]-> {_label(dst)}"
            )
        return lines

    def _to_alert(self, incident: Incident, edge: Edge, tag: Tag) -> Alert:
        band, level = incident.band
        root = self.registry.get(incident.root_node_id) if incident.root_node_id else None
        origin = self.registry.get(incident.origin_node_id) if incident.origin_node_id else None
        root_name = (root.name or root.executable) if root else "unknown"

        evidence: Dict[str, Any] = {
            "incident_id": incident.incident_id,
            "revision": incident.revision,
            "attack_chain": " -> ".join(
                f"{s.rule_id} ({s.tactic})" if s.tactic else s.rule_id for s in incident.stages
            ),
            "stage_count": len(incident.stages),
            "stages": [s.to_dict() for s in incident.stages],
            "tactics_covered": incident.tactics,
            "root_cause_process": root_name,
            "root_pid": root.pid if root else None,
            "root_inferred": bool(root and root.inferred),
            "process_lineage": self.registry.lineage(root.node_id) if root else "unknown",
            "provenance_origin": (origin.name or origin.executable) if origin else None,
            "processes_in_scope": len(incident.scope),
            "causal_path": self._causal_path(incident),
            "incident_score": incident.score,
            "score_breakdown": incident.breakdown,
            "why": incident.reasons,
            "updates_since_last_alert": incident.quiet_updates,
        }
        incident.quiet_updates = 0

        return Alert(
            alert_id=f"{incident.incident_id}-R{incident.revision}",
            rule_id=INCIDENT_RULE_ID,
            title=(
                f"[INCIDENT] {len(incident.tactics)}-tactic attack chain rooted at {root_name}"
            ),
            description=(
                f"{len(incident.stages)} causally-connected detection(s) across "
                f"{len(incident.tactics)} ATT&CK tactic(s) on {incident.host_id}, "
                f"traced back to {root_name}."
            ),
            level=level,
            severity=band,
            # An incident is only as trustworthy as its least certain technique
            # detection. Stages with no ATT&CK tactic -- behavioral signals --
            # are context, not a claim about the attack, so they do not count.
            confidence=round(
                min((s.confidence for s in incident.stages if s.tactic), default=0.5), 3
            ),
            host_id=incident.host_id,
            timestamp=edge.ts.isoformat(),
            event_id=edge.event_id,
            evidence=evidence,
            active_response=self._recommendation(incident, root),
            # The detection that produced this revision.
            mitre_tactic=tag.tactic or None,
            mitre_technique=tag.technique or None,
            tags=["attack.incident", "provenance", "multi_stage"],
            incident_id=incident.incident_id,
        )

    @staticmethod
    def _recommendation(incident: Incident, root) -> Optional[Dict[str, Any]]:
        """Recommend terminating the entry-point process, for analyst approval.

        Fails closed without ``start_time_ticks``: the token is never defaulted
        or derived, per the response contract, so an inferred root yields no
        command.
        """
        if root is None or root.pid is None or root.start_time_ticks is None:
            return None
        return {
            "action": "TERMINATE_PROCESS",
            "host_id": incident.host_id,
            "target_pid": root.pid,
            "target_guid": root.node_id,
            "target_start_time_ticks": root.start_time_ticks,
            "reason": (
                f"Entry point of incident {incident.incident_id} "
                f"({len(incident.tactics)} tactics: {', '.join(incident.tactics)})"
            ),
        }


def _label(node: Optional[Node]) -> str:
    if node is None:
        return "?"
    if node.kind == NodeKind.PROCESS:
        pid = node.attrs.get("pid")
        return f"{node.label}[{pid}]" if pid is not None else node.label
    return node.label


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
