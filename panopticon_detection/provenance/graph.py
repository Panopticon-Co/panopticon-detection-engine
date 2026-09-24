"""L2 -- the typed temporal provenance graph.

Every telemetry event becomes exactly one edge between two typed entities, and
every edge carries the time it happened. Correlation is a *query* over this
structure rather than a separate subsystem with its own identity model.

Directed, causality-constrained traversal
-----------------------------------------
:meth:`ProvenanceGraph.backward` answers "what led to this?". It follows
*information flow* backwards (King & Chen, "Backtracking Intrusions", 2003):

* a child came from its parent            (FORKED parent -> child)
* a process came from the image it ran    (EXECUTED / LOADED file -> process)
* a file came from the process that wrote it  (WROTE / RENAMED process -> file)

and it only ever steps to edges at or before the time reached so far, so
nothing is caused by its own future.

Direction matters. An undirected walk climbs from a child to its parent and
then descends into the parent's *other* children; under ``explorer.exe`` that
merges every unrelated program the user ran into one "attack". Sockets are
leaves for the same reason: two processes contacting the same address are
correlated, not causally linked. And the walk stops at boundary processes
(:mod:`.boundary`) -- the session and service hubs every process descends from.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple


class NodeKind(str, Enum):
    """Entity types. Closed on purpose -- a new kind means the agent grew a new
    telemetry family, which is a cross-repo schema change, not a local edit."""

    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"
    REGISTRY_KEY = "registry_key"
    MODULE = "module"
    USER = "user"
    HOST = "host"


class EdgeKind(str, Enum):
    """Relations, named for what the subject did to the object."""

    FORKED = "forked"              # process -> process
    EXECUTED = "executed"          # process -> file (its own image)
    WROTE = "wrote"                # process -> file
    DELETED = "deleted"            # process -> file
    RENAMED = "renamed"            # process -> file
    LOADED = "loaded"              # process -> module
    CONNECTED_TO = "connected_to"  # process -> socket
    SET_VALUE = "set_value"        # process -> registry_key
    CREATED_KEY = "created_key"    # process -> registry_key
    DELETED_KEY = "deleted_key"    # process -> registry_key
    RAN_AS = "ran_as"              # process -> user


# Which way information flows along each relation. A backward walk moves from
# the node information flowed INTO to the node it flowed FROM. Relations absent
# from both sets (CONNECTED_TO, RAN_AS) are never crossed by a causal walk.
_FLOWS_SRC_TO_DST = frozenset(
    {
        EdgeKind.FORKED,
        EdgeKind.WROTE,
        EdgeKind.RENAMED,
        EdgeKind.DELETED,
        EdgeKind.SET_VALUE,
        EdgeKind.CREATED_KEY,
        EdgeKind.DELETED_KEY,
    }
)
_FLOWS_DST_TO_SRC = frozenset({EdgeKind.EXECUTED, EdgeKind.LOADED})


def actor_of(edge: "Edge") -> str:
    """The process node that performed the action an edge records.

    For FORKED that is the *child* -- a detection on a process-create event is
    about the process created, not its parent. For every other relation it is
    the edge's source.
    """
    return edge.dst if edge.kind == EdgeKind.FORKED else edge.src


@dataclass
class Node:
    node_id: str
    kind: NodeKind
    label: str
    host_id: str
    first_seen: datetime
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    edge_id: str
    kind: EdgeKind
    src: str
    dst: str
    ts: datetime
    host_id: str
    event_id: Optional[str] = None
    # Technique tags written by L3. An edge, not an alert, is what carries a
    # detection -- so a match becomes part of the graph's structure instead of
    # a parallel stream that has to be re-joined later.
    tags: List[Any] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_tagged(self) -> bool:
        return bool(self.tags)


@dataclass
class Subgraph:
    """The result of a traversal: the edges walked and the nodes they touch."""

    root: str
    edges: List[Edge]
    nodes: Dict[str, Node]
    # Boundary processes the walk reached but did not expand through.
    boundary_nodes: Set[str] = field(default_factory=set)

    @property
    def tagged_edges(self) -> List[Edge]:
        return [e for e in self.edges if e.is_tagged]

    def __len__(self) -> int:
        return len(self.edges)


def entity_node_id(kind: NodeKind, host_id: str, identifier: str) -> str:
    """Deterministic id for a non-process entity.

    Content-derived for the same reason process node ids are (see
    ``identity.derive_node_id``): replaying an event stream must rebuild the
    same graph rather than duplicate it. Scoped by host because two machines'
    ``C:\\Windows\\System32\\cmd.exe`` are different objects, while a socket is
    scoped globally so contact with one C2 address converges across hosts.
    """
    scope = "" if kind == NodeKind.SOCKET else host_id
    key = f"{kind.value}|{scope}|{identifier.lower()}"
    return f"{kind.value[:4]}_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


class ProvenanceGraph:
    """In-memory temporal property graph over one deployment's telemetry.

    Not thread-safe: driven from the detection worker's single thread, like
    every other stateful engine in this package.
    """

    def __init__(self, max_edges_per_node: int = 4096) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, Edge] = {}
        # Undirected adjacency -- traversal direction is decided by time, not by
        # which way an edge happens to point.
        self._adjacency: Dict[str, List[str]] = {}
        # Guards against a pathological hub (a process touching a million files)
        # making every traversal from it quadratic.
        self._max_edges_per_node = max_edges_per_node

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def upsert_node(
        self,
        node_id: str,
        kind: NodeKind,
        label: str,
        host_id: str,
        when: datetime,
        **attrs: Any,
    ) -> Node:
        """Add the node, or enrich an existing one. ``first_seen`` only ever
        moves earlier, so an out-of-order arrival cannot make a node look
        younger than its true first observation."""
        node = self.nodes.get(node_id)
        if node is None:
            node = Node(
                node_id=node_id,
                kind=kind,
                label=label,
                host_id=host_id,
                first_seen=when,
                attrs={k: v for k, v in attrs.items() if v is not None},
            )
            self.nodes[node_id] = node
            self._adjacency.setdefault(node_id, [])
            return node

        if when < node.first_seen:
            node.first_seen = when
        if label and not node.label:
            node.label = label
        node.attrs.update({k: v for k, v in attrs.items() if v is not None})
        return node

    def add_edge(
        self,
        kind: EdgeKind,
        src: str,
        dst: str,
        ts: datetime,
        host_id: str,
        event_id: Optional[str] = None,
        **attrs: Any,
    ) -> Edge:
        """Append an edge. Identity is content-derived so a replayed event
        updates the existing edge instead of duplicating it."""
        edge_id = "e_" + hashlib.sha256(
            f"{kind.value}|{src}|{dst}|{ts.isoformat()}|{event_id or ''}".encode("utf-8")
        ).hexdigest()[:32]

        existing = self.edges.get(edge_id)
        if existing is not None:
            existing.attrs.update({k: v for k, v in attrs.items() if v is not None})
            return existing

        edge = Edge(
            edge_id=edge_id,
            kind=kind,
            src=src,
            dst=dst,
            ts=ts,
            host_id=host_id,
            event_id=event_id,
            attrs={k: v for k, v in attrs.items() if v is not None},
        )
        self.edges[edge_id] = edge
        for endpoint in (src, dst):
            bucket = self._adjacency.setdefault(endpoint, [])
            if len(bucket) < self._max_edges_per_node:
                bucket.append(edge_id)
        return edge

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def incident_edges(self, node_id: str) -> List[Edge]:
        return [
            self.edges[e] for e in self._adjacency.get(node_id, []) if e in self.edges
        ]

    def backward(
        self,
        start: str,
        not_after: datetime,
        *,
        horizon: timedelta = timedelta(hours=6),
        max_depth: int = 12,
        max_edges: int = 2000,
        boundary: Optional[Callable[[Node], bool]] = None,
    ) -> Subgraph:
        """Everything that causally precedes ``start`` at ``not_after``.

        Breadth-first along reversed information flow, admitting an edge only
        when it happened at or before the time already reached on that branch
        and no earlier than ``horizon`` before the anchor. A node for which
        ``boundary`` returns True is recorded but not expanded.

        ``max_depth`` and ``max_edges`` bound the worst case so one noisy host
        cannot stall the detection worker.
        """
        floor = not_after - horizon
        visited_nodes: Dict[str, Node] = {}
        walked: Dict[str, Edge] = {}
        stopped: Set[str] = set()
        seen_states: Set[Tuple[str, int]] = set()

        if start in self.nodes:
            visited_nodes[start] = self.nodes[start]

        # (node, time bound at this node, depth)
        queue: Deque[Tuple[str, datetime, int]] = deque([(start, not_after, 0)])

        while queue and len(walked) < max_edges:
            node_id, bound, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for edge in self.incident_edges(node_id):
                if edge.ts > bound or edge.ts < floor:
                    continue
                if edge.kind in _FLOWS_SRC_TO_DST and edge.dst == node_id:
                    other = edge.src
                elif edge.kind in _FLOWS_DST_TO_SRC and edge.src == node_id:
                    other = edge.dst
                else:
                    continue
                walked[edge.edge_id] = edge

                node = self.nodes.get(other)
                if node is not None:
                    visited_nodes.setdefault(other, node)
                    if boundary is not None and boundary(node):
                        stopped.add(other)
                        continue

                # Revisiting a node only helps with an earlier bound, which can
                # open edges the first visit could not follow. Bucket by whole
                # seconds to keep the state set small.
                state = (other, int(edge.ts.timestamp()))
                if state in seen_states:
                    continue
                seen_states.add(state)
                queue.append((other, edge.ts, depth + 1))

        ordered = sorted(walked.values(), key=lambda e: (e.ts, e.edge_id))
        return Subgraph(root=start, edges=ordered, nodes=visited_nodes, boundary_nodes=stopped)

    def forward_processes(
        self,
        start: str,
        not_before: datetime,
        *,
        max_depth: int = 12,
        max_nodes: int = 500,
        boundary: Optional[Callable[[Node], bool]] = None,
    ) -> Set[str]:
        """Process nodes causally downstream of ``start`` since ``not_before``.

        The complement of :meth:`backward`: follows information flow forwards --
        a process to the children it forked, and to the processes that later
        executed or loaded a file it wrote -- only ever stepping to edges at or
        after the time reached so far. Boundary processes are neither included
        nor expanded, so a payload a user launches through ``explorer.exe`` is
        still reached through the file, never through the hub.
        """
        reached: Set[str] = {start}
        queue: Deque[Tuple[str, datetime, int]] = deque([(start, not_before, 0)])
        while queue and len(reached) < max_nodes:
            node_id, bound, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.incident_edges(node_id):
                if edge.ts < bound:
                    continue
                if edge.kind in _FLOWS_SRC_TO_DST and edge.src == node_id:
                    nxt = edge.dst
                elif edge.kind in _FLOWS_DST_TO_SRC and edge.dst == node_id:
                    nxt = edge.src
                else:
                    continue
                node = self.nodes.get(nxt)
                if node is None:
                    continue
                if node.kind == NodeKind.PROCESS:
                    if nxt in reached or (boundary is not None and boundary(node)):
                        continue
                    reached.add(nxt)
                queue.append((nxt, edge.ts, depth + 1))
        return reached

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def prune(self, before: datetime) -> int:
        """Drop edges older than ``before``, then any node left isolated.

        Returns the number of edges removed. Unlike the replaced correlation
        engine this evicts keys as well as contents -- that engine kept one
        dict entry per ``(host, pid)`` for the lifetime of the process.
        """
        stale = [eid for eid, e in self.edges.items() if e.ts < before]
        for eid in stale:
            del self.edges[eid]

        if stale:
            gone = set(stale)
            for node_id, bucket in list(self._adjacency.items()):
                remaining = [e for e in bucket if e not in gone]
                if remaining:
                    self._adjacency[node_id] = remaining
                else:
                    del self._adjacency[node_id]
                    self.nodes.pop(node_id, None)

        return len(stale)

    def stats(self) -> Dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "tagged_edges": sum(1 for e in self.edges.values() if e.is_tagged),
        }
