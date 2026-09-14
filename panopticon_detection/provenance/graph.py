"""L2 -- the typed temporal provenance graph.

Every telemetry event becomes exactly one edge between two typed entities, and
every edge carries the time it happened. Correlation is then a *query* over this
structure rather than a separate subsystem with its own identity model -- which
is what the previous design got wrong: four correlators, four keys, no shared
state, so none of them composed.

Causality-constrained traversal
-------------------------------
:meth:`ProvenanceGraph.backward` answers "what led to this?". It walks the
*undirected* adjacency (a cause may reach an effect through an edge pointing
either way -- ``A --wrote--> F`` then ``P --executed--> F`` links A to P through
F, and the second edge points away from P) but only ever steps to edges that
happened **at or before** the time reached so far. Nothing can be caused by its
own future.

That single constraint is what makes the walk a root-cause analysis rather than
an arbitrary flood, and it is what the replaced ``EnterpriseAttackGraph`` had no
equivalent of -- it picked successors out of an unordered set, so the path it
reported was not even deterministic.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


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
    ) -> Subgraph:
        """Everything that could causally precede ``start`` at ``not_after``.

        Breadth-first over undirected adjacency, admitting an edge only when it
        happened at or before the time already reached on that branch, and no
        earlier than ``horizon`` before the anchor. The bound is tightened to
        each edge's own timestamp as the walk proceeds, so a branch marches
        strictly backwards through time and cannot loop forward through a later
        event.

        ``max_depth`` and ``max_edges`` bound the worst case; both are generous
        relative to real attack chains and exist so one noisy host cannot stall
        the detection worker.
        """
        floor = not_after - horizon
        visited_nodes: Dict[str, Node] = {}
        walked: Dict[str, Edge] = {}
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
                walked[edge.edge_id] = edge

                other = edge.dst if edge.src == node_id else edge.src
                # Revisiting a node is only useful if we arrive with an earlier
                # bound, which can open edges the first visit could not follow.
                # Bucket by whole seconds to keep the state set small.
                state = (other, int(edge.ts.timestamp()))
                if state in seen_states:
                    continue
                seen_states.add(state)

                node = self.nodes.get(other)
                if node is not None:
                    visited_nodes.setdefault(other, node)
                queue.append((other, edge.ts, depth + 1))

        ordered = sorted(walked.values(), key=lambda e: e.ts)
        return Subgraph(root=start, edges=ordered, nodes=visited_nodes)

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
