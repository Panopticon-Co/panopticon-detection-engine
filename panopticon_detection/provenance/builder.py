"""Turns one normalized telemetry event into one provenance graph edge.

This is the join point the old design never had. Previously a network, file,
registry or image-load event contributed nothing structural -- it was matched
against rules and then discarded, so there was no way to ask "which process did
this, and what led to that process?". Here every family produces an edge
anchored on the process that caused it, resolved through
:class:`~panopticon_detection.provenance.identity.ProcessRegistry` rather than
through an ``entity_id`` the agent derives differently per family.

Event types come from ``ingestion.telemetry``'s normalizer, the only producer of
this vocabulary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from panopticon_detection.provenance.graph import (
    Edge,
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
    entity_node_id,
)
from panopticon_detection.provenance.identity import (
    UNKNOWN_TIME,
    ProcessIncarnation,
    ProcessRegistry,
    parse_timestamp,
)

# Only the families a Panopticon agent can actually emit appear here. An
# event_type outside these tables produces no edge rather than a guessed one.
_FILE_EDGES = {
    "file_create": EdgeKind.WROTE,
    "file_write": EdgeKind.WROTE,
    "file_delete": EdgeKind.DELETED,
    "file_rename": EdgeKind.RENAMED,
}
_REGISTRY_EDGES = {
    "registry_write": EdgeKind.SET_VALUE,
    "registry_add_key": EdgeKind.CREATED_KEY,
    "registry_delete_key": EdgeKind.DELETED_KEY,
    "registry_rename_key": EdgeKind.SET_VALUE,
}


class EventGraphBuilder:
    """Applies events to a :class:`ProvenanceGraph`, keeping the registry in step.

    One instance per graph; both are driven from the detection worker's single
    thread.
    """

    def __init__(self, graph: ProvenanceGraph, registry: ProcessRegistry) -> None:
        self.graph = graph
        self.registry = registry

    # ------------------------------------------------------------------
    def apply(self, event: Dict[str, Any]) -> Optional[Edge]:
        """Record ``event`` in the graph and return the edge it created.

        Returns ``None`` when the event carries no usable timestamp, names no
        resolvable process, or belongs to a family with no structural meaning
        (``process_terminate`` closes an interval but adds no edge). A caller
        that gets ``None`` simply has nothing to tag.
        """
        when = parse_timestamp(event.get("timestamp"))
        if when == UNKNOWN_TIME:
            # Without a time the edge could not be placed in the causal order,
            # and a wrongly-ordered edge is worse than a missing one: it would
            # let the backward walk step forward through time.
            return None

        event_type = event.get("event_type") or ""

        if event_type == "process_create":
            return self._apply_process_create(event, when)
        if event_type == "process_terminate":
            self.registry.observe_stop(event)
            return None

        # Every other family hangs off the process that caused it.
        actor = self.registry.resolve_event(event)
        if actor is None:
            return None

        if event_type == "network_connect":
            return self._apply_network(event, when, actor)
        if event_type in _FILE_EDGES:
            return self._apply_file(event, when, actor, _FILE_EDGES[event_type])
        if event_type in _REGISTRY_EDGES:
            return self._apply_registry(event, when, actor, _REGISTRY_EDGES[event_type])
        if event_type == "image_load":
            return self._apply_image_load(event, when, actor)
        return None

    # ------------------------------------------------------------------
    def _apply_process_create(
        self, event: Dict[str, Any], when: datetime
    ) -> Optional[Edge]:
        incarnation = self.registry.observe_start(event)
        if incarnation is None:
            return None

        self._upsert_process(incarnation)

        # The image a process runs is a first-class file node, so a dropper that
        # wrote the binary and the process that later executed it converge on
        # the same node and the backward walk can cross between them.
        if incarnation.executable:
            file_id = entity_node_id(
                NodeKind.FILE, incarnation.host_id, incarnation.executable
            )
            self.graph.upsert_node(
                file_id,
                NodeKind.FILE,
                incarnation.executable,
                incarnation.host_id,
                when,
                sha256=incarnation.sha256,
            )
            self.graph.add_edge(
                EdgeKind.EXECUTED,
                incarnation.node_id,
                file_id,
                when,
                incarnation.host_id,
                event.get("event_id"),
            )

        if incarnation.parent_node_id is None:
            return None

        return self.graph.add_edge(
            EdgeKind.FORKED,
            incarnation.parent_node_id,
            incarnation.node_id,
            when,
            incarnation.host_id,
            event.get("event_id"),
            command_line=incarnation.command_line,
        )

    def _apply_network(
        self, event: Dict[str, Any], when: datetime, actor: ProcessIncarnation
    ) -> Optional[Edge]:
        net = event.get("network") or {}
        ip = net.get("destination_ip")
        if not ip:
            return None
        port = net.get("destination_port")
        label = f"{ip}:{port}" if port else str(ip)

        socket_id = entity_node_id(NodeKind.SOCKET, actor.host_id, label)
        self.graph.upsert_node(
            socket_id,
            NodeKind.SOCKET,
            label,
            actor.host_id,
            when,
            ip=ip,
            port=port,
            hostname=net.get("destination_hostname"),
        )
        return self.graph.add_edge(
            EdgeKind.CONNECTED_TO,
            actor.node_id,
            socket_id,
            when,
            actor.host_id,
            event.get("event_id"),
            direction=net.get("direction"),
            protocol=net.get("protocol"),
        )

    def _apply_file(
        self,
        event: Dict[str, Any],
        when: datetime,
        actor: ProcessIncarnation,
        kind: EdgeKind,
    ) -> Optional[Edge]:
        info = event.get("file") or {}
        path = info.get("path") or info.get("target_path")
        if not path:
            return None

        file_id = entity_node_id(NodeKind.FILE, actor.host_id, path)
        self.graph.upsert_node(
            file_id, NodeKind.FILE, path, actor.host_id, when, sha256=info.get("hash")
        )
        return self.graph.add_edge(
            kind,
            actor.node_id,
            file_id,
            when,
            actor.host_id,
            event.get("event_id"),
            previous_path=info.get("previous_path"),
        )

    def _apply_registry(
        self,
        event: Dict[str, Any],
        when: datetime,
        actor: ProcessIncarnation,
        kind: EdgeKind,
    ) -> Optional[Edge]:
        info = event.get("registry") or {}
        key_path = info.get("key_path") or info.get("key")
        if not key_path:
            return None

        key_id = entity_node_id(NodeKind.REGISTRY_KEY, actor.host_id, key_path)
        self.graph.upsert_node(
            key_id, NodeKind.REGISTRY_KEY, key_path, actor.host_id, when
        )
        return self.graph.add_edge(
            kind,
            actor.node_id,
            key_id,
            when,
            actor.host_id,
            event.get("event_id"),
            value_name=info.get("value_name"),
        )

    def _apply_image_load(
        self, event: Dict[str, Any], when: datetime, actor: ProcessIncarnation
    ) -> Optional[Edge]:
        info = event.get("image") or {}
        path = info.get("path")
        if not path:
            return None

        module_id = entity_node_id(NodeKind.MODULE, actor.host_id, path)
        self.graph.upsert_node(
            module_id,
            NodeKind.MODULE,
            path,
            actor.host_id,
            when,
            sha256=info.get("sha256"),
            is_signed=info.get("is_signed"),
        )
        return self.graph.add_edge(
            EdgeKind.LOADED,
            actor.node_id,
            module_id,
            when,
            actor.host_id,
            event.get("event_id"),
            signature_status=info.get("signature_status"),
        )

    # ------------------------------------------------------------------
    def _upsert_process(self, incarnation: ProcessIncarnation) -> None:
        self.graph.upsert_node(
            incarnation.node_id,
            NodeKind.PROCESS,
            incarnation.name or incarnation.executable,
            incarnation.host_id,
            incarnation.start_time,
            pid=incarnation.pid,
            executable=incarnation.executable,
            command_line=incarnation.command_line,
            user=incarnation.user,
            sha256=incarnation.sha256,
            # Threaded onto the node so a response recommendation raised from a
            # later event can still name a PID-reuse-safe kill target.
            start_time_ticks=incarnation.start_time_ticks,
        )
