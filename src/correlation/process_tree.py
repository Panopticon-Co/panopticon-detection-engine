"""Process Tree and Process State Management.

Maintains stateful parent-child process relationships, tracks process lifecycles,
resolves ancestry queries (e.g., "was any ancestor winword.exe?"), and prevents
false-positive associations caused by OS PID reuse using unique ProcessGuids.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set


@dataclass
class ProcessNode:
    """Represents a unique process instance on an endpoint."""
    process_guid: str
    pid: int
    ppid: int
    name: str
    command_line: str = ""
    path: str = ""
    user: str = ""
    parent_guid: Optional[str] = None
    host_id: str = "UNKNOWN"
    start_time: Optional[str] = None
    # Opaque, OS-native process-creation value from Schema 0.4's
    # process.start_time_ticks -- distinct from start_time above, which is
    # the event's wall-clock timestamp. Only the originating host's own
    # agent may interpret this value's magnitude; here it exists purely so a
    # correlation rule that fires on an event other than this process's own
    # creation (e.g. a later network/file event, or a rule referencing an
    # ancestor) can still recover a PID-reuse-safe KILL_PROCESS target via
    # get_node(process_guid). See
    # panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md.
    start_time_ticks: Optional[int] = None
    end_time: Optional[str] = None
    is_alive: bool = True
    children_guids: List[str] = field(default_factory=list)


class ProcessTree:
    """Tracks stateful process hierarchies across hosts."""

    def __init__(self):
        # Index: process_guid -> ProcessNode
        self.nodes_by_guid: Dict[str, ProcessNode] = {}
        # Index: (host_id, pid) -> most recent active process_guid (handles PID reuse)
        self.active_pids: Dict[tuple, str] = {}

    def handle_event(self, event: Dict[str, Any]) -> Optional[ProcessNode]:
        """Ingests process_create and process_terminate events to maintain tree state."""
        event_type = event.get("event_type")
        if event_type == "process_create":
            return self.add_process(event)
        elif event_type == "process_terminate":
            return self.terminate_process(event)
        return None

    def add_process(self, event: Dict[str, Any]) -> ProcessNode:
        """Adds or updates a process node on process_create."""
        proc = event.get("process", {})
        parent = event.get("parent", {})
        host_id = event.get("host_id", "UNKNOWN")

        guid = proc.get("process_guid") or f"SYNTH-{host_id}-{proc.get('pid')}-{event.get('timestamp')}"
        parent_guid = parent.get("process_guid")
        pid = proc.get("pid", 0)
        ppid = proc.get("ppid", parent.get("pid", 0))

        # If parent_guid is missing, lookup via (host_id, ppid)
        if not parent_guid and ppid:
            parent_guid = self.active_pids.get((host_id, ppid))

        node = ProcessNode(
            process_guid=guid,
            pid=pid,
            ppid=ppid,
            name=proc.get("name", "").lower(),
            command_line=proc.get("command_line", ""),
            path=proc.get("path", ""),
            user=proc.get("user", ""),
            parent_guid=parent_guid,
            host_id=host_id,
            start_time=event.get("timestamp"),
            start_time_ticks=proc.get("start_time_ticks"),
            is_alive=True,
        )

        self.nodes_by_guid[guid] = node
        self.active_pids[(host_id, pid)] = guid

        # Link to parent node
        if parent_guid and parent_guid in self.nodes_by_guid:
            self.nodes_by_guid[parent_guid].children_guids.append(guid)

        return node

    def terminate_process(self, event: Dict[str, Any]) -> Optional[ProcessNode]:
        """Marks a process as terminated on process_terminate."""
        proc = event.get("process", {})
        host_id = event.get("host_id", "UNKNOWN")
        guid = proc.get("process_guid")
        pid = proc.get("pid")

        node = None
        if guid and guid in self.nodes_by_guid:
            node = self.nodes_by_guid[guid]
        elif pid and (host_id, pid) in self.active_pids:
            active_guid = self.active_pids[(host_id, pid)]
            node = self.nodes_by_guid.get(active_guid)

        if node:
            node.is_alive = False
            node.end_time = event.get("timestamp")
            # Clear from active PIDs table to prevent PID reuse collision
            if (host_id, node.pid) in self.active_pids:
                del self.active_pids[(host_id, node.pid)]

        return node

    def get_node(self, process_guid: str) -> Optional[ProcessNode]:
        """Retrieves a process node by GUID."""
        return self.nodes_by_guid.get(process_guid)

    def get_ancestors(self, process_guid: str, max_depth: int = 10) -> List[ProcessNode]:
        """Returns the list of ancestor ProcessNodes from parent up to root."""
        ancestors: List[ProcessNode] = []
        current_guid = process_guid
        depth = 0

        while current_guid and depth < max_depth:
            node = self.nodes_by_guid.get(current_guid)
            if not node or not node.parent_guid:
                break
            
            parent_node = self.nodes_by_guid.get(node.parent_guid)
            if not parent_node:
                break

            # Avoid circular loops
            if parent_node in ancestors:
                break

            ancestors.append(parent_node)
            current_guid = parent_node.process_guid
            depth += 1

        return ancestors

    def has_ancestor(self, process_guid: str, ancestor_names: List[str]) -> bool:
        """Checks if any ancestor in the lineage matches any name in ancestor_names."""
        normalized_targets = {name.lower() for name in ancestor_names}
        ancestors = self.get_ancestors(process_guid)
        return any(a.name in normalized_targets for a in ancestors)

    def get_lineage_string(self, process_guid: str) -> str:
        """Generates a human-readable lineage string e.g. 'explorer.exe -> winword.exe -> cmd.exe -> powershell.exe'"""
        node = self.nodes_by_guid.get(process_guid)
        if not node:
            return "UNKNOWN"

        ancestors = self.get_ancestors(process_guid)
        names = [a.name for a in reversed(ancestors)] + [node.name]
        return " -> ".join(names)
