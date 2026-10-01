"""Per-process feature records: one extractor for training, replay and live scoring.

Rules ask questions about one event. Behavioral detectors -- and any model
trained later -- need a fixed-shape description of one *process*: who started
it, what it ran, what it went on to do. :class:`FeatureExtractor` produces that
description, :class:`ProcessFeatures`, from the process registry and the
provenance graph.

There is exactly one extractor. Live detection, ``--export-features`` and
``--learn-baseline`` all call :meth:`FeatureExtractor.extract`, so a baseline or
model can never be trained on features computed differently from the ones it is
later scored on (training/serving skew).

Every feature comes from telemetry an agent emits (schema 0.5) or from graph
joins over it. Deliberately absent, because nothing produces them: the signer
of a process's own image (only ``image_load`` carries signature data), hash
prevalence, logon sessions and WMI activity.

Schema version 2 added the 0.5 telemetry: lifetime (from an observed stop),
DNS activity, cross-process access and injection, and PowerShell script
blocks. Each is a count or a short list a person can read back, not an opaque
vector.

Behavior counts are *as of* a point in time. At process creation they are all
zero -- nothing has happened yet -- and an export taken after a replay sees the
process's whole observed life. Lineage, identity and command-line features do
not change over a process's life.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from panopticon_detection.enrichment import (
    MatchContext,
    classify_path,
    destination_scope,
    image_write_for,
    tree_root,
)
from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator
from panopticon_detection.provenance.graph import EdgeKind, NodeKind, ProvenanceGraph
from panopticon_detection.provenance.identity import (
    UNKNOWN_TIME,
    ProcessIncarnation,
    ProcessRegistry,
    parse_timestamp,
)

# Bump when a field is added, removed or changes meaning. Baselines record the
# version they were learned with and refuse to load against a different one.
FEATURE_SCHEMA_VERSION = 2

# Image types counted as "executable" by executable_write_count.
EXECUTABLE_SUFFIXES = frozenset({".exe", ".dll", ".scr", ".sys", ".com"})

_REGISTRY_WRITES = frozenset({EdgeKind.SET_VALUE, EdgeKind.CREATED_KEY, EdgeKind.DELETED_KEY})

# Fields serialised as JSON lists; restored to tuples so records stay hashable
# and compare equal after a round trip.
_TUPLE_FIELDS = ("access_targets", "remote_thread_targets")


@dataclass(frozen=True)
class ProcessFeatures:
    """Fixed-shape description of one process incarnation."""

    feature_schema_version: int

    # identity
    host_id: str
    node_id: str
    pid: int
    parent_pid: Optional[int]
    name: str
    executable: str
    path_class: Optional[str]
    start_time: str
    user: str
    inferred: bool

    # lineage
    parent_name: Optional[str]
    grandparent_name: Optional[str]
    tree_root_name: Optional[str]
    depth: int
    parent_child: Optional[str]

    # command line
    cmdline_length: int
    cmdline_token_count: int
    cmdline_entropy: float
    cmdline_obfuscated: bool
    cmdline_evasion_count: int

    # provenance of the process's own image
    image_writer_name: Optional[str]
    image_age_seconds: Optional[float]

    # behavior, as of ``as_of``
    child_count: int
    file_write_count: int
    executable_write_count: int
    registry_write_count: int
    network_connect_count: int
    public_connect_count: int
    module_load_count: int

    # lifetime: only when a stop event was observed (schema 0.5)
    lifetime_seconds: Optional[float]

    # DNS (schema 0.5), as of ``as_of``
    dns_query_count: int
    distinct_domain_count: int
    failed_dns_query_count: int

    # cross-process (schema 0.5), as of ``as_of``
    process_access_count: int
    lsass_access_count: int
    remote_thread_count: int
    injected_thread_count: int
    access_targets: Tuple[str, ...]
    remote_thread_targets: Tuple[str, ...]

    # PowerShell script blocks (schema 0.5), as of ``as_of``
    script_block_count: int
    script_block_bytes: int
    obfuscated_script_block_count: int

    as_of: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProcessFeatures":
        names = {f.name for f in fields(cls)}
        unknown = set(data) - names
        if unknown:
            raise ValueError(f"unknown feature field(s): {sorted(unknown)}")
        values = dict(data)
        for name in _TUPLE_FIELDS:
            if isinstance(values.get(name), list):
                values[name] = tuple(values[name])
        return cls(**values)


class FeatureExtractor:
    """Builds :class:`ProcessFeatures` from the registry and graph a run maintains."""

    def __init__(self, registry: ProcessRegistry, graph: ProvenanceGraph) -> None:
        self.registry = registry
        self.graph = graph
        self._ctx = MatchContext(registry=registry, graph=graph)

    def extract(
        self, process: ProcessIncarnation, as_of: Optional[datetime] = None
    ) -> ProcessFeatures:
        """Features of ``process``; behavior counts include edges up to ``as_of``
        (every observed edge when ``None``)."""
        ancestors = self.registry.ancestors(process.node_id)
        parent = ancestors[0] if ancestors else None
        grandparent = ancestors[1] if len(ancestors) > 1 else None
        root = tree_root(self.registry, process)

        cmd = process.command_line or ""
        deob = CommandDeobfuscator.deobfuscate(cmd)
        written = image_write_for(process, self._ctx)

        parent_name = (parent.name or None) if parent else None
        name = process.name or ""
        return ProcessFeatures(
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            host_id=process.host_id,
            node_id=process.node_id,
            pid=process.pid,
            parent_pid=process.parent_pid,
            name=name,
            executable=process.executable or "",
            path_class=classify_path(process.executable),
            start_time=process.start_time.isoformat(),
            user=process.user or "",
            inferred=process.inferred,
            parent_name=parent_name,
            grandparent_name=(grandparent.name or None) if grandparent else None,
            tree_root_name=(root.name or None) if root else None,
            depth=len(ancestors),
            parent_child=f"{parent_name} -> {name}" if parent_name and name else None,
            cmdline_length=len(cmd),
            cmdline_token_count=len(cmd.split()),
            cmdline_entropy=round(ShannonEntropyCalculator.calculate_entropy(cmd), 4),
            cmdline_obfuscated=bool(deob["is_obfuscated"]),
            cmdline_evasion_count=len(deob["evasion_techniques"]),
            image_writer_name=(written[0].name or None) if written else None,
            image_age_seconds=written[1] if written else None,
            **self._behavior(process.node_id, as_of),
            lifetime_seconds=_lifetime(process, as_of),
            as_of=as_of.isoformat() if as_of is not None else None,
        )

    def extract_event(self, event: Dict[str, Any]) -> Optional[ProcessFeatures]:
        """Features of the process that performed ``event``, as of the event."""
        process = self.registry.resolve_event(event)
        if process is None:
            return None
        when = parse_timestamp(event.get("timestamp"))
        return self.extract(process, None if when == UNKNOWN_TIME else when)

    def extract_all(self, as_of: Optional[datetime] = None) -> List[ProcessFeatures]:
        """Every process in the registry, in a deterministic order."""
        processes = sorted(self.registry, key=lambda p: (p.start_time, p.node_id))
        return [self.extract(p, as_of) for p in processes]

    # ------------------------------------------------------------------
    def _behavior(self, node_id: str, as_of: Optional[datetime]) -> Dict[str, Any]:
        counts: Dict[str, Any] = {
            "child_count": 0,
            "file_write_count": 0,
            "executable_write_count": 0,
            "registry_write_count": 0,
            "network_connect_count": 0,
            "public_connect_count": 0,
            "module_load_count": 0,
            "dns_query_count": 0,
            "failed_dns_query_count": 0,
            "process_access_count": 0,
            "lsass_access_count": 0,
            "remote_thread_count": 0,
            "injected_thread_count": 0,
            "script_block_count": 0,
            "script_block_bytes": 0,
            "obfuscated_script_block_count": 0,
        }
        domains = set()
        access_targets = set()
        thread_targets = set()
        for edge in self.graph.incident_edges(node_id):
            if as_of is not None and edge.ts > as_of:
                continue
            if edge.dst == node_id and edge.kind == EdgeKind.INJECTED:
                counts["injected_thread_count"] += 1
                continue
            if edge.src != node_id:
                continue
            if edge.kind == EdgeKind.FORKED:
                counts["child_count"] += 1
            elif edge.kind == EdgeKind.WROTE:
                counts["file_write_count"] += 1
                target = self.graph.nodes.get(edge.dst)
                if target is not None and _suffix(target.label) in EXECUTABLE_SUFFIXES:
                    counts["executable_write_count"] += 1
            elif edge.kind in _REGISTRY_WRITES:
                counts["registry_write_count"] += 1
            elif edge.kind == EdgeKind.CONNECTED_TO:
                counts["network_connect_count"] += 1
                socket = self.graph.nodes.get(edge.dst)
                if (
                    socket is not None
                    and socket.kind == NodeKind.SOCKET
                    and destination_scope(socket.attrs.get("ip")) == "public"
                ):
                    counts["public_connect_count"] += 1
            elif edge.kind == EdgeKind.LOADED:
                counts["module_load_count"] += 1
            elif edge.kind == EdgeKind.RESOLVED:
                counts["dns_query_count"] += 1
                domains.add(edge.dst)
                if edge.attrs.get("query_status") not in (None, 0):
                    counts["failed_dns_query_count"] += 1
            elif edge.kind == EdgeKind.ACCESSED:
                counts["process_access_count"] += 1
                target = self._label(edge.dst)
                access_targets.add(target)
                if target == "lsass.exe":
                    counts["lsass_access_count"] += 1
            elif edge.kind == EdgeKind.INJECTED:
                counts["remote_thread_count"] += 1
                thread_targets.add(self._label(edge.dst))
            elif edge.kind == EdgeKind.RAN_SCRIPT:
                counts["script_block_count"] += 1
                counts["script_block_bytes"] += edge.attrs.get("text_length") or 0
                if edge.attrs.get("obfuscated"):
                    counts["obfuscated_script_block_count"] += 1
        counts["distinct_domain_count"] = len(domains)
        counts["access_targets"] = tuple(sorted(t for t in access_targets if t))
        counts["remote_thread_targets"] = tuple(sorted(t for t in thread_targets if t))
        return counts

    def _label(self, node_id: str) -> str:
        node = self.graph.nodes.get(node_id)
        return (node.label or "").lower() if node is not None else ""


def _lifetime(process: ProcessIncarnation, as_of: Optional[datetime]) -> Optional[float]:
    """Seconds the process ran, when its stop was observed by ``as_of``."""
    if not process.end_observed or process.end_time is None:
        return None
    if as_of is not None and process.end_time > as_of:
        return None
    return round((process.end_time - process.start_time).total_seconds(), 3)


def _suffix(path: Optional[str]) -> str:
    if not path:
        return ""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[name.rfind("."):] if "." in name else ""


def write_jsonl(records: Iterable[ProcessFeatures], path: Path) -> int:
    """Write feature records as JSON lines; returns how many were written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict()) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> Iterator[ProcessFeatures]:
    """Read records written by :func:`write_jsonl`."""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield ProcessFeatures.from_dict(json.loads(line))
