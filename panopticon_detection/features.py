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

Every feature comes from telemetry the agent emits today (schema 0.3) or from
graph joins over it. Deliberately absent, because nothing produces them: the
signer of a process's own image (only ``image_load`` carries signature data),
process lifetime (no process-stop event), hash prevalence, DNS, script content
and process access.

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
from typing import Any, Dict, Iterable, Iterator, List, Optional

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
FEATURE_SCHEMA_VERSION = 1

# Image types counted as "executable" by executable_write_count.
EXECUTABLE_SUFFIXES = frozenset({".exe", ".dll", ".scr", ".sys", ".com"})

_REGISTRY_WRITES = frozenset({EdgeKind.SET_VALUE, EdgeKind.CREATED_KEY, EdgeKind.DELETED_KEY})


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
    as_of: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProcessFeatures":
        names = {f.name for f in fields(cls)}
        unknown = set(data) - names
        if unknown:
            raise ValueError(f"unknown feature field(s): {sorted(unknown)}")
        return cls(**data)


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
    def _behavior(self, node_id: str, as_of: Optional[datetime]) -> Dict[str, int]:
        counts = {
            "child_count": 0,
            "file_write_count": 0,
            "executable_write_count": 0,
            "registry_write_count": 0,
            "network_connect_count": 0,
            "public_connect_count": 0,
            "module_load_count": 0,
        }
        for edge in self.graph.incident_edges(node_id):
            if edge.src != node_id or (as_of is not None and edge.ts > as_of):
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
        return counts


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
