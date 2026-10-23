"""Full-family replay for the context model: raw recordings -> per-process checkpoint records.

Every recording is turned into canonical agent events with *all* telemetry
families (process, network, file, registry, image load, DNS, process access,
remote thread, script block) and replayed through the real engine
(``factory.build_detection_run``). A :class:`CheckpointTap` rides along as a
behavioural detector that never emits a signal. While the engine processes each
event it records, for the process concerned:

* a ``start`` record: the v5 process-start vector, and the (host, pid, start time)
  key that joins it to the labelled process-start rows (event ids can differ when a
  recording has no record numbers, because the adapter then numbers records by position);
* a checkpoint (``cp``) at the start, and each time the process gains a new
  behaviour bit (``features.edge_bits``; at most :data:`MAX_BIT_CHECKPOINTS`), and
  at its stop -- the feature record is ``FeatureExtractor.extract(p, as_of=now)``
  taken *during* the replay, exactly what a live engine could compute then;
* a short token sequence of what it did (for the sequence comparison arm).

Every alert the engine emits is recorded too (rules baseline B1 and the L3
simulation), as is a per-host census of which families were collected and the
observed host-hours.

Output: ``data/replay/<environment>/<unit>.jsonl.gz`` plus ``census.json``.
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import heapq
import json
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from panopticon_detection import enrichment
from panopticon_detection.datasets import sysmon_xml as SX
from panopticon_detection.datasets.otrf import OtrfAdapter, read_records
from panopticon_detection.factory import build_detection_run
from panopticon_detection.features import BEHAVIOR_BITS, PROCESS_VM_READ, _mask, _suffix, edge_bits
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.ml import featurizer as F
from panopticon_detection.provenance.graph import EdgeKind
from panopticon_detection.provenance.identity import UNKNOWN_TIME, parse_timestamp

REPLAY_VERSION = 2  # 2: per-node storyline roots
MAX_BIT_CHECKPOINTS = 8
MAX_TOKENS = 100
GAP_CAP_SECONDS = 3600.0
PRUNE_EVERY = timedelta(hours=1)
RETENTION = timedelta(hours=24)

ENVIRONMENT_OF_SOURCE = {
    "attack_data": "attack_range", "otrf": "mordor", "otrf_compound": "mordor", "botsv1": "botsv1",
    "officer_vm": "officer_vm", "optc": "optc", "atlasv2": "atlasv2",
}
#: Engine event type -> telemetry family (the census and the availability of feature groups).
FAMILY_OF_EVENT = {
    "network_connect": "network", "image_load": "image_load",
    "file_create": "file", "file_delete": "file", "file_rename": "file",
    "registry_write": "registry", "registry_add_key": "registry", "registry_delete_key": "registry",
    "registry_rename_key": "registry", "process_access": "process_access", "remote_thread": "remote_thread",
    "dns_query": "dns", "script_block": "script_block",
    "process_create": "process", "process_terminate": "process",
}


# ======================================================================== tap


def _token(edge: Any, graph: Any, node_id: str) -> Optional[str]:
    """A closed-vocabulary word for what ``node_id`` did on this edge (sequence arm)."""
    other = graph.nodes.get(edge.dst if edge.src == node_id else edge.src)
    label = (other.label or "") if other is not None else ""
    if edge.dst == node_id:
        return "thread:in" if edge.kind == EdgeKind.INJECTED else None
    kind = edge.kind
    if kind == EdgeKind.FORKED:
        return f"child:{F.ROLE_OF.get(label.lower(), 'other')}"
    if kind == EdgeKind.WROTE:
        ext = _suffix(label)
        ext_class = "exe" if ext in (".exe", ".dll", ".scr", ".sys", ".com") else (
            "script" if ext in (".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd") else "other")
        return f"file:write:{enrichment.classify_path(label) or 'none'}:{ext_class}"
    if kind in (EdgeKind.DELETED, EdgeKind.RENAMED):
        return f"file:{kind.value}"
    if kind in (EdgeKind.SET_VALUE, EdgeKind.CREATED_KEY, EdgeKind.DELETED_KEY):
        bits = edge_bits(edge, graph, node_id)
        return "reg:persist" if "registry:persistence_key" in bits else f"reg:{kind.value}"
    if kind == EdgeKind.LOADED:
        signed = other.attrs.get("is_signed") if other is not None else None
        return f"img:{enrichment.classify_path(label) or 'none'}" + (":unsigned" if signed is False else "")
    if kind == EdgeKind.CONNECTED_TO:
        scope = enrichment.destination_scope(other.attrs.get("ip")) if other is not None else None
        port = other.attrs.get("port") if other is not None else None
        return f"net:{scope or 'unknown'}:{'std' if port in (53, 80, 443) else 'other'}"
    if kind == EdgeKind.RESOLVED:
        return "dns:fail" if edge.attrs.get("query_status") not in (None, 0) else "dns:ok"
    if kind == EdgeKind.ACCESSED:
        mask = _mask(edge.attrs.get("access_mask", edge.attrs.get("granted_access")))
        role = "lsass" if label.lower().endswith("lsass.exe") else F.ROLE_OF.get(label.lower(), "other")
        return f"access:{role}" + (":read" if mask is not None and mask & PROCESS_VM_READ else "")
    if kind == EdgeKind.INJECTED:
        return f"thread:out:{F.ROLE_OF.get(label.lower(), 'other')}"
    if kind == EdgeKind.RAN_SCRIPT:
        return "script:obfuscated" if edge.attrs.get("obfuscated") else "script:plain"
    return None


class CheckpointTap:
    """A behavioural detector that never emits a signal; it records checkpoints."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self._bits: Dict[str, set] = collections.defaultdict(set)
        self._bit_checkpoints: Dict[str, int] = collections.Counter()
        self._tokens: Dict[str, List[str]] = collections.defaultdict(list)
        self.edge_cap_nodes: set = set()
        self._nodes: Dict[str, Dict[str, Any]] = {}  # node -> storyline root etc., at first sight

    # -- the detector interface ------------------------------------------------
    def evaluate(self, event: Dict[str, Any], extractor: Any) -> List[Any]:
        when = parse_timestamp(event.get("timestamp"))
        if when == UNKNOWN_TIME:
            return []
        registry, graph = extractor.registry, extractor.graph
        etype = event.get("event_type")
        if etype == "process_terminate":
            # The stop has already closed the incarnation at `when`; it was live just before.
            proc = event.get("process") or {}
            p = registry.resolve(event.get("host_id") or "UNKNOWN_HOST", proc.get("pid"),
                                 when - timedelta(microseconds=1))
            if p is not None:
                self._checkpoint(extractor, p, "stop", when)
            return []
        actor = registry.resolve_event(event)
        if actor is None:
            return []
        self._see(registry, actor)
        if etype == "process_create":
            self.records.append({
                "t": "start", "node": actor.node_id, "host": actor.host_id, "pid": actor.pid,
                "event_id": event.get("event_id"),
                "ts": event.get("timestamp"), "start_vector": {str(k): v for k, v in F.featurize(event).items()},
            })
            self._checkpoint(extractor, actor, "start", when)
        for edge in self._edges_of(event, actor, graph):
            for node_id in (edge.src, edge.dst):
                if registry.get(node_id) is None:
                    continue
                self._see(registry, registry.get(node_id))
                token = _token(edge, graph, node_id)
                if token is not None:
                    tokens = self._tokens[node_id]
                    if len(tokens) < MAX_TOKENS and (not tokens or tokens[-1] != token):
                        tokens.append(token)
                new = edge_bits(edge, graph, node_id) - self._bits[node_id]
                if new:
                    self._bits[node_id] |= new
                    if self._bit_checkpoints[node_id] < MAX_BIT_CHECKPOINTS:
                        self._bit_checkpoints[node_id] += 1
                        kind = "bit:" + ",".join(b for b in BEHAVIOR_BITS if b in new)
                        self._checkpoint(extractor, registry.get(node_id), kind, when)
        return []

    def prune(self, before: datetime) -> int:
        return 0  # records are emitted as they happen; per-node state is small

    # -- helpers ---------------------------------------------------------------
    def _edges_of(self, event: Dict[str, Any], actor: Any, graph: Any) -> List[Any]:
        """The edges this event just created (they carry its event id)."""
        event_id = event.get("event_id")
        adjacency = graph._adjacency.get(actor.node_id, [])
        if len(adjacency) >= graph._max_edges_per_node:
            self.edge_cap_nodes.add(actor.node_id)
        out = []
        for edge_id in adjacency[-3:]:
            edge = graph.edges.get(edge_id)
            if edge is not None and event_id is not None and edge.event_id == event_id:
                out.append(edge)
        return out

    def _checkpoint(self, extractor: Any, process: Any, kind: str, when: datetime) -> None:
        features = extractor.extract(process, as_of=when)
        self.records.append({"t": "cp", "node": process.node_id, "kind": kind,
                             "ts": when.isoformat(), "features": features.to_dict()})

    def _see(self, registry: Any, process: Any) -> None:
        """Remember a process's storyline root (``enrichment.tree_root``) the first time it is seen."""
        if process.node_id in self._nodes:
            return
        root = enrichment.tree_root(registry, process)
        self._nodes[process.node_id] = {"t": "node", "node": process.node_id, "host": process.host_id,
                                        "root": root.node_id if root is not None else process.node_id,
                                        "name": (process.name or "").lower(), "inferred": bool(process.inferred)}

    def node_records(self) -> List[Dict[str, Any]]:
        return [self._nodes[k] for k in sorted(self._nodes)]

    def token_records(self) -> List[Dict[str, Any]]:
        return [{"t": "tokens", "node": node, "tokens": tokens} for node, tokens in sorted(self._tokens.items())]


# ====================================================================== units


@dataclass
class Unit:
    """One replay: a recording (or one host's merged runs) of one source.

    Plain data (``kind`` + ``args``) so units pickle into worker processes;
    :func:`unit_events` turns a unit into its canonical events in time order.
    """

    unit_id: str
    source: str
    dataset: str
    kind: str  # attack_data_log | otrf_archive | botsv1_json | officer_rows | atlasv2_host | runs | inline
    args: tuple = ()
    normalized: bool = False  # events are already engine-normalized
    weight: int = 0  # bytes on disk, to schedule big units first

    @property
    def environment(self) -> str:
        return ENVIRONMENT_OF_SOURCE[self.source]

    def events(self) -> Iterable[Dict[str, Any]]:
        return unit_events(self)


def _adapter_events(dataset_id: str, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events, _report = OtrfAdapter(dataset_id).normalize(records)
    return events


def _runs(folder: Path) -> Iterator[Iterator[Dict[str, Any]]]:
    for run in sorted(folder.glob("run-*.ndjson.gz")):
        yield (json.loads(line) for line in gzip.open(run, "rt", encoding="utf-8"))


def unit_events(unit: Unit) -> Iterable[Dict[str, Any]]:
    if unit.kind == "attack_data_log":
        return _adapter_events(unit.dataset, list(SX.read_attack_data_log(Path(unit.args[0]))))
    if unit.kind == "otrf_archive":
        return _adapter_events(unit.dataset, read_records(Path(unit.args[0])))
    if unit.kind == "botsv1_json":
        return _adapter_events(unit.dataset, list(SX.read_botsv1_json(Path(unit.args[0]))))
    if unit.kind == "officer_rows":
        events = []
        with gzip.open(unit.args[0], "rt", encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                if row["dataset"] == unit.dataset:
                    event = dict(row["event"])
                    event.setdefault("event_id", row["row_id"])
                    events.append(event)
        return sorted(events, key=lambda e: (e.get("timestamp") or "", e.get("event_id") or ""))
    if unit.kind in ("atlasv2_host", "runs"):
        streams = [run for folder in unit.args for run in _runs(Path(folder))]
        return heapq.merge(*streams, key=lambda e: (e["event"]["timestamp"], e["event"]["id"]))
    if unit.kind == "inline":
        return list(unit.args[0])
    raise ValueError(f"unknown unit kind {unit.kind!r}")


def attack_data_units(raw: Path) -> List[Unit]:
    from pdtrain.normalize import _attack_data_meta

    units = []
    for rel, _meta in sorted(_attack_data_meta(raw).items()):
        path = raw / "attack_data" / rel
        if path.exists():
            units.append(Unit(f"attack_data--{_safe(rel)}", "attack_data", "attack_data:" + rel,
                              "attack_data_log", (str(path),), weight=path.stat().st_size))
    return units


def otrf_units(raw: Path) -> List[Unit]:
    base = raw / "otrf"
    units = []
    for path in sorted(base.glob("datasets/**/*")):
        if not path.is_file() or not path.name.endswith((".zip", ".tar.gz")):
            continue
        rel = str(path.relative_to(base))
        if rel.startswith("datasets/atomic/windows/") and "/host/" in rel:
            source = "otrf"
        elif rel.startswith("datasets/compound/") and "pcap" not in rel:
            source = "otrf_compound"
        else:
            continue
        units.append(Unit(f"{source}--{_safe(rel)}", source, "otrf:" + rel, "otrf_archive", (str(path),),
                          weight=path.stat().st_size))
    return units


def botsv1_units(raw: Path) -> List[Unit]:
    return [Unit(f"botsv1--{_safe(p.name)}", "botsv1", "botsv1", "botsv1_json", (str(p),),
                 weight=p.stat().st_size * 10)
            for p in sorted((raw / "botsv1").glob("*.json.gz"))]


def officer_vm_units(rows_dir: Path) -> List[Unit]:
    """The agent recording kept starts only; its row events are already engine-normalized."""
    path = rows_dir / "officer_vm.jsonl.gz"
    if not path.exists():
        return []
    counts: collections.Counter = collections.Counter()
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            counts[json.loads(line)["dataset"]] += 1
    return [Unit(f"officer_vm--{_safe(d)}", "officer_vm", d, "officer_rows", (str(path),),
                 normalized=True, weight=n * 1000) for d, n in sorted(counts.items())]


def atlasv2_units(canonical: Path) -> List[Unit]:
    """One unit per ATLASv2 host: every Sysmon export's runs merged in time order."""
    root = canonical / "atlasv2"
    units = []
    for host in ("h1", "h2"):
        folders = sorted(p for p in root.glob(f"*/{host}/*") if p.is_dir())
        if folders:
            units.append(Unit(f"atlasv2--{host}", "atlasv2", f"atlasv2:{host}", "atlasv2_host",
                              tuple(str(f) for f in folders),
                              weight=sum(r.stat().st_size for f in folders for r in f.glob("run-*")) * 20))
    return units


def _safe(text: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", text)[-80:]
    return f"{stem}-{hashlib.sha256(text.encode()).hexdigest()[:8]}"


# ===================================================================== replay


def replay_unit(unit: Unit, repo: Path, out_dir: Path) -> Dict[str, Any]:
    """Replay one unit through the engine; write its records; return its summary."""
    tap = CheckpointTap()
    run, ctx = build_detection_run(repo / "rules", retention=RETENTION, behavioral_detectors=[tap])
    registry = ctx.registry
    families: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    hours: Dict[Tuple[str, str], float] = collections.defaultdict(float)
    last_seen: Dict[Tuple[str, str], datetime] = {}
    alerts: List[Dict[str, Any]] = []
    next_prune: Optional[datetime] = None
    count = 0
    for raw_event in unit.events():
        event = raw_event if unit.normalized else OfficerIngestionAdapter.transform_officer_event(raw_event)
        event.pop("_raw_officer_event", None)
        when = parse_timestamp(event.get("timestamp"))
        host = event.get("host_id") or "UNKNOWN_HOST"
        count += 1
        families[host][FAMILY_OF_EVENT.get(event.get("event_type"), "other")] += 1
        if when != UNKNOWN_TIME:
            key = (unit.dataset, host)
            previous = last_seen.get(key)
            if previous is not None and when > previous:
                hours[key] += min((when - previous).total_seconds(), GAP_CAP_SECONDS) / 3600.0
            if previous is None or when > previous:
                last_seen[key] = when
            if next_prune is None:
                next_prune = when + PRUNE_EVERY
            elif when >= next_prune:
                ctx.prune(when - RETENTION)
                next_prune = when + PRUNE_EVERY
        enrichment.reset(event)
        produced = run.process_event(event)
        if produced:
            actor = registry.resolve_event(event)
            for alert in produced:
                evidence = alert.evidence or {}
                alerts.append({
                    "t": "alert", "node": actor.node_id if actor is not None else None, "host": host,
                    "rule_id": alert.rule_id, "level": alert.level, "ts": alert.timestamp,
                    "tactic": alert.mitre_tactic, "technique": alert.mitre_technique,
                    "incident_id": alert.incident_id, "confidence": alert.confidence,
                    "action": (alert.active_response or {}).get("action"),
                    "root": evidence.get("root") if isinstance(evidence.get("root"), (str, dict)) else None,
                })
    summary = {
        "t": "unit", "unit": unit.unit_id, "env": unit.environment, "source": unit.source,
        "dataset": unit.dataset, "events": count, "replay_version": REPLAY_VERSION,
        "hosts": {h: {"families": dict(sorted(c.items())), "hours": round(hours.get((unit.dataset, h), 0.0), 4)}
                  for h, c in sorted(families.items())},
        "edge_cap_nodes": len(tap.edge_cap_nodes), "alerts": len(alerts),
        "checkpoints": sum(1 for r in tap.records if r["t"] == "cp"),
        "starts": sum(1 for r in tap.records if r["t"] == "start"),
    }
    path = out_dir / unit.environment / f"{unit.unit_id}.jsonl.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        for record in [summary, *tap.records, *alerts, *tap.token_records(), *tap.node_records()]:
            handle.write((json.dumps(record, sort_keys=True, default=str) + "\n").encode("utf-8"))
    return summary


def _worker(args: Tuple[Unit, Path, Path]) -> Dict[str, Any]:
    unit, repo, out_dir = args
    try:
        return replay_unit(unit, repo, out_dir)
    except Exception as exc:  # reported in the census; one bad recording must not stop the rest
        return {"t": "unit", "unit": unit.unit_id, "env": unit.environment, "error": f"{type(exc).__name__}: {exc}"}


def collect_units(data: Path, sources: Iterable[str]) -> List[Unit]:
    raw, wanted = data / "raw", set(sources)
    units: List[Unit] = []
    if "attack_data" in wanted:
        units += attack_data_units(raw)
    if wanted & {"otrf", "otrf_compound"}:
        units += [u for u in otrf_units(raw) if u.source in wanted]
    if "botsv1" in wanted:
        units += botsv1_units(raw)
    if "officer_vm" in wanted:
        units += officer_vm_units(data / "rows")
    if "atlasv2" in wanted:
        units += atlasv2_units(data / "canonical")
    if "optc" in wanted:
        from pdtrain.optc_replay import optc_units

        units += optc_units(data / "canonical")
    return units


def replay_all(data: Path, repo: Path, sources: Iterable[str], workers: int = 4, log=print) -> Dict[str, Any]:
    out_dir = data / "replay"
    units = sorted(collect_units(data, sources), key=lambda u: -u.weight)
    summaries: List[Dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_worker, (u, repo, out_dir)): u for u in units}
        for done, future in enumerate(as_completed(futures), 1):
            summary = future.result()
            summaries.append(summary)
            if done % 25 == 0 or done == len(units) or "error" in summary:
                log(f"[replay] {done}/{len(units)} {summary['unit']}: "
                    f"{summary.get('error') or str(summary['events']) + ' events'}", flush=True)
    census = census_of(out_dir)
    return {"units": len(units), "errors": [s for s in summaries if "error" in s], "census": census}


def census_of(out_dir: Path) -> Dict[str, Any]:
    """Families collected, host-hours and record counts per environment, from the unit summaries."""
    envs: Dict[str, Dict[str, Any]] = {}
    for path in sorted(out_dir.glob("*/*.jsonl.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            summary = json.loads(handle.readline())
        env = envs.setdefault(summary["env"], {"units": 0, "events": 0, "starts": 0, "checkpoints": 0,
                                               "alerts": 0, "edge_cap_nodes": 0, "host_hours": 0.0,
                                               "families": collections.Counter(),
                                               "hours_with_family": collections.Counter()})
        env["units"] += 1
        for key in ("events", "starts", "checkpoints", "alerts", "edge_cap_nodes"):
            env[key] += summary.get(key, 0)
        for info in summary.get("hosts", {}).values():
            # Only hosts with process telemetry are monitored endpoints. BOTSv1's export also
            # names ~1,750 hosts seen only in inbound NetBIOS broadcasts from "System".
            if not info["families"].get("process"):
                continue
            env["host_hours"] += info["hours"]
            for fam, n in info["families"].items():
                env["families"][fam] += n
                env["hours_with_family"][fam] += info["hours"]
    for env in envs.values():
        env["host_hours"] = round(env["host_hours"], 2)
        env["families"] = dict(sorted(env["families"].items()))
        env["hours_with_family"] = {k: round(v, 2) for k, v in sorted(env["hours_with_family"].items())}
    (out_dir / "census.json").write_text(json.dumps(envs, indent=2) + "\n")
    return envs
