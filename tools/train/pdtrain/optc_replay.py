"""OpTC benign eCAR -> per-host canonical runs -> replay units (context model).

One pass over each eCAR file maps every record the agent has an equivalent of
(``panopticon_detection.datasets.ecar``) and writes per-host, time-sorted runs
of at most :data:`RUN_RECORDS` events to ``data/canonical/optc/<range>/<host>/``.
A replay unit then merges one host's runs lazily, like ATLASv2.

Only two 25-host ranges are replayed by default (:data:`DEFAULT_RANGES`): the
benign fleet's job is false positives and rarity, and replay cost grows with
every range.
"""

from __future__ import annotations

import collections
import gzip
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from panopticon_detection.datasets.ecar import to_canonical

DEFAULT_RANGES = ("AIA-51-75", "AIA-201-225")
RUN_RECORDS = 100_000
_MAPPED = ('"PROCESS"', '"FLOW"', '"FILE"', '"MODULE"', '"REGISTRY"', '"THREAD"')


def _write_run(events: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    events.sort(key=lambda e: (e["event"]["timestamp"], e["event"]["id"]))
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        for event in events:
            handle.write((json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))


def split_file(path: Path, out_dir: Path, log=print) -> Dict[str, Any]:
    """One eCAR file -> per-host sorted runs; returns counts."""
    range_name = path.name.split(".")[0]
    dataset = f"optc:{path.parent.name}/{range_name}"
    buffers: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    run_index: Dict[str, int] = collections.Counter()
    counts: collections.Counter = collections.Counter()
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            counts["records"] += 1
            if not any(tag in line for tag in _MAPPED):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                counts["unparseable"] += 1
                continue
            event = to_canonical(record, dataset)
            if event is None:
                continue
            host = event["host"]["id"]
            counts[f"{event['event']['category']}:{event['event']['type']}"] += 1
            buffers[host].append(event)
            if len(buffers[host]) >= RUN_RECORDS:
                _write_run(buffers[host], out_dir / range_name / host / f"run-{run_index[host]:04d}.ndjson.gz")
                run_index[host] += 1
                buffers[host] = []
            if counts["records"] % 5_000_000 == 0:
                log(f"[optc-split] {range_name}: {counts['records']:,} records", flush=True)
    for host, events in buffers.items():
        if events:
            _write_run(events, out_dir / range_name / host / f"run-{run_index[host]:04d}.ndjson.gz")
    return {"file": path.name, "dataset": dataset, "hosts": len(set(buffers) | set(run_index)),
            "counts": dict(sorted(counts.items()))}


def split_all(raw: Path, canonical: Path, ranges: Iterable[str] = DEFAULT_RANGES, log=print) -> Dict[str, Any]:
    out_dir = canonical / "optc"
    results = []
    for range_name in ranges:
        path = raw / "optc" / "benign" / "19Sep19" / f"{range_name}.ecar-last.json.gz"
        results.append(split_file(path, out_dir, log=log))
    manifest = {"ranges": list(ranges), "files": results}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def optc_units(canonical: Path) -> list:
    from pdtrain.replay import Unit

    units = []
    for host_dir in sorted(p for p in (canonical / "optc").glob("*/*") if p.is_dir()):
        range_name, host = host_dir.parent.name, host_dir.name
        size = sum(r.stat().st_size for r in host_dir.glob("run-*"))
        units.append(Unit(f"optc--{range_name}--{host}", "optc", f"optc:19Sep19/{range_name}", "runs",
                          (str(host_dir),), weight=size * 20))
    return units
