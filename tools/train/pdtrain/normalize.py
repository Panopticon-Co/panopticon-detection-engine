"""Every Sysmon process start in the raw sources -> one row table per source.

Each row carries:

* ``event`` -- the *normalized* event exactly as the engine would see it
  (dataset adapter -> canonical event -> ``OfficerIngestionAdapter``), which
  is what the featurizer consumes. Training therefore sees the same input as
  serving would.
* ``integrity`` -- Sysmon's IntegrityLevel (side channel; not in schema 0.5).
* labelling context -- Sysmon process GUIDs, parent image and command line,
  host and time. These are for labelling and grouping only and are never
  features.

Output: ``data/rows/<source>.jsonl.gz`` plus ``data/rows/<source>.manifest.json``.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Tuple

import yaml

from panopticon_detection.datasets import canonical as C
from panopticon_detection.datasets import sysmon_xml as X
from panopticon_detection.datasets.otrf import SYSMON_CHANNEL, OtrfAdapter, _int, _v, read_records
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter

_EID1 = re.compile(r"<EventID[^>]*>\s*1\s*</EventID>")


# ------------------------------------------------------------------ readers


def _attack_data_records(path: Path) -> List[Dict[str, Any]]:
    """Only the EID 1 events of an attack_data log (cheap substring pre-filter)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for match in X._EVENT_BLOCK.finditer(text):
        block = match.group(0)
        if _EID1.search(block):
            record = X.parse_event_xml(block)
            if record is not None:
                out.append(record)
    return out


def _eid1(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in records if r.get("Channel") == SYSMON_CHANNEL and _int(r, "EventID") == 1]


# --------------------------------------------------------------- row building


def _row_key(dataset_id: str, record: Dict[str, Any], index: int) -> str:
    host = _v(record, "Hostname", "host") or "UNKNOWN_HOST"
    record_id = _int(record, "RecordNumber", "EventRecordID")
    key = record_id if record_id is not None else f"line{index}"
    return C.event_id(dataset_id, host, record.get("Channel"), 1, key)


def _slim(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """The full normalized event minus the raw copy the adapter keeps.

    Kept whole so the rules-only baseline can replay exactly what the engine
    would receive; the featurizer reads only the fields it documents.
    """
    return {k: v for k, v in normalized.items() if k != "_raw_officer_event"}


def rows_for(
    source: str, dataset_id: str, records: List[Dict[str, Any]], meta: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Normalize one recording's EID 1 records into rows."""
    records = _eid1(records)
    by_key = {_row_key(dataset_id, r, i): r for i, r in enumerate(records)}
    events, _report = OtrfAdapter(dataset_id).normalize(records)
    rows = []
    for event in events:
        record = by_key.get(event["event"]["id"])
        if record is None:
            continue
        normalized = OfficerIngestionAdapter.transform_officer_event(event)
        if normalized.get("event_type") != "process_create":
            continue
        rows.append(
            {
                "row_id": event["event"]["id"],
                "source": source,
                "dataset": dataset_id,
                "techniques": meta.get("techniques", []),
                "tool": meta.get("tool"),
                "host": (event.get("host") or {}).get("id"),
                "utc": event["event"]["timestamp"],
                "guid": _v(record, "ProcessGuid"),
                "parent_guid": _v(record, "ParentProcessGuid"),
                "pid": _int(record, "ProcessId"),
                "image": _v(record, "Image"),
                "parent_image": _v(record, "ParentImage"),
                "command_line": _v(record, "CommandLine"),
                "parent_command_line": _v(record, "ParentCommandLine"),
                "integrity": _v(record, "IntegrityLevel"),
                "event": _slim(normalized),
            }
        )
    return rows


# --------------------------------------------------------------- per source


def _attack_data_meta(raw: Path) -> Dict[str, Dict[str, Any]]:
    """log path -> {techniques, tool, yml} from every dataset YAML."""
    out: Dict[str, Dict[str, Any]] = {}
    base = raw / "attack_data"
    for yml in sorted(base.glob("datasets/attack_techniques/**/*.y*ml")):
        meta = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        techniques = [str(t) for t in (meta.get("mitre_technique") or [])]
        for entry in meta.get("datasets") or []:
            path = str((entry or {}).get("path") or "").lstrip("/")
            if path:
                out[path] = {
                    "techniques": techniques,
                    "tool": meta.get("directory") or yml.parent.name,
                    "yml": str(yml.relative_to(base)),
                }
    return out


def _attack_data_one(args: Tuple[str, str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    path, rel, meta = args
    return rows_for("attack_data", "attack_data:" + rel, _attack_data_records(Path(path)), meta)


def _otrf_meta(raw: Path) -> Dict[str, Dict[str, Any]]:
    """recording file name -> techniques, from the OTRF metadata YAMLs."""
    out: Dict[str, Dict[str, Any]] = {}
    for yml in sorted((raw / "otrf" / "datasets" / "atomic" / "_metadata").glob("SDWIN-*.yaml")):
        meta = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        techniques = []
        for mapping in meta.get("attack_mappings") or []:
            technique, sub = mapping.get("technique"), mapping.get("sub-technique")
            if technique:
                techniques.append(f"{technique}.{sub}" if sub else str(technique))
        for item in meta.get("files") or []:
            link = str((item or {}).get("link") or "")
            if link:
                out[link.rsplit("/", 1)[-1]] = {"techniques": techniques, "tool": "otrf", "yml": yml.name}
    return out


def _otrf_one(args: Tuple[str, str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    path, rel, meta = args
    return rows_for(meta["source"], "otrf:" + rel, read_records(Path(path)), meta)


def _botsv1_one(path: str) -> List[Dict[str, Any]]:
    records = list(X.only_event_ids(X.read_botsv1_json(Path(path)), {1}))
    return rows_for("botsv1", "botsv1", records, {"techniques": [], "tool": "botsv1"})


# --------------------------------------------------------------- driver


def _write(rows: List[Dict[str, Any]], out_dir: Path, source: str, inputs: List[str]) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows.sort(key=lambda r: (r["dataset"], r["utc"], r["row_id"]))
    path = out_dir / f"{source}.jsonl.gz"
    # mtime=0 keeps the gzip bytes reproducible run to run.
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        for row in rows:
            handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
    manifest = {
        "source": source,
        "rows": len(rows),
        "datasets": len({r["dataset"] for r in rows}),
        "hosts": len({(r["dataset"], r["host"]) for r in rows}),
        "with_integrity": sum(1 for r in rows if r["integrity"]),
        "inputs": len(inputs),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    (out_dir / f"{source}.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def normalize_all(raw: Path, out_dir: Path, sources: List[str], workers: int = 6) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        if "attack_data" in sources:
            meta = _attack_data_meta(raw)
            jobs = [
                (str(raw / "attack_data" / rel), rel, m)
                for rel, m in sorted(meta.items())
                if (raw / "attack_data" / rel).exists()
            ]
            rows = [row for chunk in pool.map(_attack_data_one, jobs, chunksize=4) for row in chunk]
            summary["attack_data"] = _write(rows, out_dir, "attack_data", [j[1] for j in jobs])
        if "otrf" in sources or "otrf_compound" in sources:
            meta = _otrf_meta(raw)
            base = raw / "otrf"
            atomic, compound = [], []
            for path in sorted(base.glob("datasets/**/*")):
                if not path.is_file() or not path.name.endswith((".zip", ".tar.gz")):
                    continue
                rel = str(path.relative_to(base))
                if rel.startswith("datasets/atomic/windows/") and "/host/" in rel:
                    m = meta.get(path.name, {"techniques": [], "tool": "otrf"})
                    atomic.append((str(path), rel, {**m, "source": "otrf"}))
                elif rel.startswith("datasets/compound/") and "pcap" not in rel:
                    m = {"techniques": [], "tool": rel.split("/")[2], "source": "otrf_compound"}
                    compound.append((str(path), rel, m))
            if "otrf" in sources:
                rows = [row for chunk in pool.map(_otrf_one, atomic) for row in chunk]
                summary["otrf"] = _write(rows, out_dir, "otrf", [j[1] for j in atomic])
            if "otrf_compound" in sources:
                rows = [row for chunk in pool.map(_otrf_one, compound) for row in chunk]
                summary["otrf_compound"] = _write(rows, out_dir, "otrf_compound", [j[1] for j in compound])
        if "botsv1" in sources:
            files = sorted(str(p) for p in (raw / "botsv1").glob("*.json.gz"))
            rows = [row for chunk in pool.map(_botsv1_one, files) for row in chunk]
            summary["botsv1"] = _write(rows, out_dir, "botsv1", files)
    if "optc" in sources:
        from pdtrain.optc import read_ecar_process_creates

        files = sorted((raw / "optc").glob("benign/*/*.json.gz"))
        rows = []
        for path in files:
            dataset = f"optc:{path.parent.name}/{path.name.split('.')[0]}"
            rows.extend(read_ecar_process_creates(path, dataset))
        summary["optc"] = _write(rows, out_dir, "optc", [str(p.relative_to(raw)) for p in files])
    # officer_sealed: a recording from another machine, kept for the one-shot final test
    # (pdtrain.final_test). It is never labelled or trained on (pdtrain.loeo.SOURCES).
    for name in ("officer_vm", "officer_sealed"):
        if name not in sources:
            continue
        from pdtrain.officer_vm import prepare, read_package

        rows, inputs, counts = [], [], {}
        for package in sorted(p for p in (raw / name).glob("*") if p.is_dir()):
            records, meta = read_package(package)
            collection = (meta.get("manifest") or {}).get("collection_id") or package.name
            pkg_rows, counts[package.name] = prepare(records, meta, f"{name}:{collection}")
            for row in pkg_rows:
                row["source"] = name
                row["group"] = f"{name}:{row['host']}"
            rows.extend(pkg_rows)
            inputs.append(package.name)
        summary[name] = _write(rows, out_dir, name, inputs)
        summary[name]["kit_issue_counts"] = counts
        (out_dir / f"{name}.manifest.json").write_text(json.dumps(summary[name], indent=2) + "\n")
    return summary


def read_rows(out_dir: Path, source: str) -> Iterator[Dict[str, Any]]:
    with gzip.open(out_dir / f"{source}.jsonl.gz", "rt", encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)
