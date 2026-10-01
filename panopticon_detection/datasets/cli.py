"""``panopticon-dataset``: fetch and normalise external datasets.

The output of ``normalize`` is canonical NDJSON -- the agent's wire format --
so everything downstream is the ordinary engine CLI::

    panopticon-dataset fetch empire_launcher_vbs --dest data/otrf
    panopticon-dataset normalize --format otrf \\
        --input data/otrf/empire_launcher_vbs.zip \\
        --metadata data/otrf/SDWIN-190518182022.yaml \\
        --output data/canonical/empire_launcher_vbs.ndjson
    panopticon-detect --rules rules \\
        --officer-ndjson data/canonical/empire_launcher_vbs.ndjson \\
        --export-features data/features/empire_launcher_vbs.jsonl

No database, queue or service: files in, files out, deterministic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import List, Optional

from panopticon_detection.datasets.otrf import (
    OtrfAdapter,
    load_metadata,
    read_records,
    write_ndjson,
)
from panopticon_detection.datasets.sources import OTRF_COMMIT, SAMPLES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="panopticon-dataset",
        description="Fetch and normalise external security datasets into canonical Panopticon NDJSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("sources", help="List the vetted OTRF recordings and what they exercise")

    fetch = sub.add_parser("fetch", help="Download a vetted OTRF recording and its metadata, hash-checked")
    fetch.add_argument("name", choices=sorted(SAMPLES), help="Recording name (see `sources`)")
    fetch.add_argument("--dest", default="data/otrf", help="Directory to download into")

    normalize = sub.add_parser("normalize", help="Convert a dataset file to canonical Panopticon NDJSON")
    normalize.add_argument("--format", choices=["otrf"], default="otrf", help="Input dataset format")
    normalize.add_argument("--input", required=True, help="Dataset file (.zip, .tar.gz or JSON lines)")
    normalize.add_argument("--metadata", default=None, help="The dataset's metadata YAML (labels)")
    normalize.add_argument("--dataset-id", default=None, help="Id used in event ids (default: input file stem)")
    normalize.add_argument("--output", required=True, help="Canonical NDJSON to write")
    normalize.add_argument(
        "--manifest", default=None, help="Manifest JSON to write (default: <output>.manifest.json)"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "sources":
        return _sources()
    if args.command == "fetch":
        return _fetch(args.name, Path(args.dest))
    return _normalize(args)


def _sources() -> int:
    print(f"OTRF Security-Datasets @ {OTRF_COMMIT} (MIT)")
    for sample in SAMPLES.values():
        print(f"  {sample.name:<46} {', '.join(sample.exercises)}")
    return 0


def _download(url: str, expected_sha256: str, target: Path) -> None:
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected_sha256:
        print(f"[=] {target} (already present, hash verified)")
        return
    with urllib.request.urlopen(url, timeout=120) as response:
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    print(f"[+] {target} ({len(payload)} bytes, sha256 {digest[:12]}...)")


def _fetch(name: str, dest: Path) -> int:
    sample = SAMPLES[name]
    try:
        _download(sample.url, sample.sha256, dest / Path(sample.path).name)
        _download(sample.metadata_url, sample.metadata_sha256, dest / sample.metadata)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


def _normalize(args) -> int:
    source = Path(args.input)
    try:
        records = read_records(source)
        metadata = load_metadata(Path(args.metadata)) if args.metadata else None
    except (OSError, ValueError) as exc:
        print(f"[ERROR] could not read {source}: {exc}", file=sys.stderr)
        return 1
    dataset_id = args.dataset_id or source.name.split(".")[0]
    events, report = OtrfAdapter(dataset_id).normalize(records, metadata)

    output = Path(args.output)
    write_ndjson(events, output)
    manifest = Path(args.manifest) if args.manifest else output.with_name(output.name + ".manifest.json")
    payload = {
        "input": {"path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
        "output": output.name,
        **report.to_dict(),
    }
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"[+] {report.records_read} record(s) read, {report.events_written} canonical event(s) "
        f"written to {output}; {sum(report.skipped.values())} skipped, "
        f"{sum(report.rejected.values())} rejected. Manifest: {manifest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
