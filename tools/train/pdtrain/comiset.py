"""COMISET real environment (university computer lab), streamed -- never stored.

The release is one zip holding one JSON-lines member of 934.5 GB (31.7 GB
compressed), far more than the disk can hold. It is read over HTTP in
parallel 64 MiB ranges (at most :data:`IN_FLIGHT` chunks buffered on disk at
a time), inflated in order, and only Sysmon process creates (EID 1) are kept.
The SHA-256 of the whole archive is computed on the way and pinned.

Because a month of a computer lab repeats the same process starts millions of
times, rows are aggregated: one row per (host, featurizer key) with an
occurrence ``count``; per-host observed hours come from the distinct minutes
in which process starts were seen (gaps capped at an hour, like the other
sources).

Labels: COMISET's "real environment" is students' ordinary use; the release
marks some events with detection-rule matches (``Rule_*`` fields). Those rows
are excluded (``excluded/comiset_rule_hit``) -- a rule match is neither a
benign certainty nor an attack label -- and counted.
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import json
import os
import struct
import threading
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from panopticon_detection.datasets import canonical as C
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from pdtrain.label import dedup_key

URL = "https://zenodo.org/api/records/15375146/files/Comiset23_Real_Environment_Dataset.zip/content"
PIN_KEY = "comiset/Comiset23_Real_Environment_Dataset.zip"
CHUNK = 64 * 1024 * 1024
IN_FLIGHT = 24
WORKERS = 12
_EID1 = b'"event_id":"1"'
_SYSMON = b'"log_name":"Microsoft-Windows-Sysmon/Operational"'
ADAPTER = {"id": "dataset-adapter:comiset", "version": "1"}


# ------------------------------------------------------------------ transport


def _get_range(url: str, start: int, end: int, attempts: int = 10) -> bytes:
    last: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}",
                                                       "User-Agent": "panopticon-training-fetch"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            if len(data) != end - start + 1:
                raise OSError(f"short read {len(data)} != {end - start + 1}")
            return data
        except Exception as exc:  # OSError, http.client.IncompleteRead, ... -- all retried
            last = exc
            time.sleep(min(60, 3 * 2 ** attempt))
    raise OSError(f"range {start}-{end} failed: {last}")


def ranged_chunks(url: str, size: int, spool: Path, log=print) -> Iterator[bytes]:
    """Yield the file's bytes in order, fetched in parallel through a bounded disk spool."""
    spool.mkdir(parents=True, exist_ok=True)
    n = (size + CHUNK - 1) // CHUNK
    window = threading.Semaphore(IN_FLIGHT)
    errors: List[Exception] = []

    def fetch(i: int) -> None:
        try:
            start, end = i * CHUNK, min(size, (i + 1) * CHUNK) - 1
            data = _get_range(url, start, end)
            tmp = spool / f"{i:06d}.part"
            tmp.write_bytes(data)
            os.replace(tmp, spool / f"{i:06d}.chunk")
        except Exception as exc:  # surfaced to the consumer
            errors.append(exc)

    def producer() -> None:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for i in range(n):
                window.acquire()
                pool.submit(fetch, i)

    threading.Thread(target=producer, daemon=True).start()
    started = time.time()
    for i in range(n):
        path = spool / f"{i:06d}.chunk"
        while not path.exists():
            if errors:
                raise errors[0]
            time.sleep(0.2)
        data = path.read_bytes()
        path.unlink()  # our own temporary spool chunk
        window.release()
        if i % 20 == 0:
            done = (i + 1) * CHUNK
            log(f"[comiset] {min(done, size) / 1e9:.1f}/{size / 1e9:.1f} GB "
                f"({done / max(1.0, time.time() - started) / 1e6:.1f} MB/s)", flush=True)
        yield data


# ------------------------------------------------------------------ zip + lines


def member_lines(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Sysmon EID 1 lines of the single deflated member, given the zip's bytes in order."""
    inflater = None
    head = b""
    pending = b""
    for chunk in chunks:
        if inflater is None:
            head += chunk
            sig = head.find(b"PK\x03\x04")
            if sig < 0 or len(head) < sig + 30:
                continue
            method = struct.unpack("<H", head[sig + 8:sig + 10])[0]
            if method != 8:
                raise ValueError(f"unsupported zip method {method}")
            nlen, elen = struct.unpack("<HH", head[sig + 26:sig + 30])
            start = sig + 30 + nlen + elen
            if len(head) < start:
                continue
            inflater = zlib.decompressobj(-15)
            chunk, head = head[start:], b""
        if inflater.eof:
            continue  # trailing central directory: still consumed for the hash
        data = pending + inflater.decompress(chunk)
        cut = data.rfind(b"\n")
        if cut < 0:
            pending = data
            continue
        pending = data[cut + 1:]
        yield from _sysmon_eid1_lines(data[:cut])
    if pending:
        yield from _sysmon_eid1_lines(pending)


def _sysmon_eid1_lines(block: bytes) -> Iterator[bytes]:
    """Only lines that are Sysmon EID 1 -- found by substring, not by parsing every line."""
    pos = block.find(_EID1)
    while pos >= 0:
        start = block.rfind(b"\n", 0, pos) + 1
        end = block.find(b"\n", pos)
        end = len(block) if end < 0 else end
        line = block[start:end]
        if _SYSMON in line:
            yield line
        pos = block.find(_EID1, end)


# ------------------------------------------------------------------ records


def _when(src: Dict[str, Any]) -> Optional[datetime]:
    text = src.get("event_original_time") or src.get("@timestamp")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed - parsed.utcoffset()).replace(tzinfo=None) if parsed.tzinfo else parsed


def row_from_source(src: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    host = str(src.get("host_name") or "UNKNOWN_HOST").lower()
    when = _when(src)
    try:
        pid = int(src.get("process_id"))
    except (TypeError, ValueError):
        return None
    image = src.get("process_path")
    if when is None or not image:
        return None
    try:
        ppid = int(src.get("process_parent_id"))
    except (TypeError, ValueError):
        ppid = None
    name, domain = C.split_account(src.get("user_account"))
    event = C.build_event(
        category="process", type_="start",
        event_key=("comiset", host, src.get("record_number"), src.get("process_guid")),
        when=when,
        source={"kind": "sysmon", "provider": "Microsoft-Windows-Sysmon",
                "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": src.get("record_number")},
        agent=ADAPTER,
        host={"id": host, "hostname": host, "os": {"name": "Windows", "build": "unknown"}},
        user={"name": name, "domain": domain, "sid": None},
        process={
            "entity_id": C.process_entity_id(host, pid, when),
            "pid": pid,
            "name": src.get("process_name") or C.basename(image),
            "executable": image,
            "command_line": src.get("CommandLine"),
            "sha256": None,
            "parent": {"entity_id": None, "pid": ppid,
                       "name": src.get("process_parent_name") or C.basename(src.get("process_parent_path"))},
        },
    )
    normalized = OfficerIngestionAdapter.transform_officer_event(event)
    rule_hit = any(k.lower().startswith("rule_") for k in src)
    return {
        "row_id": event["event"]["id"],
        "source": "comiset",
        "dataset": "comiset:real",
        "techniques": [],
        "tool": "comiset-real-environment",
        "host": host,
        "utc": event["event"]["timestamp"],
        "guid": src.get("process_guid"),
        "parent_guid": src.get("process_parent_guid"),
        "pid": pid,
        "image": image,
        "parent_image": src.get("process_parent_path"),
        "command_line": src.get("CommandLine"),
        "parent_command_line": src.get("ParentCommandLine"),
        "integrity": src.get("IntegrityLevel"),
        "label": None if rule_hit else 0,
        "label_rule": "excluded/comiset_rule_hit" if rule_hit else "benign/comiset_real_environment",
        "group": f"comiset:{host}",
        "event": {k: v for k, v in normalized.items() if k != "_raw_officer_event"},
    }


class Aggregator:
    """One row per (host, featurizer key) with a count; distinct minutes per host."""

    def __init__(self) -> None:
        self.rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.minutes: Dict[str, set] = collections.defaultdict(set)
        self.counts: collections.Counter = collections.Counter()

    def add(self, line: bytes) -> None:
        self.counts["sysmon_eid1_lines"] += 1
        try:
            src = json.loads(line).get("_source") or {}
        except (json.JSONDecodeError, AttributeError):
            self.counts["unparseable"] += 1
            return
        row = row_from_source(src)
        if row is None:
            self.counts["unusable"] += 1
            return
        self.counts[row["label_rule"]] += 1
        self.minutes[row["host"]].add(row["utc"][:16])
        key = (row["host"], dedup_key(row))
        held = self.rows.get(key)
        if held is None:
            row["count"] = 1
            self.rows[key] = row
        else:
            held["count"] += 1

    def observed_hours(self) -> Dict[str, float]:
        out = {}
        for host, minutes in self.minutes.items():
            stamps = sorted(datetime.fromisoformat(m) for m in minutes)
            gaps = sum(min((b - a).total_seconds(), 3600.0) for a, b in zip(stamps, stamps[1:]))
            out[host] = (gaps + 60.0) / 3600.0  # +1 minute for the last bucket
        return out


def stream(out_dir: Path, spool: Path, pins_path: Optional[Path], url: str = URL, size: Optional[int] = None,
           chunks: Optional[Iterable[bytes]] = None, log=print) -> Dict[str, Any]:
    if size is None:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "panopticon-training-fetch"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            size = int(resp.headers["Content-Length"])
    digest = hashlib.sha256()
    total = 0

    def hashed(source: Iterable[bytes]) -> Iterator[bytes]:
        nonlocal total
        for chunk in source:
            digest.update(chunk)
            total += len(chunk)
            yield chunk

    agg = Aggregator()
    source = chunks if chunks is not None else ranged_chunks(url, size, spool, log=log)
    seen = 0
    for line in member_lines(hashed(source)):
        agg.add(line)
        seen += 1
        if seen % 20000 == 0:
            log(f"[comiset] process starts so far: {seen} ({len(agg.rows)} distinct, "
                f"{len(agg.minutes)} hosts) at {total / 1e9:.1f} GB", flush=True)

    out_dir.mkdir(parents=True, exist_ok=True)
    rows = sorted(agg.rows.values(), key=lambda r: (r["host"], r["utc"], r["row_id"]))
    with gzip.GzipFile(out_dir / "comiset.jsonl.gz", "wb", mtime=0) as handle:
        for row in rows:
            handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
    hours = agg.observed_hours()
    (out_dir / "comiset.hours.json").write_text(json.dumps(hours, indent=1, sort_keys=True) + "\n")
    manifest = {
        "source": "comiset", "url": url, "bytes": total, "expected_bytes": size,
        "sha256": digest.hexdigest(), "complete": total == size,
        "rows_distinct": len(rows), "hosts": len(hours), "observed_host_hours": round(sum(hours.values()), 2),
        "counts": dict(agg.counts),
    }
    (out_dir / "comiset.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if total == size and pins_path is not None:
        pins = json.loads(pins_path.read_text()) if pins_path.exists() else {}
        pin = pins.get(PIN_KEY)
        if pin and pin["sha256"] != manifest["sha256"]:
            raise ValueError(f"pin mismatch for {PIN_KEY}")
        pins[PIN_KEY] = {"sha256": manifest["sha256"], "bytes": total, "url": url, "licence": "unverified (see Zenodo record 15375146)",
                         "note": "streamed and filtered; the archive itself is not stored"}
        pins_path.write_text(json.dumps(dict(sorted(pins.items())), indent=1) + "\n")
    return manifest
