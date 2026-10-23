"""ATLASv2 (two Windows 7 workstations, 4 benign days + 1 attack day), streamed.

The 12.2 GB ``atlasv2.tar.gz`` is read over HTTP in parallel ranges (see
:func:`pdtrain.comiset.ranged_chunks`) and never stored; only the Sysmon
exports (``data/{benign,attack}/h{1,2}/sysmon/*.xml``) are parsed, and only
their process creates (EID 1) kept.

Role: the *untouched final test* (E9). Labels are fixed here, before any
ATLASv2 score has been looked at:

* benign period -> benign;
* attack day -> REAPr ground truth (bitbucket.org/sts-lab/reapr-ground-truth):
  a process start is malicious iff a REAPr ``attack`` label matches it on
  host + PID + creation time (within :data:`MATCH_SECONDS`). Processes REAPr
  marks only because the attack touched them after they started
  (:data:`TOUCHED_NOT_STARTED`), ``conhost.exe`` and browsers are excluded,
  as everywhere else in this pipeline. Unmatched attack-day starts are the
  second experimenter's ongoing activity -> benign.
"""

from __future__ import annotations

import codecs
import collections
import gzip
import hashlib
import io
import json
import re
import tarfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from panopticon_detection.datasets import sysmon_xml as X
from pdtrain.comiset import ranged_chunks
from pdtrain.normalize import rows_for

URL = ("https://uofi.box.com/index.php?rm=box_download_shared_file"
       "&shared_name=feunur7280afxrfeb0af73recexa73yc&file_id=f_1294229670092")
SIZE = 12208351555
PIN_KEY = "atlasv2/atlasv2.tar.gz"
REAPR = "https://api.bitbucket.org/2.0/repositories/sts-lab/reapr-ground-truth/src/HEAD/atlasv2/"
SCENARIOS = [f"h1-s{i}" for i in range(1, 5)] + [f"h{h}-m{i}" for h in (1, 2) for i in range(1, 7)]
MATCH_SECONDS = 2.0
TOUCHED_NOT_STARTED = frozenset({"explorer.exe", "lsass.exe", "taskhost.exe", "audiodg.exe", "osppsvc.exe",
                                 "services.exe", "svchost.exe", "winlogon.exe", "csrss.exe"})
EXCLUDED = frozenset({"conhost.exe", "firefox.exe", "plugin-container.exe", "iexplore.exe", "chrome.exe"})
_SYSMON_MEMBER = re.compile(r"data/(benign|attack)/(h[12])/sysmon/([^/]+\.xml)$", re.I)
_EVENT_END = "</Event>"


class ChunkStream(io.RawIOBase):
    """A read-only file object over an iterator of byte chunks (for tarfile 'r|gz')."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self.digest = hashlib.sha256()
        self.total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:
        while not self._buf:
            try:
                chunk = next(self._it)
            except StopIteration:
                return 0
            self.digest.update(chunk)
            self.total += len(chunk)
            self._buf = chunk
        n = min(len(target), len(self._buf))
        target[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def drain(self) -> None:
        for chunk in self._it:
            self.digest.update(chunk)
            self.total += len(chunk)


def _xml_events(handle, block: int = 16 * 1024 * 1024, only_eid1: bool = True) -> Iterator[Dict[str, Any]]:
    """Records of an Event Viewer XML export (UTF-8 or UTF-16), read incrementally.

    EID 1 only by default (the process-start tables); every event with ``only_eid1=False``.
    """
    first = handle.read(block)
    encoding = "utf-16" if first[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    text = decoder.decode(first)
    while True:
        cut = text.rfind(_EVENT_END)
        if cut >= 0:
            ready, text = text[:cut + len(_EVENT_END)], text[cut + len(_EVENT_END):]
            for match in X._EVENT_BLOCK.finditer(ready):
                piece = match.group(0)
                if not only_eid1 or ">1</EventID>" in piece:
                    record = X.parse_event_xml(piece)
                    if record is not None and (not only_eid1 or record.get("EventID") == "1"):
                        yield record
        data = handle.read(block)
        if not data:
            break
        text += decoder.decode(data)


# ------------------------------------------------------------------ REAPr labels


def filetime_to_utc(value: str) -> datetime:
    ticks = int(value, 16)
    return datetime.fromtimestamp((ticks - 116444736000000000) / 1e7, tz=timezone.utc).replace(tzinfo=None)


def parse_reapr(text: str, scenario: str) -> List[Dict[str, Any]]:
    out = []
    for line in text.splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or parts[4] != "attack":
            continue
        uuid = parts[3].split("-")
        if len(uuid) < 5:
            continue
        out.append({"scenario": scenario, "host": scenario.split("-")[0], "image": parts[1].lower(),
                    "pid": int(uuid[2], 16), "start": filetime_to_utc(uuid[4])})
    return out


def fetch_reapr(dest: Path) -> List[Dict[str, Any]]:
    dest.mkdir(parents=True, exist_ok=True)
    labels: List[Dict[str, Any]] = []
    for scenario in SCENARIOS:
        path = dest / f"{scenario}.labels"
        for attempt in range(6):
            if path.exists():
                break
            try:
                req = urllib.request.Request(REAPR + f"{scenario}.labels",
                                             headers={"User-Agent": "panopticon-training-fetch"})
                with urllib.request.urlopen(req, timeout=120) as resp:
                    path.write_bytes(resp.read())
            except Exception:  # retried; a missing label file fails loudly below
                time.sleep(5 * (attempt + 1))
        labels.extend(parse_reapr(path.read_text(encoding="utf-8"), scenario))
    return labels


def label_rows(rows: List[Dict[str, Any]], period: str, host: str, attack_labels: List[Dict[str, Any]]) -> None:
    index: Dict[Tuple[str, int], List[datetime]] = collections.defaultdict(list)
    for lab in attack_labels:
        index[(lab["host"], lab["pid"])].append(lab["start"])
    for row in rows:
        image = (row.get("image") or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
        row["group"] = f"atlasv2:{host}"
        if period == "benign":
            row.update(label=0, label_rule="benign/atlasv2_benign_period")
            continue
        when = datetime.fromisoformat(row["utc"].replace("Z", ""))
        hit = any(abs((t - when).total_seconds()) <= MATCH_SECONDS for t in index.get((host, row.get("pid")), []))
        if hit and (image in TOUCHED_NOT_STARTED or image in EXCLUDED):
            row.update(label=None, label_rule="excluded/atlasv2_touched_or_excluded")
        elif hit:
            row.update(label=1, label_rule="malicious/reapr", group="atlasv2:attack")
        elif image in EXCLUDED:
            row.update(label=None, label_rule="excluded/atlasv2_excluded_image")
        else:
            row.update(label=0, label_rule="benign/atlasv2_attack_day_background")


# ------------------------------------------------------------------ all families (context model)

RUN_RECORDS = 100_000  # records per sorted run: bounds memory on multi-GB exports


def _write_run(events: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        for event in events:
            handle.write((json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))


def stream_all_families(out_dir: Path, spool: Path, pins_path: Optional[Path],
                        chunks: Optional[Iterable[bytes]] = None, size: int = SIZE, log=print) -> Dict[str, Any]:
    """Every Sysmon event of every member, as canonical agent events in time-sorted runs.

    Writes ``<out_dir>/<period>/<host>/<file>/run-NNNN.ndjson.gz``. Each run holds at most
    :data:`RUN_RECORDS` records and is sorted by event time, so a replay merges a host's runs
    lazily. Event ids are the dataset adapter's (``OtrfAdapter``) for the same dataset ids as
    the process-start rows, so EID 1 ids equal the existing ``row_id`` values.
    """
    from panopticon_detection.datasets.otrf import OtrfAdapter

    source = ChunkStream(chunks if chunks is not None else ranged_chunks(URL, size, spool, log=log))
    counts: collections.Counter = collections.Counter()
    eid1_ids: List[str] = []
    runs = 0
    with tarfile.open(fileobj=io.BufferedReader(source, 1 << 20), mode="r|gz") as tar:
        for member in tar:
            match = _SYSMON_MEMBER.search(member.name)
            if not match or not member.isfile():
                continue
            period, host, name = match.groups()
            dataset_id = f"atlasv2:{period}/{host}/{name}"
            folder = out_dir / period / host / name.removesuffix(".xml")
            buffer: List[Dict[str, Any]] = []
            index = 0

            def flush() -> None:
                nonlocal buffer, index, runs
                if not buffer:
                    return
                events, _report = OtrfAdapter(dataset_id).normalize(buffer)
                for event in events:
                    counts[f"{period}/{host} {event['event']['category']}"] += 1
                    if event["event"]["category"] == "process" and event["event"]["type"] == "start":
                        eid1_ids.append(event["event"]["id"])
                _write_run(events, folder / f"run-{index:04d}.ndjson.gz")
                index += 1
                runs += 1
                buffer = []

            for record in _xml_events(tar.extractfile(member), only_eid1=False):
                counts[f"{period}/{host} sysmon_eid_{record.get('EventID')}"] += 1
                buffer.append(record)
                if len(buffer) >= RUN_RECORDS:
                    flush()
            flush()
            log(f"[atlasv2-all] {member.name}: {index} runs", flush=True)
    source.drain()
    manifest = {"source": "atlasv2", "bytes": source.total, "expected_bytes": size,
                "complete": source.total == size, "sha256": source.digest.hexdigest(), "runs": runs,
                "process_starts": len(eid1_ids), "counts": dict(sorted(counts.items()))}
    if manifest["complete"] and pins_path is not None and pins_path.exists():
        pin = json.loads(pins_path.read_text()).get(PIN_KEY)
        if pin and pin["sha256"] != manifest["sha256"]:
            raise ValueError(f"pin mismatch for {PIN_KEY}")
        manifest["pin_verified"] = bool(pin)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eid1_ids.txt").write_text("\n".join(sorted(eid1_ids)) + "\n")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


# ------------------------------------------------------------------ driver


def stream(out_dir: Path, spool: Path, pins_path: Optional[Path], raw_dir: Path,
           chunks: Optional[Iterable[bytes]] = None, size: int = SIZE, log=print) -> Dict[str, Any]:
    attack_labels = fetch_reapr(raw_dir / "reapr") if chunks is None else []
    source = ChunkStream(chunks if chunks is not None else ranged_chunks(URL, size, spool, log=log))
    rows: List[Dict[str, Any]] = []
    counts: collections.Counter = collections.Counter()
    with tarfile.open(fileobj=io.BufferedReader(source, 1 << 20), mode="r|gz") as tar:
        for member in tar:
            match = _SYSMON_MEMBER.search(member.name)
            if not match or not member.isfile():
                continue
            period, host, name = match.groups()
            handle = tar.extractfile(member)
            records = list(_xml_events(handle))
            member_rows = rows_for("atlasv2", f"atlasv2:{period}/{host}/{name}", records,
                                   {"techniques": [], "tool": f"atlasv2-{period}"})
            label_rows(member_rows, period, host, attack_labels)
            rows.extend(member_rows)
            counts[f"{period}/{host} files"] += 1
            counts[f"{period}/{host} process starts"] += len(member_rows)
            log(f"[atlasv2] {member.name}: {len(member_rows)} process starts", flush=True)
    source.drain()
    out_dir.mkdir(parents=True, exist_ok=True)
    rows.sort(key=lambda r: (r["dataset"], r["utc"], r["row_id"]))
    with gzip.GzipFile(out_dir / "atlasv2.jsonl.gz", "wb", mtime=0) as handle:
        for row in rows:
            handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
    counts.update(collections.Counter(r["label_rule"] for r in rows))
    manifest = {"source": "atlasv2", "bytes": source.total, "expected_bytes": size,
                "complete": source.total == size, "sha256": source.digest.hexdigest(),
                "rows": len(rows), "reapr_attack_labels": len(attack_labels), "counts": dict(counts)}
    (out_dir / "atlasv2.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if manifest["complete"] and pins_path is not None:
        pins = json.loads(pins_path.read_text()) if pins_path.exists() else {}
        pin = pins.get(PIN_KEY)
        if pin and pin["sha256"] != manifest["sha256"]:
            raise ValueError(f"pin mismatch for {PIN_KEY}")
        pins[PIN_KEY] = {"sha256": manifest["sha256"], "bytes": source.total, "url": URL,
                         "licence": "see dataset README", "note": "streamed and filtered; not stored"}
        pins_path.write_text(json.dumps(dict(sorted(pins.items())), indent=1) + "\n")
    return manifest
