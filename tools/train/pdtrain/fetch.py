"""Download the training sources into ``data/raw`` and pin every file.

``pins.json`` (committed, next to this package) maps a file key to its SHA-256
and size. A key seen for the first time is pinned; a key already pinned must
match byte for byte, or the run fails. Re-running is cheap: a present file whose
hash matches its pin is not downloaded again.

The selection of attack_data logs is itself derived from pinned inputs: the
repository tree at :data:`sources.ATTACK_DATA_COMMIT` and each dataset's YAML,
keeping only logs whose declared ``source`` is the Sysmon Operational channel.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from pdtrain import sources as S

PINS_PATH = Path(__file__).resolve().parent.parent / "pins.json"
_USER_AGENT = "panopticon-detection-engine/training-fetch"


@dataclass(frozen=True)
class Job:
    key: str  # path under data/raw, also the pin key
    url: str
    licence: str


class Pins:
    """Thread-safe trust-on-first-use pin store."""

    def __init__(self, path: Path = PINS_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.data: Dict[str, Dict[str, Any]] = (
            json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        )

    def check(self, job: Job, sha256: str, size: int) -> None:
        with self._lock:
            pin = self.data.get(job.key)
            if pin is None:
                self.data[job.key] = {"sha256": sha256, "bytes": size, "url": job.url, "licence": job.licence}
                return
            if pin["sha256"] != sha256:
                raise ValueError(f"pin mismatch for {job.key}: pinned {pin['sha256']}, got {sha256}")

    def expected(self, key: str) -> Optional[str]:
        pin = self.data.get(key)
        return pin["sha256"] if pin else None

    def save(self) -> None:
        with self._lock:
            payload = json.dumps(dict(sorted(self.data.items())), indent=1) + "\n"
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self.path)


def _stream(url: str, tmp: Path) -> Tuple[str, int]:
    # A per-socket-operation timeout: a stalled connection fails in a minute
    # and is retried, instead of holding a worker for ten.
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=60) as response, tmp.open("wb") as out:
        for chunk in iter(lambda: response.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    return digest.hexdigest(), size


_MAGIC = {".gz": b"\x1f\x8b", ".tgz": b"\x1f\x8b", ".zip": b"PK"}


def _content_problem(key: str, path: Path) -> Optional[str]:
    """A reason the payload is not the file we asked for, or None.

    Hosts answer an exhausted quota or a sign-in wall with an HTML page and a
    200 status; pinning that page would make a wrong file "verified" forever.
    """
    with path.open("rb") as handle:
        head = handle.read(512)
    for suffix, magic in _MAGIC.items():
        if key.endswith(suffix) and not head.startswith(magic):
            hint = " (looks like an HTML page)" if b"<html" in head.lower() or b"<!doctype" in head.lower() else ""
            return f"expected a {suffix} file, got {head[:16]!r}{hint}"
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(job: Job, root: Path, pins: Pins, attempts: int = 4) -> str:
    """Fetch one file (unless already present and matching its pin), with retries."""
    target = root / job.key
    expected = pins.expected(job.key)
    if target.exists() and expected and _sha256_file(target) == expected:
        return "cached"
    if target.exists() and not expected and _content_problem(job.key, target) is None:
        # Placed by hand (e.g. a Google Drive file whose anonymous download
        # quota is exhausted): pin what is there instead of re-downloading.
        pins.check(job, _sha256_file(target), target.stat().st_size)
        return "registered"
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".part")
    last_error: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            sha, size = _stream(job.url, tmp)
            break
        except OSError as exc:  # socket timeouts and HTTP errors are OSErrors
            last_error = exc
            time.sleep(2 * (attempt + 1))
    else:
        raise OSError(f"{attempts} attempts failed: {last_error}")
    if size < 200 and b"git-lfs" in tmp.read_bytes():
        tmp.unlink()
        raise ValueError(f"{job.url} returned a Git LFS pointer, not the object")
    problem = _content_problem(job.key, tmp)
    if problem:
        tmp.unlink()
        raise ValueError(f"{job.url}: {problem}")
    pins.check(job, sha, size)
    os.replace(tmp, target)
    return "downloaded"


# ------------------------------------------------------------------ job lists


def attack_data_jobs(root: Path, pins: Pins) -> List[Job]:
    """Every Sysmon-sourced log declared by an attack_data dataset YAML."""
    tree_job = Job("attack_data/_tree.json", S.ATTACK_DATA_TREE, S.LICENCES["attack_data"])
    download(tree_job, root, pins)
    tree = json.loads((root / tree_job.key).read_text(encoding="utf-8"))
    if tree.get("truncated"):
        raise RuntimeError("attack_data tree listing is truncated; cannot select files reliably")
    ymls = sorted(
        e["path"]
        for e in tree["tree"]
        if e["type"] == "blob"
        and e["path"].startswith("datasets/attack_techniques/")
        and e["path"].endswith((".yml", ".yaml"))
    )
    yml_jobs = [Job(f"attack_data/{p}", f"{S.ATTACK_DATA_RAW}/{p}", S.LICENCES["attack_data"]) for p in ymls]
    _run(yml_jobs, root, pins, label="attack_data metadata")

    blobs = {e["path"] for e in tree["tree"] if e["type"] == "blob"}
    jobs: List[Job] = []
    for p in ymls:
        meta = yaml.safe_load((root / "attack_data" / p).read_text(encoding="utf-8")) or {}
        for entry in meta.get("datasets") or []:
            if (entry or {}).get("source") != S.SYSMON_SOURCE:
                continue
            path = str(entry.get("path") or "").lstrip("/")
            if path in blobs:
                jobs.append(Job(f"attack_data/{path}", f"{S.ATTACK_DATA_MEDIA}/{path}", S.LICENCES["attack_data"]))
    return sorted(set(jobs), key=lambda j: j.key)


def otrf_jobs(root: Path, pins: Pins) -> List[Job]:
    """All Windows host recordings at the pinned commit, plus their metadata."""
    tree_job = Job("otrf/_tree.json", S.OTRF_TREE, S.LICENCES["otrf"])
    download(tree_job, root, pins)
    tree = json.loads((root / tree_job.key).read_text(encoding="utf-8"))
    if tree.get("truncated"):
        raise RuntimeError("OTRF tree listing is truncated")
    jobs = []
    for entry in tree["tree"]:
        path = entry["path"]
        if entry["type"] != "blob":
            continue
        is_recording = (
            path.startswith("datasets/atomic/windows/") and "/host/" in path and path.endswith(".zip")
        )
        is_metadata = path.startswith("datasets/atomic/_metadata/SDWIN-") and path.endswith(".yaml")
        if is_recording or is_metadata:
            jobs.append(Job(f"otrf/{path}", f"{S.OTRF_RAW}/{path}", S.LICENCES["otrf"]))
    return sorted(jobs, key=lambda j: j.key)


def static_jobs() -> List[Job]:
    files = [S.BOTSV1_SYSMON, *S.WINLOLBIN_SAMPLES]
    return [Job(f.key, f.url, f.licence) for f in files]


def compound_jobs() -> List[Job]:
    return [Job(f"otrf/{p}", f"{S.OTRF_RAW}/{p}", S.LICENCES["otrf"]) for p in S.OTRF_COMPOUND]


def optc_jobs() -> List[Job]:
    return [Job(f.key, f.url, f.licence) for f in S.OPTC_BENIGN]


def _run(jobs: List[Job], root: Path, pins: Pins, *, label: str, workers: int = 8) -> Dict[str, int]:
    counts: Dict[str, int] = {"downloaded": 0, "cached": 0, "registered": 0, "failed": 0}
    failures: List[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(download, job, root, pins): job for job in jobs}
        for done, future in enumerate(as_completed(futures), 1):
            job = futures[future]
            try:
                counts[future.result()] += 1
            except Exception as exc:  # report every failure, keep going
                counts["failed"] += 1
                failures.append(f"{job.key}: {exc}")
            if done % 50 == 0 or done == len(jobs):
                pins.save()
                print(f"[{label}] {done}/{len(jobs)} {counts}", flush=True)
    for failure in failures:
        print(f"[FAILED] {failure}", file=sys.stderr)
    return counts


def fetch_all(root: Path, groups: List[str]) -> int:
    pins = Pins()
    summary: Dict[str, Dict[str, int]] = {}
    if "static" in groups:
        summary["static"] = _run(static_jobs(), root, pins, label="static", workers=2)
    if "otrf" in groups:
        summary["otrf"] = _run(otrf_jobs(root, pins), root, pins, label="otrf")
    if "attack_data" in groups:
        summary["attack_data"] = _run(attack_data_jobs(root, pins), root, pins, label="attack_data")
    if "compound" in groups:
        summary["compound"] = _run(compound_jobs(), root, pins, label="compound")
    if "optc" in groups:
        summary["optc"] = _run(optc_jobs(), root, pins, label="optc", workers=2)
    pins.save()
    manifest = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pins_sha256": _sha256_file(pins.path),
        "commits": {"attack_data": S.ATTACK_DATA_COMMIT, "otrf": S.OTRF_COMMIT},
        "summary": summary,
    }
    (root / "fetch_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    failed = sum(c["failed"] for c in summary.values())
    print(json.dumps(manifest, indent=2))
    return 1 if failed else 0
