"""OTRF Security-Datasets (formerly Mordor) -> canonical Panopticon events.

`OTRF Security-Datasets <https://github.com/OTRF/Security-Datasets>`_ (MIT) are
recordings of ATT&CK techniques run on lab Windows hosts, exported as one JSON
object per line. Each object is one Windows event with its EventData fields
flattened to the top level, so a Sysmon process create carries ``Image``,
``ProcessId``, ``ParentImage``, ``CommandLine`` ... directly -- the same facts
the Officer agent decodes from the same Sysmon events.

Two export flavours exist and both are handled: a Winlogbeat-style export
(``@timestamp``, ``TimeCreated``) and an NXLog export (``EventTime``,
``RecordNumber``, ``ExecutionProcessID``, ``UserID``).

What maps, and how
------------------
Sysmon Operational (``source.kind = sysmon``):

==========  =====================================  ========
EventID     canonical event                          schema
==========  =====================================  ========
1           process / start                         0.3
3           network / connect                       0.3
5           process / stop                          0.5
7           image_load / load                       0.3
8           remote_thread / create                  0.5
10          process_access / access                 0.5
11          file / create                           0.3
12          registry / add_key or delete_key        0.3
13          registry / set_value                    0.3
14          registry / rename_key                   0.3
22          dns / query                             0.5
23, 26      file / delete                           0.3
==========  =====================================  ========

PowerShell Operational EventID 4104 -> script_block / execute (0.5,
``source.kind = windows_event_log``). Everything else -- the Security and
System channels, PowerShell 4103/800, Sysmon 2/9/17/18/24 -- is counted in the
report as skipped, never guessed into a family it is not.

Field choices that are not obvious:

* **Time.** Sysmon's own ``UtcTime`` is used for Sysmon events. The exported
  ``@timestamp``/``TimeCreated`` are *not* reliable UTC: in several recordings
  they sit a whole number of hours away from ``UtcTime`` (the collector's local
  time labelled as UTC). Events without ``UtcTime`` (PowerShell) take the
  export time corrected by the offset measured on that same file's Sysmon
  events -- the median of ``UtcTime - export time``. The report records the
  offset and how many events it was measured on.
* **User.** For Sysmon events the process user is Sysmon's ``User`` field. The
  NXLog ``UserID`` on those records is the Sysmon *service* account (SYSTEM)
  and is ignored. For 4104 ``UserID`` is the PowerShell user's SID and is used.
* **4104 process.** The event names only a PID (``ExecutionProcessID``). The
  image path is filled from a Sysmon process-create for that PID earlier in the
  same file, exactly as the agent backfills from its PID cache; otherwise it is
  null.
* **Registry values** stay metadata-only (``value_data`` null), matching the
  agent's policy, even though the recording has ``Details``.
* **Script text** is capped exactly as the agent caps it
  (:func:`canonical.truncate_script_text`). Text is otherwise kept as recorded,
  including export artefacts such as ``&amp;``.

Labels
------
OTRF labels a *recording*, not an event: each dataset's metadata YAML maps the
whole file to ATT&CK technique(s). The recording also contains ordinary OS
activity (svchost, Defender, search indexer ...) that is not part of the
attack, and the attack itself often exercises techniques the mapping does not
list. The adapter therefore never writes a label onto an event; it reports the
dataset-level mapping in the manifest, with that caveat stated.
"""

from __future__ import annotations

import io
import json
import re
import statistics
import tarfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import yaml

from panopticon_detection.datasets import canonical as C

ADAPTER_ID = "dataset-adapter:otrf"
ADAPTER_VERSION = "1"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

LABEL_SEMANTICS = (
    "Dataset-level only. The OTRF metadata maps the whole recording to the listed "
    "ATT&CK technique(s). Individual events and processes are NOT labelled: the "
    "recording also contains unrelated OS activity, and the attack may exercise "
    "techniques the mapping omits. Do not treat every event in the file as malicious."
)

_SHA256_RE = re.compile(r"SHA256=([0-9A-Fa-f]{64})")


# --------------------------------------------------------------------- input


def read_records(path: Path) -> List[Dict[str, Any]]:
    """Every JSON record in an OTRF file: ``.zip``, ``.tar.gz`` or JSON lines."""
    path = Path(path)
    name = path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            members = sorted(m for m in archive.namelist() if m.lower().endswith(".json"))
            return [r for m in members for r in _json_lines(archive.read(m).decode("utf-8"))]
    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(path, "r:gz") as archive:
            members = sorted(
                (m for m in archive.getmembers() if m.isfile() and m.name.lower().endswith(".json")),
                key=lambda m: m.name,
            )
            records: List[Dict[str, Any]] = []
            for member in members:
                handle = archive.extractfile(member)
                if handle is not None:
                    records.extend(_json_lines(io.TextIOWrapper(handle, encoding="utf-8").read()))
            return records
    return list(_json_lines(path.read_text(encoding="utf-8")))


def _json_lines(text: str) -> Iterator[Dict[str, Any]]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            record = json.loads(line)
            if isinstance(record, dict):
                yield record


def load_metadata(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """The dataset's OTRF metadata YAML, reduced to what the manifest reports."""
    if path is None:
        return None
    meta = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    mappings = []
    for mapping in meta.get("attack_mappings") or []:
        technique = mapping.get("technique")
        sub = mapping.get("sub-technique")
        mappings.append(
            {
                "technique": f"{technique}.{sub}" if technique and sub else technique,
                "tactics": list(mapping.get("tactics") or []),
            }
        )
    simulation = meta.get("simulation") or {}
    return {
        "id": meta.get("id"),
        "title": meta.get("title"),
        "description": meta.get("description"),
        "attack_mappings": mappings,
        "adversary_view": simulation.get("adversary_view"),
        "label_semantics": LABEL_SEMANTICS,
    }


# -------------------------------------------------------------------- report


@dataclass
class NormalizationReport:
    """What a normalisation run did -- written next to the output as a manifest."""

    dataset_id: Optional[str]
    records_read: int = 0
    events_written: int = 0
    duplicates_dropped: int = 0
    mapped: Counter = field(default_factory=Counter)
    skipped: Counter = field(default_factory=Counter)
    rejected: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    time_offset_seconds: float = 0.0
    time_offset_samples: int = 0
    first_event: Optional[str] = None
    last_event: Optional[str] = None
    labels: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        def keyed(counter: Counter) -> Dict[str, int]:
            return {f"{ch} {eid}": n for (ch, eid), n in sorted(counter.items(), key=lambda kv: str(kv[0]))}

        return {
            "adapter": {"id": ADAPTER_ID, "version": ADAPTER_VERSION},
            "dataset_id": self.dataset_id,
            "records_read": self.records_read,
            "events_written": self.events_written,
            "duplicates_dropped": self.duplicates_dropped,
            "mapped": keyed(self.mapped),
            "skipped": keyed(self.skipped),
            "rejected": dict(sorted(self.rejected.items())),
            "hosts": dict(sorted(self.hosts.items())),
            "time_alignment": {
                "method": (
                    "Sysmon UtcTime as-is; other events: export time + "
                    "median(UtcTime - export time) of this file's Sysmon events"
                ),
                "offset_seconds": self.time_offset_seconds,
                "measured_on_events": self.time_offset_samples,
            },
            "time_range": {"first": self.first_event, "last": self.last_event},
            "labels": self.labels,
        }


# ------------------------------------------------------------------- helpers


class _Reject(Exception):
    """A record that cannot become a valid canonical event (reason in the message)."""


def _v(record: Dict[str, Any], *keys: str) -> Optional[str]:
    """First present value; Sysmon writes ``-`` for "none", which becomes None."""
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text and text != "-":
            return text
    return None


def _int(record: Dict[str, Any], *keys: str) -> Optional[int]:
    value = _v(record, *keys)
    if value is None:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _hex(record: Dict[str, Any], key: str) -> Optional[str]:
    """A hex field kept as Sysmon renders it, or None if it is not hex."""
    value = _v(record, key)
    return value if value and re.fullmatch(r"0x[0-9A-Fa-f]+", value) else None


def _sysmon_utc(record: Dict[str, Any]) -> Optional[datetime]:
    text = _v(record, "UtcTime")
    if not text:
        return None
    for fmt, width in (("%Y-%m-%d %H:%M:%S.%f", 23), ("%Y-%m-%d %H:%M:%S", 19)):
        try:
            return datetime.strptime(text[:width], fmt)
        except ValueError:
            continue
    return None


def _export_time(record: Dict[str, Any]) -> Optional[datetime]:
    text = _v(record, "@timestamp", "TimeCreated")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = (parsed - parsed.utcoffset()).replace(tzinfo=None)
    return parsed


def _sha256(record: Dict[str, Any]) -> Optional[str]:
    match = _SHA256_RE.search(_v(record, "Hashes") or "")
    return match.group(1).lower() if match else None


def _registry_value_type(details: Optional[str]) -> Optional[str]:
    # The agent's mapping (sysmon_telemetry_decoder.cpp), so both producers agree.
    if details is None:
        return None
    if details.startswith("DWORD"):
        return "REG_DWORD"
    if details.startswith("QWORD"):
        return "REG_QWORD"
    if details.startswith("Binary Data"):
        return "REG_BINARY"
    return "REG_SZ"


def _leaf(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return path.rsplit("\\", 1)[-1] or None


def measure_time_offset(records: Iterable[Dict[str, Any]]) -> Tuple[float, int]:
    """Median ``UtcTime - export time`` over Sysmon records carrying both."""
    deltas = []
    for record in records:
        utc, wall = _sysmon_utc(record), _export_time(record)
        if utc is not None and wall is not None:
            deltas.append((utc - wall).total_seconds())
    if not deltas:
        return 0.0, 0
    return float(round(statistics.median(deltas))), len(deltas)


# ------------------------------------------------------------------- adapter

_Starts = Dict[Tuple[str, int], List[Tuple[datetime, str]]]


class OtrfAdapter:
    """Normalises OTRF records to canonical events (see the module docstring)."""

    def __init__(self, dataset_id: Optional[str] = None) -> None:
        self.dataset_id = dataset_id or "otrf"

    def normalize(
        self, records: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Dict[str, Any]], NormalizationReport]:
        report = NormalizationReport(dataset_id=self.dataset_id, labels=metadata)
        report.records_read = len(records)
        offset, samples = measure_time_offset(records)
        report.time_offset_seconds, report.time_offset_samples = offset, samples

        # PID -> [(start, image)] from Sysmon process creates, to fill the image
        # of a 4104 event (which names only a PID), like the agent's PID cache.
        starts: _Starts = {}
        for record in records:
            if record.get("Channel") == SYSMON_CHANNEL and _int(record, "EventID") == 1:
                when, pid, image = _sysmon_utc(record), _int(record, "ProcessId"), _v(record, "Image")
                if when and pid is not None and image:
                    starts.setdefault((self._host(record)["id"], pid), []).append((when, image))

        produced: List[Tuple[datetime, int, Dict[str, Any]]] = []
        seen_ids = set()
        for index, record in enumerate(records):
            channel = record.get("Channel")
            event_number = _int(record, "EventID")
            key = (channel, event_number)
            builder = self._builder(channel, event_number)
            if builder is None:
                report.skipped[key] += 1
                continue
            when = _sysmon_utc(record) if channel == SYSMON_CHANNEL else None
            if when is None:
                wall = _export_time(record)
                when = wall + timedelta(seconds=offset) if wall is not None else None
            if when is None:
                report.rejected["no usable timestamp"] += 1
                continue
            try:
                event = builder(self, record, when, index, starts)
            except _Reject as reason:
                report.rejected[str(reason)] += 1
                continue
            if event["event"]["id"] in seen_ids:
                report.duplicates_dropped += 1
                continue
            seen_ids.add(event["event"]["id"])
            report.mapped[key] += 1
            report.hosts[event["host"]["id"]] += 1
            produced.append((when, index, event))

        # Replay assumes near-ordered arrival; order by event time, then by the
        # record's position in the file so equal times stay stable.
        produced.sort(key=lambda item: (item[0], item[1]))
        events = [event for _, _, event in produced]
        report.events_written = len(events)
        if events:
            report.first_event = events[0]["event"]["timestamp"]
            report.last_event = events[-1]["event"]["timestamp"]
        return events, report

    # ------------------------------------------------------------------
    @staticmethod
    def _builder(channel: Any, event_number: Optional[int]) -> Optional[Callable[..., Dict[str, Any]]]:
        if channel == SYSMON_CHANNEL:
            return _SYSMON_BUILDERS.get(event_number)
        if channel == POWERSHELL_CHANNEL and event_number == 4104:
            return OtrfAdapter._script_block
        return None

    @staticmethod
    def _host(record: Dict[str, Any]) -> Dict[str, Any]:
        hostname = _v(record, "Hostname", "host") or "UNKNOWN_HOST"
        # The recordings do not say which Windows build they ran on; "unknown"
        # fills the schema's required string as a stated unknown, not a guess.
        return {"id": hostname, "hostname": hostname, "os": {"name": "Windows", "build": "unknown"}}

    def _base(self, record: Dict[str, Any], *, provider: str, kind: str, index: int) -> Dict[str, Any]:
        host = self._host(record)
        record_id = _int(record, "RecordNumber", "EventRecordID")
        return {
            "host": host,
            "source": {
                "kind": kind,
                "provider": _v(record, "SourceName") or provider,
                "channel": record.get("Channel"),
                "record_id": record_id,
            },
            "event_key": (
                self.dataset_id,
                host["id"],
                record.get("Channel"),
                _int(record, "EventID"),
                record_id if record_id is not None else f"line{index}",
            ),
            "agent": {"id": ADAPTER_ID, "version": ADAPTER_VERSION},
        }

    def _context(self, record: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Process context from the (``Source``-prefixed) Sysmon fields."""
        host = self._host(record)["id"]
        pid = _int(record, f"{prefix}ProcessId")
        if pid is None:
            raise _Reject(f"no {prefix}ProcessId")
        image = _v(record, f"{prefix}Image")
        guid = _v(record, f"{prefix}ProcessGuid", f"{prefix}ProcessGUID")
        return {
            "entity_id": C.context_entity_id(host, pid, guid),
            "pid": pid,
            "name": C.basename(image),
            "executable": image,
        }

    def _target(self, record: Dict[str, Any]) -> Dict[str, Any]:
        host = self._host(record)["id"]
        pid = _int(record, "TargetProcessId")
        guid = _v(record, "TargetProcessGuid", "TargetProcessGUID")
        return {
            "entity_id": C.context_entity_id(host, pid, guid) if pid is not None else None,
            "pid": pid,
            "executable": _v(record, "TargetImage"),
            "user": _v(record, "TargetUser"),
        }

    def _sysmon_event(
        self,
        record: Dict[str, Any],
        when: datetime,
        index: int,
        *,
        category: str,
        type_: str,
        process: Dict[str, Any],
        block: Optional[Dict[str, Any]] = None,
        user_field: str = "User",
    ) -> Dict[str, Any]:
        base = self._base(record, provider="Microsoft-Windows-Sysmon", kind="sysmon", index=index)
        name, domain = C.split_account(_v(record, user_field))
        return C.build_event(
            category=category,
            type_=type_,
            event_key=base["event_key"],
            when=when,
            source=base["source"],
            agent=base["agent"],
            host=base["host"],
            user={"name": name, "domain": domain, "sid": None},
            process=process,
            block=block,
        )

    # ---------------------------------------------------------- Sysmon EIDs
    def _process_start(self, record, when, index, starts):
        host = self._host(record)["id"]
        pid = _int(record, "ProcessId")
        if pid is None:
            raise _Reject("no ProcessId")
        image = _v(record, "Image")
        parent_pid = _int(record, "ParentProcessId")
        process = {
            "entity_id": C.process_entity_id(host, pid, when),
            "pid": pid,
            "name": C.basename(image),
            "executable": image,
            "command_line": _v(record, "CommandLine"),
            "sha256": _sha256(record),
            "parent": {
                "entity_id": (
                    C.context_entity_id(host, parent_pid, _v(record, "ParentProcessGuid"))
                    if parent_pid is not None
                    else None
                ),
                "pid": parent_pid,
                "name": C.basename(_v(record, "ParentImage")),
            },
        }
        return self._sysmon_event(record, when, index, category="process", type_="start", process=process)

    def _process_stop(self, record, when, index, starts):
        return self._sysmon_event(
            record, when, index, category="process", type_="stop", process=self._context(record)
        )

    def _network(self, record, when, index, starts):
        protocol = (_v(record, "Protocol") or "").lower()
        block = {
            "direction": "outbound" if (_v(record, "Initiated") or "").lower() in ("true", "1") else "inbound",
            "protocol": protocol if protocol in ("tcp", "udp") else None,
            "source_ip": _v(record, "SourceIp"),
            "source_port": _int(record, "SourcePort"),
            "destination_ip": _v(record, "DestinationIp"),
            "destination_port": _int(record, "DestinationPort"),
            "destination_hostname": _v(record, "DestinationHostname"),
        }
        return self._sysmon_event(
            record, when, index, category="network", type_="connect", process=self._context(record), block=block
        )

    def _image_load(self, record, when, index, starts):
        signed = _v(record, "Signed")
        block = {
            "path": _v(record, "ImageLoaded"),
            "is_signed": None if signed is None else signed.lower() in ("true", "1"),
            "signature_status": _v(record, "SignatureStatus"),
            "hash": {"sha256": _sha256(record)},
        }
        return self._sysmon_event(
            record, when, index, category="image_load", type_="load", process=self._context(record), block=block
        )

    def _file(self, record, when, index, starts):
        operation = "create" if _int(record, "EventID") == 11 else "delete"
        block = {
            "operation": operation,
            "path": _v(record, "TargetFilename"),
            "target_path": None,
            "previous_path": None,
            "hash": {"sha256": _sha256(record)},
        }
        return self._sysmon_event(
            record, when, index, category="file", type_=operation, process=self._context(record), block=block
        )

    def _registry(self, record, when, index, starts):
        event_number = _int(record, "EventID")
        key_path = _v(record, "TargetObject")
        if event_number == 12:
            operation = "delete_key" if (_v(record, "EventType") or "") == "DeleteKey" else "add_key"
        elif event_number == 13:
            operation = "set_value"
        else:
            operation = "rename_key"
        block = {
            "operation": operation,
            "key_path": key_path,
            "value_name": _leaf(key_path) if operation == "set_value" else None,
            "value_type": _registry_value_type(_v(record, "Details")) if operation == "set_value" else None,
            "value_data": None,  # metadata-only, as the agent
        }
        return self._sysmon_event(
            record, when, index, category="registry", type_=operation, process=self._context(record), block=block
        )

    def _process_access(self, record, when, index, starts):
        block = {
            "target": self._target(record),
            "granted_access": _hex(record, "GrantedAccess"),
            "call_trace": _v(record, "CallTrace"),
        }
        return self._sysmon_event(
            record, when, index, category="process_access", type_="access",
            process=self._context(record, "Source"), block=block, user_field="SourceUser",
        )

    def _remote_thread(self, record, when, index, starts):
        block = {
            "target": self._target(record),
            "new_thread_id": _int(record, "NewThreadId"),
            "start_address": _hex(record, "StartAddress"),
            "start_module": _v(record, "StartModule"),
            "start_function": _v(record, "StartFunction"),
        }
        return self._sysmon_event(
            record, when, index, category="remote_thread", type_="create",
            process=self._context(record, "Source"), block=block, user_field="SourceUser",
        )

    def _dns(self, record, when, index, starts):
        block = {
            "query_name": _v(record, "QueryName"),
            "query_status": _int(record, "QueryStatus"),
            "query_results": _v(record, "QueryResults"),
        }
        return self._sysmon_event(
            record, when, index, category="dns", type_="query", process=self._context(record), block=block
        )

    # ------------------------------------------------------ PowerShell 4104
    def _script_block(self, record, when, index, starts: _Starts):
        pid = _int(record, "ExecutionProcessID", "ProcessID", "ProcessId")
        if pid is None:
            raise _Reject("4104 without a process id")
        base = self._base(record, provider="Microsoft-Windows-PowerShell", kind="windows_event_log", index=index)
        host = base["host"]["id"]
        image = None
        for start, start_image in sorted(starts.get((host, pid), ())):
            if start <= when:
                image = start_image
        block = {
            "script_block_id": _v(record, "ScriptBlockId"),
            "message_number": _int(record, "MessageNumber"),
            "message_total": _int(record, "MessageTotal"),
            "path": _v(record, "Path"),
            **C.truncate_script_text(record.get("ScriptBlockText")),
        }
        return C.build_event(
            category="script_block",
            type_="execute",
            event_key=base["event_key"],
            when=when,
            source=base["source"],
            agent=base["agent"],
            host=base["host"],
            user={"name": _v(record, "AccountName"), "domain": _v(record, "Domain"), "sid": _v(record, "UserID")},
            process={
                "entity_id": C.context_entity_id(host, pid, None),
                "pid": pid,
                "name": C.basename(image),
                "executable": image,
            },
            block=block,
        )


_SYSMON_BUILDERS: Dict[int, Callable[..., Dict[str, Any]]] = {
    1: OtrfAdapter._process_start,
    3: OtrfAdapter._network,
    5: OtrfAdapter._process_stop,
    7: OtrfAdapter._image_load,
    8: OtrfAdapter._remote_thread,
    10: OtrfAdapter._process_access,
    11: OtrfAdapter._file,
    12: OtrfAdapter._registry,
    13: OtrfAdapter._registry,
    14: OtrfAdapter._registry,
    22: OtrfAdapter._dns,
    23: OtrfAdapter._file,
    26: OtrfAdapter._file,
}


def write_ndjson(events: Iterable[Dict[str, Any]], path: Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count
