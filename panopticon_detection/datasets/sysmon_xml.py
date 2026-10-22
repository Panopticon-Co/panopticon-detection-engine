"""Sysmon events in their native XML form -> the flattened records ``otrf.py`` maps.

Splunk's ``XmlWinEventLog`` exports (``splunk/attack_data`` ``.log`` files,
BOTSv1's ``_raw`` field) carry each Windows event as the original
``<Event>...</Event>`` XML. This module only flattens that XML into the same
key/value shape OTRF ships (``Channel``, ``EventID``, ``Hostname``,
``EventRecordID``, ``@timestamp`` and every ``EventData/Data[@Name]``), so the
existing :class:`~panopticon_detection.datasets.otrf.OtrfAdapter` does the
canonical mapping -- one EID-to-event mapping for every Sysmon source.

Integrity level is not in the agent's schema 0.5, so it cannot ride in a
canonical event. :func:`integrity_by_event_id` returns it as a side table keyed
by the canonical ``event.id`` the adapter will assign to each process start.
"""

from __future__ import annotations

import gzip
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional

from panopticon_detection.datasets import canonical as C
from panopticon_detection.datasets.otrf import SYSMON_CHANNEL, _int, _v

_EVENT_BLOCK = re.compile(r"<Event[\s>].*?</Event>", re.S)
_NS = re.compile(r"\{[^}]*\}")


def _local(tag: str) -> str:
    return _NS.sub("", tag)


def parse_event_xml(text: str) -> Optional[Dict[str, Any]]:
    """Flatten one ``<Event>`` element; ``None`` if it is not well-formed."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    record: Dict[str, Any] = {}
    for section in root:
        name = _local(section.tag)
        if name == "System":
            for child in section:
                tag = _local(child.tag)
                if tag == "Provider":
                    record["SourceName"] = child.get("Name")
                elif tag == "TimeCreated":
                    record["@timestamp"] = child.get("SystemTime")
                elif tag == "Computer":
                    record["Hostname"] = (child.text or "").strip()
                elif tag in ("EventID", "EventRecordID", "Channel", "Version"):
                    record[tag] = (child.text or "").strip()
        elif name == "EventData":
            for data in section:
                key = data.get("Name")
                if key:
                    record[key] = data.text if data.text is not None else ""
    return record or None


def iter_xml_events(text: str) -> Iterator[Dict[str, Any]]:
    """Every ``<Event>`` in a blob that may hold one or many, one per line or not."""
    for match in _EVENT_BLOCK.finditer(text):
        record = parse_event_xml(match.group(0))
        if record is not None:
            yield record


def read_attack_data_log(path: Path) -> Iterator[Dict[str, Any]]:
    """A ``splunk/attack_data`` XmlWinEventLog ``.log`` file."""
    yield from iter_xml_events(Path(path).read_text(encoding="utf-8", errors="replace"))


def read_botsv1_json(path: Path) -> Iterator[Dict[str, Any]]:
    """BOTSv1's per-sourcetype JSON export (gzip or plain): one Splunk result per line."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line).get("result") or {}
            except (json.JSONDecodeError, AttributeError):
                continue
            raw = result.get("_raw")
            if raw:
                record = parse_event_xml(raw)
                if record is not None:
                    yield record


def only_event_ids(records: Iterable[Dict[str, Any]], event_ids: Iterable[int]) -> Iterator[Dict[str, Any]]:
    """Sysmon records whose EventID is in ``event_ids`` (cheap pre-filter)."""
    wanted = set(event_ids)
    for record in records:
        if record.get("Channel") == SYSMON_CHANNEL and _int(record, "EventID") in wanted:
            yield record


def integrity_by_event_id(records: Iterable[Dict[str, Any]], dataset_id: str) -> Dict[str, str]:
    """``{canonical event.id: IntegrityLevel}`` for every Sysmon process start.

    Mirrors the key :class:`OtrfAdapter` builds (dataset, host, channel,
    EventID, record id) so the side table joins the canonical events exactly.
    Pass the *same* record list, in the same order, that the adapter receives:
    a record without an id is keyed by its position.
    """
    table: Dict[str, str] = {}
    for index, record in enumerate(records):
        if record.get("Channel") != SYSMON_CHANNEL or _int(record, "EventID") != 1:
            continue
        level = _v(record, "IntegrityLevel")
        if level is None:
            continue
        host = _v(record, "Hostname", "host") or "UNKNOWN_HOST"
        record_id = _int(record, "RecordNumber", "EventRecordID")
        key = (dataset_id, host, record.get("Channel"), 1, record_id if record_id is not None else f"line{index}")
        table[C.event_id(*key)] = level
    return table
