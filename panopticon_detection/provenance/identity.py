"""L1 -- process identity resolution by time-interval stabbing.

The problem this exists to solve
--------------------------------
A Panopticon agent derives ``process.entity_id`` with *two different formulas*
depending on the telemetry family (see ``panopticon-agent``'s
``include/panopticon/officer/core/entity_id.hpp``):

* process-create events use ``derive_process_entity_id(host, pid, start_time)``
* network / file / registry / image_load events use
  ``derive_process_context_entity_id(host, pid, sysmon_process_guid)``

The agent's own header states these are not guaranteed to be equal. So an
``entity_id`` can never join a process's creation to its later activity, and any
index keyed on it silently misses for four of the five families.

The agent contract instead says: *cross-family correlation is by PID within a
time window*. This module makes that join explicit and PID-reuse-safe.

How
---
Every ``(host_id, pid)`` owns a time-ordered list of **incarnations**, each
covering the half-open interval ``[start_time, end_time)``. Resolving an
arbitrary event to its process is then an interval-stabbing query: binary search
for the latest incarnation starting at or before the event, and confirm the
event falls before that incarnation's end. Two processes that reused the same
PID occupy disjoint intervals, so they can never be confused.

End times
---------
The agent's schema currently admits only ``event.type: "start"`` for the process
family, so no ``process_terminate`` ever arrives and a true end time is
unavailable. An incarnation is therefore closed *implicitly* when a later
incarnation appears on the same ``(host_id, pid)`` -- the OS cannot have two live
processes with one PID. Until that happens the incarnation stays open, bounded
only by ``max_lifetime``. When the agent gains a ``stop`` event,
:meth:`ProcessRegistry.observe_stop` already handles it and the inference below
becomes a fallback rather than the primary mechanism.
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Tuple

# An event whose timestamp cannot be parsed. Kept distinct from "no timestamp"
# so callers can decide; resolution treats it as unresolvable rather than
# matching it against an arbitrary incarnation.
UNKNOWN_TIME = datetime.min

# How long an incarnation with no observed successor stays resolvable. Generous
# on purpose: closing too eagerly would orphan the later telemetry of a
# long-lived process, which is the exact failure this module exists to prevent.
DEFAULT_MAX_LIFETIME = timedelta(hours=24)


def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp, returning :data:`UNKNOWN_TIME` when absent
    or unparseable. Timezone-aware inputs are normalised to naive UTC so that
    all comparisons in this package are between like kinds."""
    if not value:
        return UNKNOWN_TIME
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return UNKNOWN_TIME
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(tz=None).replace(tzinfo=None)
    return parsed


def derive_node_id(host_id: str, pid: int, start_time: datetime) -> str:
    """A stable, content-derived identifier for one process incarnation.

    Deterministic rather than random so that replaying the same event stream --
    after a crash, or across a manager restart -- reproduces identical node ids
    and the persisted graph deduplicates instead of forking.
    """
    key = f"{host_id}|{pid}|{start_time.isoformat()}"
    return "proc_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


@dataclass
class ProcessIncarnation:
    """One live run of one PID on one host, over ``[start_time, end_time)``."""

    node_id: str
    host_id: str
    pid: int
    start_time: datetime
    end_time: Optional[datetime] = None

    name: str = ""
    executable: str = ""
    command_line: str = ""
    user: str = ""
    sha256: Optional[str] = None

    parent_pid: Optional[int] = None
    parent_node_id: Optional[str] = None

    # Opaque, OS-native process-creation token from schema 0.4's
    # ``process.start_time_ticks``. Never interpreted, compared or derived
    # here -- it is carried solely so a response recommendation raised from a
    # *later* event (a network connection, a correlated campaign) can still
    # name a PID-reuse-safe kill target. response_engine.translate_recommendation
    # fails closed without it, which is why threading it through matters.
    start_time_ticks: Optional[int] = None

    # The agent's own id for this process as seen on its creation event. Kept
    # for forensic traceability only -- never used as a join key, for the
    # reasons in this module's docstring.
    entity_id: Optional[str] = None

    # True when this incarnation was never observed being created -- it was
    # inferred from a child's parent reference. An agent that starts on an
    # already-running machine never sees the creation of existing processes, so
    # without inference every lineage would stop at the first such process.
    inferred: bool = False

    def covers(self, when: datetime, max_lifetime: timedelta) -> bool:
        """Whether this incarnation was live at ``when``."""
        if when == UNKNOWN_TIME or when < self.start_time:
            return False
        if self.end_time is not None:
            return when < self.end_time
        return when - self.start_time <= max_lifetime

    @property
    def is_open(self) -> bool:
        return self.end_time is None


@dataclass
class ProcessRegistry:
    """Interval index over process incarnations, keyed by ``(host_id, pid)``.

    Not thread-safe; the detection worker drives one instance from a single
    thread, matching how every other stateful engine here is used.
    """

    max_lifetime: timedelta = DEFAULT_MAX_LIFETIME

    # (host_id, pid) -> incarnations, ascending by start_time.
    _timeline: Dict[Tuple[str, int], List[ProcessIncarnation]] = field(
        default_factory=dict, repr=False
    )
    _by_node_id: Dict[str, ProcessIncarnation] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------
    def observe_start(self, event: Dict[str, Any]) -> Optional[ProcessIncarnation]:
        """Record a process-creation event. Returns the new incarnation, or
        ``None`` when the event carries no PID or no usable timestamp -- both
        make it unindexable, and guessing would defeat the point of the index."""
        proc = event.get("process") or {}
        pid = proc.get("pid")
        host_id = event.get("host_id") or "UNKNOWN_HOST"
        start = parse_timestamp(event.get("timestamp"))

        if not isinstance(pid, int) or isinstance(pid, bool) or start == UNKNOWN_TIME:
            return None

        parent = event.get("parent") or {}
        parent_pid = parent.get("pid")

        incarnation = ProcessIncarnation(
            node_id=derive_node_id(host_id, pid, start),
            host_id=host_id,
            pid=pid,
            start_time=start,
            name=(proc.get("name") or "").lower(),
            executable=proc.get("executable") or proc.get("executable_path") or "",
            command_line=proc.get("command_line") or "",
            user=proc.get("user") or "",
            sha256=proc.get("sha256") or proc.get("file_hash"),
            parent_pid=parent_pid if isinstance(parent_pid, int) else None,
            start_time_ticks=_coerce_ticks(proc.get("start_time_ticks")),
            entity_id=proc.get("entity_id"),
        )

        # The parent is whichever incarnation of the parent PID was live when
        # this child started -- itself an interval-stabbing query, so parent
        # links are PID-reuse-safe too. When the parent's own creation was never
        # observed, infer a placeholder from the reference this event carries.
        if incarnation.parent_pid is not None:
            parent_inc = self.resolve(host_id, incarnation.parent_pid, start)
            if parent_inc is None:
                parent_inc = self._infer_parent(
                    host_id, incarnation.parent_pid, parent.get("name"), start
                )
            if parent_inc is not None:
                incarnation.parent_node_id = parent_inc.node_id

        self._insert(incarnation)
        return incarnation

    def _infer_parent(
        self, host_id: str, pid: int, name: Optional[str], child_start: datetime
    ) -> Optional["ProcessIncarnation"]:
        """Create a placeholder for a parent whose creation was never seen.

        Dated one microsecond before the child so the interval index places it
        correctly, and marked ``inferred`` so a consumer can tell a reconstructed
        ancestor from an observed one. Carries no ``start_time_ticks``: the token
        was never observed, and inventing one would defeat the PID-reuse guard in
        ``response_engine.translate_recommendation``.
        """
        if not isinstance(pid, int) or isinstance(pid, bool):
            return None
        start = child_start - timedelta(microseconds=1)
        placeholder = ProcessIncarnation(
            node_id=derive_node_id(host_id, pid, start),
            host_id=host_id,
            pid=pid,
            start_time=start,
            name=(name or "").lower(),
            inferred=True,
        )
        self._insert(placeholder)
        return placeholder

    def observe_stop(self, event: Dict[str, Any]) -> Optional[ProcessIncarnation]:
        """Record a process-termination event, closing the live incarnation.

        No Panopticon agent emits this yet -- the schema's process family admits
        only ``event.type: "start"``. Implemented now so that adding the ``stop``
        event upstream needs no change here.
        """
        proc = event.get("process") or {}
        pid = proc.get("pid")
        host_id = event.get("host_id") or "UNKNOWN_HOST"
        when = parse_timestamp(event.get("timestamp"))
        if not isinstance(pid, int) or when == UNKNOWN_TIME:
            return None

        incarnation = self.resolve(host_id, pid, when)
        if incarnation is None:
            return None
        incarnation.end_time = when
        return incarnation

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def resolve(
        self, host_id: str, pid: Optional[int], when: datetime
    ) -> Optional[ProcessIncarnation]:
        """The incarnation of ``pid`` on ``host_id`` that was live at ``when``.

        This is the join the whole package rests on: it lets a network, file,
        registry or image-load event find the process that caused it without
        depending on an ``entity_id`` the agent derives differently per family.
        """
        if not isinstance(pid, int) or isinstance(pid, bool) or when == UNKNOWN_TIME:
            return None

        timeline = self._timeline.get((host_id, pid))
        if not timeline:
            return None

        # Rightmost incarnation starting at or before `when`.
        idx = bisect.bisect_right([inc.start_time for inc in timeline], when) - 1
        if idx < 0:
            return None

        candidate = timeline[idx]
        return candidate if candidate.covers(when, self.max_lifetime) else None

    def resolve_event(self, event: Dict[str, Any]) -> Optional[ProcessIncarnation]:
        """Resolve the process responsible for any normalized event."""
        proc = event.get("process") or {}
        return self.resolve(
            event.get("host_id") or "UNKNOWN_HOST",
            proc.get("pid"),
            parse_timestamp(event.get("timestamp")),
        )

    def get(self, node_id: str) -> Optional[ProcessIncarnation]:
        return self._by_node_id.get(node_id)

    def ancestors(self, node_id: str, max_depth: int = 16) -> List[ProcessIncarnation]:
        """Walk parent links from a node up to the root, nearest parent first.

        Unlike the previous ``ProcessTree`` this is reachable from *any* event,
        because ``node_id`` comes from :meth:`resolve_event` rather than from an
        ``entity_id`` that only matches on process-create.
        """
        chain: List[ProcessIncarnation] = []
        seen = {node_id}
        current = self._by_node_id.get(node_id)

        while current is not None and current.parent_node_id and len(chain) < max_depth:
            if current.parent_node_id in seen:
                break  # defensive: a cycle cannot happen, but never spin on one
            seen.add(current.parent_node_id)
            parent = self._by_node_id.get(current.parent_node_id)
            if parent is None:
                break
            chain.append(parent)
            current = parent

        return chain

    def lineage(self, node_id: str) -> str:
        """``explorer.exe -> winword.exe -> cmd.exe -> powershell.exe``."""
        node = self._by_node_id.get(node_id)
        if node is None:
            return "UNKNOWN"
        names = [a.name for a in reversed(self.ancestors(node_id))] + [node.name]
        return " -> ".join(n for n in names if n)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def prune(self, before: datetime) -> int:
        """Drop incarnations that ended before ``before``. Returns the count.

        Bounds memory for a long-running worker. Open incarnations are kept
        regardless of age until ``max_lifetime`` has elapsed, so a legitimately
        long-lived process is never orphaned mid-campaign.
        """
        removed = 0
        for key, timeline in list(self._timeline.items()):
            kept = []
            for inc in timeline:
                expiry = inc.end_time or (inc.start_time + self.max_lifetime)
                if expiry < before:
                    self._by_node_id.pop(inc.node_id, None)
                    removed += 1
                else:
                    kept.append(inc)
            if kept:
                self._timeline[key] = kept
            else:
                # Evict the key itself, not just its contents -- the previous
                # correlation engine leaked one dict key per (host, pid) forever.
                del self._timeline[key]
        return removed

    def __len__(self) -> int:
        return len(self._by_node_id)

    def __iter__(self) -> Iterator[ProcessIncarnation]:
        return iter(self._by_node_id.values())

    # ------------------------------------------------------------------
    def _insert(self, incarnation: ProcessIncarnation) -> None:
        key = (incarnation.host_id, incarnation.pid)
        timeline = self._timeline.setdefault(key, [])
        starts = [inc.start_time for inc in timeline]
        idx = bisect.bisect_right(starts, incarnation.start_time)

        # A PID cannot host two live processes: the predecessor must have ended
        # by the time this one started. Close it if nothing else already did.
        if idx > 0:
            previous = timeline[idx - 1]
            if previous.is_open:
                previous.end_time = incarnation.start_time

        # An out-of-order arrival: bound the new incarnation by its successor.
        if idx < len(timeline):
            incarnation.end_time = timeline[idx].start_time

        timeline.insert(idx, incarnation)
        self._by_node_id[incarnation.node_id] = incarnation


def _coerce_ticks(value: Any) -> Optional[int]:
    """Accept ``start_time_ticks`` only as a genuine positive integer.

    Deliberately strict: this token ends up as a ``KILL_PROCESS`` target, and
    ``response_engine.translate_recommendation`` refuses anything it cannot
    trust. Normalising a bad value here would launder it past that check.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value
