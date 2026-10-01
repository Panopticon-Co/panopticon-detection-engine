"""Derived event fields: computed once per event, readable by any rule.

Rules read raw normalized fields (``process.command_line``) and these derived
ones (``process.path_class``, ``process.image_writer_name`` ...). Each derived
value is computed at most once per event and cached on the event under
``_derived``, so ten rules asking for the deobfuscated command line cost one
decode, not ten.

Every field here is computed from telemetry the agent actually emits, the
provenance registry, or the provenance graph -- nothing is inferred from data
that does not exist. ``DERIVED_FIELDS`` says which event types each field is
meaningful for; ``scripts/check_rule_sourcing.py`` uses it to reject a rule that
reads a derived field on an event type that cannot produce it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple

from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator
from panopticon_detection.provenance.boundary import is_boundary
from panopticon_detection.provenance.graph import EdgeKind, NodeKind, entity_node_id

DERIVED_KEY = "_derived"

_FILE_TYPES = frozenset({"file_create", "file_delete", "file_rename"})
_PROCESS_TYPES = frozenset({"process_create"})
_NETWORK_TYPES = frozenset({"network_connect"})
_IMAGE_TYPES = frozenset({"image_load"})


@dataclass
class MatchContext:
    """What a rule may consult beyond the event itself."""

    registry: Any = None
    graph: Any = None
    threat_intel: Any = None


# ---------------------------------------------------------------- path class

_TEMP = ("/temp/", "/tmp/", "/var/tmp/", "/dev/shm/")
_USER_WRITABLE = ("/users/", "/appdata/", "/programdata/", "/home/", "/downloads/")
_PROGRAM_FILES = ("/program files/", "/program files (x86)/", "/opt/")
_SYSTEM = (
    "/windows/system32/",
    "/windows/syswow64/",
    "/windows/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/bin/",
    "/sbin/",
    "/lib/",
)


def classify_path(path: Optional[str]) -> Optional[str]:
    """``temp`` / ``user_writable`` / ``program_files`` / ``system`` / ``other``.

    ``None`` when there is no path, ``unknown`` for a bare file name. Temp is
    checked first because ``...\\AppData\\Local\\Temp\\`` is both user-writable
    and temp, and temp is the stronger signal for a dropped payload.
    """
    if not path:
        return None
    norm = "/" + str(path).replace("\\", "/").lower().lstrip("/")
    if norm.count("/") < 2:
        return "unknown"
    for classification, markers in (
        ("temp", _TEMP),
        ("user_writable", _USER_WRITABLE),
        ("program_files", _PROGRAM_FILES),
        ("system", _SYSTEM),
    ):
        if any(marker in norm for marker in markers):
            return classification
    return "other"


def _suffix(path: Optional[str]) -> str:
    if not path:
        return ""
    return PurePosixPath(str(path).replace("\\", "/")).suffix.lower()


_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def destination_scope(ip: Optional[str]) -> Optional[str]:
    """``public`` / ``private`` / ``loopback`` / ``link_local`` / ``multicast`` / ``reserved``."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "unknown"
    # RFC 5737 blocks are reserved so documentation and examples can stand in
    # for Internet hosts; samples and fixtures use them that way. Python files
    # them under is_private, which would make every example C2 address look
    # internal. Real telemetry never contains them.
    if any(addr in net for net in _DOCUMENTATION_NETS):
        return "public"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


# ------------------------------------------------------------------ helpers


def _deob(event: Dict[str, Any]) -> Dict[str, Any]:
    cache = event.setdefault(DERIVED_KEY, {})
    if "_deobfuscation" not in cache:
        cmd = (event.get("process") or {}).get("command_line", "")
        cache["_deobfuscation"] = CommandDeobfuscator.deobfuscate(cmd)
    return cache["_deobfuscation"]


def _actor(event: Dict[str, Any], ctx: MatchContext):
    if ctx.registry is None:
        return None
    cache = event.setdefault(DERIVED_KEY, {})
    if "_actor" not in cache:
        cache["_actor"] = ctx.registry.resolve_event(event)
    return cache["_actor"]


def tree_root(registry, incarnation):
    """The topmost non-boundary ancestor-or-self: the process tree's entry point.

    ``winword.exe -> powershell.exe -> payload.exe`` under ``explorer.exe`` has
    tree root ``winword.exe``; a process whose parent is a boundary process is
    its own root.
    """
    if incarnation is None:
        return None
    root = incarnation
    for ancestor in registry.ancestors(incarnation.node_id):
        if is_boundary(ancestor.name):
            break
        root = ancestor
    return root


def image_write(event: Dict[str, Any], ctx: MatchContext) -> Optional[Tuple[Any, float]]:
    """The last write of the acting process's own image before it started.

    Returns ``(writer_incarnation, seconds_between_write_and_start)`` or
    ``None``. This is the graph join that makes "dropped, then executed"
    expressible: the file node a process EXECUTED is the same node another
    process WROTE.
    """
    cache = event.setdefault(DERIVED_KEY, {})
    if "_image_write" not in cache:
        cache["_image_write"] = image_write_for(_actor(event, ctx), ctx)
    return cache["_image_write"]


def image_write_for(actor, ctx: MatchContext) -> Optional[Tuple[Any, float]]:
    """:func:`image_write` for a process incarnation rather than an event.

    The feature extractor calls this directly, so a feature and a rule field
    computed for the same process can never disagree.
    """
    if actor is None or not actor.executable or ctx.graph is None or ctx.registry is None:
        return None
    file_id = entity_node_id(NodeKind.FILE, actor.host_id, actor.executable)
    best = None
    for edge in ctx.graph.incident_edges(file_id):
        if edge.kind not in (EdgeKind.WROTE, EdgeKind.RENAMED) or edge.dst != file_id:
            continue
        if edge.src == actor.node_id or edge.ts > actor.start_time:
            continue
        if best is None or edge.ts > best.ts:
            best = edge
    if best is None:
        return None
    writer = ctx.registry.get(best.src)
    if writer is None:
        return None
    return writer, (actor.start_time - best.ts).total_seconds()


# --------------------------------------------------------------- the fields


def _lineage(event, ctx):
    actor = _actor(event, ctx)
    return ctx.registry.lineage(actor.node_id) if actor is not None else None


def _ancestor_names(event, ctx):
    actor = _actor(event, ctx)
    if actor is None:
        return None
    return [a.name for a in ctx.registry.ancestors(actor.node_id)]


def _tree_root_name(event, ctx):
    root = tree_root(ctx.registry, _actor(event, ctx)) if ctx.registry else None
    return root.name if root is not None else None


def _image_writer_name(event, ctx):
    hit = image_write(event, ctx)
    return hit[0].name if hit else None


def _image_age_seconds(event, ctx):
    hit = image_write(event, ctx)
    return hit[1] if hit else None


def _extension_changed(event, ctx):
    info = event.get("file") or {}
    old, new = _suffix(info.get("previous_path")), _suffix(info.get("path"))
    if not info.get("previous_path") or not info.get("path"):
        return None
    return bool(new) and new != old


def _hash_match(event, ctx):
    if ctx.threat_intel is None:
        return None
    proc = event.get("process") or {}
    return ctx.threat_intel.check_hash(proc.get("file_hash") or (event.get("file") or {}).get("hash"))


def _ip_match(event, ctx):
    if ctx.threat_intel is None:
        return None
    return ctx.threat_intel.check_ip((event.get("network") or {}).get("destination_ip"))


# name -> (function, event types it is meaningful for; None = every type)
DERIVED_FIELDS: Dict[str, Tuple[Callable[[Dict[str, Any], MatchContext], Any], Optional[FrozenSet[str]]]] = {
    "process.deobfuscated_command": (lambda e, c: _deob(e)["full_deobfuscated"], None),
    "process.normalized_command": (lambda e, c: _deob(e)["full_deobfuscated"], None),
    "process.is_obfuscated": (lambda e, c: _deob(e)["is_obfuscated"], None),
    "process.evasion_techniques": (lambda e, c: _deob(e)["evasion_techniques"], None),
    "process.entropy": (
        lambda e, c: ShannonEntropyCalculator.calculate_entropy(
            (e.get("process") or {}).get("command_line", "")
        ),
        None,
    ),
    "process.is_high_entropy": (
        lambda e, c: ShannonEntropyCalculator.analyze_tokens(
            (e.get("process") or {}).get("command_line", "")
        )["is_anomaly"],
        None,
    ),
    "process.path_class": (lambda e, c: classify_path((e.get("process") or {}).get("executable")), None),
    "process.lineage": (_lineage, None),
    "process.ancestry": (_lineage, None),
    "process.ancestor_names": (_ancestor_names, None),
    "process.tree_root_name": (_tree_root_name, None),
    "process.image_writer_name": (_image_writer_name, None),
    "process.image_age_seconds": (_image_age_seconds, None),
    "file.path_class": (lambda e, c: classify_path((e.get("file") or {}).get("path")), _FILE_TYPES | _PROCESS_TYPES),
    "file.extension": (lambda e, c: _suffix((e.get("file") or {}).get("path")) or None, _FILE_TYPES | _PROCESS_TYPES),
    "file.extension_changed": (_extension_changed, frozenset({"file_rename"})),
    "image.path_class": (lambda e, c: classify_path((e.get("image") or {}).get("path")), _IMAGE_TYPES),
    "network.destination_scope": (
        lambda e, c: destination_scope((e.get("network") or {}).get("destination_ip")),
        _NETWORK_TYPES,
    ),
    "threat_intel.hash_match": (_hash_match, None),
    "threat_intel.ip_match": (_ip_match, _NETWORK_TYPES),
}


def derived_available(field: str, event_type: str) -> bool:
    entry = DERIVED_FIELDS.get(field)
    return entry is not None and (entry[1] is None or event_type in entry[1])


def derive(event: Dict[str, Any], field: str, ctx: MatchContext) -> Any:
    """Value of derived ``field`` for ``event``, cached per event."""
    cache = event.setdefault(DERIVED_KEY, {})
    if field not in cache:
        fn, _ = DERIVED_FIELDS[field]
        cache[field] = fn(event, ctx)
    return cache[field]


def reset(event: Dict[str, Any]) -> None:
    """Drop cached derived values (the registry/graph may have changed)."""
    event.pop(DERIVED_KEY, None)
