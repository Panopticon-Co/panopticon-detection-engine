"""Process-in-context vectorizer for the L1 model (context model, CONTEXT_VERSION 1).

One process incarnation, as of a checkpoint, in; one sparse vector out. The
inputs are a :class:`~panopticon_detection.features.ProcessFeatures` record
(lineage and behaviour from the provenance graph, feature schema 3) and the
process-start vector of :mod:`.featurizer` (v5) for the same process.

Features come in *groups*. Each behaviour group belongs to one telemetry
family. When a family is not collected on a host (an old Sysmon configuration,
an ETW-only agent, a recording kit that keeps starts only), its whole group is
set to an explicit NaN -- "unknown", not "did nothing" -- so a model never
reads absence of telemetry as evidence of innocence. Collected-but-silent is 0.

Every behaviour feature is a yes/no bit or a capped count of distinct objects
(``features.BIT_OBJECT_CAP``); raw event counts are not used, because a Sysmon
configuration decides how dense each family is. Names outside the closed
binary vocabulary of :mod:`.featurizer` never become features.

Stdlib only. Bump :data:`CONTEXT_VERSION` on any change to names or order.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from panopticon_detection.ml import featurizer as F

CONTEXT_VERSION = 1
NAN = float("nan")

#: Roles that make a lineage interesting, and service/remote-execution parents.
_DESCENDS_ROLES = ("office", "browser", "script_host", "server_app")
_DESCENDS_NAMES = ("wmiprvse.exe", "psexesvc.exe", "services.exe")
_ANCESTOR_LEVELS = 4

#: Behaviour bits by group (= telemetry family); see features.BEHAVIOR_BITS.
GROUP_BITS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("network", ("network:public_destination", "network:public_nonstandard_port")),
    ("image_load", ("image_load:user_path_module", "image_load:unsigned_module")),
    ("file", ("file:executable_to_user_path",)),
    ("registry", ("registry:persistence_key",)),
    ("process_access", ("process_access:lsass_read",)),
    ("remote_thread", ("remote_thread:out", "remote_thread:in")),
    ("dns", ("dns:failed_query",)),
    ("script_block", ("script_block:obfuscated",)),
)
#: Groups that do not depend on an optional telemetry family.
CORE_GROUPS = ("start", "lineage", "children")
ALL_GROUPS: Tuple[str, ...] = CORE_GROUPS + tuple(g for g, _ in GROUP_BITS)
FAMILY_GROUPS = tuple(g for g, _ in GROUP_BITS)

_START_INDEX = [i for i, n in enumerate(F.FEATURE_NAMES) if n not in F.STATS_FEATURES]
_WRITER_ROLES = F.ROLES + ("none",)


def _layout() -> Tuple[List[Tuple[str, str]], Dict[str, int]]:
    named: List[Tuple[str, str]] = [("start", f"start:{F.FEATURE_NAMES[i]}") for i in _START_INDEX]
    for level in range(1, _ANCESTOR_LEVELS + 1):
        named += [("lineage", f"anc{level}_role={r}") for r in F.ROLES]
    named += [("lineage", "depth")]
    named += [("lineage", f"descends_from_role={r}") for r in _DESCENDS_ROLES]
    named += [("lineage", f"descends_from={n}") for n in _DESCENDS_NAMES]
    named += [("children", "child:shell_or_lolbin"), ("children", "child:shell_or_lolbin_objects"),
              ("children", "child_count_log"), ("children", "elapsed_log")]
    for group, bits in GROUP_BITS:
        for bit in bits:
            named += [(group, bit), (group, f"{bit}_objects")]
    named += [("file", f"image_writer_role={r}") for r in _WRITER_ROLES]
    named += [("file", "image_age_log")]
    return named, {name: i for i, (_, name) in enumerate(named)}


_NAMED, _INDEX = _layout()
FEATURE_NAMES: Tuple[str, ...] = tuple(name for _, name in _NAMED)
GROUP_OF: Dict[str, str] = {name: group for group, name in _NAMED}
#: Features that may only raise a score (monotone +1): the behaviour bits themselves.
MONOTONE_FEATURES: Tuple[str, ...] = tuple(
    bit for _, bits in GROUP_BITS for bit in bits) + ("child:shell_or_lolbin",)


def _role(name: Optional[str]) -> str:
    if not name:
        return "missing"
    return F.ROLE_OF.get(name.lower(), "other")


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def vectorize(
    features: Any,
    start_vector: Mapping[int, float],
    available: Optional[Iterable[str]] = None,
    groups: Optional[Iterable[str]] = None,
) -> Dict[int, float]:
    """Sparse vector ``{index into FEATURE_NAMES: value}`` (NaN entries are explicit).

    ``features`` is a ``ProcessFeatures`` (schema 3). ``start_vector`` is
    ``featurizer.featurize`` of the process's start event. ``available`` names the
    telemetry families collected on this host (``None``: all of them, as with
    the live agent). ``groups`` restricts output to admitted groups (``None``: all).
    """
    admitted = set(ALL_GROUPS if groups is None else groups)
    collected = set(FAMILY_GROUPS if available is None else available)
    vector: Dict[int, float] = {}

    def put(name: str, value: float) -> None:
        if value:
            vector[_INDEX[name]] = round(float(value), 6)

    if "start" in admitted:
        for i in _START_INDEX:
            value = start_vector.get(i)
            if value:
                put(f"start:{F.FEATURE_NAMES[i]}", value)

    if "lineage" in admitted:
        names = list(features.ancestor_names or ())
        for level in range(1, _ANCESTOR_LEVELS + 1):
            put(f"anc{level}_role={_role(names[level - 1] if level <= len(names) else None)}", 1.0)
        put("depth", min(int(features.depth or 0), 10))
        roles = {_role(n) for n in names}
        lowered = {n.lower() for n in names}
        for r in _DESCENDS_ROLES:
            put(f"descends_from_role={r}", 1.0 if r in roles else 0.0)
        for n in _DESCENDS_NAMES:
            put(f"descends_from={n}", 1.0 if n in lowered else 0.0)

    objects = dict(features.behavior_bit_objects or ())
    bits = set(features.behavior_bits or ())
    if "children" in admitted:
        put("child:shell_or_lolbin", 1.0 if "child:shell_or_lolbin" in bits else 0.0)
        put("child:shell_or_lolbin_objects", objects.get("child:shell_or_lolbin", 0))
        put("child_count_log", math.log1p(min(int(features.child_count or 0), 50)))
        start, as_of = _parse(features.start_time), _parse(features.as_of)
        if start is not None and as_of is not None:
            put("elapsed_log", math.log1p(max((as_of - start).total_seconds(), 0.0)))

    for group, group_bits in GROUP_BITS:
        if group not in admitted:
            continue
        names = [n for b in group_bits for n in (b, f"{b}_objects")]
        if group == "file":
            names += [f"image_writer_role={r}" for r in _WRITER_ROLES] + ["image_age_log"]
        if group not in collected:
            for name in names:
                vector[_INDEX[name]] = NAN
            continue
        for bit in group_bits:
            put(bit, 1.0 if bit in bits else 0.0)
            put(f"{bit}_objects", objects.get(bit, 0))
        if group == "file":
            writer = features.image_writer_name
            put(f"image_writer_role={_role(writer) if writer else 'none'}", 1.0)
            if features.image_age_seconds is not None:
                put("image_age_log", math.log1p(max(float(features.image_age_seconds), 0.0)))

    return dict(sorted(vector.items()))


def spec() -> Dict[str, Any]:
    """What a bundle's ``features.json`` records about this vectorizer."""
    return {"context_version": CONTEXT_VERSION, "start_featurizer_version": F.FEATURIZER_VERSION,
            "feature_count": len(FEATURE_NAMES), "groups": list(ALL_GROUPS),
            "monotone_features": list(MONOTONE_FEATURES)}
