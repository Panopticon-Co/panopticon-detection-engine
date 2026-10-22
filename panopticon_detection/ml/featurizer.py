"""Process-start featurizer for the supervised classifier (ProblemChild-style).

One process-creation event in, one sparse feature vector out. The function is
*event-local* -- it never reads the provenance graph -- so it is stateless and
gives the same answer in training, replay and serving.

Inputs are only what the Officer agent emits on a process start today, plus
the integrity level (carried separately until the agent's schema adds it):

* ``process.name``, ``process.executable``, ``process.command_line``
* ``parent.name``
* ``user.name`` / ``user.domain`` -- reduced to a *category*, never the name
* ``integrity_level`` (optional argument; Variant B models only)

Deliberately unused: pid/ppid, host, timestamps, entity ids and file hashes
(they identify a machine or a binary build, so a model would memorise them).

Determinism: hashed n-gram buckets use :func:`hashlib.blake2b`, never the
built-in ``hash()``, so vectors do not depend on ``PYTHONHASHSEED``. No set is
iterated to build a vector. Every value is finite.

Bump :data:`FEATURIZER_VERSION` on *any* change to names, order, normalisation
or hashing: it invalidates every model trained on the previous version.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from panopticon_detection.enrichment import classify_path
from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator

FEATURIZER_VERSION = 1

# ------------------------------------------------------------- normalisation

_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HEX = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b")
_DIGITS = re.compile(r"\d{3,}")
_USER_DIR = re.compile(r"([a-z]:\\users\\)[^\\\"' ]+")
_SYSTEM_DIRS = re.compile(r"[a-z]:\\windows\\(?:system32|syswow64|sysnative)")
_WINDOWS_DIR = re.compile(r"[a-z]:\\windows")
_PROGRAM_FILES = re.compile(r"[a-z]:\\program files(?: \(x86\))?")
_SPACES = re.compile(r"\s+")


def normalize_text(value: Optional[str]) -> str:
    """Lower-case and replace per-machine detail with placeholders.

    Usernames in profile paths, GUIDs, long hex and digit runs and the
    system directories are replaced (ProblemChild's normalisation), so the
    model learns the shape of a path or command, not one lab's names.
    """
    if not value:
        return ""
    text = str(value).lower().replace("/", "\\")
    text = _GUID.sub("<guid>", text)
    text = _USER_DIR.sub(r"\1<user>", text)
    text = _SYSTEM_DIRS.sub("win_system_dir", text)
    text = _WINDOWS_DIR.sub("win_dir", text)
    text = _PROGRAM_FILES.sub("program_files_dir", text)
    text = _HEX.sub("<hex>", text)
    text = _DIGITS.sub("<n>", text)
    return _SPACES.sub(" ", text).strip()


# ---------------------------------------------------------------- vocabulary

_PATH_CLASSES = ("system", "program_files", "user_writable", "temp", "other", "unknown", "none")
_USER_CATEGORIES = ("system", "service", "user", "unknown")
_INTEGRITY_LEVELS = ("low", "medium", "high", "system", "missing")

_URL = re.compile(r"\b(?:https?|ftp)://", re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_FLAG_ENCODED = re.compile(r"(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c)?\s", re.I)
_FLAG_HIDDEN = re.compile(r"[-/]w(?:indowstyle)?\s+h(?:idden)?\b", re.I)
_FLAG_BYPASS = re.compile(r"[-/](?:nop(?:rofile)?|ex(?:ec(?:utionpolicy)?)?\s+bypass|ep\s+bypass)\b", re.I)
_TOKEN = re.compile(r"[a-z0-9_.$<>-]+")

# (namespace, number of buckets). Order is part of the feature layout.
_HASHED: Tuple[Tuple[str, int], ...] = (
    ("cmd", 4096),      # command-line word unigrams + bigrams
    ("path", 1024),     # executable path tokens
    ("name", 256),      # process-name character bigrams
    ("parent", 256),    # parent-name character bigrams
    ("pair", 1024),     # parent -> child name pair
)

_DENSE: Tuple[str, ...] = (
    "cmd_missing",
    "cmd_length",
    "cmd_token_count",
    "cmd_entropy",
    "cmd_obfuscated",
    "cmd_evasion_count",
    "cmd_has_url",
    "cmd_has_ip",
    "cmd_has_base64_blob",
    "cmd_flag_encoded",
    "cmd_flag_hidden",
    "cmd_flag_bypass",
    "cmd_quote_count",
    "cmd_special_char_ratio",
    "name_missing",
    "name_ends_with_exe",
    "name_length",
    "path_depth",
    "path_in_system_dir",
    "parent_missing",
    "name_equals_parent",
    *(f"path_class={c}" for c in _PATH_CLASSES),
    *(f"user_category={c}" for c in _USER_CATEGORIES),
    *(f"integrity={c}" for c in _INTEGRITY_LEVELS),
)

INTEGRITY_FEATURES: Tuple[str, ...] = tuple(f"integrity={c}" for c in _INTEGRITY_LEVELS)


def _build_names() -> List[str]:
    names = list(_DENSE)
    for namespace, buckets in _HASHED:
        names.extend(f"{namespace}#{i}" for i in range(buckets))
    return names


FEATURE_NAMES: Tuple[str, ...] = tuple(_build_names())
_INDEX: Dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}
_OFFSET: Dict[str, int] = {}
_cursor = len(_DENSE)
for _namespace, _buckets in _HASHED:
    _OFFSET[_namespace] = _cursor
    _cursor += _buckets
_BUCKETS: Dict[str, int] = dict(_HASHED)

_SYSTEM_ACCOUNTS = ("system", "local system")
_SERVICE_ACCOUNTS = ("local service", "network service")
_NT_AUTHORITY = ("nt authority", "nt-autorität", "autorite nt")


def _bucket(namespace: str, token: str) -> int:
    digest = hashlib.blake2b(f"{namespace}\x1f{token}".encode("utf-8"), digest_size=8).digest()
    return _OFFSET[namespace] + int.from_bytes(digest, "big") % _BUCKETS[namespace]


def _add(vector: Dict[int, float], index: int, value: float = 1.0) -> None:
    vector[index] = vector.get(index, 0.0) + value


def _char_bigrams(text: str) -> List[str]:
    padded = f"^{text}$"
    return [padded[i : i + 2] for i in range(len(padded) - 1)]


def user_category(name: Optional[str], domain: Optional[str]) -> str:
    """``system`` / ``service`` / ``user`` / ``unknown`` -- never the identity."""
    user = (name or "").strip().lower()
    dom = (domain or "").strip().lower()
    if not user:
        return "unknown"
    if user in _SYSTEM_ACCOUNTS or user.endswith("$"):
        return "system"
    if user in _SERVICE_ACCOUNTS or (dom in _NT_AUTHORITY and user not in _SYSTEM_ACCOUNTS):
        return "service"
    return "user"


def integrity_category(value: Optional[str]) -> str:
    text = (value or "").strip().lower()
    for level in ("low", "medium", "high", "system"):
        if text.startswith(level):
            return level
    return "missing"


def _field(event: Dict[str, Any], section: str, key: str) -> Optional[str]:
    block = event.get(section)
    if isinstance(block, dict):
        value = block.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def featurize(event: Dict[str, Any], integrity_level: Optional[str] = None) -> Dict[int, float]:
    """Sparse feature vector ``{index into FEATURE_NAMES: value}`` for one process start.

    ``event`` is a normalized event (``ingestion.telemetry.normalize`` output).
    Absent indices mean 0.0. Integrity features are always emitted; a model
    trained without them (Variant A) simply never splits on them.
    """
    vector: Dict[int, float] = {}
    name = _field(event, "process", "name")
    executable = _field(event, "process", "executable")
    command_line = _field(event, "process", "command_line")
    parent = _field(event, "parent", "name")
    user = event.get("user") if isinstance(event.get("user"), dict) else {}

    name_n = normalize_text(name)
    parent_n = normalize_text(parent)
    path_n = normalize_text(executable)
    cmd_n = normalize_text(command_line)

    # -- command line
    if command_line is None:
        _add(vector, _INDEX["cmd_missing"])
    else:
        # Shape statistics are measured on the *normalised* text so a longer
        # username in a profile path cannot move them; obfuscation markers
        # (carets, backticks, case games) are read from the raw text.
        tokens = _TOKEN.findall(cmd_n)
        deob = CommandDeobfuscator.deobfuscate(command_line)
        length = len(cmd_n)
        _add(vector, _INDEX["cmd_length"], math.log1p(length))
        _add(vector, _INDEX["cmd_token_count"], math.log1p(len(tokens)))
        _add(vector, _INDEX["cmd_entropy"], float(ShannonEntropyCalculator.calculate_entropy(cmd_n)))
        _add(vector, _INDEX["cmd_obfuscated"], 1.0 if deob["is_obfuscated"] else 0.0)
        _add(vector, _INDEX["cmd_evasion_count"], float(len(deob["evasion_techniques"])))
        _add(vector, _INDEX["cmd_has_url"], 1.0 if _URL.search(command_line) else 0.0)
        _add(vector, _INDEX["cmd_has_ip"], 1.0 if _IP.search(command_line) else 0.0)
        _add(vector, _INDEX["cmd_has_base64_blob"], 1.0 if _B64.search(command_line) else 0.0)
        _add(vector, _INDEX["cmd_flag_encoded"], 1.0 if _FLAG_ENCODED.search(command_line + " ") else 0.0)
        _add(vector, _INDEX["cmd_flag_hidden"], 1.0 if _FLAG_HIDDEN.search(command_line) else 0.0)
        _add(vector, _INDEX["cmd_flag_bypass"], 1.0 if _FLAG_BYPASS.search(command_line) else 0.0)
        _add(vector, _INDEX["cmd_quote_count"], float(cmd_n.count('"') + cmd_n.count("'")))
        special = sum(1 for ch in cmd_n if not ch.isalnum() and not ch.isspace())
        _add(vector, _INDEX["cmd_special_char_ratio"], round(special / length, 6) if length else 0.0)
        for token in tokens:
            _add(vector, _bucket("cmd", token))
        for left, right in zip(tokens, tokens[1:]):
            _add(vector, _bucket("cmd", f"{left} {right}"))

    # -- process name and path
    if not name_n:
        _add(vector, _INDEX["name_missing"])
    else:
        _add(vector, _INDEX["name_ends_with_exe"], 1.0 if name_n.endswith(".exe") else 0.0)
        _add(vector, _INDEX["name_length"], float(len(name_n)))
        for gram in _char_bigrams(name_n):
            _add(vector, _bucket("name", gram))
    if path_n:
        _add(vector, _INDEX["path_depth"], float(path_n.count("\\")))
        _add(vector, _INDEX["path_in_system_dir"], 1.0 if path_n.startswith("win_system_dir") else 0.0)
        for token in _TOKEN.findall(path_n):
            _add(vector, _bucket("path", token))
    path_class = classify_path(executable) or "none"
    _add(vector, _INDEX[f"path_class={path_class if path_class in _PATH_CLASSES else 'other'}"])

    # -- parent
    if not parent_n:
        _add(vector, _INDEX["parent_missing"])
    else:
        for gram in _char_bigrams(parent_n):
            _add(vector, _bucket("parent", gram))
        if name_n:
            _add(vector, _INDEX["name_equals_parent"], 1.0 if name_n == parent_n else 0.0)
    _add(vector, _bucket("pair", f"{parent_n or '<none>'}->{name_n or '<none>'}"))

    # -- user and integrity
    _add(vector, _INDEX[f"user_category={user_category(user.get('name'), user.get('domain'))}"])
    _add(vector, _INDEX[f"integrity={integrity_category(integrity_level)}"])

    # Drop explicit zeros so the vector stays sparse and canonical.
    return {i: round(v, 6) for i, v in sorted(vector.items()) if v != 0.0}


def feature_spec() -> Dict[str, Any]:
    """What ``features.json`` records about this featurizer."""
    return {
        "featurizer_version": FEATURIZER_VERSION,
        "feature_count": len(FEATURE_NAMES),
        "dense_features": list(_DENSE),
        "hashed_namespaces": [{"namespace": ns, "buckets": n, "hash": "blake2b-64"} for ns, n in _HASHED],
        "integrity_features": list(INTEGRITY_FEATURES),
    }
