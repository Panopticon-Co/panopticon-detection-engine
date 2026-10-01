"""Behavioral rarity: has this kind of process start been seen before?

Rules recognise behavior someone has already described. This detector asks a
different question -- *is this normal here?* -- by counting what ordinary
activity looks like and reporting process starts that fall outside it.

How it works
------------
:class:`RarityBaseline` is a table of counts learned from telemetry that is
believed to be benign:

* ``parent_child`` -- how often each ``parent -> child`` name pair started,
  e.g. ``explorer.exe -> chrome.exe``.
* ``name_path_class`` -- how often each program ran from each kind of location,
  e.g. ``svchost.exe @ system``. Scored only for a program the baseline already
  knows, so it reads "a known program running from an unusual place" (a
  ``svchost.exe`` in Temp); a never-seen program is reported once, by
  ``parent_child``, not twice.
* ``name`` -- how often each program started, kept to support the above.

Scoring a new process start against the table gives, per dimension, one of:

* ``not_ready`` -- the baseline has not seen enough to judge (cold start);
* ``unseen``    -- the count is 0;
* ``uncommon``  -- the count is between 1 and ``uncommon_max_count``;
* ``common``    -- anything more frequent.

The category is the decision. ``observed_count``, ``baseline_total`` and
``relative_frequency`` are the literal measurement behind it. None of it is a
probability that the process is malicious: rare is not bad, and legitimate
software does rare things. That is why a rarity signal is low-level evidence
that joins incidents rules have found, never an incident or a response on its
own.

Learning policy
---------------
The baseline is learned offline (``panopticon-detect --learn-baseline``) and is
read-only while detecting: :class:`RarityDetector` never updates it. That keeps
replay deterministic and stops activity during an intrusion from teaching the
baseline that the intrusion is normal. Inferred processes -- whose start the
agent never saw -- are not learned from, because their lineage was not
observed.

The file it is saved as names its own meaning: type, format, the feature schema
it was learned with, readiness and threshold settings, the event-time window it
covers, and a content-derived version that every signal carries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from panopticon_detection.behavioral.signal import BehavioralSignal
from panopticon_detection.features import FEATURE_SCHEMA_VERSION, ProcessFeatures

BASELINE_TYPE = "process_rarity"
FORMAT_VERSION = 1

DETECTOR_NAME = "rarity"
DETECTOR_VERSION = "1"

NOT_READY = "not_ready"
UNSEEN = "unseen"
UNCOMMON = "uncommon"
COMMON = "common"

PARENT_CHILD = "parent_child"
NAME_PATH_CLASS = "name_path_class"
_NAME = "name"

# Defaults for a real deployment: a few hundred process starts and a few dozen
# distinct relationships before any judgement is made.
DEFAULT_MIN_OBSERVATIONS = 200
DEFAULT_MIN_RELATIONSHIPS = 25
DEFAULT_UNCOMMON_MAX_COUNT = 2

# How each dimension is reported. Levels sit far below the incident anchor
# threshold (10) and below every rule that matters to scoring.
_REPORTING = {
    PARENT_CHILD: (
        "BHV-RARE-001",
        "rare_parent_child",
        "Rare parent-child process relationship",
    ),
    NAME_PATH_CLASS: (
        "BHV-RARE-002",
        "rare_process_location",
        "Known process running from an unusual location",
    ),
}
_LEVEL = {UNSEEN: 4, UNCOMMON: 2}


@dataclass(frozen=True)
class RarityResult:
    """How one aspect of one process start compares with the baseline."""

    dimension: str
    value: str
    category: str
    observed_count: int
    baseline_total: int

    @property
    def relative_frequency(self) -> float:
        if not self.baseline_total:
            return 0.0
        return round(self.observed_count / self.baseline_total, 6)


class RarityBaseline:
    """Counts of normal process-start behavior, with readiness and thresholds."""

    def __init__(
        self,
        *,
        min_observations: int = DEFAULT_MIN_OBSERVATIONS,
        min_relationships: int = DEFAULT_MIN_RELATIONSHIPS,
        uncommon_max_count: int = DEFAULT_UNCOMMON_MAX_COUNT,
    ) -> None:
        self.min_observations = min_observations
        self.min_relationships = min_relationships
        self.uncommon_max_count = uncommon_max_count
        self.counts: Dict[str, Dict[str, int]] = {_NAME: {}, PARENT_CHILD: {}, NAME_PATH_CLASS: {}}
        self.total_observations = 0
        self.observed_from: Optional[str] = None
        self.observed_to: Optional[str] = None
        self.created_at: Optional[str] = None

    # ------------------------------------------------------------ learning
    def observe(self, features: ProcessFeatures) -> bool:
        """Count one process start. Returns False when it was not learned from."""
        if features.inferred or not features.name:
            return False
        self.total_observations += 1
        self._bump(_NAME, features.name)
        if features.parent_child:
            self._bump(PARENT_CHILD, features.parent_child)
        if features.path_class:
            self._bump(NAME_PATH_CLASS, _located(features.name, features.path_class))
        if self.observed_from is None or features.start_time < self.observed_from:
            self.observed_from = features.start_time
        if self.observed_to is None or features.start_time > self.observed_to:
            self.observed_to = features.start_time
        return True

    def fit(self, records: Iterable[ProcessFeatures]) -> int:
        """Observe every record; returns how many were learned from."""
        return sum(1 for r in records if self.observe(r))

    def _bump(self, dimension: str, value: str) -> None:
        table = self.counts[dimension]
        table[value] = table.get(value, 0) + 1

    # ----------------------------------------------------------- readiness
    @property
    def relationships(self) -> int:
        return len(self.counts[PARENT_CHILD])

    @property
    def is_ready(self) -> bool:
        return (
            self.total_observations >= self.min_observations
            and self.relationships >= self.min_relationships
        )

    def readiness(self) -> Dict[str, Any]:
        return {
            "ready": self.is_ready,
            "observations": self.total_observations,
            "relationships": self.relationships,
            "min_observations": self.min_observations,
            "min_relationships": self.min_relationships,
        }

    # ------------------------------------------------------------- scoring
    def score(self, features: ProcessFeatures) -> List[RarityResult]:
        """Compare one process start with the baseline, per dimension."""
        results = []
        if features.parent_child:
            results.append(self._result(PARENT_CHILD, features.parent_child))
        if features.path_class and self.counts[_NAME].get(features.name):
            results.append(
                self._result(NAME_PATH_CLASS, _located(features.name, features.path_class))
            )
        return results

    def _result(self, dimension: str, value: str) -> RarityResult:
        count = self.counts[dimension].get(value, 0)
        if not self.is_ready:
            category = NOT_READY
        elif count == 0:
            category = UNSEEN
        elif count <= self.uncommon_max_count:
            category = UNCOMMON
        else:
            category = COMMON
        return RarityResult(dimension, value, category, count, self.total_observations)

    # ------------------------------------------------------- serialization
    @property
    def version(self) -> str:
        """Content-derived: the same training data and settings give the same version."""
        payload = json.dumps(self._content(), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    def _content(self) -> Dict[str, Any]:
        return {
            "baseline_type": BASELINE_TYPE,
            "format_version": FORMAT_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "readiness": {
                "min_observations": self.min_observations,
                "min_relationships": self.min_relationships,
            },
            "thresholds": {"uncommon_max_count": self.uncommon_max_count},
            "observed_from": self.observed_from,
            "observed_to": self.observed_to,
            "total_observations": self.total_observations,
            "counts": {dim: dict(sorted(table.items())) for dim, table in self.counts.items()},
        }

    def to_dict(self) -> Dict[str, Any]:
        content = self._content()
        return {
            "baseline_type": content.pop("baseline_type"),
            "format_version": content.pop("format_version"),
            "feature_schema_version": content.pop("feature_schema_version"),
            "baseline_version": self.version,
            # Informational only; excluded from the version.
            "created_at": self.created_at,
            **content,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RarityBaseline":
        if data.get("baseline_type") != BASELINE_TYPE:
            raise ValueError(f"not a {BASELINE_TYPE} baseline: {data.get('baseline_type')!r}")
        if data.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"unsupported baseline format_version {data.get('format_version')!r}")
        if data.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"baseline was learned with feature schema {data.get('feature_schema_version')!r}; "
                f"this engine extracts schema {FEATURE_SCHEMA_VERSION} -- relearn it"
            )
        readiness = data.get("readiness") or {}
        thresholds = data.get("thresholds") or {}
        baseline = cls(
            min_observations=int(readiness.get("min_observations", DEFAULT_MIN_OBSERVATIONS)),
            min_relationships=int(readiness.get("min_relationships", DEFAULT_MIN_RELATIONSHIPS)),
            uncommon_max_count=int(thresholds.get("uncommon_max_count", DEFAULT_UNCOMMON_MAX_COUNT)),
        )
        counts = data.get("counts") or {}
        for dimension in baseline.counts:
            baseline.counts[dimension] = {str(k): int(v) for k, v in (counts.get(dimension) or {}).items()}
        baseline.total_observations = int(data.get("total_observations", 0))
        baseline.observed_from = data.get("observed_from")
        baseline.observed_to = data.get("observed_to")
        baseline.created_at = data.get("created_at")
        recorded = data.get("baseline_version")
        if recorded is not None and recorded != baseline.version:
            raise ValueError(
                f"baseline_version {recorded!r} does not match its contents ({baseline.version!r}); "
                "the file was edited or corrupted"
            )
        return baseline

    def save(self, path: Path) -> None:
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "RarityBaseline":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


class RarityDetector:
    """Scores each process start against a frozen :class:`RarityBaseline`."""

    name = DETECTOR_NAME
    version = DETECTOR_VERSION

    def __init__(self, baseline: RarityBaseline) -> None:
        self.baseline = baseline

    def evaluate(self, event: Dict[str, Any], extractor) -> List[BehavioralSignal]:
        if event.get("event_type") != "process_create" or not self.baseline.is_ready:
            return []
        features = extractor.extract_event(event)
        if features is None:
            return []
        return [
            self._signal(result, features, event)
            for result in self.baseline.score(features)
            if result.category in (UNSEEN, UNCOMMON)
        ]

    def prune(self, before: datetime) -> int:
        """Nothing to prune: the baseline is frozen and the detector keeps no state."""
        return 0

    # ------------------------------------------------------------------
    def _signal(
        self, result: RarityResult, features: ProcessFeatures, event: Dict[str, Any]
    ) -> BehavioralSignal:
        baseline = self.baseline
        rule_id, signal_type, title = _REPORTING[result.dimension]
        return BehavioralSignal(
            detector=self.name,
            detector_version=self.version,
            model_version=baseline.version,
            signal_type=signal_type,
            rule_id=rule_id,
            title=title,
            category=result.category,
            measurement={
                "dimension": result.dimension,
                "value": result.value,
                "observed_count": result.observed_count,
                "baseline_total": result.baseline_total,
                "relative_frequency": result.relative_frequency,
                "uncommon_max_count": baseline.uncommon_max_count,
            },
            explanation=self._explain(result, features),
            host_id=features.host_id,
            event_id=event.get("event_id"),
            timestamp=event.get("timestamp") or features.start_time,
            node_id=features.node_id,
            pid=features.pid,
            process_name=features.name,
            level=_LEVEL[result.category],
            evidence={
                "process": {
                    "name": features.name,
                    "executable": features.executable,
                    "path_class": features.path_class,
                    "parent_name": features.parent_name,
                    "grandparent_name": features.grandparent_name,
                    "tree_root_name": features.tree_root_name,
                },
                "baseline": {
                    "baseline_type": BASELINE_TYPE,
                    "baseline_version": baseline.version,
                    "observed_from": baseline.observed_from,
                    "observed_to": baseline.observed_to,
                    "total_observations": baseline.total_observations,
                    "relationships": baseline.relationships,
                },
            },
        )

    def _explain(self, result: RarityResult, features: ProcessFeatures) -> str:
        baseline = self.baseline
        where = f"rarity baseline {baseline.version}"
        if result.dimension == PARENT_CHILD:
            if result.category == UNSEEN:
                return (
                    f"Previously unseen parent-child relationship: {result.value} "
                    f"(0 of {result.baseline_total} process starts in {where})."
                )
            return (
                f"Uncommon parent-child relationship: {result.value} "
                f"(seen {result.observed_count} of {result.baseline_total} process starts in "
                f"{where}; uncommon means at most {baseline.uncommon_max_count})."
            )
        starts = baseline.counts[_NAME].get(features.name, 0)
        seen = "never" if result.category == UNSEEN else f"only {result.observed_count} time(s)"
        return (
            f"{features.name} ran from a {features.path_class} path; {where} has {seen} "
            f"seen it run from there across {starts} start(s) of {features.name}."
        )


def _located(name: str, path_class: str) -> str:
    return f"{name} @ {path_class}"
