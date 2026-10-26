"""Behaviour oracle: hashes of what the engine and the ML feature path produce.

    python scripts/engine_oracle.py [--json out.json] [--check baseline.json]

Replays every corpus scenario and the bundled samples through the fully wired
engine, with the training replay's ``CheckpointTap`` riding along, and hashes:

* the alerts (``Alert.to_dict``), per stream;
* the provenance graph's stats and its edge list (kind, endpoints, event id);
* every checkpoint feature record (``FeatureExtractor.extract`` as of the
  checkpoint), and the context vector of each (``context_featurizer.vectorize``);
* ``telemetry.FIELD_REGISTRY`` and the feature-name layouts.

A refactor that claims "no behaviour change" must reproduce these hashes
exactly (``--check``). They are engineering regression evidence over synthetic
fixtures, not detection results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "train"))

from panopticon_detection.factory import build_detection_run  # noqa: E402
from panopticon_detection.ingestion import telemetry  # noqa: E402
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter  # noqa: E402
from panopticon_detection.ml import context_featurizer as CF  # noqa: E402
from panopticon_detection.ml import featurizer as F  # noqa: E402
from pdtrain.replay import CheckpointTap  # noqa: E402

STREAMS = sorted((ROOT / "tests" / "corpus").glob("*/events.ndjson")) + [
    ROOT / "samples" / "officer_live_sample.ndjson",
    ROOT / "samples" / "attack_simulation.ndjson",
    ROOT / "samples" / "v3" / "mixed_families_sample.ndjson",
]


def _digest(value) -> str:
    blob = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


class _Features:
    """Attribute view over a serialised ProcessFeatures record (as the training path reads it)."""

    def __init__(self, record: dict) -> None:
        self.__dict__.update(record)


def replay(path: Path) -> dict:
    tap = CheckpointTap()
    run, context = build_detection_run(ROOT / "rules", behavioral_detectors=[tap])
    alerts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            alerts += [a.to_dict() for a in run.process_event(event)]
    starts = {r["node"]: r["start_vector"] for r in tap.records if r["t"] == "start"}
    checkpoints = [r for r in tap.records if r["t"] == "cp"]
    vectors = []
    for record in checkpoints:
        start = {int(k): v for k, v in starts.get(record["node"], {}).items()}
        vec = CF.vectorize(_Features(record["features"]), start)
        vectors.append({str(k): (None if v != v else v) for k, v in sorted(vec.items())})
    edges = sorted((e.kind.value, e.src, e.dst, e.event_id or "") for e in context.graph.edges.values())
    return {
        "alerts": _digest(alerts),
        "alert_count": len(alerts),
        "graph_stats": context.graph.stats(),
        "edges": _digest(edges),
        "tap_records": _digest(tap.records),
        "checkpoints": len(checkpoints),
        "vectors": _digest(vectors),
    }


def oracle() -> dict:
    return {
        "field_registry": _digest({k: sorted(v) for k, v in telemetry.FIELD_REGISTRY.items()}),
        "start_feature_names": _digest(list(F.FEATURE_NAMES)),
        "context_feature_names": _digest(list(CF.FEATURE_NAMES)),
        "context_version": CF.CONTEXT_VERSION,
        "streams": {str(p.relative_to(ROOT)): replay(p) for p in STREAMS},
    }


def _diff(a, b, path="") -> list:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += _diff(a.get(key), b.get(key), f"{path}.{key}" if path else key)
        return out
    return [] if a == b else [f"{path}: {a!r} -> {b!r}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", type=Path, help="write the oracle here")
    parser.add_argument("--check", type=Path, help="compare against a saved oracle; exit 1 on any difference")
    args = parser.parse_args()
    result = oracle()
    if args.json:
        args.json.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    if args.check:
        diffs = _diff(json.loads(args.check.read_text(encoding="utf-8")), result)
        for line in diffs:
            print("DIFF", line)
        print("oracle:", "identical" if not diffs else f"{len(diffs)} difference(s)")
        return 1 if diffs else 0
    if not args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
