"""The one supported way to construct a wired :class:`DetectionRun`.

Keeping the wiring here means the engine owns its own composition and
downstream consumers (the CLI, ``manager/detection/factory.py``) depend on one
function whose signature is part of the public contract.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.detection_run import DetectionRun
from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.evaluator.stateful import StatefulEvaluator
from panopticon_detection.ml.artifact import ArtifactError, load_bundle
from panopticon_detection.ml.stage import MODES, MLStage
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.incident import IncidentTracker
from panopticon_detection.provenance.risk_scorer import EntityRiskScorer
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine

log = logging.getLogger(__name__)

ENV_MODEL_PATH = "PANOPTICON_MODEL_PATH"
ENV_MODEL_MODE = "PANOPTICON_ML_MODE"
ENV_MODEL_SHA256 = "PANOPTICON_MODEL_SHA256"


def build_ml_stage(
    model_path: Optional[str] = None, mode: Optional[str] = None
) -> Tuple[Optional[MLStage], Dict[str, Any]]:
    """Load the optional ML stage; **never raises**.

    ``model_path`` / ``mode`` default to the ``PANOPTICON_MODEL_PATH`` /
    ``PANOPTICON_ML_MODE`` environment variables. No path means rules-only and
    no ``ml_*`` stats at all (unchanged behaviour). A path that fails validation
    leaves the run rules-only, logs the reason once and reports
    ``ml_state: "disabled"``: a raise here would put the manager's detection
    worker into ``fatal_error`` and stop *rule* detection over an optional
    model (docs/adr/003).
    """
    path = model_path or os.environ.get(ENV_MODEL_PATH)
    if not path:
        return None, {}
    chosen = (mode or os.environ.get(ENV_MODEL_MODE) or "shadow").lower()
    try:
        if chosen not in MODES:
            raise ArtifactError(f"unknown ML mode {chosen!r} (expected one of {MODES})")
        bundle = load_bundle(path, expect_sha256=os.environ.get(ENV_MODEL_SHA256))
        return MLStage(bundle, chosen), {}
    except Exception as exc:  # fail open, loudly
        log.error("ML stage DISABLED: %s; running rules-only", exc)
        return None, {"ml_state": "disabled", "ml_error": str(exc)[:200]}


class DetectionContext:
    """The stateful objects behind a run, exposed for inspection and upkeep.

    A caller needs these for two things the run itself does not do: periodic
    :meth:`prune` so a long-lived worker stays bounded, and reading the graph
    and incidents to render an investigation.
    """

    def __init__(
        self,
        graph: ProvenanceGraph,
        registry: ProcessRegistry,
        incidents: IncidentTracker,
        run: DetectionRun,
        ml_status: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.graph = graph
        self.registry = registry
        self.incidents = incidents
        self.run = run
        self.ml_status = ml_status or {}

    def prune(self, before: datetime) -> Dict[str, int]:
        """Drop every piece of detection state older than ``before`` (naive UTC).

        Covers the graph, the process registry, open incidents, stateful rule
        state, the beacon detector, behavioral detectors, the risk meter and
        alert dedup, so a long-running worker stays bounded.
        """
        run = self.run
        detector_state = (
            run.stateful.prune(before)
            + run.risk_scorer.prune(before)
            + run.beacon_detector.prune(before)
            + sum(detector.prune(before) for detector in run.behavioral_detectors)
            + (run.ml_stage.prune(before) if run.ml_stage is not None else 0)
            + run.prune(before)
        )
        return {
            "edges_removed": self.graph.prune(before),
            "processes_removed": self.registry.prune(before),
            "incidents_closed": self.incidents.prune(before),
            "detector_state_removed": detector_state,
        }

    def stats(self) -> Dict[str, Any]:
        stage = self.run.ml_stage
        return {
            **self.graph.stats(),
            "processes": len(self.registry),
            "open_incidents": len(self.incidents.incidents),
            **self.run.stateful.state_size(),
            **(stage.stats() if stage is not None else self.ml_status),
        }


def build_detection_run(
    rules_dir: Path,
    *,
    emit: Optional[Callable[[Any], None]] = None,
    retention: timedelta = timedelta(hours=24),
    campaign_horizon: timedelta = timedelta(hours=6),
    behavioral_detectors: Sequence[Any] = (),
    ml_model_path: Optional[str] = None,
    ml_mode: Optional[str] = None,
) -> Tuple[DetectionRun, DetectionContext]:
    """Load rules and wire a detection run over a fresh provenance graph.

    ``emit`` is called once per alert produced. ``retention`` bounds how long a
    process incarnation stays resolvable; ``campaign_horizon`` bounds how far
    back an incident's causal walk may reach. ``behavioral_detectors`` (e.g. a
    :class:`~panopticon_detection.behavioral.rarity.RarityDetector`) are
    optional; with none, the run behaves exactly as it did before they existed.

    ``ml_model_path`` (default: ``$PANOPTICON_MODEL_PATH``) names an exported
    model bundle and ``ml_mode`` (``shadow`` or ``active``; default
    ``$PANOPTICON_ML_MODE``, else ``shadow``) what the ML stage may emit. With
    no path the run is rules-only, byte-identical to before. An invalid bundle
    never raises: the stage is disabled and ``stats()["ml_state"]`` says so.
    """
    rules = RuleLoader().load_directory(Path(rules_dir))
    ml_stage, ml_status = build_ml_stage(ml_model_path, ml_mode)

    graph = ProvenanceGraph()
    registry = ProcessRegistry(max_lifetime=retention)
    threat_intel = ThreatIntelEngine()
    incidents = IncidentTracker(graph=graph, registry=registry, horizon=campaign_horizon)

    run = DetectionRun(
        graph_builder=EventGraphBuilder(graph, registry),
        evaluator=RuleEvaluator(rules, registry=registry, threat_intel=threat_intel, graph=graph),
        stateful=StatefulEvaluator(rules, registry=registry, graph=graph, threat_intel=threat_intel),
        incidents=incidents,
        risk_scorer=EntityRiskScorer(breach_threshold=75),
        beacon_detector=C2BeaconDetector(registry=registry),
        emit=emit,
        behavioral_detectors=behavioral_detectors,
        ml_stage=ml_stage,
    )
    return run, DetectionContext(graph, registry, incidents, run, ml_status)
