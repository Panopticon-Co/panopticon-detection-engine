"""The one supported way to construct a wired :class:`DetectionRun`.

Keeping the wiring here means the engine owns its own composition and
downstream consumers (the CLI, ``manager/detection/factory.py``) depend on one
function whose signature is part of the public contract.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.detection_run import DetectionRun
from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.evaluator.stateful import StatefulEvaluator
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.incident import IncidentTracker
from panopticon_detection.provenance.risk_scorer import EntityRiskScorer
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


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
    ) -> None:
        self.graph = graph
        self.registry = registry
        self.incidents = incidents
        self.run = run

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
            + run.prune(before)
        )
        return {
            "edges_removed": self.graph.prune(before),
            "processes_removed": self.registry.prune(before),
            "incidents_closed": self.incidents.prune(before),
            "detector_state_removed": detector_state,
        }

    def stats(self) -> Dict[str, int]:
        return {
            **self.graph.stats(),
            "processes": len(self.registry),
            "open_incidents": len(self.incidents.incidents),
            **self.run.stateful.state_size(),
        }


def build_detection_run(
    rules_dir: Path,
    *,
    emit: Optional[Callable[[Any], None]] = None,
    retention: timedelta = timedelta(hours=24),
    campaign_horizon: timedelta = timedelta(hours=6),
    behavioral_detectors: Sequence[Any] = (),
) -> Tuple[DetectionRun, DetectionContext]:
    """Load rules and wire a detection run over a fresh provenance graph.

    ``emit`` is called once per alert produced. ``retention`` bounds how long a
    process incarnation stays resolvable; ``campaign_horizon`` bounds how far
    back an incident's causal walk may reach. ``behavioral_detectors`` (e.g. a
    :class:`~panopticon_detection.behavioral.rarity.RarityDetector`) are
    optional; with none, the run behaves exactly as it did before they existed.
    """
    rules = RuleLoader().load_directory(Path(rules_dir))

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
    )
    return run, DetectionContext(graph, registry, incidents, run)
