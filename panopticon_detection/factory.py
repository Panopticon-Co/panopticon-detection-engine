"""The one supported way to construct a wired :class:`DetectionRun`.

Previously ``DetectionRun`` took eleven pre-built engines and had no factory, so
every consumer -- the CLI here, and ``manager/detection/factory.py`` in
panopticon-manager -- hand-assembled the same object graph. The manager's own
ADR 001 called that out: it duplicated wiring it did not own, and a constructor
change upstream broke it silently.

Keeping the wiring here means the engine owns its own composition and downstream
consumers depend on one function whose signature is part of the public contract.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from panopticon_detection.behavioral.beacon import C2BeaconDetector
from panopticon_detection.behavioral.port_scan import PortScanDetector
from panopticon_detection.behavioral.ransomware import RansomwareShield
from panopticon_detection.detection_run import DetectionRun
from panopticon_detection.evaluator.engine import RuleEvaluator
from panopticon_detection.evaluator.threshold import ThresholdEngine
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.campaign import CampaignDetector
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry
from panopticon_detection.provenance.risk_scorer import EntityRiskScorer
from panopticon_detection.rules.loader import RuleLoader
from panopticon_detection.threat_intel.ioc_lookup import ThreatIntelEngine


class DetectionContext:
    """The stateful objects behind a run, exposed for inspection and upkeep.

    A caller needs these for two things the run itself does not do: periodic
    :meth:`prune` so a long-lived worker stays bounded, and reading the graph to
    render an incident's provenance.
    """

    def __init__(
        self,
        graph: ProvenanceGraph,
        registry: ProcessRegistry,
        campaign_detector: CampaignDetector,
    ) -> None:
        self.graph = graph
        self.registry = registry
        self.campaign_detector = campaign_detector

    def prune(self, before: datetime) -> Dict[str, int]:
        """Drop graph edges and process incarnations older than ``before``."""
        return {
            "edges_removed": self.graph.prune(before),
            "processes_removed": self.registry.prune(before),
        }

    def stats(self) -> Dict[str, int]:
        return {**self.graph.stats(), "processes": len(self.registry)}


def build_detection_run(
    rules_dir: Path,
    *,
    emit: Optional[Callable[[Any], None]] = None,
    retention: timedelta = timedelta(hours=24),
    campaign_horizon: timedelta = timedelta(hours=6),
) -> Tuple[DetectionRun, DetectionContext]:
    """Load rules and wire a detection run over a fresh provenance graph.

    ``emit`` is called once per alert produced. ``retention`` bounds how long a
    process incarnation stays resolvable; ``campaign_horizon`` bounds how far
    back a campaign traversal may reach.
    """
    rules = RuleLoader().load_directory(Path(rules_dir))

    graph = ProvenanceGraph()
    registry = ProcessRegistry(max_lifetime=retention)
    builder = EventGraphBuilder(graph, registry)
    campaign_detector = CampaignDetector(
        graph=graph, registry=registry, horizon=campaign_horizon
    )

    run = DetectionRun(
        graph_builder=builder,
        evaluator=RuleEvaluator(
            rules, registry=registry, threat_intel=ThreatIntelEngine()
        ),
        threshold_engine=ThresholdEngine(),
        campaign_detector=campaign_detector,
        risk_scorer=EntityRiskScorer(breach_threshold=75),
        beacon_detector=C2BeaconDetector(min_samples=4, max_cv_threshold=0.22),
        port_scan_detector=PortScanDetector(
            horizontal_ip_threshold=5, vertical_port_threshold=6
        ),
        ransomware_shield=RansomwareShield(burst_threshold=4, burst_window_seconds=5.0),
        emit=emit,
    )
    return run, DetectionContext(graph, registry, campaign_detector)
