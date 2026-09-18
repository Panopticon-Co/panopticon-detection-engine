"""Provenance layer: identity resolution, graph construction, campaign search.

Each test names the design failure it locks out. The old correlation layer
passed its own tests while being unable to do any of this against real agent
telemetry, so the cases here deliberately use the *mismatched entity_id* shape
that a live Panopticon agent actually emits.
"""

from datetime import datetime, timedelta

import pytest

from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.campaign import CampaignDetector
from panopticon_detection.provenance.graph import EdgeKind, NodeKind, ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry, parse_timestamp
from panopticon_detection.provenance.tagging import Tag

BASE = datetime(2026, 9, 14, 10, 0, 0)


def ts(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).isoformat()


def proc_create(pid, name, offset, *, ppid=None, entity_id=None, ticks=None, exe=None):
    """A process-create event as the officer adapter would hand it over."""
    return {
        "event_id": f"evt-create-{pid}-{offset}",
        "event_type": "process_create",
        "host_id": "HOST-01",
        "timestamp": ts(offset),
        "process": {
            "pid": pid,
            "name": name,
            "executable": exe or f"C:\\Windows\\System32\\{name}",
            "command_line": f"{name} --run",
            # Derived by the agent's process-entity formula.
            "entity_id": entity_id or f"proc_start_{pid}_{offset}",
            "start_time_ticks": ticks,
        },
        "parent": {"pid": ppid} if ppid else {},
    }


def net_connect(pid, offset, ip="203.0.113.10", port=443):
    """A network event. Its entity_id is derived by the agent's *context*
    formula, so it deliberately does NOT match the process-create one -- this is
    the exact shape that silently broke every ancestry lookup before."""
    return {
        "event_id": f"evt-net-{pid}-{offset}",
        "event_type": "network_connect",
        "host_id": "HOST-01",
        "timestamp": ts(offset),
        "process": {"pid": pid, "name": "child.exe", "entity_id": f"proc_ctx_{pid}"},
        "network": {
            "direction": "outbound",
            "protocol": "tcp",
            "destination_ip": ip,
            "destination_port": port,
        },
    }


def file_write(pid, offset, path):
    return {
        "event_id": f"evt-file-{pid}-{offset}",
        "event_type": "file_create",
        "host_id": "HOST-01",
        "timestamp": ts(offset),
        "process": {"pid": pid, "name": "writer.exe", "entity_id": f"proc_ctx_{pid}"},
        "file": {"operation": "create", "path": path},
    }


@pytest.fixture
def wired():
    graph = ProvenanceGraph()
    registry = ProcessRegistry()
    return graph, registry, EventGraphBuilder(graph, registry)


# ---------------------------------------------------------------- identity


def test_resolves_a_process_by_pid_and_time_not_by_entity_id(wired):
    """F1: the agent derives entity_id differently per telemetry family, so the
    join must be (host, pid, timestamp)."""
    _, registry, builder = wired
    builder.apply(proc_create(4242, "powershell.exe", 0))

    actor = registry.resolve_event(net_connect(4242, 30))

    assert actor is not None
    assert actor.pid == 4242
    assert actor.name == "powershell.exe"
    # The network event's own entity_id never matched, and must not be consulted.
    assert actor.entity_id == "proc_start_4242_0"


def test_pid_reuse_never_confuses_two_processes(wired):
    """The whole reason identity is an interval and not a key."""
    _, registry, builder = wired
    builder.apply(proc_create(1000, "first.exe", 0))
    builder.apply(proc_create(1000, "second.exe", 600))

    early = registry.resolve("HOST-01", 1000, parse_timestamp(ts(10)))
    late = registry.resolve("HOST-01", 1000, parse_timestamp(ts(900)))

    assert early.name == "first.exe"
    assert late.name == "second.exe"
    assert early.node_id != late.node_id
    # The first incarnation was closed implicitly when the second appeared --
    # no process_terminate event exists in the agent schema today.
    assert early.end_time == parse_timestamp(ts(600))


def test_an_event_before_any_known_process_resolves_to_nothing(wired):
    _, registry, builder = wired
    builder.apply(proc_create(500, "late.exe", 300))
    assert registry.resolve("HOST-01", 500, parse_timestamp(ts(10))) is None


def test_ancestry_resolves_from_a_network_event(wired):
    """F1, the headline case: before this, has_ancestor returned False for every
    non-process event because the guid lookup missed."""
    _, registry, builder = wired
    builder.apply(proc_create(100, "explorer.exe", 0))
    builder.apply(proc_create(200, "winword.exe", 1, ppid=100))
    builder.apply(proc_create(300, "powershell.exe", 2, ppid=200))

    actor = registry.resolve_event(net_connect(300, 5))
    names = [a.name for a in registry.ancestors(actor.node_id)]

    assert names == ["winword.exe", "explorer.exe"]
    assert registry.lineage(actor.node_id) == (
        "explorer.exe -> winword.exe -> powershell.exe"
    )


def test_prune_evicts_keys_not_just_contents(wired):
    """F9: the replaced engine kept one dict key per (host, pid) forever."""
    _, registry, builder = wired
    builder.apply(proc_create(700, "gone.exe", 0))
    assert len(registry) == 1

    registry.prune(before=BASE + timedelta(days=3))
    assert len(registry) == 0


# ------------------------------------------------------------------- graph


def test_every_telemetry_family_becomes_an_edge(wired):
    graph, _, builder = wired
    builder.apply(proc_create(100, "parent.exe", 0))
    builder.apply(proc_create(200, "child.exe", 1, ppid=100))

    net_edge = builder.apply(net_connect(200, 2))
    file_edge = builder.apply(file_write(200, 3, "C:\\Users\\a\\payload.dll"))

    assert net_edge.kind is EdgeKind.CONNECTED_TO
    assert file_edge.kind is EdgeKind.WROTE
    kinds = {e.kind for e in graph.edges.values()}
    assert EdgeKind.FORKED in kinds
    assert EdgeKind.EXECUTED in kinds
    assert {n.kind for n in graph.nodes.values()} >= {
        NodeKind.PROCESS,
        NodeKind.FILE,
        NodeKind.SOCKET,
    }


def test_an_event_with_no_resolvable_process_creates_no_edge(wired):
    """Fail closed rather than inventing an actor."""
    graph, _, builder = wired
    assert builder.apply(net_connect(9999, 5)) is None
    assert graph.edges == {}


def test_backward_walk_never_steps_forward_in_time(wired):
    """The pruning rule the replaced EnterpriseAttackGraph had no equivalent of."""
    graph, registry, builder = wired
    builder.apply(proc_create(100, "root.exe", 0))
    builder.apply(proc_create(200, "mid.exe", 10, ppid=100))
    early = builder.apply(file_write(200, 20, "C:\\tmp\\early.txt"))
    late = builder.apply(file_write(200, 900, "C:\\tmp\\later.txt"))

    actor = registry.resolve_event(net_connect(200, 30))
    walked = graph.backward(actor.node_id, parse_timestamp(ts(30)))
    walked_ids = {e.edge_id for e in walked.edges}

    assert early.edge_id in walked_ids
    assert late.edge_id not in walked_ids, "reached an event from the future"


def test_backward_walk_respects_the_horizon(wired):
    graph, registry, builder = wired
    builder.apply(proc_create(100, "root.exe", 0))
    builder.apply(proc_create(200, "mid.exe", 10, ppid=100))
    builder.apply(file_write(200, 20, "C:\\tmp\\a.txt"))

    actor = registry.resolve_event(net_connect(200, 10_000))
    walked = graph.backward(
        actor.node_id, parse_timestamp(ts(10_000)), horizon=timedelta(seconds=60)
    )
    assert len(walked.edges) == 0


# ---------------------------------------------------------------- campaign


def tag(rule_id, tactic, level=12, technique="T1059", confidence=0.9):
    return Tag(
        rule_id=rule_id,
        rule_name=f"rule {rule_id}",
        tactic=tactic,
        technique=technique,
        level=level,
        severity="high",
        confidence=confidence,
    )


def test_campaign_links_stages_across_different_processes(wired):
    """F3: the replaced engine bucketed on host:pid, so a chain spanning two
    PIDs -- which is every real intrusion -- could never correlate. Its own
    CORR-002 (recon then shadow-copy deletion) was structurally dead."""
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)

    builder.apply(proc_create(100, "explorer.exe", 0, ticks=111111))
    recon_edge = builder.apply(proc_create(200, "whoami.exe", 10, ppid=100))
    impact_edge = builder.apply(proc_create(300, "vssadmin.exe", 20, ppid=100))

    # Stage 1: discovery in one process.
    recon_edge.tags.append(tag("DET-PROC-008", "Discovery", level=8))
    assert detector.on_tagged_edge(recon_edge, recon_edge.tags[-1]) is None

    # Stage 2: impact in a *different* process. Anchors the search.
    anchor = tag("DET-PROC-006", "Impact", level=14, technique="T1490")
    impact_edge.tags.append(anchor)
    campaign = detector.on_tagged_edge(impact_edge, anchor)

    assert campaign is not None
    assert {t.rule_id for t in campaign.stages} == {"DET-PROC-008", "DET-PROC-006"}
    assert campaign.tactics == ["Discovery", "Impact"]
    assert campaign.root_process_name == "explorer.exe"


def test_a_non_terminal_tactic_does_not_anchor_a_search(wired):
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)
    builder.apply(proc_create(100, "a.exe", 0))
    edge = builder.apply(proc_create(200, "b.exe", 5, ppid=100))

    t = tag("DET-X", "Discovery", level=15)
    edge.tags.append(t)
    assert detector.on_tagged_edge(edge, t) is None


def test_a_campaign_is_reported_once(wired):
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)
    builder.apply(proc_create(100, "a.exe", 0))
    first = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    second = builder.apply(proc_create(300, "c.exe", 10, ppid=100))

    first.tags.append(tag("R1", "Discovery", level=8))
    anchor = tag("R2", "Impact", level=14)
    second.tags.append(anchor)

    assert detector.on_tagged_edge(second, anchor) is not None
    assert detector.on_tagged_edge(second, anchor) is None


def test_campaign_recommendation_carries_start_time_ticks(wired):
    """F5: previously every correlation- or network-triggered TERMINATE_PROCESS
    failed closed in translate_recommendation because start_time_ticks was only
    ever present on a process's own creation event."""
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)

    builder.apply(proc_create(100, "dropper.exe", 0, ticks=987654321))
    staged = builder.apply(proc_create(200, "loader.exe", 5, ppid=100))
    anchor_edge = builder.apply(proc_create(300, "beacon.exe", 9, ppid=100))

    staged.tags.append(tag("R1", "Execution", level=9))
    anchor = tag("R2", "Command and Control", level=14, technique="T1071")
    anchor_edge.tags.append(anchor)

    campaign = detector.on_tagged_edge(anchor_edge, anchor)
    recommendation = campaign.to_alert().active_response

    assert recommendation["action"] == "TERMINATE_PROCESS"
    assert recommendation["target_pid"] == 100
    assert recommendation["target_start_time_ticks"] == 987654321


def test_campaign_fails_closed_without_start_time_ticks(wired):
    """The token is never defaulted or derived -- absent means no command."""
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)

    builder.apply(proc_create(100, "root.exe", 0))  # no ticks
    staged = builder.apply(proc_create(200, "mid.exe", 5, ppid=100))
    anchor_edge = builder.apply(proc_create(300, "end.exe", 9, ppid=100))

    staged.tags.append(tag("R1", "Execution", level=9))
    anchor = tag("R2", "Exfiltration", level=14)
    anchor_edge.tags.append(anchor)

    campaign = detector.on_tagged_edge(anchor_edge, anchor)
    assert campaign.to_alert().active_response is None


def test_campaign_confidence_is_the_weakest_stage(wired):
    graph, registry, builder = wired
    detector = CampaignDetector(graph=graph, registry=registry)
    builder.apply(proc_create(100, "a.exe", 0))
    staged = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    anchor_edge = builder.apply(proc_create(300, "c.exe", 9, ppid=100))

    staged.tags.append(tag("R1", "Execution", level=9, confidence=0.61))
    anchor = tag("R2", "Impact", level=14, confidence=0.99)
    anchor_edge.tags.append(anchor)

    campaign = detector.on_tagged_edge(anchor_edge, anchor)
    assert campaign.to_alert().confidence == 0.61
