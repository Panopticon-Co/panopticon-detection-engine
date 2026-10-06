"""Provenance layer: identity resolution, graph construction, incidents.

Each test names the design failure it locks out. The old correlation layer
passed its own tests while being unable to do any of this against real agent
telemetry, so the cases here deliberately use the *mismatched entity_id* shape
that a live Panopticon agent actually emits.
"""

from datetime import datetime, timedelta

import pytest

from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import EdgeKind, NodeKind, ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry, parse_timestamp
from panopticon_detection.provenance.incident import IncidentTracker
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


def test_an_unseen_process_is_inferred_from_its_first_event(wired):
    """An agent starting on a running machine never sees existing processes
    created. Their telemetry still needs an actor, flagged as inferred."""
    graph, registry, builder = wired
    edge = builder.apply(net_connect(9999, 5))

    assert edge is not None
    actor = registry.get(edge.src)
    assert actor.pid == 9999 and actor.inferred is True
    assert actor.start_time_ticks is None  # never invented
    # The next event from the same process resolves to the same node.
    assert builder.apply(net_connect(9999, 9)).src == edge.src


def test_an_inferred_process_links_to_its_parent(wired):
    graph, registry, builder = wired
    builder.apply(proc_create(100, "winword.exe", 0))
    event = net_connect(4242, 30)
    event["parent"] = {"pid": 100, "name": "winword.exe"}
    edge = builder.apply(event)

    actor = registry.get(edge.src)
    assert [a.name for a in registry.ancestors(actor.node_id)] == ["winword.exe"]
    forked = [e for e in graph.edges.values() if e.kind is EdgeKind.FORKED and e.dst == actor.node_id]
    assert forked and forked[0].attrs.get("inferred") is True


def test_a_loaded_module_is_the_same_node_as_the_file_written(wired):
    graph, _, builder = wired
    builder.apply(proc_create(100, "dropper.exe", 0))
    builder.apply(proc_create(200, "host.exe", 1))
    wrote = builder.apply(file_write(100, 2, "C:\\Users\\a\\evil.dll"))
    loaded = builder.apply(
        {
            "event_id": "evt-load",
            "event_type": "image_load",
            "host_id": "HOST-01",
            "timestamp": ts(3),
            "process": {"pid": 200, "name": "host.exe"},
            "image": {"path": "C:\\Users\\a\\evil.dll", "is_signed": False},
        }
    )
    assert loaded.dst == wrote.dst


# --------------------------------------------------------- directed walk


def test_the_walk_follows_information_flow_backwards(wired):
    """A wrote F, B executed F: walking back from B reaches A through F."""
    graph, registry, builder = wired
    builder.apply(proc_create(100, "chrome.exe", 0))
    builder.apply(file_write(100, 10, "C:\\Users\\a\\Downloads\\invoice.exe"))
    builder.apply(proc_create(200, "invoice.exe", 20, exe="C:\\Users\\a\\Downloads\\invoice.exe"))

    b = registry.resolve("HOST-01", 200, parse_timestamp(ts(25)))
    walked = graph.backward(b.node_id, parse_timestamp(ts(25)))
    names = {n.label for n in walked.nodes.values() if n.kind is NodeKind.PROCESS}
    assert "chrome.exe" in names


def test_the_walk_never_descends_into_a_parents_other_children(wired):
    """The dependency-explosion bug: an undirected walk climbed to the shared
    parent and came back down into an unrelated sibling."""
    graph, registry, builder = wired
    builder.apply(proc_create(100, "shell.exe", 0))
    builder.apply(proc_create(200, "sibling.exe", 5, ppid=100))
    builder.apply(proc_create(300, "target.exe", 10, ppid=100))

    target = registry.resolve("HOST-01", 300, parse_timestamp(ts(15)))
    walked = graph.backward(target.node_id, parse_timestamp(ts(15)))
    names = {n.label for n in walked.nodes.values()}
    assert "shell.exe" in names
    assert "sibling.exe" not in names


def test_the_walk_never_steps_forward_in_time(wired):
    graph, registry, builder = wired
    builder.apply(proc_create(100, "a.exe", 0))
    builder.apply(file_write(100, 900, "C:\\Users\\a\\later.exe"))
    builder.apply(proc_create(200, "b.exe", 20, exe="C:\\Users\\a\\later.exe"))

    b = registry.resolve("HOST-01", 200, parse_timestamp(ts(30)))
    walked = graph.backward(b.node_id, parse_timestamp(ts(30)))
    assert "a.exe" not in {n.label for n in walked.nodes.values()}, "reached a write from the future"


def test_the_walk_stops_at_a_boundary_process(wired):
    graph, registry, builder = wired
    builder.apply(proc_create(10, "services.exe", 0))
    builder.apply(proc_create(100, "explorer.exe", 1, ppid=10))
    builder.apply(proc_create(200, "app.exe", 5, ppid=100))

    app = registry.resolve("HOST-01", 200, parse_timestamp(ts(6)))
    walked = graph.backward(
        app.node_id, parse_timestamp(ts(6)), boundary=lambda n: n.label == "explorer.exe"
    )
    labels = {n.label for n in walked.nodes.values()}
    assert "explorer.exe" in labels and "services.exe" not in labels
    assert any(graph.nodes[n].label == "explorer.exe" for n in walked.boundary_nodes)


def test_the_walk_respects_the_horizon(wired):
    graph, registry, builder = wired
    builder.apply(proc_create(100, "root.exe", 0))
    builder.apply(proc_create(200, "mid.exe", 10, ppid=100))

    mid = registry.resolve("HOST-01", 200, parse_timestamp(ts(10_000)))
    walked = graph.backward(
        mid.node_id, parse_timestamp(ts(10_000)), horizon=timedelta(seconds=60)
    )
    assert len(walked.edges) == 0


# -------------------------------------------------------------- incidents


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


def fire(tracker, edge, t):
    edge.tags.append(t)
    return tracker.on_tag(edge, t)


@pytest.fixture
def tracker(wired):
    graph, registry, _ = wired
    return IncidentTracker(graph=graph, registry=registry)


def test_siblings_under_a_hub_are_not_merged(wired, tracker):
    """Recon under explorer and, later, an unrelated impact under explorer are
    two separate things; the replaced walk merged them and blamed explorer."""
    _, _, builder = wired
    builder.apply(proc_create(100, "explorer.exe", 0, ticks=111))
    recon = builder.apply(proc_create(200, "whoami.exe", 10, ppid=100))
    impact = builder.apply(proc_create(300, "vssadmin.exe", 20, ppid=100))

    assert fire(tracker, recon, tag("DET-PROC-008", "Discovery", level=10)) is None
    assert fire(tracker, impact, tag("DET-PROC-006", "Impact", level=14)) is None
    assert tracker.incidents == {}


def test_a_parent_child_chain_is_one_incident_rooted_at_its_entry_point(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "explorer.exe", 0))
    builder.apply(proc_create(200, "winword.exe", 5, ppid=100, ticks=222))
    ps = builder.apply(proc_create(300, "powershell.exe", 10, ppid=200))
    dump = builder.apply(proc_create(400, "rundll32.exe", 20, ppid=300))

    assert fire(tracker, ps, tag("DET-PROC-001", "Execution")) is None
    alert = fire(tracker, dump, tag("DET-PROC-005", "Credential Access", level=14, technique="T1003.001"))

    assert alert is not None
    assert alert.rule_id == "PROV-CAMPAIGN"
    assert alert.evidence["root_cause_process"] == "winword.exe"
    assert alert.evidence["process_lineage"] == "explorer.exe -> winword.exe"
    assert alert.evidence["tactics_covered"] == ["Execution", "Credential Access"]
    assert alert.mitre_technique == "T1003.001"
    assert alert.incident_id and alert.alert_id == f"{alert.incident_id}-R1"
    assert alert.active_response["target_pid"] == 200
    assert alert.active_response["target_start_time_ticks"] == 222
    assert alert.evidence["score_breakdown"]["context"]["factors"]["initial_access_vector"] > 0


def test_a_dropped_payload_links_to_its_dropper_through_the_file(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "explorer.exe", 0))
    builder.apply(proc_create(150, "chrome.exe", 1, ppid=100))
    builder.apply(file_write(150, 10, "C:\\Users\\a\\Downloads\\invoice.exe"))
    run = builder.apply(
        proc_create(200, "invoice.exe", 20, ppid=100, exe="C:\\Users\\a\\Downloads\\invoice.exe", ticks=9)
    )
    dump = builder.apply(proc_create(300, "rundll32.exe", 30, ppid=200))

    fire(tracker, run, tag("DET-EXEC-001", "Execution", level=11))
    alert = fire(tracker, dump, tag("DET-PROC-005", "Credential Access", level=14))

    assert alert is not None
    # The user launched the payload from explorer, so it is its own entry point;
    # the browser that delivered it is the provenance origin.
    assert alert.evidence["root_cause_process"] == "invoice.exe"
    assert alert.evidence["provenance_origin"] == "chrome.exe"
    assert any("chrome.exe" in line and "wrote" in line for line in alert.evidence["causal_path"])


def test_a_later_stage_attaches_and_a_new_tactic_emits_a_revision(wired, tracker):
    _, registry, builder = wired
    builder.apply(proc_create(200, "winword.exe", 0))
    ps = builder.apply(proc_create(300, "powershell.exe", 10, ppid=200))
    payload = builder.apply(
        proc_create(400, "payload.exe", 20, ppid=300, exe="C:\\Users\\a\\AppData\\Local\\Temp\\p.exe")
    )
    fire(tracker, ps, tag("R-EXEC", "Execution"))
    opened = fire(tracker, payload, tag("R-C2", "Command and Control", level=13))
    assert opened is not None

    run_key = builder.apply(
        {
            "event_id": "evt-reg",
            "event_type": "registry_write",
            "host_id": "HOST-01",
            "timestamp": ts(40),
            "process": {"pid": 400, "name": "payload.exe"},
            "registry": {"key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        }
    )
    update = fire(tracker, run_key, tag("R-PERS", "Persistence", level=10))

    assert update is not None
    assert update.incident_id == opened.incident_id
    assert update.alert_id.endswith("-R2")
    assert "Persistence" in update.evidence["tactics_covered"]
    assert len(tracker.incidents) == 1


def test_a_repeat_without_a_new_tactic_is_recorded_quietly(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(200, "winword.exe", 0))
    ps = builder.apply(proc_create(300, "powershell.exe", 10, ppid=200))
    c2 = builder.apply(proc_create(400, "beacon.exe", 20, ppid=300))
    fire(tracker, ps, tag("R-EXEC", "Execution"))
    assert fire(tracker, c2, tag("R-C2", "Command and Control", level=13)) is not None

    more = builder.apply(proc_create(500, "cmd.exe", 30, ppid=300))
    assert fire(tracker, more, tag("R-EXEC-2", "Execution")) is None
    incident = next(iter(tracker.incidents.values()))
    assert incident.quiet_updates == 1
    assert {s.rule_id for s in incident.stages} >= {"R-EXEC", "R-C2", "R-EXEC-2"}


def test_a_non_terminal_tactic_does_not_open_an_incident(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "a.exe", 0))
    edge = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    other = builder.apply(proc_create(300, "c.exe", 6, ppid=200))
    fire(tracker, edge, tag("R1", "Execution"))
    assert fire(tracker, other, tag("R2", "Discovery", level=15)) is None


def test_a_single_stage_never_opens_an_incident(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "a.exe", 0))
    edge = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    assert fire(tracker, edge, tag("R1", "Impact", level=15)) is None


def test_the_recommendation_fails_closed_without_start_time_ticks(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "root.exe", 0))  # no ticks
    mid = builder.apply(proc_create(200, "mid.exe", 5, ppid=100))
    end = builder.apply(proc_create(300, "end.exe", 9, ppid=200))
    fire(tracker, mid, tag("R1", "Execution"))
    alert = fire(tracker, end, tag("R2", "Exfiltration", level=14))
    assert alert is not None and alert.active_response is None


def test_incident_confidence_is_its_weakest_stage(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "a.exe", 0))
    mid = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    end = builder.apply(proc_create(300, "c.exe", 9, ppid=200))
    fire(tracker, mid, tag("R1", "Execution", confidence=0.61))
    alert = fire(tracker, end, tag("R2", "Impact", level=14, confidence=0.99))
    assert alert.confidence == 0.61


def test_prune_closes_idle_incidents(wired, tracker):
    _, _, builder = wired
    builder.apply(proc_create(100, "a.exe", 0))
    mid = builder.apply(proc_create(200, "b.exe", 5, ppid=100))
    end = builder.apply(proc_create(300, "c.exe", 9, ppid=200))
    fire(tracker, mid, tag("R1", "Execution"))
    fire(tracker, end, tag("R2", "Impact", level=14))
    assert tracker.prune(BASE + timedelta(days=1)) == 1
    assert tracker.incidents == {} and tracker._by_node == {}
