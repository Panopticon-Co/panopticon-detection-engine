"""C++-generated canonical records through standalone fleet detection."""

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

from panopticon_detection.factory import build_detection_run
from panopticon_detection.ingestion.endpoint_adapter import EndpointIngestionAdapter
from panopticon_detection.ingestion.live_stream import LiveTelemetryStream
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.provenance.builder import EventGraphBuilder
from panopticon_detection.provenance.graph import ProvenanceGraph
from panopticon_detection.provenance.identity import ProcessRegistry, parse_timestamp


def records():
    return json.loads((Path(__file__).parent / "fixtures/endpoint-record-1.0.json").read_text())


def native_variant(record, *, ticks=None, boot=None):
    result = copy.deepcopy(record)
    ref = result["subject"]
    if ticks:
        ref["native_creation_ticks"] = ticks
    if boot:
        ref["boot_id"] = result["endpoint"]["boot_id"] = boot
    fields = [
        "native-process-instance-v1",
        result["endpoint"]["host_id"],
        ref["boot_id"],
        str(ref["observed_pid"]),
        ref["native_creation_ticks"],
    ]
    material = "".join(str(len(x.encode())) + ":" + x for x in fields)
    ref["entity_id"] = "proc_" + hashlib.sha256(material.encode()).hexdigest()
    result["data"]["process"]["entity_id"] = ref["entity_id"]
    result["data"]["process"]["start_time_ticks"] = ref["native_creation_ticks"]
    return result


def test_pid_reuse_at_same_wallclock_and_cross_boot_never_merge():
    original = records()[0]
    variants = [
        original,
        native_variant(original, ticks="133700000000000002"),
        native_variant(original, boot="boot_" + "b" * 64),
    ]
    registry = ProcessRegistry()
    actors = [registry.observe_start(EndpointIngestionAdapter.transform(x)) for x in variants]
    assert len({x.node_id for x in actors}) == 3
    assert len(registry) == 3
    assert registry.resolve("host-1", 1234, parse_timestamp(original["observed_at"])) is None
    for raw, actor in zip(variants, actors):
        assert registry.resolve_event(EndpointIngestionAdapter.transform(raw)) is actor


def test_source_activity_can_arrive_before_start_without_native_alias():
    native, start, network, unresolved = records()[:4]
    network["data"]["network"]["destination_ip"] = "192.0.2.1"
    network["data"]["network"]["destination_port"] = 443
    registry = ProcessRegistry()
    graph = ProvenanceGraph()
    builder = EventGraphBuilder(graph, registry)
    activity = EndpointIngestionAdapter.transform(network)
    edge = builder.apply(activity)
    assert edge is not None
    actor = registry.resolve_event(activity)
    assert actor.inferred
    builder.apply(EndpointIngestionAdapter.transform(start))
    assert registry.resolve_event(activity) is actor
    assert not actor.inferred
    assert actor.node_id == start["subject"]["entity_id"]
    builder.apply(EndpointIngestionAdapter.transform(native))
    assert len(registry) == 2
    assert registry.resolve_event(EndpointIngestionAdapter.transform(unresolved)) is None
    assert builder.apply(EndpointIngestionAdapter.transform(unresolved)) is None
    assert activity["process"]["start_time_ticks"] is None


def test_exact_tokens_and_raw_provenance_survive_normalization():
    raw = records()[0]
    out = EndpointIngestionAdapter.transform(raw)
    assert out["process"]["start_time_ticks"] == 133700000000000001
    assert out["provenance"] == raw["provenance"]
    assert out["_raw_endpoint_record"] == raw
    assert out["event_id"] == raw["record_id"]
    out["endpoint_data"]["process"]["pid"] = 999
    assert raw["data"]["process"]["pid"] == 1234


def test_unresolved_parent_never_inherits_live_pid_ancestry():
    raw = records()[0]
    registry = ProcessRegistry()
    registry.observe_start(EndpointIngestionAdapter.transform(raw))
    child = native_variant(raw, ticks="133700000000000002")
    child["data"]["process"]["parent"].update(pid=1234, entity_id=raw["subject"]["entity_id"])
    actor = registry.observe_start(EndpointIngestionAdapter.transform(child))
    assert actor.parent_node_id is None
    assert registry.ancestors(actor.node_id) == []


def test_bad_subject_or_payload_cannot_enter_identity_graph():
    raw = records()[0]
    raw["subject"]["entity_id"] = "proc_" + "0" * 64
    with pytest.raises(ValueError, match="digest"):
        EndpointIngestionAdapter.transform(raw)
    raw = records()[0]
    raw["data"]["process"]["start_time_ticks"] = 133700000000000001
    with pytest.raises(ValueError, match="contradicts"):
        EndpointIngestionAdapter.transform(raw)


def test_full_record_kinds_reach_file_and_stdout_streams(tmp_path):
    path = tmp_path / "records.ndjson"
    values = records()
    path.write_text("".join(json.dumps(x) + "\n" for x in values))
    stream = list(LiveTelemetryStream.stream_from_file(path))
    assert len(stream) == 6
    assert stream[4]["event_type"] == "endpoint_health_endpoint_health"
    assert stream[5]["record_kind"] == "state"
    for raw, normalized in zip(values, stream):
        assert OfficerIngestionAdapter.parse_line(json.dumps(raw)) == normalized


def test_identity_pruning_and_utc_are_independent_of_machine_timezone():
    assert parse_timestamp("2026-10-06T12:00:00+05:30") == datetime(2026, 10, 6, 6, 30)
    registry = ProcessRegistry()
    registry.observe_start(EndpointIngestionAdapter.transform(records()[0]))
    assert registry.prune(datetime(2030, 1, 1)) == 1
    assert len(registry) == 0


def test_alert_replay_and_agent_scope_preserve_full_trigger_context():
    rules = Path(__file__).resolve().parents[1] / "rules"
    raw = records()[0]
    raw["data"]["process"].update(name="whoami.exe", command_line="whoami /priv")

    def alert_ids(record):
        run, _context = build_detection_run(rules)
        return run, [x for x in run.process_event(EndpointIngestionAdapter.transform(record))
                     if x.rule_id == "DET-PROC-008"]

    run, alerts = alert_ids(raw)
    assert len(alerts) == 1
    alert = alerts[0]
    assert len(alert.alert_id) == 68
    assert alert.endpoint_context["subject"] == raw["subject"]
    assert alert.endpoint_context["provenance"] == raw["provenance"]
    # Replay in the same run is suppressed by the engine's dedup window...
    replay = run.process_event(EndpointIngestionAdapter.transform(raw))
    assert [x for x in replay if x.rule_id == "DET-PROC-008"] == []
    assert run.suppressed_duplicates >= 1
    # ...and a replay in a fresh run reproduces the same agent-scoped identity.
    assert [x.alert_id for x in alert_ids(raw)[1]] == [alert.alert_id]
    other = copy.deepcopy(raw)
    other["endpoint"]["agent_id"] = "another-agent"
    assert [x.alert_id for x in alert_ids(other)[1]] != [alert.alert_id]

# Shared producer fixtures (panopticon-contracts, generated by Officer's real
# decoders/factory from synthetic inputs). Sibling checkout layout; skipped if absent.
FAMILY_FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "panopticon-contracts/fixtures/endpoint-record/1.0/families"
)
needs_families = pytest.mark.skipif(
    not FAMILY_FIXTURES.is_dir(), reason="panopticon-contracts family fixtures unavailable"
)


def family(name):
    return json.loads((FAMILY_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["records"]


@needs_families
def test_every_officer_family_record_is_consumed_by_the_canonical_adapter():
    run, _context = build_detection_run(Path(__file__).resolve().parents[1] / "rules")
    for path in sorted(FAMILY_FIXTURES.glob("*.json")):
        for record in json.loads(path.read_text(encoding="utf-8"))["records"]:
            event = EndpointIngestionAdapter.transform(record)
            run.process_event(event)
            assert event["identity_model"] == "endpoint_record_v1"
            assert event["process_reference"] == record["subject"]


@needs_families
def test_canonical_extended_families_reach_existing_rules_with_exact_values():
    run, _context = build_detection_run(Path(__file__).resolve().parents[1] / "rules")
    access = family("process_access")[0]
    event = EndpointIngestionAdapter.transform(access)
    # Canonical decimal "2097151" must become 0x1fffff, never be re-read as hex.
    assert event["process_access"]["access_mask"] == int(
        access["data"]["process_access"]["granted_access"]
    )
    assert event["target_reference"] == access["data"]["process_access"]["target"]["identity"]
    assert {"DET-CRED-010", "DET-CRED-011"} <= {a.rule_id for a in run.process_event(event)}
    thread = EndpointIngestionAdapter.transform(family("remote_thread")[0])
    assert thread["event_type"] == "remote_thread"
    assert int(thread["remote_thread"]["start_address"], 16) == int(
        family("remote_thread")[0]["data"]["remote_thread"]["start_address"]
    )
    assert "DET-INJ-011" in {a.rule_id for a in run.process_event(thread)}
    dns = EndpointIngestionAdapter.transform(family("dns")[0])
    assert dns["event_type"] == "dns_query" and dns["dns"]["answers"]


@needs_families
def test_canonical_stop_closes_the_same_exact_instance():
    run, _context = build_detection_run(Path(__file__).resolve().parents[1] / "rules")
    start, stop = family("process")[0], family("process_stop")[0]
    assert start["subject"]["entity_id"] == stop["subject"]["entity_id"]
    run.process_event(EndpointIngestionAdapter.transform(start))
    stopped = EndpointIngestionAdapter.transform(stop)
    assert stopped["event_type"] == "process_terminate"
    run.process_event(stopped)
    instance = run.graph_builder.registry.get(stop["subject"]["entity_id"])
    assert instance.end_observed and instance.end_time > instance.start_time
    assert not instance.inferred
