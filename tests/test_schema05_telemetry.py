"""Schema 0.5 telemetry through the engine: process stop, DNS, process access,
remote threads and PowerShell script blocks.

Each family is followed the whole way: agent-schema event -> normalizer ->
graph edge -> derived fields -> rules / features / behavioral signal -> the
existing incident engine. Events are built with the dataset canonical builder,
so they carry the same ids and shapes the agent emits.
"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from panopticon_detection import enrichment
from panopticon_detection.behavioral.rarity import RarityBaseline, RarityDetector
from panopticon_detection.datasets import canonical as C
from panopticon_detection.enrichment import MatchContext
from panopticon_detection.factory import build_detection_run
from panopticon_detection.features import FeatureExtractor
from panopticon_detection.ingestion import telemetry
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter
from panopticon_detection.provenance.graph import EdgeKind, NodeKind

ROOT = Path(__file__).resolve().parent.parent
HOST = {"id": "H", "hostname": "H", "os": {"name": "Windows 11", "build": "26100"}}
AGENT = {"id": "agent-test", "version": "0.5.0"}
SYSMON = {"kind": "sysmon", "provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
T0 = datetime(2026, 9, 1, 12, 0, 0)


def _event(category, type_, pid, second, *, block=None, image=None, cmd=None, ppid=None, parent_name=None,
           source=SYSMON):
    when = T0 + timedelta(seconds=second)
    if category == "process" and type_ == "start":
        process = {
            "entity_id": C.process_entity_id("H", pid, when),
            "pid": pid,
            "name": C.basename(image),
            "executable": image,
            "command_line": cmd or C.basename(image),
            "parent": {"entity_id": None, "pid": ppid, "name": parent_name},
        }
    else:
        process = {"entity_id": C.context_entity_id("H", pid, None), "pid": pid,
                   "name": C.basename(image), "executable": image}
    raw = C.build_event(
        category=category, type_=type_, event_key=(category, type_, pid, second), when=when,
        source=source, agent=AGENT, host=HOST, user={"name": "bob", "domain": "LAB", "sid": None},
        process=process, block=block,
    )
    return OfficerIngestionAdapter.transform_officer_event(raw)


def _target(pid, image):
    return {"entity_id": C.context_entity_id("H", pid, None), "pid": pid, "executable": image, "user": None}


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"


def _access(pid, image, second, granted="0x1410", trace=r"C:\Windows\SYSTEM32\ntdll.dll+9c584", target=(700, LSASS)):
    return _event("process_access", "access", pid, second, image=image, block={
        "target": _target(*target), "granted_access": granted, "call_trace": trace})


def _thread(pid, image, second, module=None, function=None, target=(900, NOTEPAD)):
    return _event("remote_thread", "create", pid, second, image=image, block={
        "target": _target(*target), "new_thread_id": 77, "start_address": "0x00007FFB9285E540",
        "start_module": module, "start_function": function})


def _script(pid, second, text):
    return _event("script_block", "execute", pid, second, image=PS, source={
        "kind": "windows_event_log", "provider": "Microsoft-Windows-PowerShell",
        "channel": "Microsoft-Windows-PowerShell/Operational"},
        block={"script_block_id": f"sb-{second}", "message_number": 1, "message_total": 1, "path": None,
               **C.truncate_script_text(text)})


def _dns(pid, second, name, status=0, results="type:  5 cdn.example;::ffff:93.184.216.34;"):
    return _event("dns", "query", pid, second, image=PS, block={
        "query_name": name, "query_status": status, "query_results": results})


# ------------------------------------------------------------- normalizer


def test_each_family_has_an_explicit_engine_event_type():
    assert _dns(1, 1, "a.example")["event_type"] == "dns_query"
    assert _access(1, RUNDLL, 1)["event_type"] == "process_access"
    assert _thread(1, PS, 1)["event_type"] == "remote_thread"
    assert _script(1, 1, "Get-Date")["event_type"] == "script_block"
    assert _event("process", "stop", 1, 1, image=PS)["event_type"] == "process_terminate"


def test_dns_answers_are_parsed_without_losing_the_raw_string():
    event = _dns(1, 1, "Update.Example.")
    assert event["dns"]["query_name"] == "update.example"
    assert event["dns"]["answers"] == ["93.184.216.34"]
    assert event["dns"]["query_results"].startswith("type:  5")
    assert _dns(1, 2, "x.example", results=None)["dns"]["answers"] == []


def test_cross_process_target_and_access_mask():
    event = _access(5, RUNDLL, 1, granted="0x1fffff")
    assert event["process"]["pid"] == 5  # the source is the process context
    assert event["target"] == {
        "entity_id": C.context_entity_id("H", 700, None), "pid": 700,
        "executable": LSASS, "name": "lsass.exe", "user": None,
    }
    assert event["process_access"]["access_mask"] == 0x1FFFFF


def test_malformed_and_missing_family_fields_do_not_raise():
    bad_mask = _access(5, RUNDLL, 1, granted="0xZZ")
    assert bad_mask["process_access"]["access_mask"] is None
    empty = telemetry.normalize({
        "schema_version": "0.5", "event": {"category": "process_access", "type": "access", "timestamp": "t"},
        "process": {"pid": 1}, "source": {}, "host": {"id": "H"},
    })
    assert empty["target"]["pid"] is None and empty["process_access"]["call_trace"] is None
    assert telemetry.normalize({
        "schema_version": "0.5", "event": {"category": "script_block", "type": "execute"},
        "process": {"pid": 1}, "source": {},
    })["script_block"]["text"] == ""


def test_schema_05_is_accepted_and_the_field_registry_knows_the_families():
    assert "0.5" in OfficerIngestionAdapter.SUPPORTED_SCHEMA_VERSIONS
    assert "dns.query_name" in telemetry.producible_fields("dns_query")
    assert "target.name" in telemetry.producible_fields("remote_thread")
    assert "process_access.call_trace" in telemetry.producible_fields("process_access")
    assert "script_block.text" in telemetry.producible_fields("script_block")
    assert "target.name" not in telemetry.producible_fields("network_connect")


# ------------------------------------------------- identity, graph, features


def _run(*events, detectors=()):
    run, context = build_detection_run(ROOT / "rules", behavioral_detectors=detectors)
    alerts = []
    for event in events:
        enrichment.reset(event)
        alerts += run.process_event(event)
    return run, context, alerts


def test_process_stop_closes_the_incarnation_and_gives_a_lifetime():
    run, context, _ = _run(
        _event("process", "start", 10, 0, image=PS, ppid=1),
        _event("process", "stop", 10, 42, image=PS),
    )
    (process,) = [p for p in context.registry if p.name == "powershell.exe"]
    assert process.end_observed and process.end_time == T0 + timedelta(seconds=42)
    features = run.feature_extractor.extract(process)
    assert features.lifetime_seconds == 42.0
    # As of a moment before the stop, the lifetime is not yet known.
    assert run.feature_extractor.extract(process, T0 + timedelta(seconds=10)).lifetime_seconds is None


def test_a_stop_for_an_unseen_process_is_ignored():
    _, context, _ = _run(_event("process", "stop", 55, 3, image=PS))
    assert len(context.registry) == 0


def test_an_unseen_target_is_inferred_and_flagged():
    _, context, _ = _run(_event("process", "start", 5, 0, image=RUNDLL, ppid=1), _access(5, RUNDLL, 1))
    lsass = next(p for p in context.registry if p.name == "lsass.exe")
    assert lsass.inferred and lsass.pid == 700 and lsass.executable == LSASS


def test_injection_is_causal_but_access_and_dns_are_not():
    loader_image = r"C:\Users\b\Desktop\loader.exe"
    _, context, _ = _run(
        _event("process", "start", 20, 0, image=loader_image, ppid=1),
        _event("process", "start", 900, 1, image=NOTEPAD, ppid=1),
        _thread(20, loader_image, 2),
        _event("process", "start", 950, 3, image=r"C:\Windows\System32\PING.EXE", ppid=900),
        _access(20, loader_image, 4),
        _dns(20, 5, "c2.example"),
    )
    reg = context.registry
    loader = next(p for p in reg if p.name == "loader.exe")
    ping = next(p for p in reg if p.name == "ping.exe")
    lsass = next(p for p in reg if p.name == "lsass.exe")
    later = T0 + timedelta(seconds=10)
    # What the injected notepad went on to do has the injector upstream of it.
    assert loader.node_id in context.graph.backward(ping.node_id, later).nodes
    # Opening lsass is not causation in either direction.
    assert lsass.node_id not in context.graph.backward(loader.node_id, later).nodes
    assert loader.node_id not in context.graph.backward(lsass.node_id, later).nodes
    kinds = {e.kind for e in context.graph.edges.values()}
    assert {EdgeKind.INJECTED, EdgeKind.ACCESSED, EdgeKind.RESOLVED} <= kinds
    assert any(n.kind == NodeKind.DOMAIN and n.label == "c2.example" for n in context.graph.nodes.values())


def test_v2_features_count_the_new_behaviour():
    text = "$a='Amsi'+'Utils';[Ref].Assembly.GetType('System.Management.Automation.'+$a)"
    run, context, _ = _run(
        _event("process", "start", 30, 0, image=PS, ppid=1),
        _script(30, 1, text),
        _script(30, 2, "Get-Date"),
        _dns(30, 3, "a.example"),
        _dns(30, 4, "a.example"),
        _dns(30, 5, "nx.example", status=9003, results=None),
        _access(30, PS, 6),
        _access(30, PS, 7, target=(800, r"C:\Windows\explorer.exe")),
        _thread(30, PS, 8),
    )
    ps = next(p for p in context.registry if p.name == "powershell.exe")
    notepad = next(p for p in context.registry if p.name == "notepad.exe")
    f = run.feature_extractor.extract(ps)
    assert (f.script_block_count, f.obfuscated_script_block_count) == (2, 1)
    assert f.script_block_bytes == len(text) + len("Get-Date")
    assert (f.dns_query_count, f.distinct_domain_count, f.failed_dns_query_count) == (3, 2, 1)
    assert (f.process_access_count, f.lsass_access_count) == (2, 1)
    assert f.access_targets == ("explorer.exe", "lsass.exe")
    assert (f.remote_thread_count, f.remote_thread_targets) == (1, ("notepad.exe",))
    assert run.feature_extractor.extract(notepad).injected_thread_count == 1


# ---------------------------------------------------------- derived fields


@pytest.mark.parametrize(
    "granted,read,write", [("0x1410", True, False), ("0x1000", False, False), ("0x1fffff", True, True)]
)
def test_access_rights_come_from_the_mask(granted, read, write):
    event = _access(5, RUNDLL, 1, granted=granted)
    ctx = MatchContext()
    assert enrichment.derive(event, "process_access.can_read_memory", ctx) is read
    assert enrichment.derive(event, "process_access.can_write_memory", ctx) is write


def test_minidump_call_trace_and_script_deobfuscation():
    ctx = MatchContext()
    dump = _access(5, RUNDLL, 1, trace=r"C:\Windows\SYSTEM32\dbgcore.DLL+9447|C:\Windows\System32\comsvcs.dll+3c56f")
    assert enrichment.derive(dump, "process_access.via_minidump", ctx) is True
    assert enrichment.derive(_access(5, RUNDLL, 2), "process_access.via_minidump", ctx) is False
    script = _script(1, 1, "$x='amsiInitF'+'ailed'")
    assert "amsiInitFailed" in enrichment.derive(script, "script_block.deobfuscated_text", ctx)
    assert enrichment.derive(script, "script_block.is_obfuscated", ctx) is True
    assert enrichment.derive(_dns(1, 1, "github.com"), "dns.is_dga", ctx) is False


# ------------------------------------------------------------------ rules


def _fired(*events):
    return {a.rule_id for a in _run(*events)[2]}


def test_lsass_rules_fire_on_a_dumper_and_not_on_benign_access():
    start = _event("process", "start", 5, 0, image=RUNDLL, ppid=1)
    assert "DET-CRED-010" in _fired(start, _access(5, RUNDLL, 1, granted="0x1410"))
    minidump = _access(5, RUNDLL, 1, granted="0x1fffff", trace=r"C:\Windows\SYSTEM32\dbgcore.DLL+9447")
    assert {"DET-CRED-010", "DET-CRED-011"} <= _fired(start, minidump)
    # No read right: a query-only handle is not credential access.
    assert not {"DET-CRED-010", "DET-CRED-011"} & _fired(start, _access(5, RUNDLL, 1, granted="0x1000"))
    # A listed LSASS reader (Defender) is not flagged.
    defender = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
    assert "DET-CRED-010" not in _fired(_access(6, defender, 1, granted="0x1410"))
    # Reading memory of anything but lsass is not this rule.
    assert "DET-CRED-010" not in _fired(start, _access(5, RUNDLL, 1, target=(800, NOTEPAD)))


def test_injection_rules_distinguish_unbacked_from_loadlibrary_starts():
    loader = r"C:\Users\b\Desktop\loader.exe"
    assert "DET-INJ-010" in _fired(_thread(20, loader, 1))
    assert "DET-INJ-011" not in _fired(_thread(20, loader, 1))
    loadlib = _thread(20, loader, 1, module=r"C:\Windows\System32\KERNEL32.DLL", function="LoadLibraryW")
    assert "DET-INJ-011" in _fired(loadlib)
    assert "DET-INJ-010" not in _fired(loadlib)
    assert not {"DET-INJ-010", "DET-INJ-011"} & _fired(
        _thread(20, loader, 1, module=r"C:\Windows\System32\ntdll.dll", function="RtlUserThreadStart")
    )


def test_script_block_rule_sees_through_concatenation_but_not_into_benign_scripts():
    empire_like = "[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')"
    assert "DET-PS-010" in _fired(_script(1, 1, empire_like))
    assert "DET-PS-010" in _fired(_script(1, 1, "$s['EnableScriptB'+'lockLogging']=0"))
    assert "DET-PS-010" not in _fired(_script(1, 1, "Get-ChildItem C:\\Users | Measure-Object"))


# -------------------------------------------------- cross-process rarity


def _cross_baseline(min_cross=2):
    svchost = r"C:\Windows\System32\svchost.exe"
    explorer = (800, r"C:\Windows\explorer.exe")
    run, _, _ = _run(
        *[_event("process", "start", 100 + i, i, image=svchost, ppid=1, parent_name="services.exe") for i in range(4)],
        *[_access(100 + i, svchost, 10 + i, granted="0x1000", target=explorer) for i in range(4)],
    )
    baseline = RarityBaseline(
        min_observations=3, min_relationships=1, uncommon_max_count=0, min_cross_process=min_cross
    )
    baseline.fit(run.feature_extractor.extract_all())
    return baseline


def test_cross_process_relationships_are_learned_and_scored():
    baseline = _cross_baseline()
    assert baseline.counts["cross_process"] == {"svchost.exe -> explorer.exe [access]": 4}
    assert baseline.score_cross_process("svchost.exe", "explorer.exe", "access").category == "common"
    unseen = baseline.score_cross_process("rundll32.exe", "lsass.exe", "access")
    assert (unseen.category, unseen.observed_count, unseen.baseline_total) == ("unseen", 0, 4)


def test_rare_cross_process_access_becomes_a_tagged_signal():
    baseline = _cross_baseline()
    _, context, alerts = _run(
        _event("process", "start", 5, 0, image=RUNDLL, ppid=1),
        _access(5, RUNDLL, 1, granted="0x1000"),
        detectors=[RarityDetector(baseline)],
    )
    (signal,) = [a for a in alerts if a.rule_id == "BHV-RARE-003"]
    assert "rundll32.exe -> lsass.exe [access]" in signal.description
    assert signal.active_response is None and signal.mitre_tactic is None
    tagged = [e for e in context.graph.edges.values() if any(t.rule_id == "BHV-RARE-003" for t in e.tags)]
    assert [e.kind for e in tagged] == [EdgeKind.ACCESSED]


def test_cross_process_rarity_waits_for_its_own_readiness():
    baseline = _cross_baseline(min_cross=50)
    assert baseline.is_ready and not baseline.cross_process_ready
    _, _, alerts = _run(
        _event("process", "start", 5, 0, image=RUNDLL, ppid=1),
        _access(5, RUNDLL, 1, granted="0x1000"),
        detectors=[RarityDetector(baseline)],
    )
    assert not [a for a in alerts if a.rule_id == "BHV-RARE-003"]


def test_pre_05_telemetry_yields_empty_05_features():
    _, context, _ = _run(_event("process", "start", 10, 0, image=PS, ppid=1))
    f = FeatureExtractor(context.registry, context.graph).extract(next(iter(context.registry)))
    assert f.feature_schema_version == 2
    assert (f.dns_query_count, f.process_access_count, f.script_block_count, f.lifetime_seconds) == (0, 0, 0, None)
    assert f.access_targets == () and f.remote_thread_targets == ()
