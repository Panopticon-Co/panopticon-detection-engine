"""Full-family replay: checkpoints recorded live equal features extracted afterwards (criterion C7)."""

from __future__ import annotations

import gzip
import json
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("lightgbm")

from pdtrain import replay as R  # noqa: E402

from panopticon_detection import enrichment  # noqa: E402
from panopticon_detection.factory import build_detection_run  # noqa: E402
from panopticon_detection.features import FeatureExtractor  # noqa: E402
from panopticon_detection.provenance.identity import parse_timestamp  # noqa: E402
from tests.test_schema05_telemetry import PS, RUNDLL, T0, _access, _event  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _events():
    return [
        _event("process", "start", 10, 0, image=PS, ppid=1, cmd="powershell -nop -w hidden -enc QUFBQUFBQUFBQUFBQUFBQUFB"),
        _event("process", "start", 20, 1, image=RUNDLL, ppid=10, parent_name="powershell.exe"),
        _access(20, RUNDLL, 2, granted="0x1410"),
        _event("network", "connect", 20, 4, image=RUNDLL, block={
            "direction": "outbound", "protocol": "tcp", "source_ip": "10.0.0.5", "source_port": 50000,
            "destination_ip": "93.184.216.34", "destination_port": 4444, "destination_hostname": None}),
        _event("process", "stop", 20, 9, image=RUNDLL),
    ]


def test_tap_checkpoints_equal_post_hoc_extraction():
    tap = R.CheckpointTap()
    run, ctx = build_detection_run(ROOT / "rules", behavioral_detectors=[tap])
    for event in _events():
        enrichment.reset(event)
        run.process_event(event)
    extractor = FeatureExtractor(ctx.registry, ctx.graph)
    cps = [r for r in tap.records if r["t"] == "cp"]
    kinds = [(ctx.registry.get(r["node"]).name, r["kind"]) for r in cps]
    assert ("rundll32.exe", "start") in kinds and ("rundll32.exe", "stop") in kinds
    assert ("rundll32.exe", "bit:process_access:lsass_read") in kinds
    assert ("powershell.exe", "bit:child:shell_or_lolbin") in kinds
    assert ("rundll32.exe", "bit:network:public_destination,network:public_nonstandard_port") in kinds
    for record in cps:
        when = parse_timestamp(record["ts"])
        post_hoc = extractor.extract(ctx.registry.get(record["node"]), as_of=when).to_dict()
        assert post_hoc == record["features"], record["kind"]
    tokens = dict((r["node"], r["tokens"]) for r in tap.token_records())
    rundll = next(p for p in ctx.registry if p.name == "rundll32.exe")
    assert tokens[rundll.node_id][:2] == ["access:lsass:read", "net:public:other"]


def test_replay_unit_writes_summary_starts_and_alerts(tmp_path):
    unit = R.Unit("u1", "officer_vm", "officer_vm:test", "inline", (_events(),), normalized=True)
    summary = R.replay_unit(unit, ROOT, tmp_path)
    assert summary["starts"] == 2 and summary["events"] == 5
    assert summary["hosts"]["H"]["families"]["process_access"] == 1
    assert summary["hosts"]["H"]["hours"] == pytest.approx(9 / 3600, abs=1e-4)
    records = [json.loads(line) for line in gzip.open(tmp_path / "officer_vm" / "u1.jsonl.gz", "rt")]
    start = next(r for r in records if r["t"] == "start" and r["pid"] == 20)
    assert start["ts"] == (T0 + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert any(r["t"] == "alert" for r in records)
    census = R.census_of(tmp_path)
    assert census["officer_vm"]["starts"] == 2
    nodes = {r["name"]: r for r in records if r["t"] == "node"}
    assert nodes["rundll32.exe"]["root"] == nodes["powershell.exe"]["root"]  # one storyline
