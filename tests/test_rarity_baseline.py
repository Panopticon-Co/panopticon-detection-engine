"""Rarity baseline: counting, categories, readiness, versioning and save/load."""

import json

import pytest

from panopticon_detection.behavioral.rarity import (
    COMMON,
    NAME_PATH_CLASS,
    NOT_READY,
    PARENT_CHILD,
    UNCOMMON,
    UNSEEN,
    RarityBaseline,
)
from panopticon_detection.features import FEATURE_SCHEMA_VERSION, ProcessFeatures


def _features(parent, name, path_class="system", *, start="2026-09-01T12:00:00", inferred=False):
    return ProcessFeatures(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        host_id="H", node_id=f"proc_{parent}_{name}_{start}", pid=100, parent_pid=50,
        name=name, executable=f"C:\\x\\{name}", path_class=path_class, start_time=start,
        user="", inferred=inferred,
        parent_name=parent, grandparent_name=None, tree_root_name=name, depth=1,
        parent_child=f"{parent} -> {name}" if parent else None,
        cmdline_length=0, cmdline_token_count=0, cmdline_entropy=0.0,
        cmdline_obfuscated=False, cmdline_evasion_count=0,
        image_writer_name=None, image_age_seconds=None,
        child_count=0, file_write_count=0, executable_write_count=0,
        registry_write_count=0, network_connect_count=0, public_connect_count=0,
        module_load_count=0, lifetime_seconds=None,
        dns_query_count=0, distinct_domain_count=0, failed_dns_query_count=0,
        process_access_count=0, lsass_access_count=0, remote_thread_count=0,
        injected_thread_count=0, access_targets=(), remote_thread_targets=(),
        script_block_count=0, script_block_bytes=0, obfuscated_script_block_count=0,
        as_of=None,
    )


def _trained(**settings):
    """explorer starts chrome 10x, outlook 2x, notepad 1x; services starts svchost 5x."""
    baseline = RarityBaseline(**{"min_observations": 10, "min_relationships": 3, **settings})
    records = (
        [_features("explorer.exe", "chrome.exe", "program_files", start=f"2026-09-01T12:00:{i:02d}") for i in range(10)]
        + [_features("explorer.exe", "outlook.exe", "program_files")] * 2
        + [_features("explorer.exe", "notepad.exe")]
        + [_features("services.exe", "svchost.exe")] * 5
    )
    assert baseline.fit(records) == 18
    return baseline


def _category(baseline, features, dimension=PARENT_CHILD):
    return next(r for r in baseline.score(features) if r.dimension == dimension)


def test_observations_are_counted():
    b = _trained()
    assert b.total_observations == 18
    assert b.relationships == 4
    assert b.counts[PARENT_CHILD]["explorer.exe -> chrome.exe"] == 10
    assert b.counts[NAME_PATH_CLASS]["svchost.exe @ system"] == 5
    assert (b.observed_from, b.observed_to) == ("2026-09-01T12:00:00", "2026-09-01T12:00:09")


def test_common_uncommon_and_unseen():
    b = _trained()
    common = _category(b, _features("explorer.exe", "chrome.exe", "program_files"))
    assert (common.category, common.observed_count, common.baseline_total) == (COMMON, 10, 18)
    assert common.relative_frequency == round(10 / 18, 6)
    assert _category(b, _features("explorer.exe", "outlook.exe", "program_files")).category == UNCOMMON
    assert _category(b, _features("explorer.exe", "notepad.exe")).category == UNCOMMON
    unseen = _category(b, _features("winword.exe", "powershell.exe"))
    assert (unseen.category, unseen.observed_count, unseen.relative_frequency) == (UNSEEN, 0, 0.0)


def test_uncommon_threshold_is_configurable_and_can_be_switched_off():
    b = _trained(uncommon_max_count=0)
    assert _category(b, _features("explorer.exe", "notepad.exe")).category == COMMON
    b = _trained(uncommon_max_count=10)
    assert _category(b, _features("explorer.exe", "chrome.exe", "program_files")).category == UNCOMMON


def test_cold_start_reports_not_ready():
    empty = RarityBaseline()
    assert not empty.is_ready
    assert _category(empty, _features("winword.exe", "powershell.exe")).category == NOT_READY


def test_each_readiness_threshold_applies():
    too_few_observations = _trained(min_observations=19)
    assert not too_few_observations.is_ready
    assert _category(too_few_observations, _features("a.exe", "b.exe")).category == NOT_READY

    too_few_relationships = _trained(min_relationships=5)
    assert not too_few_relationships.is_ready
    assert too_few_relationships.readiness() == {
        "ready": False, "observations": 18, "relationships": 4,
        "min_observations": 10, "min_relationships": 5,
        "cross_process_ready": False, "cross_process_observations": 0, "min_cross_process": 10,
    }

    just_enough = _trained(min_observations=18, min_relationships=4)
    assert just_enough.is_ready
    assert _category(just_enough, _features("a.exe", "b.exe")).category == UNSEEN


def test_path_class_dimension_only_scores_known_programs():
    b = _trained()
    masquerade = _features("services.exe", "svchost.exe", "temp")
    results = {r.dimension: r for r in b.score(masquerade)}
    assert results[PARENT_CHILD].category == COMMON
    assert results[NAME_PATH_CLASS].value == "svchost.exe @ temp"
    assert results[NAME_PATH_CLASS].category == UNSEEN
    # A program the baseline never saw is reported once, by parent_child.
    new_program = _features("winword.exe", "payload.exe", "temp")
    assert [r.dimension for r in b.score(new_program)] == [PARENT_CHILD]


def test_inferred_and_nameless_processes_are_not_learned():
    b = RarityBaseline()
    assert b.observe(_features("explorer.exe", "x.exe", inferred=True)) is False
    assert b.observe(_features(None, "")) is False
    assert b.total_observations == 0


def test_scoring_is_deterministic_and_does_not_learn():
    b = _trained()
    probe = _features("winword.exe", "powershell.exe")
    before = json.dumps(b.to_dict(), sort_keys=True)
    assert b.score(probe) == b.score(probe)
    assert json.dumps(b.to_dict(), sort_keys=True) == before


def test_save_and_load_round_trip(tmp_path):
    b = _trained()
    path = tmp_path / "baseline.json"
    b.save(path)
    loaded = RarityBaseline.load(path)
    assert loaded.version == b.version
    assert loaded.counts == b.counts
    assert loaded.readiness() == b.readiness()
    probe = _features("winword.exe", "powershell.exe")
    assert loaded.score(probe) == b.score(probe)


def test_version_metadata():
    data = _trained().to_dict()
    assert data["baseline_type"] == "process_rarity"
    assert data["format_version"] == 1
    assert data["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert data["readiness"] == {"min_observations": 10, "min_relationships": 3, "min_cross_process": 10}
    assert data["thresholds"] == {"uncommon_max_count": 2}
    assert data["total_observations"] == 18
    assert len(data["baseline_version"]) == 12
    assert {"created_at", "observed_from", "observed_to", "counts"} <= set(data)


def test_version_is_content_derived():
    assert _trained().version == _trained().version
    more = _trained()
    more.observe(_features("explorer.exe", "chrome.exe", "program_files"))
    assert more.version != _trained().version
    assert _trained(uncommon_max_count=0).version != _trained().version
    stamped = _trained()
    stamped.created_at = "2026-01-01T00:00:00+00:00"
    assert stamped.version == _trained().version  # wall-clock time is not content


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("baseline_type", "something_else", "not a process_rarity"),
        ("format_version", 99, "format_version"),
        ("feature_schema_version", FEATURE_SCHEMA_VERSION + 1, "relearn"),
        ("baseline_version", "000000000000", "does not match"),
    ],
)
def test_load_rejects_what_it_cannot_trust(field, value, message):
    data = _trained().to_dict()
    data[field] = value
    with pytest.raises(ValueError, match=message):
        RarityBaseline.from_dict(data)


def test_edited_counts_are_detected():
    data = _trained().to_dict()
    data["counts"][PARENT_CHILD]["winword.exe -> powershell.exe"] = 50
    with pytest.raises(ValueError, match="does not match"):
        RarityBaseline.from_dict(data)
