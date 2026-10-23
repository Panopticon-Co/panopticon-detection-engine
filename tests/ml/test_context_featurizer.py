"""Process-in-context vectorizer (context model L1): layout, groups, availability NaN, determinism."""

from __future__ import annotations

import ast
import math
import sys
from pathlib import Path

from panopticon_detection.features import FEATURE_SCHEMA_VERSION, ProcessFeatures
from panopticon_detection.ml import context_featurizer as CF
from panopticon_detection.ml import featurizer as F


def _features(**overrides):
    base = dict(
        feature_schema_version=FEATURE_SCHEMA_VERSION, host_id="h", node_id="n", pid=1, parent_pid=2,
        name="rundll32.exe", executable=r"C:\Windows\System32\rundll32.exe", path_class="system",
        start_time="2026-01-01T10:00:00", user="u", inferred=False, parent_name="winword.exe",
        grandparent_name="explorer.exe", tree_root_name="winword.exe", depth=2,
        parent_child="winword.exe -> rundll32.exe", cmdline_length=10, cmdline_token_count=2,
        cmdline_entropy=3.0, cmdline_obfuscated=False, cmdline_evasion_count=0, image_writer_name=None,
        image_age_seconds=None, child_count=1, file_write_count=0, executable_write_count=0,
        registry_write_count=0, network_connect_count=3, public_connect_count=3, module_load_count=40,
        lifetime_seconds=None, dns_query_count=0, distinct_domain_count=0, failed_dns_query_count=0,
        process_access_count=0, lsass_access_count=0, remote_thread_count=0, injected_thread_count=0,
        access_targets=(), remote_thread_targets=(), script_block_count=0, script_block_bytes=0,
        obfuscated_script_block_count=0, as_of="2026-01-01T10:01:00",
        ancestor_names=("winword.exe", "explorer.exe"),
        behavior_bits=("network:public_destination",),
        behavior_bit_objects=(("network:public_destination", 2),),
    )
    base.update(overrides)
    return ProcessFeatures(**base)


def _value(vector, name):
    return vector.get(CF.FEATURE_NAMES.index(name), 0.0)


def test_layout_is_unique_and_grouped():
    assert len(set(CF.FEATURE_NAMES)) == len(CF.FEATURE_NAMES)
    assert set(CF.GROUP_OF.values()) == set(CF.ALL_GROUPS)
    assert set(CF.MONOTONE_FEATURES) <= set(CF.FEATURE_NAMES)
    assert not any(n.startswith("start:") and n[6:] in F.STATS_FEATURES for n in CF.FEATURE_NAMES)


def test_lineage_and_behaviour_are_encoded_without_raw_names():
    v = CF.vectorize(_features(), F.featurize({"process": {"name": "rundll32.exe"}, "parent": {"name": "winword.exe"}}))
    assert _value(v, "anc1_role=office") == 1.0 and _value(v, "anc2_role=session") == 1.0
    assert _value(v, "anc3_role=missing") == 1.0 and _value(v, "descends_from_role=office") == 1.0
    assert _value(v, "network:public_destination") == 1.0
    assert _value(v, "network:public_destination_objects") == 2.0
    assert _value(v, "elapsed_log") == round(math.log1p(60.0), 6)
    assert _value(v, "start:bin=rundll32.exe") == 1.0


def test_uncollected_family_is_nan_and_collected_silence_is_zero():
    available = set(CF.FAMILY_GROUPS) - {"registry"}
    v = CF.vectorize(_features(), {}, available=available)
    assert math.isnan(_value(v, "registry:persistence_key"))
    assert math.isnan(_value(v, "registry:persistence_key_objects"))
    assert CF.FEATURE_NAMES.index("file:executable_to_user_path") not in v  # collected, silent -> 0
    only_core = CF.vectorize(_features(), {}, available=())
    assert all(math.isnan(only_core[CF.FEATURE_NAMES.index(n)]) for n, g in CF.GROUP_OF.items() if g in CF.FAMILY_GROUPS)


def test_groups_restrict_the_output():
    v = CF.vectorize(_features(), {}, groups=("lineage",))
    assert {CF.GROUP_OF[CF.FEATURE_NAMES[i]] for i in v} == {"lineage"}


def test_vectorizer_is_stdlib_only():
    tree = ast.parse(Path(CF.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            root = (module or "").split(".")[0]
            assert root in sys.stdlib_module_names or root in ("panopticon_detection", "__future__")
