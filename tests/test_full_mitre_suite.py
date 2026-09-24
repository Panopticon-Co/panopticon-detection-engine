"""MITRE ATT&CK rule-metadata coverage, Navigator export, and the cidr/windash operators."""

from panopticon_detection.evaluator.operators import op_cidr, op_windash
from panopticon_detection.mitre.attack import MitreMatrixNavigator
from panopticon_detection.rules.loader import RuleLoader


def test_100_percent_mitre_tactic_coverage():
    loader = RuleLoader()
    rules = loader.load_directory("rules")

    report = MitreMatrixNavigator.analyze_coverage(rules)
    
    # Verify 100% tactic breadth
    assert report["tactics_covered_count"] == 12
    assert report["tactics_coverage_percent"] == "100.0%"
    assert report["unique_techniques_covered"] >= 15


def test_cidr_operator_matching():
    # Test CIDR block matching
    assert op_cidr("192.168.1.50", "192.168.0.0/16") is True
    assert op_cidr("10.0.5.1", "10.0.0.0/8") is True
    assert op_cidr("8.8.8.8", "192.168.0.0/16") is False


def test_windash_operator_matching():
    # Test matching both -param and /param
    cmd1 = "wmic.exe /node:DC-01 process call create calc.exe"
    cmd2 = "wmic.exe -node:DC-01 process call create calc.exe"
    cmd3 = "wmic.exe process list"

    assert op_windash(cmd1, "node") is True
    assert op_windash(cmd2, "node") is True
    assert op_windash(cmd3, "node") is False


def test_navigator_layer_export():
    loader = RuleLoader()
    rules = loader.load_directory("rules")

    layer = MitreMatrixNavigator.export_navigator_layer(rules)
    assert layer["name"] == "eyedetect Detection Engine Coverage"
    assert len(layer["techniques"]) >= 15
    assert layer["domain"] == "enterprise-attack"
