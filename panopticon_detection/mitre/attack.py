"""MITRE ATT&CK Enterprise Matrix Navigator, Tactic Taxonomy, and Coverage Heatmap Generator.

Maps detection rules across all 14 official Enterprise ATT&CK Tactics:
TA0001 (Initial Access) -> TA0040 (Impact).
Generates console heatmaps and exports official MITRE ATT&CK Navigator JSON layer formats.
"""

from collections import defaultdict
from typing import Any, Dict, List

from panopticon_detection.rules.schema import Rule

# Official MITRE ATT&CK Enterprise Matrix Tactics
MITRE_TACTICS_ORDER = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

TACTIC_NAME_TO_ID = {name.lower(): tid for tid, name in MITRE_TACTICS_ORDER}
TACTIC_ID_TO_NAME = {tid: name for tid, name in MITRE_TACTICS_ORDER}


class MitreMatrixNavigator:
    """Analyzes rulebases to compute MITRE ATT&CK coverage metrics and matrix heatmaps."""

    @classmethod
    def analyze_coverage(cls, rules: List[Rule]) -> Dict[str, Any]:
        """Analyzes rules and groups them by MITRE Tactic and Technique."""
        coverage_by_tactic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        unique_techniques: set = set()

        for r in rules:
            if not r.mitre or not r.mitre.technique:
                continue

            tactic_name = (r.mitre.tactic or "Unknown").strip()
            # Normalize tactic name
            tactic_id = TACTIC_NAME_TO_ID.get(tactic_name.lower(), "TA9999")
            display_tactic = TACTIC_ID_TO_NAME.get(tactic_id, tactic_name)

            unique_techniques.add(r.mitre.technique)
            coverage_by_tactic[display_tactic].append({
                "rule_id": r.id,
                "rule_name": r.name,
                "technique_id": r.mitre.technique,
                "technique_name": r.mitre.name or "N/A",
                "level": r.level,
                "severity": r.severity,
            })

        covered_tactics_count = len([t for t, name in MITRE_TACTICS_ORDER if name in coverage_by_tactic])
        total_tactics = len(MITRE_TACTICS_ORDER)
        coverage_percent = round((covered_tactics_count / total_tactics) * 100, 1)

        return {
            "total_rules_analyzed": len(rules),
            "unique_techniques_covered": len(unique_techniques),
            "tactics_covered_count": covered_tactics_count,
            "total_enterprise_tactics": total_tactics,
            "tactics_coverage_percent": f"{coverage_percent}%",
            "coverage_by_tactic": dict(coverage_by_tactic),
        }

    @classmethod
    def render_console_heatmap(cls, rules: List[Rule]) -> str:
        """Renders an executive ASCII heatmap of MITRE ATT&CK coverage."""
        report = cls.analyze_coverage(rules)
        coverage = report["coverage_by_tactic"]

        sep = "=" * 80
        lines = [
            sep,
            "[*] MITRE ATT&CK Enterprise Matrix Coverage & Technique Density Heatmap",
            sep,
            f"  * Total Detection Rules: {report['total_rules_analyzed']}",
            f"  * Unique Techniques    : {report['unique_techniques_covered']}",
            f"  * Matrix Tactic Breadth: {report['tactics_covered_count']} / {report['total_enterprise_tactics']} ({report['tactics_coverage_percent']})",
            "-" * 80,
            f"{'Tactic ID':<10} | {'Enterprise Tactic':<24} | {'Status':<10} | {'Rules':<10} | {'Techniques Covered'}",
            "-" * 80,
        ]

        for tid, tname in MITRE_TACTICS_ORDER:
            rule_list = coverage.get(tname, [])
            tech_set = {r["technique_id"] for r in rule_list}
            tech_str = ", ".join(sorted(list(tech_set))) if tech_set else "-"

            if len(rule_list) > 0:
                status = "\033[92m[COVERED]\033[0m"
                count_str = f"{len(rule_list):2d} rule(s)"
            else:
                status = "\033[90m[NO RULES]\033[0m"
                count_str = " 0"

            lines.append(f"{tid:<10} | {tname:<24} | {status:<10} | {count_str:<10} | {tech_str}")

        lines.append(sep)
        return "\n".join(lines)

    @classmethod
    def export_navigator_layer(cls, rules: List[Rule]) -> Dict[str, Any]:
        """Generates an official MITRE ATT&CK Navigator v4 JSON Layer."""
        techniques_layer = []
        for r in rules:
            if r.mitre and r.mitre.technique:
                techniques_layer.append({
                    "techniqueID": r.mitre.technique,
                    "score": r.level,
                    "color": "#e02424" if r.level >= 12 else ("#e3a008" if r.level >= 7 else "#3f83f8"),
                    "comment": f"Rule [{r.id}]: {r.name} (Level {r.level})",
                    "enabled": True,
                })

        return {
            "name": "eyedetect Detection Engine Coverage",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Auto-generated MITRE ATT&CK Navigator Layer from eyedetect rulebase",
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#3f83f8", "#e3a008", "#e02424"],
                "minValue": 0,
                "maxValue": 16,
            },
        }
