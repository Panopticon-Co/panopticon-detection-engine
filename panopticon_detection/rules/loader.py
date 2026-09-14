"""Loader for discovering and parsing YAML detection rules."""

from pathlib import Path
from typing import Dict, List, Union

import yaml

from panopticon_detection.rules.schema import Rule, RuleStatus
from panopticon_detection.rules.validator import RuleValidationError, RuleValidator


class RuleLoader:
    """Discovers, parses, validates, and indexes detection rules."""

    def __init__(self, validator: RuleValidator = None):
        self.validator = validator or RuleValidator()

    def load_file(self, file_path: Union[str, Path]) -> Rule:
        """Loads and validates a single YAML rule file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Rule file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)

        if not isinstance(raw_data, dict):
            raise RuleValidationError(f"File {path} does not contain a valid YAML dictionary")

        rule = Rule(**raw_data)
        self.validator.validate_rule(rule)
        return rule

    # Rules whose event_type no Panopticon agent can emit live under this
    # directory. They are kept for MITRE coverage and for replay against
    # synthetic telemetry, but must never load into a live detection run --
    # a rule that can never fire is not coverage, it is a claim.
    EXCLUDED_DIRS = frozenset({"unsourced"})

    def load_directory(
        self,
        dir_path: Union[str, Path],
        recursive: bool = True,
        include_unsourced: bool = False,
    ) -> List[Rule]:
        """Scans a directory for .yaml and .yml rules.

        Skips :attr:`EXCLUDED_DIRS` unless ``include_unsourced`` is set, so the
        live rule set only ever contains rules the agents can actually trigger.
        """
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Rules directory not found: {path}")

        pattern = "**/*.y*ml" if recursive else "*.y*ml"
        rules: List[Rule] = []

        for file_path in sorted(path.glob(pattern)):
            if not include_unsourced and self.EXCLUDED_DIRS.intersection(
                file_path.relative_to(path).parts
            ):
                continue
            try:
                rule = self.load_file(file_path)
                if rule.status == RuleStatus.ENABLED:
                    rules.append(rule)
            except Exception as e:
                raise RuleValidationError(f"Failed loading rule {file_path}: {e}") from e

        return rules

    @staticmethod
    def index_by_event_type(rules: List[Rule]) -> Dict[str, List[Rule]]:
        """Groups rules by event_type for fast O(1) partition matching."""
        indexed: Dict[str, List[Rule]] = {}
        for rule in rules:
            indexed.setdefault(rule.event_type, []).append(rule)
        return indexed
