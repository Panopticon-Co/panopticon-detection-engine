"""Sigma-Style Field Modifiers Pipeline.

Applies pre-comparison value transformations directly on event fields:
e.g. |base64, |utf16le, |cidr, |windash, |endswith, |startswith.
"""

import ipaddress
import re
from typing import Any, Optional


class FieldModifierPipeline:
    """Applies transformations to target or actual values based on Sigma-style modifiers."""

    @classmethod
    def apply_modifiers(cls, field_path: str, actual_value: Any) -> tuple[str, Any]:
        """Parses modifier suffixes from field path (e.g. 'network.ip|cidr') and applies transforms."""
        if "|" not in field_path:
            return field_path, actual_value

        parts = field_path.split("|")
        base_field = parts[0]
        modifiers = parts[1:]

        transformed = actual_value
        for mod in modifiers:
            transformed = cls._apply_single_modifier(mod.lower(), transformed)

        return base_field, transformed

    @classmethod
    def check_cidr(cls, actual_ip: Optional[str], cidr_block: str) -> bool:
        """Checks if an IPv4/IPv6 address falls within a given CIDR network."""
        if not actual_ip or not isinstance(actual_ip, str):
            return False
        try:
            ip_obj = ipaddress.ip_address(actual_ip.strip())
            net_obj = ipaddress.ip_network(cidr_block.strip(), strict=False)
            return ip_obj in net_obj
        except (ValueError, TypeError):
            return False

    @classmethod
    def match_windash(cls, actual_cmd: Optional[str], target_param: str) -> bool:
        """Matches Windows CLI parameter with either '-' or '/' prefix (e.g. -enc or /enc)."""
        if not actual_cmd or not isinstance(actual_cmd, str):
            return False
        clean_param = target_param.lstrip("-/")
        pattern = rf"(?:^|\s)[-/]{re.escape(clean_param)}(?:\s|$|:|=)"
        return bool(re.search(pattern, actual_cmd, re.IGNORECASE))

    @staticmethod
    def _apply_single_modifier(modifier: str, val: Any) -> Any:
        if val is None:
            return None

        if modifier == "lower":
            return str(val).lower()
        elif modifier == "strip":
            return str(val).strip()

        return val
