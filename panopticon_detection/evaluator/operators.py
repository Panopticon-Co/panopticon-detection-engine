"""Operator functions for comparing event fields against rule condition values."""

import ipaddress
import re
from typing import Any, List, Union


def _normalize_case(val: Any, case_sensitive: bool) -> Any:
    if isinstance(val, str) and not case_sensitive:
        return val.lower()
    return val


def op_equals(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    if actual is None:
        return False
    return _normalize_case(actual, case_sensitive) == _normalize_case(target, case_sensitive)


def op_not_equals(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    if actual is None:
        return True
    return _normalize_case(actual, case_sensitive) != _normalize_case(target, case_sensitive)


def op_contains(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    if actual is None or target is None:
        return False
    act = _normalize_case(str(actual), case_sensitive)
    tgt = _normalize_case(str(target), case_sensitive)
    return tgt in act


def op_not_contains(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    return not op_contains(actual, target, case_sensitive)


def op_in(actual: Any, target_list: Union[List[Any], set, tuple], case_sensitive: bool = False) -> bool:
    if actual is None or not isinstance(target_list, (list, set, tuple)):
        return False
    norm_actual = _normalize_case(actual, case_sensitive)
    return any(norm_actual == _normalize_case(item, case_sensitive) for item in target_list)


def op_not_in(actual: Any, target_list: Union[List[Any], set, tuple], case_sensitive: bool = False) -> bool:
    return not op_in(actual, target_list, case_sensitive)


def op_starts_with(actual: Any, prefix: Any, case_sensitive: bool = False) -> bool:
    if actual is None or prefix is None:
        return False
    act = _normalize_case(str(actual), case_sensitive)
    pre = _normalize_case(str(prefix), case_sensitive)
    return act.startswith(pre)


def op_ends_with(actual: Any, suffix: Any, case_sensitive: bool = False) -> bool:
    if actual is None or suffix is None:
        return False
    act = _normalize_case(str(actual), case_sensitive)
    suf = _normalize_case(str(suffix), case_sensitive)
    return act.endswith(suf)


def op_regex(actual: Any, pattern: str, case_sensitive: bool = False) -> bool:
    if actual is None or not isinstance(pattern, str):
        return False
    flags = 0 if case_sensitive else re.IGNORECASE
    return bool(re.search(pattern, str(actual), flags=flags))


def op_greater_than(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    if actual is None or target is None:
        return False
    try:
        return float(actual) > float(target)
    except (ValueError, TypeError):
        return False


def op_less_than(actual: Any, target: Any, case_sensitive: bool = False) -> bool:
    if actual is None or target is None:
        return False
    try:
        return float(actual) < float(target)
    except (ValueError, TypeError):
        return False


def op_cidr(actual_ip: Any, cidr_target: Any, case_sensitive: bool = False) -> bool:
    """Checks if actual IP is within target CIDR block or list of CIDR blocks."""
    if not actual_ip:
        return False
    targets = cidr_target if isinstance(cidr_target, list) else [cidr_target]
    try:
        ip_obj = ipaddress.ip_address(str(actual_ip).strip())
        for block in targets:
            if ip_obj in ipaddress.ip_network(str(block).strip(), strict=False):
                return True
    except (ValueError, TypeError):
        return False
    return False


def op_windash(actual_cmd: Any, target_param: Any, case_sensitive: bool = False) -> bool:
    """Matches parameter prefixed by either '-' or '/'."""
    if not actual_cmd or not target_param:
        return False
    clean = str(target_param).lstrip("-/")
    pattern = rf"(?:^|\s)[-/]{re.escape(clean)}(?:\s|$|:|=)"
    return bool(re.search(pattern, str(actual_cmd), re.IGNORECASE))


OPERATOR_MAP = {
    "equals": op_equals,
    "not_equals": op_not_equals,
    "contains": op_contains,
    "not_contains": op_not_contains,
    "in": op_in,
    "not_in": op_not_in,
    "starts_with": op_starts_with,
    "ends_with": op_ends_with,
    "regex": op_regex,
    "greater_than": op_greater_than,
    "less_than": op_less_than,
    "cidr": op_cidr,
    "windash": op_windash,
}
