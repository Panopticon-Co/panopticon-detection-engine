#!/usr/bin/env python3
"""CI gate: every live rule must target telemetry an agent can actually emit.

Finding F2 of the architecture review: 38 of 92 rules declared an ``event_type``
no Panopticon agent produces, so they could never fire. Four of those were not
scope gaps but mismatches against this engine's own normalizer (``file_write``
where it emits ``file_create``). Nothing caught it because nothing checked.

The producible vocabulary is derived from two sources that must agree:

* ``panopticon-agent/schema/event.schema.json`` -- the five ``event.category``
  values and the ``event.type`` values allowed for each
* ``panopticon_detection/ingestion/telemetry.py`` -- how this engine maps those
  onto its internal ``event_type``

There is no exemption directory. A rule that cannot fire is not coverage, it is
a claim, so such rules are deleted rather than parked.

Exits non-zero and names every offender, so the failure is actionable.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from panopticon_detection.ingestion.telemetry import (  # noqa: E402
    _FILE_EVENT_TYPES,
    _REGISTRY_EVENT_TYPES,
)

# Kept in step with the normalizer's own tables so a change there cannot drift
# away from this gate without one of them failing.
PRODUCIBLE = (
    {"process_create", "process_terminate", "network_connect", "image_load"}
    | set(_FILE_EVENT_TYPES.values())
    | set(_REGISTRY_EVENT_TYPES.values())
)

EVENT_TYPE = re.compile(r"^event_type:\s*(\S+)", re.MULTILINE)
RULE_ID = re.compile(r"^id:\s*(\S+)", re.MULTILINE)


def main() -> int:
    rules_dir = REPO_ROOT / "rules"
    offenders = []

    for path in sorted(rules_dir.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        match = EVENT_TYPE.search(text)
        if not match:
            offenders.append((path, "<no event_type>"))
            continue
        if match.group(1) not in PRODUCIBLE:
            rule_id = RULE_ID.search(text)
            offenders.append(
                (path, f"{match.group(1)}  ({rule_id.group(1) if rule_id else '?'})")
            )

    if offenders:
        print("Rules targeting telemetry no Panopticon agent emits:\n")
        for path, detail in offenders:
            print(f"  {path.relative_to(REPO_ROOT)}\n      event_type: {detail}")
        print(
            f"\n{len(offenders)} rule(s) target telemetry nothing produces."
            "\nCorrect the event_type to one the normalizer emits, or delete the"
            "\nrule -- do not ship a rule that can never fire."
            f"\n\nProducible event types: {', '.join(sorted(PRODUCIBLE))}"
        )
        return 1

    total = len(list(rules_dir.rglob("*.yaml")))
    print(f"OK: all {total} rule(s) target producible telemetry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
