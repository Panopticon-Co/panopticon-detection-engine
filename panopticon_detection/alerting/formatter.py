"""Alert formatters for console and file output.

The console view renders only what the alert itself carries: what was observed
and what was recommended. It must never describe the engine as having acted --
the engine executes nothing, and every destructive recommendation waits for
analyst approval in panopticon-response-engine.
"""

import json
import textwrap

from panopticon_detection.alerting.alert import Alert
from panopticon_detection.alerting.story_formatter import recommendation_text

_WIDTH = 78
_LABEL = 14
_BODY = _WIDTH - 4 - _LABEL - 3


class AlertFormatter:
    """Formats alerts for display."""

    @staticmethod
    def to_console(alert: Alert) -> str:
        level = getattr(alert, "level", 0)
        sev = str(getattr(alert, "severity", "")).upper()
        if level >= 15:
            badge = "[CRITICAL]"
        elif level >= 12:
            badge = "[HIGH]"
        else:
            badge = "[DETECTION]"

        technique = ""
        if alert.mitre_tactic or alert.mitre_technique:
            technique = f"{alert.mitre_tactic or '-'} / {alert.mitre_technique or '-'}"

        rows = [
            ("Host", alert.host_id),
            ("Rule", alert.rule_id),
            ("Observed", alert.description),
            ("ATT&CK", technique),
            ("Severity", f"level {level}/16 ({sev}), confidence {alert.confidence * 100:.0f}%"),
            ("Recommended", recommendation_text(alert)),
        ]

        title_lines = textwrap.wrap(f"{badge} {alert.title}", _WIDTH - 4) or [badge]
        lines = ["┌" + "─" * (_WIDTH - 2) + "┐"]
        lines += [f"│ {t:<{_WIDTH - 4}} │" for t in title_lines]
        lines.append("├" + "─" * (_WIDTH - 2) + "┤")
        for label, value in rows:
            if not value:
                continue
            wrapped = textwrap.wrap(str(value), _BODY) or [""]
            for i, chunk in enumerate(wrapped):
                head = label if i == 0 else ""
                sep = ":" if i == 0 else " "
                lines.append(f"│ {head:<{_LABEL}} {sep} {chunk:<{_BODY}} │")
        lines.append("└" + "─" * (_WIDTH - 2) + "┘")
        return "\n".join(lines)

    @staticmethod
    def to_json(alert: Alert) -> str:
        return json.dumps(alert.to_dict(), indent=2)

    @staticmethod
    def to_ndjson(alert: Alert) -> str:
        return json.dumps(alert.to_dict())
