"""Boundary processes: hubs a causal walk may reach but must not expand through.

``explorer.exe`` is the parent of nearly every interactive program; ``services.exe``
and ``svchost.exe`` of nearly every service. Treating them as ordinary nodes lets a
provenance walk climb to the hub and descend into unrelated siblings -- the
"dependency explosion" problem in provenance-based detection. Stopping at them
keeps an incident to the activity that actually caused it.

A hub is identified by image name. This is a deliberate, documented heuristic:
a process masquerading as ``svchost.exe`` would also stop a walk, which is why
masquerading is a detection of its own rather than something correlation relies
on.
"""

from __future__ import annotations

from typing import Iterable, Optional

DEFAULT_BOUNDARY_PROCESSES = frozenset(
    {
        # Windows session / service infrastructure
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "svchost.exe",
        "lsass.exe",
        "userinit.exe",
        "explorer.exe",
        "sihost.exe",
        "runtimebroker.exe",
        "taskhostw.exe",
        "taskeng.exe",
        "wmiprvse.exe",
        "dllhost.exe",
        # Linux init / session infrastructure
        "systemd",
        "init",
        "sshd",
        "cron",
        "crond",
    }
)


def is_boundary(name: Optional[str], boundary: Iterable[str] = DEFAULT_BOUNDARY_PROCESSES) -> bool:
    return bool(name) and name.lower() in boundary
