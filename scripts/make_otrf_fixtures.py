"""Build the trimmed OTRF test fixtures in tests/datasets/otrf/ from full recordings.

    panopticon-dataset fetch <name> --dest data/otrf      # for each name below
    python scripts/make_otrf_fixtures.py --source data/otrf

Each fixture keeps, in the recording's original order:

* every record of the low-volume families: Sysmon 1 (process start), 5 (stop),
  8 (remote thread), 22 (DNS) and PowerShell 4104 (script block);
* the attack's own process tree in the other Sysmon families -- records whose
  acting, parent, source or target PID is one the recording itself shows
  (process creates, and the metadata's adversary view) -- capped at 12 per
  event ID for the high-volume ones (image load 7, process access 10, registry
  12/13), except that every access to lsass.exe is kept;
* the first 20 other records, as background noise and skipped channels.

Only the ``Message`` field is dropped: it repeats every other field as
rendered text and is most of each record's size. Nothing else is edited.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from panopticon_detection.datasets.otrf import read_records
from panopticon_detection.datasets.sources import SAMPLES

# Attack process tree per recording, read from the recording itself.
CHAINS = {
    # wscript launcher.vbs (2440) -> powershell (2316, the Empire agent per the
    # metadata's adversary view) -> conhost (7700), whoami (9152)
    "empire_launcher_vbs": {2440, 2316, 7700, 9152},
    # powershell (6100) -> rundll32 comsvcs.dll MiniDump (4824)
    "psh_lsass_memory_dump_comsvcs": {6100, 4824},
    # powershell (3904) -> notepad (3440, injected) and mavinject (3224)
    "psh_mavinject_dll_notepad": {3904, 3440, 3224},
    # cmd (4840) -> PurpleSharp (8972) -> notepad (9908, injected) -> ping (5232) -> conhost (9700)
    "purplesharp_pe_injection_createremotethread": {4840, 8972, 9908, 5232, 9700},
}
_PID_FIELDS = ("ProcessId", "ParentProcessId", "SourceProcessId", "TargetProcessId", "ExecutionProcessID")
_LOW_VOLUME = {
    ("Microsoft-Windows-Sysmon/Operational", 1),
    ("Microsoft-Windows-Sysmon/Operational", 5),
    ("Microsoft-Windows-Sysmon/Operational", 8),
    ("Microsoft-Windows-Sysmon/Operational", 22),
    ("Microsoft-Windows-PowerShell/Operational", 4104),
}
BACKGROUND = 20
SYSMON = "Microsoft-Windows-Sysmon/Operational"
_CAPPED = {7, 10, 12, 13}
CAP = 12


def _pid(record, field):
    try:
        return int(str(record.get(field)))
    except (TypeError, ValueError):
        return None


def trim(records, chain):
    kept, background, per_id = [], 0, {}
    for record in records:
        channel, event_id = record.get("Channel"), _pid(record, "EventID")
        keep = (channel, event_id) in _LOW_VOLUME
        if not keep and channel == SYSMON and any(_pid(record, f) in chain for f in _PID_FIELDS):
            lsass = "lsass.exe" in str(record.get("TargetImage", "")).lower()
            if event_id not in _CAPPED or lsass or per_id.get(event_id, 0) < CAP:
                keep = True
                if event_id in _CAPPED and not lsass:
                    per_id[event_id] = per_id.get(event_id, 0) + 1
        if not keep:
            if background >= BACKGROUND:
                continue
            background += 1
        kept.append({k: v for k, v in record.items() if k != "Message"})
    return kept


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", default="data/otrf", help="Directory of fetched recordings")
    parser.add_argument("--dest", default="tests/datasets/otrf", help="Fixture directory")
    args = parser.parse_args()
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    for name, chain in CHAINS.items():
        sample = SAMPLES[name]
        records = read_records(Path(args.source) / Path(sample.path).name)
        kept = trim(records, chain)
        with open(dest / f"{name}.json", "w", encoding="utf-8") as handle:
            for record in kept:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        (dest / sample.metadata).write_bytes((Path(args.source) / sample.metadata).read_bytes())
        print(f"{name}: kept {len(kept)} of {len(records)} records")


if __name__ == "__main__":
    main()
