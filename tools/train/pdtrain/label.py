"""Per-process labels from provenance and dataset documentation -- never from rules.

The engine's detection rules are deliberately NOT used: a model trained on
labels that rules produced can only learn to imitate those rules, and an
evaluation against them is circular.

Two labelling regimes, chosen per source:

**Documented scenario (BOTSv1).** The attacks in BOTSv1 are documented
narratives. A process is malicious iff it is, or descends from (Sysmon
ProcessGuid -> ParentProcessGuid), one of the documented attack roots below.
Everything else is the real environment and is benign -- including the
authorised Nessus scan, a realistic attacker-looking benign workload.

**Attack recording (Splunk attack_data, OTRF).** These files were captured
while a technique ran on a lab host, so they hold the attack plus whatever the
host was doing. Background subtraction:

* ``benign/background`` -- the process image is OS housekeeping or lab
  infrastructure (:data:`BACKGROUND_IMAGES`) and so is every ancestor seen in
  the file (or the parent seen only as a name);
* ``excluded/interactive`` -- an interactive desktop application
  (:data:`INTERACTIVE_IMAGES`) that does not descend from a malicious process:
  it could be the lab operator browsing, so no label is guessed;
* ``excluded/console_host`` -- ``conhost.exe`` carries no attacker signal and
  appears identically under both classes;
* ``excluded/defensive_tool`` -- defensive software running in the lab
  (:data:`DEFENSIVE_IMAGES`);
* ``malicious/attack_recording`` -- everything else.

Finally, rows are de-duplicated on what the featurizer sees (normalised name,
parent, path and command line, plus integrity); a key that occurs with *both*
labels is excluded as a label conflict. Every count is written to the manifest
so the noise this heuristic introduces is visible.
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from panopticon_detection.ml.featurizer import integrity_category, normalize_text
from pdtrain.normalize import read_rows

LABELLER_VERSION = 3


def leaf(path: Optional[str]) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


# OS housekeeping and lab infrastructure. A process counts as background only if
# its whole observed lineage is made of these, so an attacker cannot hide by
# launching a payload *from* one of them.
BACKGROUND_IMAGES = frozenset(
    {
        # session / boot
        "system", "smss.exe", "autochk.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "logonui.exe", "lsass.exe", "lsm.exe", "lsaiso.exe", "dwm.exe", "fontdrvhost.exe",
        "services.exe", "svchost.exe", "sihost.exe", "userinit.exe",
        # task / COM / broker hosts
        "taskhostw.exe", "taskhost.exe", "taskeng.exe", "runtimebroker.exe",
        "backgroundtaskhost.exe", "backgroundtransferhost.exe", "dllhost.exe", "unsecapp.exe",
        "wmiadap.exe", "wmiapsrv.exe", "consent.exe", "ctfmon.exe", "audiodg.exe",
        "shellexperiencehost.exe", "searchui.exe", "startmenuexperiencehost.exe", "lockapp.exe",
        "lockapphost.exe", "smartscreen.exe", "securityhealthservice.exe", "sgrmbroker.exe",
        # search / servicing / telemetry / maintenance
        "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "ngen.exe", "ngentask.exe", "mscorsvw.exe", "tiworker.exe", "trustedinstaller.exe",
        "wuauclt.exe", "usoclient.exe", "mousocoreworker.exe", "musnotification.exe",
        "musnotificationux.exe", "compattelrunner.exe", "devicecensus.exe", "wermgr.exe",
        "werfault.exe", "sppsvc.exe", "sppextcomobj.exe", "slui.exe", "wsqmcons.exe",
        "sihclient.exe", "dmclient.exe", "defrag.exe", "cleanmgr.exe", "dstokenclean.exe",
        "disksnapshot.exe", "provtool.exe", "lpremove.exe", "mcbuilder.exe", "srtasks.exe",
        "aitagent.exe", "installagent.exe", "wifitask.exe", "locationnotificationwindows.exe",
        "wudfhost.exe", "spoolsv.exe", "splwow64.exe", "osppsvc.exe", "sdclt.exe", "mobsync.exe",
        "hubtaskhost.exe", "skypehost.exe", "devicedisplayobjectprovider.exe", "gpupdate.exe",
        "dsregcmd.exe", "vssvc.exe", "msiexec.exe", "waasmedicagent.exe", "sedlauncher.exe",
        # Defender
        "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "mpdefendercoreservice.exe",
        # lab telemetry / management agents
        "sysmon.exe", "sysmon64.exe", "splunkd.exe", "splunk.exe", "btool.exe",
        "splunk-admon.exe", "splunk-netmon.exe", "splunk-monitornohandle.exe",
        "splunk-powershell.exe", "splunk-regmon.exe", "splunk-winprintmon.exe",
        "splunk-winhostinfo.exe", "splunk-perfmon.exe", "splunk-winevtlog.exe",
        "waappagent.exe", "windowsazureguestagent.exe", "collectguestlogs.exe",
        "amazon-ssm-agent.exe", "ec2config.exe", "vmtoolsd.exe", "vm3dservice.exe",
    }
)

# Interactive applications: with no malicious ancestor they may be the lab
# operator's own activity, so they are excluded rather than guessed.
INTERACTIVE_IMAGES = frozenset(
    {
        "explorer.exe", "firefox.exe", "chrome.exe", "msedge.exe", "iexplore.exe",
        "notepad.exe", "notepad++.exe", "7zg.exe", "7zfm.exe", "mmc.exe", "taskmgr.exe",
        "onedrive.exe", "teams.exe", "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "code.exe", "regedit.exe", "procexp.exe", "procexp64.exe", "procmon.exe", "procmon64.exe",
        "mstsc.exe", "rdpclip.exe", "tstheme.exe", "snippingtool.exe", "calc.exe",
        "applicationframehost.exe", "systemsettings.exe", "winver.exe",
        "brave.exe", "opera.exe", "vivaldi.exe",
    }
)

# Defensive tooling present in some recordings (e.g. Raccine intercepting
# vssadmin and running YARA). Neither attack nor ordinary workload: excluded.
DEFENSIVE_IMAGES = frozenset({"raccine.exe", "yara64.exe", "yara32.exe", "yara.exe"})

# Lab telemetry installs: anything whose lineage runs through these paths is the
# recording infrastructure (Splunk forwarder helpers spawn cmd/btool/openssl).
_INFRA_PATH_MARKERS = (
    "\\splunkuniversalforwarder\\", "\\splunk\\bin\\",
    "\\packages\\plugins\\microsoft.",  # Azure VM extensions (CustomScript, NetworkWatcher, ...)
)

# Browsers: always excluded (see label_attack_recording).
BROWSER_IMAGES = frozenset(
    {"firefox.exe", "chrome.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
)

# Cloud / update agents: their whole subtree is platform activity, not the
# attack (found by the label audit: Azure guest-agent logman/CustomScript
# runs, Defender signature updates, the Edge updater).
INFRA_ROOT_IMAGES = frozenset(
    {
        "waappagent.exe", "windowsazureguestagent.exe", "collectguestlogs.exe",
        "am_delta.exe", "am_delta_patch.exe", "mpsigstub.exe",
        "microsoftedgeupdate.exe", "msedgeupdate.exe", "dismhost.exe", "networkwatcheragent.exe",
    }
)

# BOTSv1's documented scenarios: (host prefix, parent leaf, image leaf, scenario).
_BOTSV1_ROOTS: Tuple[Tuple[str, Optional[str], str, str], ...] = (
    ("we1149srv", "php-cgi.exe", "cmd.exe", "botsv1:po1s0n1vy_webshell"),
    ("we1149srv", None, "3791.exe", "botsv1:po1s0n1vy_webshell"),
    ("we8105desk", "winword.exe", "cmd.exe", "botsv1:cerber_macro"),
)


# ------------------------------------------------------------------ helpers


def _lineage(row: Dict[str, Any], by_guid: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ancestors of ``row`` seen in the same recording, nearest first (cycle-safe)."""
    out: List[Dict[str, Any]] = []
    seen = {row.get("guid")}
    current = by_guid.get(row.get("parent_guid") or "")
    while current is not None and current.get("guid") not in seen:
        out.append(current)
        seen.add(current.get("guid"))
        current = by_guid.get(current.get("parent_guid") or "")
    return out


def dedup_key(row: Dict[str, Any]) -> str:
    """Identity of a row *as the featurizer sees it* (plus integrity)."""
    event = row["event"]
    parts = (
        normalize_text(event["process"].get("name")),
        normalize_text(event["parent"].get("name")),
        normalize_text(event["process"].get("command_line")),
        normalize_text(event["process"].get("executable")),
        integrity_category(row.get("integrity")),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


# ------------------------------------------------------------------ labellers


def label_botsv1(rows: List[Dict[str, Any]]) -> None:
    by_guid = {r["guid"]: r for r in rows if r.get("guid")}

    def root_of(row: Dict[str, Any]) -> Optional[str]:
        host = (row.get("host") or "").lower()
        for prefix, parent, image, scenario in _BOTSV1_ROOTS:
            if host.startswith(prefix) and leaf(row["image"]) == image and (
                parent is None or leaf(row["parent_image"]) == parent
            ):
                return scenario
        return None

    for row in rows:
        scenario = root_of(row) or next(
            (s for s in (root_of(a) for a in _lineage(row, by_guid)) if s), None
        )
        if scenario:
            row.update(label=1, label_rule="malicious/documented_scenario", group=scenario)
        else:
            row.update(label=0, label_rule="benign/environment", group=f"botsv1:{row['host']}")


def label_attack_recording(
    rows: List[Dict[str, Any]], group_of: Callable[[Dict[str, Any]], str]
) -> None:
    by_guid = {r["guid"]: r for r in rows if r.get("guid")}
    malicious: Dict[str, bool] = {}

    def is_infrastructure(row: Dict[str, Any]) -> bool:
        lineage = _lineage(row, by_guid)
        paths = [row.get("image"), row.get("parent_image")] + [a.get("image") for a in lineage]
        if any(m in (p or "").lower() for p in paths for m in _INFRA_PATH_MARKERS):
            return True
        if any(leaf(p) in INFRA_ROOT_IMAGES for p in paths):
            return True
        # OTRF compound recordings ship packet captures taken with `netsh trace`;
        # its stop routine runs a diagnostics script (cscript -> reg export, ...).
        if row["source"] == "otrf_compound":
            for node in [row] + lineage:
                if leaf(node.get("image")) == "netsh.exe" and " trace " in f" {(node.get('command_line') or '').lower()} ":
                    return True
        return False

    def is_store_app(row: Dict[str, Any]) -> bool:
        return "\\program files\\windowsapps\\" in (row.get("image") or "").lower() and leaf(
            row.get("parent_image")
        ) in ("svchost.exe", "runtimebroker.exe", "explorer.exe")

    def is_background(row: Dict[str, Any]) -> bool:
        if is_infrastructure(row):
            return True
        if leaf(row["image"]) not in BACKGROUND_IMAGES:
            return False
        lineage = _lineage(row, by_guid)
        if any(leaf(a["image"]) not in BACKGROUND_IMAGES for a in lineage):
            return False
        top = lineage[-1] if lineage else row
        parent = leaf(top["parent_image"])
        return parent == "" or parent in BACKGROUND_IMAGES

    # Parents before children, so "descends from malicious" is already known.
    for row in sorted(rows, key=lambda r: (r["utc"], r["row_id"])):
        image = leaf(row["image"])
        lineage = _lineage(row, by_guid)
        ancestor_malicious = any(malicious.get(a.get("guid") or "", False) for a in lineage)
        if image == "conhost.exe":
            row.update(label=None, label_rule="excluded/console_host")
        elif image in DEFENSIVE_IMAGES:
            row.update(label=None, label_rule="excluded/defensive_tool")
        elif image in BROWSER_IMAGES:
            # Browser sub-processes (renderer, GPU, ...) carry no attacker signal
            # even when an attack opened the browser.
            row.update(label=None, label_rule="excluded/browser")
        elif is_infrastructure(row):
            # Recording / cloud infrastructure wins over inherited labels: an
            # attack that restarts the Splunk forwarder does not make the
            # forwarder's own helpers malicious.
            row.update(label=0, label_rule="benign/infrastructure")
        elif not ancestor_malicious and is_background(row):
            row.update(label=0, label_rule="benign/background")
        elif not ancestor_malicious and (image in INTERACTIVE_IMAGES or is_store_app(row)):
            row.update(label=None, label_rule="excluded/interactive")
        else:
            row.update(label=1, label_rule="malicious/attack_recording")
            malicious[row.get("guid") or row["row_id"]] = True
        row["group"] = group_of(row) if row.get("label") == 1 else f"{row['source']}:{row['host']}"


def technique_group(row: Dict[str, Any]) -> str:
    """Leave-one-technique-out group: the parent ATT&CK technique, else the recording family."""
    techniques = row.get("techniques") or []
    if techniques:
        return "T:" + sorted(techniques)[0].split(".")[0]
    return f"{row['source']}:{row.get('tool') or row['dataset']}"


# ------------------------------------------------------------------ driver


def _by_dataset(rows: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        grouped[row["dataset"]].append(row)
    return grouped


def finalize(labelled: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int, int]:
    """De-duplicate on featurizer input; drop keys seen with both labels.

    Returns (rows, duplicates removed, conflicting keys removed).
    """
    kept: Dict[str, Dict[str, Any]] = {}
    labels_by_key: Dict[str, set] = collections.defaultdict(set)
    for row in sorted(labelled, key=lambda r: (r["source"], r["dataset"], r["utc"], r["row_id"])):
        if row.get("label") is None:
            continue
        key = dedup_key(row)
        row["dedup_key"] = key
        labels_by_key[key].add(row["label"])
        kept.setdefault(key, row)
    conflicts = {k for k, v in labels_by_key.items() if len(v) > 1}
    final = [r for k, r in kept.items() if k not in conflicts]
    duplicates = sum(1 for r in labelled if r.get("label") is not None) - len(kept)
    return final, duplicates, len(conflicts)


def label_all(rows_dir: Path, out_dir: Path, sources: List[str]) -> Dict[str, Any]:
    labelled: List[Dict[str, Any]] = []
    for source in sources:
        for _, rows in sorted(_by_dataset(read_rows(rows_dir, source)).items()):
            if source == "botsv1":
                label_botsv1(rows)
            elif source in ("officer_vm", "optc"):
                pass  # labelled benign by pdtrain.officer_vm (user-recorded ordinary use)
            else:
                label_attack_recording(rows, technique_group)
            labelled.extend(rows)

    rule_counts = collections.Counter((r["source"], r["label_rule"]) for r in labelled)
    final, duplicates, conflicts = finalize(labelled)

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "rows.jsonl.gz"
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        for row in sorted(final, key=lambda r: r["row_id"]):
            handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))

    by_source_label = collections.Counter((r["source"], r["label"]) for r in final)
    manifest = {
        "labeller_version": LABELLER_VERSION,
        "sources": sources,
        "rows_in": len(labelled),
        "by_rule": {f"{s} {rule}": n for (s, rule), n in sorted(rule_counts.items())},
        "duplicates_removed": duplicates,
        "label_conflict_keys_removed": conflicts,
        "rows_out": len(final),
        "rows_out_by_label": dict(sorted(collections.Counter(str(r["label"]) for r in final).items())),
        "rows_out_by_source_label": {f"{s} {lab}": n for (s, lab), n in sorted(by_source_label.items())},
        "malicious_groups": len({r["group"] for r in final if r["label"] == 1}),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    (out_dir / "labels_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def read_labelled(out_dir: Path) -> List[Dict[str, Any]]:
    with gzip.open(out_dir / "rows.jsonl.gz", "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]
