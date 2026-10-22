"""Where the training data comes from, pinned.

Every remote file is fetched from an immutable location (a git commit or a
Zenodo record) and checked against ``pins.json``. The first fetch of a file
records its SHA-256 there (trust on first use); every later fetch must match.

Licences (recorded again in the datasheet):

* Splunk attack_data -- Apache-2.0
* Splunk BOTSv1 -- CC0-1.0
* OTRF Security-Datasets -- MIT
* WinLOLBIN-GT -- CC BY 4.0 (attribution: Jeremiah, Rafiq et al., DOI 10.5281/zenodo.20533434)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

ATTACK_DATA_REPO = "splunk/attack_data"
ATTACK_DATA_COMMIT = "7be4e723d31aa3c953e99cc99acab3bbd37818c8"
ATTACK_DATA_RAW = f"https://raw.githubusercontent.com/{ATTACK_DATA_REPO}/{ATTACK_DATA_COMMIT}"
# Large files are Git LFS objects; media.githubusercontent.com resolves them.
ATTACK_DATA_MEDIA = f"https://media.githubusercontent.com/media/{ATTACK_DATA_REPO}/{ATTACK_DATA_COMMIT}"
ATTACK_DATA_TREE = (
    f"https://api.github.com/repos/{ATTACK_DATA_REPO}/git/trees/{ATTACK_DATA_COMMIT}?recursive=1"
)

OTRF_REPO = "OTRF/Security-Datasets"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"  # same pin as panopticon_detection.datasets
OTRF_RAW = f"https://raw.githubusercontent.com/{OTRF_REPO}/{OTRF_COMMIT}"
OTRF_TREE = f"https://api.github.com/repos/{OTRF_REPO}/git/trees/{OTRF_COMMIT}?recursive=1"

SYSMON_SOURCE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True)
class StaticFile:
    """A single pinned remote file."""

    key: str
    url: str
    licence: str


BOTSV1_SYSMON = StaticFile(
    key="botsv1/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz",
    url=(
        "https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/"
        "botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz"
    ),
    licence="CC0-1.0",
)

_WINLOLBIN = "https://zenodo.org/api/records/20533434/files/{name}/content"
WINLOLBIN_SAMPLES = tuple(
    StaticFile(key=f"winlolbin/{name}", url=_WINLOLBIN.format(name=name), licence="CC-BY-4.0")
    for name in (
        "winlolbin_gt_sample_unprocessed_benign_500_lines.csv",
        "winlolbin_gt_sample_unprocessed_malicious_500_lines.csv",
        "winlolbin_gt_sample_processed_features_benign_500_lines.csv",
        "winlolbin_gt_sample_processed_features_malicious_500_lines.csv",
    )
)

#: OTRF compound (multi-step, multi-host) recordings: Sysmon with real OS
#: background. Packet captures are excluded -- they carry no process starts.
OTRF_COMPOUND = (
    "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
    "datasets/compound/windows/apt3/empire_apt3.tar.gz",
    "datasets/compound/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz",
    *(
        f"datasets/compound/LSASS_campaign_0{n}/{name}"
        for n, name in (
            (1, "metasploit_logonpasswords_lsass_memory_dump.zip"),
            (2, "metasploit_procdump_lsass_memory_dump.zip"),
            (3, "metasploit_comsvcs_lsass_memory_dump.zip"),
            (4, "metasploit_out-minidump_lsass_memory_dump.zip"),
            (5, "metasploit_sharpdump_lsass_memory_dump.zip"),
            (6, "metasploit_outflank-dumpert_lsass_memory_dump.zip"),
            (7, "metasploit_nanodump_lsass_memory_dump.zip"),
        )
    ),
)

# DARPA OpTC benign eCAR, public domain (Distribution A). Google Drive folder
# 1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa -> ecar/benign/19Sep19/<host range>/.
# Two different 25-host ranges on the same day: one trains, one is a fully
# held-out false-positive test set.
_DRIVE = "https://drive.usercontent.google.com/download?id={id}&export=download&confirm=t"
OPTC_BENIGN = (
    StaticFile(
        key="optc/benign/19Sep19/AIA-51-75.ecar-last.json.gz",
        url=_DRIVE.format(id="1RVK5tuJr1vJ_c-8JWy36SRFZB3u6cSzx"),
        licence="public-domain",
    ),
    StaticFile(
        key="optc/benign/19Sep19/AIA-201-225.ecar-last.json.gz",
        url=_DRIVE.format(id="1rFGhX76Msjqdl39yfK5fAuZDLNhKI-Mb"),
        licence="public-domain",
    ),
)

LICENCES: Dict[str, str] = {
    "attack_data": "Apache-2.0",
    "botsv1": "CC0-1.0",
    "otrf": "MIT",
    "optc": "public-domain",
    "winlolbin": "CC-BY-4.0",
}
