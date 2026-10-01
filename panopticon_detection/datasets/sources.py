"""Vetted OTRF recordings, pinned to one commit and checked by SHA-256.

Each entry was downloaded, inspected (channels, event IDs, field names, time
alignment) and normalised end to end before being listed here; ``exercises``
says which canonical families it contains. ``panopticon-dataset fetch`` refuses
a download whose hash differs, so a reproduction gets exactly these bytes.

Source: https://github.com/OTRF/Security-Datasets (MIT, (c) 2021 Open Threat
Research Forge), commit :data:`OTRF_COMMIT`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
OTRF_BASE = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}/datasets/atomic"


@dataclass(frozen=True)
class OtrfSample:
    name: str
    path: str  # under datasets/atomic/windows/
    sha256: str
    metadata: str  # SDWIN-*.yaml under datasets/atomic/_metadata/
    metadata_sha256: str
    exercises: Tuple[str, ...]

    @property
    def url(self) -> str:
        return f"{OTRF_BASE}/windows/{self.path}"

    @property
    def metadata_url(self) -> str:
        return f"{OTRF_BASE}/_metadata/{self.metadata}"


SAMPLES: Dict[str, OtrfSample] = {
    s.name: s
    for s in (
        OtrfSample(
            "empire_launcher_vbs",
            "execution/host/empire_launcher_vbs.zip",
            "812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c",
            "SDWIN-190518182022.yaml",
            "04f5d168d72ccf00cec9489e3d5951e9b87e893bf88af1f8e8553b5f926dede1",
            ("process", "network", "dns", "process_access", "script_block", "file", "registry", "image_load"),
        ),
        OtrfSample(
            "psh_lsass_memory_dump_comsvcs",
            "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
            "0af9e920220d746432f0972be83ad057629695540aecd68c15869d190786e1ae",
            "SDWIN-201018195009.yaml",
            "8bdae73ea97738b5cfd5303dc0d78fa292a9db713d3a4bee141fe1565c9a1550",
            ("process", "process_access", "file", "registry", "image_load"),
        ),
        OtrfSample(
            "psh_mavinject_dll_notepad",
            "defense_evasion/host/psh_mavinject_dll_notepad.zip",
            "262680222316edb2dc0d7dca380dfe75191fb96779b8dacc8aac8a1d8bdc046b",
            "SDWIN-201019232515.yaml",
            "977bb8e9eeb644f5c06398d129b62bd308d607f9c0d7c90ef23fa2837d538f40",
            ("process", "network", "dns", "remote_thread", "process_access", "file", "registry", "image_load"),
        ),
        OtrfSample(
            "purplesharp_pe_injection_createremotethread",
            "defense_evasion/host/purplesharp_pe_injection_createremotethread.zip",
            "d1cfff7404448fd9ac7558967837a9903bb474957949218c293c09fd56a5ca7a",
            "SDWIN-201023031210.yaml",
            "7884b8e334c71fd62fa4e5e06cb7a517a932b4848da3d1d0c1c9e260df6539ea",
            ("process", "remote_thread", "process_access", "file", "registry", "image_load"),
        ),
        OtrfSample(
            "cmd_bitsadmin_download_psh_script",
            "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
            "8fb7bc9f3d82f672dc39a55e50006137aa540c4a9860acdcc5d08a4fd609b594",
            "SDWIN-201023023651.yaml",
            "dfbd2247bd2b898be68e07415e52fab53741b0d1b8e7f9959c55cc91a5e6fa41",
            ("process", "network", "dns", "process_access", "file", "registry", "image_load"),
        ),
        OtrfSample(
            "cmd_mshta_vbscript_execute_psh",
            "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
            "f5f700bc986bbe73edcc209754b28a3e0ad38c56877f7fc5ed6fd04bc036d9f4",
            "SDWIN-201022025808.yaml",
            "24e22d6aff8c1586c2c12f90cfe0a950b6449e2eaf6cfc8b47974d8fa888b9e7",
            ("process", "process_access", "file", "registry", "image_load"),
        ),
    )
}
