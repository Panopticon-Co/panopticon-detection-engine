"""Process-start featurizer for the supervised classifier, version 4 (behavioural, closed vocabulary).

One process-creation event in, one sparse feature vector out. The function is
*event-local* -- it never reads the provenance graph -- so it is stateless and
gives the same answer in training, replay and serving.

Inputs are only what the Officer agent emits on a process start:
``process.name``, ``process.executable``, ``process.command_line`` and
``parent.name``. User and integrity level are **not** features any more
(v4): in the training data both mostly identify *where* a row was recorded
(lab attacks ran as a user at High integrity, lab background as SYSTEM, two
benign sources carry no integrity), not what the process did -- see
docs/ml/EVAL_REPORT.md (run v6) and training-plan D21.

Why a closed vocabulary (v4)
----------------------------
v1-v3 hashed free-text n-grams of names, paths and command lines. Two
ablations showed they added nothing measurable, while the top hashed buckets
were environment fingerprints (one lab's git flags, another's script paths)
and collisions made them impossible to audit. v4 keeps only:

* identity for a fixed list of security-relevant Windows binaries
  (:data:`ROLE_MEMBERS`, from ``rules/lists`` and the LOLBAS project); every
  other binary is ``other``, so arbitrary software names cannot be learned;
* the *role* of the process and its parent, and the role pair;
* command-line indicators defined from LOLBAS / MITRE ATT&CK documentation
  (:data:`INDICATORS`), written before any v4 model was trained;
* path semantics (location class, a Windows binary name outside the system
  directories, double extensions) and a few shape statistics.

An optional *token vocabulary* (``featurize(..., vocabulary=...)``) appends
one column per known token after :data:`FEATURE_NAMES`; the training tool
builds it from tokens seen in several environments and ships it with a model.

Determinism: no hashing, no set iteration, every value finite. Bump
:data:`FEATURIZER_VERSION` on any change to names, order or normalisation.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from panopticon_detection.enrichment import classify_path
from panopticon_detection.evaluator.deobfuscator import CommandDeobfuscator
from panopticon_detection.evaluator.entropy import ShannonEntropyCalculator

FEATURIZER_VERSION = 4

# ------------------------------------------------------------- normalisation
# Unchanged from v3: training de-duplicates rows on this normalisation.

_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HEX = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b")
# Per-run random file names (PowerShell Add-Type's csc.exe temp files, etc.).
_RANDOM_FILE = re.compile(r"\b[a-z0-9]{8}\.(cmdline|dll|pdb|out|err|tmp|0)\b")
_DIGITS = re.compile(r"\d{3,}")
_USER_DIR = re.compile(r"([a-z]:\\users\\)[^\\\"' ]+")
_SYSTEM_DIRS = re.compile(r"[a-z]:\\windows\\(?:system32|syswow64|sysnative)")
_WINDOWS_DIR = re.compile(r"[a-z]:\\windows")
_PROGRAM_FILES = re.compile(r"[a-z]:\\program files(?: \(x86\))?")
_SPACES = re.compile(r"\s+")


def normalize_text(value: Optional[str]) -> str:
    """Lower-case and replace per-machine detail with placeholders.

    Usernames in profile paths, GUIDs, long hex and digit runs and the
    system directories are replaced (ProblemChild's normalisation). Carets are
    dropped because cmd.exe ignores them outside quotes.
    """
    if not value:
        return ""
    text = str(value).replace("^", "").lower().replace("/", "\\")
    text = _GUID.sub("<guid>", text)
    text = _USER_DIR.sub(r"\1<user>", text)
    text = _SYSTEM_DIRS.sub("win_system_dir", text)
    text = _WINDOWS_DIR.sub("win_dir", text)
    text = _PROGRAM_FILES.sub("program_files_dir", text)
    text = _RANDOM_FILE.sub(r"<rand>.\1", text)
    text = _HEX.sub("<hex>", text)
    text = _DIGITS.sub("<n>", text)
    return _SPACES.sub(" ", text).strip()


# ---------------------------------------------------------------- vocabulary

#: Role -> member binaries. A binary belongs to exactly one role (first listed
#: wins). Sources: rules/lists (office, script_hosts, discovery_tools) and the
#: LOLBAS project's binaries; nothing here was chosen from model errors.
ROLE_MEMBERS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("office", ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                "mspub.exe", "visio.exe")),
    ("browser", ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe",
                 "microsoftedge.exe")),
    ("shell", ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")),
    ("script_host", ("wscript.exe", "cscript.exe", "mshta.exe")),
    ("lolbin", ("rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                "cmstp.exe", "msiexec.exe", "odbcconf.exe", "forfiles.exe", "pcalua.exe", "msdt.exe", "msxsl.exe",
                "hh.exe", "ieexec.exe", "infdefaultinstall.exe", "presentationhost.exe",
                "syncappvpublishingserver.exe", "control.exe", "atbroker.exe", "mavinject.exe", "verclsid.exe",
                "xwizard.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "esentutl.exe", "expand.exe",
                "extrac32.exe", "makecab.exe", "replace.exe", "desktopimgdownldr.exe", "finger.exe", "csc.exe",
                "vbc.exe", "jsc.exe", "ftp.exe", "curl.exe", "scriptrunner.exe", "wsl.exe", "bash.exe",
                "cmdl32.exe", "diskshadow.exe", "dnscmd.exe", "mmc.exe", "createdump.exe", "sqldumper.exe",
                "rpcping.exe", "wuauclt.exe", "msconfig.exe", "ntdsutil.exe", "procdump.exe")),
    ("admin_tool", ("schtasks.exe", "at.exe", "sc.exe", "reg.exe", "regedit.exe", "vssadmin.exe", "wbadmin.exe",
                    "bcdedit.exe", "netsh.exe", "wevtutil.exe", "auditpol.exe", "taskkill.exe", "icacls.exe",
                    "takeown.exe", "attrib.exe", "fsutil.exe", "cipher.exe", "psexec.exe", "psexesvc.exe")),
    ("discovery", ("whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe",
                   "quser.exe", "qwinsta.exe", "tasklist.exe", "netstat.exe", "arp.exe", "route.exe",
                   "hostname.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "cmdkey.exe", "adfind.exe")),
    ("service_host", ("services.exe", "svchost.exe", "wmiprvse.exe", "taskeng.exe", "taskhost.exe",
                      "taskhostw.exe", "dllhost.exe")),
    ("session", ("explorer.exe", "userinit.exe", "winlogon.exe", "runtimebroker.exe", "sihost.exe")),
    ("server_app", ("w3wp.exe", "php-cgi.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "tomcat.exe",
                    "tomcat8.exe", "tomcat9.exe")),
    ("system_core", ("smss.exe", "csrss.exe", "wininit.exe", "lsass.exe", "werfault.exe", "consent.exe")),
)
ROLES: Tuple[str, ...] = tuple(role for role, _ in ROLE_MEMBERS) + ("other", "missing")
ROLE_OF: Dict[str, str] = {}
for _role, _members in ROLE_MEMBERS:
    for _member in _members:
        ROLE_OF.setdefault(_member, _role)
BINARIES: Tuple[str, ...] = tuple(member for _, members in ROLE_MEMBERS for member in members)
#: Binaries that ship in the Windows directories: found elsewhere, the name is a masquerade signal.
_WINDOWS_BINARIES = frozenset(
    b for b in BINARIES if ROLE_OF[b] not in ("office", "browser", "server_app")
    and b not in ("pwsh.exe", "psexec.exe", "psexesvc.exe", "adfind.exe", "procdump.exe", "sqldumper.exe",
                  "curl.exe")
)
_PATH_CLASSES = ("system", "program_files", "user_writable", "temp", "other", "unknown", "none")

#: Command-line indicators (name, pattern), matched on the lower-cased
#: command line with carets removed. Defined from LOLBAS / ATT&CK technique
#: documentation. Every one may only *raise* a score (monotone constraint).
INDICATORS: Tuple[Tuple[str, str], ...] = (
    ("ps_encoded", r"(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c)?\s+[a-z0-9+/=]{16,}"),
    ("ps_hidden_window", r"[-/]w(?:indowstyle)?\s+h(?:idden)?\b"),
    ("ps_exec_bypass", r"[-/](?:ex(?:ec(?:utionpolicy)?)?|ep)\s+(?:bypass|unrestricted)\b"),
    ("ps_noprofile", r"[-/]nop(?:rofile)?\b"),
    ("ps_noninteractive", r"[-/]noni(?:nteractive)?\b"),
    ("ps_iex", r"\b(?:iex|invoke-expression)\b"),
    ("download_cradle", r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|"
                        r"invoke-restmethod|\birm\b|start-bitstransfer|\bwget\b|\bcurl\b"),
    ("url", r"\b(?:https?|ftp)://"),
    ("ip_literal", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("unc_path", r"\\\\[a-z0-9._$-]+\\"),
    ("base64_blob", r"[a-z0-9+/]{40,}={0,2}"),
    ("frombase64", r"frombase64string"),
    ("reflective_load", r"reflection\.assembly|\[system\.reflection|assembly\]::load"),
    ("defender_tamper", r"set-mppreference|add-mppreference|disablerealtimemonitoring|amsiutils|amsiinitfailed"),
    ("scriptlet_remote", r"scrobj\.dll|/i:(?:https?|\\\\)"),
    ("script_protocol", r"\b(?:javascript|vbscript):"),
    ("rundll32_ordinal", r"rundll32(?:\.exe)?[\"']?\s+[^,]+,\s*#\d"),
    ("certutil_transfer", r"certutil(?:\.exe)?[\"']?\s.*[-/](?:urlcache|decode|encode|verifyctl)\b"),
    ("bitsadmin_transfer", r"bitsadmin(?:\.exe)?[\"']?\s.*/(?:transfer|addfile|setnotifycmdline)\b"),
    ("mshta_remote", r"mshta(?:\.exe)?[\"']?\s+[\"']?(?:https?|ftp)://"),
    ("msiexec_remote", r"msiexec(?:\.exe)?[\"']?\s.*/[iq]\S*\s+[\"']?https?://"),
    ("wmic_process_create", r"wmic.*process\s+call\s+create"),
    ("wmic_remote_node", r"wmic.*/node:"),
    ("schtasks_create", r"schtasks(?:\.exe)?[\"']?\s.*/create\b"),
    ("service_create", r"\bsc(?:\.exe)?[\"']?\s+(?:\\\\\S+\s+)?(?:create|config)\b.*binpath|new-service\b"),
    ("run_key_write", r"(?:reg(?:\.exe)?[\"']?\s+add|set-itemproperty|new-itemproperty)"
                      r".*\\currentversion\\run(?:once)?\b"),
    ("hive_dump", r"reg(?:\.exe)?[\"']?\s+save\s+hklm\\(?:sam|system|security)\b"),
    ("shadow_delete", r"vssadmin.*delete\s+shadows|shadowcopy\s+delete|wbadmin.*delete\s+catalog|"
                      r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures"),
    ("log_clear", r"wevtutil(?:\.exe)?[\"']?\s+(?:cl|clear-log)\b|clear-eventlog|remove-eventlog"),
    ("firewall_change", r"netsh.*(?:advfirewall|firewall).*\b(?:add|set|delete|disable|off)\b|netsh.*portproxy"),
    ("account_add", r"\bnet1?(?:\.exe)?[\"']?\s+(?:user|localgroup|group)\b.*/add\b|new-localuser|"
                    r"add-localgroupmember"),
    ("discovery_command", r"\bwhoami\b|\bnet1?(?:\.exe)?[\"']?\s+(?:user|group|localgroup|view|share|session|"
                          r"accounts)\b|\bnltest\b|\bsysteminfo\b|ipconfig\s+/all|\bquser\b|query\s+user|"
                          r"\barp\s+-a\b|\bdsquery\b|\badfind\b|get-ad(?:user|computer|group)\b"),
    ("lsass_access", r"\blsass\b|minidump"),
    ("credential_tooling", r"mimikatz|sekurlsa|lsadump|kerberos::|rubeus|kerberoast|ntds\.dit"),
    ("remote_exec", r"\bpsexec|\\admin\$|\\c\$|\bwinrs\b|invoke-command\s.*-computername|enter-pssession|"
                    r"new-pssession"),
    ("wmi_dcom_exec", r"invoke-wmimethod|win32_process|mmc20\.application|shellwindows|shellbrowserwindow"),
    ("script_from_user_dir", r"(?:\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|\\downloads\\)"
                             r"[^\s\"']*\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|dll|scr|wsf)\b"),
    ("archive_staging", r"compress-archive|\b7za?(?:\.exe)?[\"']?\s+a\b|\brar(?:\.exe)?[\"']?\s+a\b"),
    ("hide_attrib", r"\battrib(?:\.exe)?[\"']?\s.*\+[hs]\b"),
    ("acl_takeover", r"icacls.*/grant\s+(?:everyone|\*s-1-1-0)|takeown(?:\.exe)?[\"']?\s+/f\b"),
    ("uac_bypass", r"\\ms-settings\\shell\\open\\command|\\mscfile\\shell\\open\\command|\bfodhelper\b|"
                   r"\bcomputerdefaults\b|\bsdclt\b.*/kickoffelev"),
    ("string_obfuscation", r"\[char\]\s*\d|-join\s*\(|-bxor\b|-f\s*[\"']\{\d\}"),
    ("command_chaining", r"&&|\|\||\s&\s|\s\|\s"),
)
_INDICATOR_RE: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple((n, re.compile(p)) for n, p in INDICATORS)
_DOUBLE_EXTENSION = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip)\.(?:exe|scr|com|bat|cmd|pif|js|vbs|hta)$")
_TOKEN = re.compile(r"[a-z0-9_.$<>-]+")

#: Shape statistics; they may encode an environment's habits, so the training
#: tool can ablate them as one family.
STATS_FEATURES: Tuple[str, ...] = (
    "cmd_length", "cmd_token_count", "cmd_entropy", "cmd_quote_count", "cmd_special_char_ratio",
    "name_length", "name_entropy", "name_digit_ratio", "path_depth",
)
_DENSE: Tuple[str, ...] = (
    "cmd_missing", "name_missing", "parent_missing",
    "cmd_obfuscated", "cmd_evasion_count",
    *(f"ind_{name}" for name, _ in INDICATORS),
    "path_masquerade", "name_double_extension", "name_not_exe", "name_equals_parent",
    *(f"path_class={c}" for c in _PATH_CLASSES),
    *STATS_FEATURES,
)
FEATURE_NAMES: Tuple[str, ...] = (
    *_DENSE,
    *(f"bin={b}" for b in BINARIES), "bin=other",
    *(f"parent_bin={b}" for b in BINARIES), "parent_bin=other", "parent_bin=missing",
    *(f"role={r}" for r in ROLES),
    *(f"parent_role={r}" for r in ROLES),
    *(f"pair={p}>{c}" for p in ROLES for c in ROLES),
)
_INDEX: Dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}
#: Features that may only raise a score (LightGBM monotone constraint +1).
MONOTONE_FEATURES: Tuple[str, ...] = (
    "cmd_obfuscated", "cmd_evasion_count", *(f"ind_{name}" for name, _ in INDICATORS),
    "path_masquerade", "name_double_extension",
)

_SYSTEM_ACCOUNTS = ("system", "local system")
_SERVICE_ACCOUNTS = ("local service", "network service", "servicio local", "servicio de red")
_NT_AUTHORITY = ("nt authority", "nt-autorität", "autorite nt")


def _add(vector: Dict[int, float], index: int, value: float = 1.0) -> None:
    vector[index] = vector.get(index, 0.0) + value


def user_category(name: Optional[str], domain: Optional[str]) -> str:
    """``system`` / ``service`` / ``user`` / ``unknown``. Not a v4 feature; kept for data audits."""
    user = (name or "").strip().lower()
    dom = (domain or "").strip().lower()
    if not user:
        return "unknown"
    if user in _SYSTEM_ACCOUNTS or user.endswith("$"):
        return "system"
    if user in _SERVICE_ACCOUNTS or (dom in _NT_AUTHORITY and user not in _SYSTEM_ACCOUNTS):
        return "service"
    return "user"


def integrity_category(value: Optional[str]) -> str:
    """Not a v4 feature; training uses it in de-duplication keys."""
    text = (value or "").strip().lower()
    for level in ("low", "medium", "high", "system"):
        if text.startswith(level):
            return level
    return "missing"


def _field(event: Dict[str, Any], section: str, key: str) -> Optional[str]:
    block = event.get(section)
    if isinstance(block, dict):
        value = block.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _leaf(value: Optional[str]) -> str:
    return (value or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().strip("\"'").lower()


def binary_name(event: Dict[str, Any]) -> str:
    return _leaf(_field(event, "process", "name")) or _leaf(_field(event, "process", "executable"))


def raw_tokens(event: Dict[str, Any]) -> List[str]:
    """Namespaced tokens for an optional token vocabulary: command-line unigrams/bigrams, path tokens."""
    cmd = _TOKEN.findall(normalize_text(_field(event, "process", "command_line")))
    path = _TOKEN.findall(normalize_text(_field(event, "process", "executable")))
    out = {f"c:{t}" for t in cmd} | {f"c:{a} {b}" for a, b in zip(cmd, cmd[1:])} | {f"p:{t}" for t in path}
    return sorted(out)


def _name_entropy(stem: str) -> float:
    return float(ShannonEntropyCalculator.calculate_entropy(stem)) if stem else 0.0


def featurize(event: Dict[str, Any], vocabulary: Optional[Mapping[str, int]] = None) -> Dict[int, float]:
    """Sparse feature vector ``{index: value}`` for one process start.

    ``event`` is a normalized event (``ingestion.telemetry.normalize`` output).
    Absent indices mean 0.0. With ``vocabulary`` (token -> column), token
    ``t`` sets column ``len(FEATURE_NAMES) + vocabulary[t]``.
    """
    vector: Dict[int, float] = {}
    executable = _field(event, "process", "executable")
    command_line = _field(event, "process", "command_line")
    name = binary_name(event)
    parent = _leaf(_field(event, "parent", "name"))

    # -- command line
    if command_line is None:
        _add(vector, _INDEX["cmd_missing"])
    else:
        cmd_l = command_line.replace("^", "").lower()
        cmd_n = normalize_text(command_line)
        deob = CommandDeobfuscator.deobfuscate(command_line)
        _add(vector, _INDEX["cmd_obfuscated"], 1.0 if deob["is_obfuscated"] else 0.0)
        _add(vector, _INDEX["cmd_evasion_count"], float(len(deob["evasion_techniques"])))
        for ind_name, pattern in _INDICATOR_RE:
            if pattern.search(cmd_l):
                _add(vector, _INDEX[f"ind_{ind_name}"])
        length = len(cmd_n)
        _add(vector, _INDEX["cmd_length"], math.log1p(length))
        _add(vector, _INDEX["cmd_token_count"], math.log1p(len(_TOKEN.findall(cmd_n))))
        _add(vector, _INDEX["cmd_entropy"], float(ShannonEntropyCalculator.calculate_entropy(cmd_n)))
        _add(vector, _INDEX["cmd_quote_count"], float(cmd_n.count('"') + cmd_n.count("'")))
        special = sum(1 for ch in cmd_n if not ch.isalnum() and not ch.isspace())
        _add(vector, _INDEX["cmd_special_char_ratio"], round(special / length, 6) if length else 0.0)

    # -- the binary
    path_class = classify_path(executable) or "none"
    path_class = path_class if path_class in _PATH_CLASSES else "other"
    _add(vector, _INDEX[f"path_class={path_class}"])
    if not name:
        _add(vector, _INDEX["name_missing"])
        _add(vector, _INDEX["bin=other"])
        child_role = "missing"
    else:
        stem = name.rsplit(".", 1)[0]
        _add(vector, _INDEX[f"bin={name}"] if name in ROLE_OF else _INDEX["bin=other"])
        child_role = ROLE_OF.get(name, "other")
        _add(vector, _INDEX["name_not_exe"], 0.0 if name.endswith(".exe") else 1.0)
        _add(vector, _INDEX["name_double_extension"], 1.0 if _DOUBLE_EXTENSION.search(name) else 0.0)
        _add(vector, _INDEX["path_masquerade"],
             1.0 if name in _WINDOWS_BINARIES and path_class not in ("system", "none", "unknown") else 0.0)
        _add(vector, _INDEX["name_length"], float(len(stem)))
        _add(vector, _INDEX["name_entropy"], _name_entropy(stem))
        _add(vector, _INDEX["name_digit_ratio"], round(sum(ch.isdigit() for ch in stem) / len(stem), 6) if stem else 0.0)
    if executable:
        _add(vector, _INDEX["path_depth"], float(normalize_text(executable).count("\\")))

    # -- the parent
    if not parent:
        _add(vector, _INDEX["parent_missing"])
        _add(vector, _INDEX["parent_bin=missing"])
        parent_role = "missing"
    else:
        _add(vector, _INDEX[f"parent_bin={parent}"] if parent in ROLE_OF else _INDEX["parent_bin=other"])
        parent_role = ROLE_OF.get(parent, "other")
        if name:
            _add(vector, _INDEX["name_equals_parent"], 1.0 if name == parent else 0.0)
    _add(vector, _INDEX[f"role={child_role}"])
    _add(vector, _INDEX[f"parent_role={parent_role}"])
    _add(vector, _INDEX[f"pair={parent_role}>{child_role}"])

    # -- optional token vocabulary (shipped with a model, built by the training tool)
    if vocabulary:
        base = len(FEATURE_NAMES)
        for token in raw_tokens(event):
            column = vocabulary.get(token)
            if column is not None:
                _add(vector, base + column)

    # Drop explicit zeros so the vector stays sparse and canonical.
    return {i: round(v, 6) for i, v in sorted(vector.items()) if v != 0.0}


def feature_spec() -> Dict[str, Any]:
    """What ``features.json`` records about this featurizer."""
    return {
        "featurizer_version": FEATURIZER_VERSION,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": list(FEATURE_NAMES),
        "indicators": [{"name": n, "pattern": p} for n, p in INDICATORS],
        "monotone_features": list(MONOTONE_FEATURES),
        "stats_features": list(STATS_FEATURES),
    }
