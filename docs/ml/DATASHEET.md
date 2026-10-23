# Datasheet: process-start training and evaluation data

Structure follows Gebru et al., *Datasheets for Datasets*. Raw data lives under the
git-ignored `data/` directory and is rebuilt with `python -m pdtrain fetch` (run from
`tools/train`). Every downloaded file is pinned by SHA-256 in
[`tools/train/pins.json`](../../tools/train/pins.json). Reproduce with
`fetch → normalize → label → experiment`.

## Motivation

The data trains and evaluates a supervised classifier for Windows process starts, in the
style of Elastic's ProblemChild, as a triage signal for the Panopticon detection engine.
It uses only public data, because no benign corpus recorded with the Officer agent exists
yet.

## Sources

| Source | Licence and attribution | Pinned at | Files / size | Role |
|---|---|---|---|---|
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0, © Splunk | commit `7be4e723` | 1,727 files incl. 473 Sysmon logs + YAML; 3.9 GB | malicious examples; same-lab background |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT, © Open Threat Research Forge | commit `d9d40ef1` | 114 atomic + 11 compound recordings + metadata; 180 MB | atomic: leave-source-out test (E3); compound: training |
| [Splunk BOTSv1](https://github.com/splunk/botsv1) | CC0-1.0 | file SHA-256 in pins | 1 Sysmon JSON export; 145 MB | realistic environment: servers train; desktop `we8105desk` is the held-out host (E4) |
| [WinLOLBIN-GT](https://zenodo.org/records/20533434) | **CC BY 4.0**: Jeremiah, D., Rafiq, H. et al., DOI 10.5281/zenodo.20533434 | Zenodo record | 4 sample CSVs (500 rows each); 1.3 MB | out-of-distribution test only (E5); **never trained on** |
| Officer agent recording (own VM) | collected by the project owner; not redistributed | package SHA-256 `d50df8d2…5b879d` | 6 NDJSON segments (each checksum-verified); 46 MB | agent-native benign: E6 test (v2), first half also trains (v3) |
| [DARPA OpTC](https://github.com/FiveDirections/OpTC-data) | public domain (Distribution A) | file SHA-256s in pins | 7 eCAR files, benign period 19 Sep 2019, host ranges AIA-51-75, -151-175, -201-225, -251-275, -301-325, -351-375, -401-425; 11.5 GB (downloaded by the project owner after the anonymous quota blocked automation) | AIA-51-75 trains (v5); the five further ranges also train (v6); AIA-201-225 is held-out test E7 (25 hosts) |
| ATLASv2 (UIUC) with [REAPr ground truth](https://bitbucket.org/sts-lab/reapr-ground-truth) | **licence not verified**: used for evaluation only, nothing redistributed | archive SHA-256 in pins (streamed, never stored) | `atlasv2.tar.gz`, 12.2 GB; only the Sysmon XML exports are read | **training environment (v7)**; first planned as the final test, never scored before the switch (training-plan D20) |
| [COMISET](https://zenodo.org/records/15375146) | **licence not verified** | — (stream stopped) | real-environment JSON, 31.7 GB compressed / 934 GB uncompressed | **not used**: streaming stopped after 1.4 GB for low process-start yield; backup source |

## Composition

| Source | Sysmon process starts | Recordings | Hosts | Rows after labelling + deduplication (malicious / benign) |
|---|---|---|---|---|
| attack_data | 69,889 | 363 | 512 | 5,332 / 268 |
| OTRF atomic | 1,037 | 77 | 98 | 113 / 183 |
| OTRF compound | 1,976 | 9 | 15 | 116 / 180 |
| BOTSv1 | 767 | 1 | 3 | 46 / 262 |
| **Total** | **73,669** | | | **5,607 / 893** (98 malicious technique groups) |

**What each row holds:**
- the engine's normalized process-start event (process name, executable, command line,
  parent name, user);
- Sysmon's IntegrityLevel (present on every row except one);
- labelling context (Sysmon process GUIDs, parent image and command line, host, time).
  This context is never used as a feature.

**Deduplication.** Rows are de-duplicated on what the featurizer sees: normalised name,
parent, path, command line and integrity. 65,572 repeats were removed. 13 keys that
occurred with both labels were dropped.

## Collection and known gaps

- **Splunk attack_data** comes from Atomic Red Team and other technique runs in Splunk's
  Attack Range, plus contributed captures. Most files are attack-only extracts (median 8
  process starts). The background in the larger files is dominated by the Splunk forwarder
  restarting its helpers.
- **OTRF:**
  - Mordor lab recordings on Azure VMs, which carry Azure guest-agent and Defender activity.
  - **466 process starts from 31 NXLog-collected recordings have no ProcessId** and are
    rejected (they're mostly Empire/Covenant runs).
  - 14 recordings were zipped on a Mac. Their AppleDouble members are now skipped (commit
    `60087a9`).
- **BOTSv1:**
  - three hosts of the fictional Wayne Enterprises, 10 and 24 Aug 2016;
  - contains a webshell intrusion (`we1149srv`) and the Cerber ransomware (`we8105desk`);
  - also contains an authorised Nessus scan, kept as benign. It's a realistic,
    attacker-looking benign workload.
- **WinLOLBIN-GT is generated, not captured.** Command lines are copied from LOLBAS/libLOL
  documentation, with placeholders such as `ExampleTask` and `$path`. `raw_event` is
  synthetic, and the benign rows are templated, with implausible parent→child pairs.

## OpTC (`tools/train/pdtrain/optc.py`)

**What it is.** eCAR `PROCESS`/`CREATE` records from the benign collection period. They come
from enterprise-like Windows 10 hosts in DARPA's evaluation network, where user activity was
emulated by scripts, often `python.exe`. That shows up as a fingerprint, `python.exe →
cmd.exe` (see EVAL_REPORT).

**Processing:**
- 61,818 process creates, 50 hosts;
- kernel device paths are mapped to `C:\`;
- **17,106 rows (28%) that name the image without a path are excluded**. The agent never
  emits that shape, and it acted as a label leak;
- 44,712 rows kept, 1,585 distinct after deduplication;
- no integrity level, and no hash.

## Officer agent recording (`tools/train/pdtrain/officer_vm.py`)

**What it is.** 4.5 h of ordinary use of the project owner's Windows 11 VM (arm64),
22–23 Oct 2026. It was collected with the Officer collection kit 1.0.0 (the package says
1.0.1, the packaging version), in the `officer-endpoint-record-1.0` envelope format.

**Kit issues handled:**
1. **Self-tagged records** (215), with the out-of-schema `self` field, are stripped and
   dropped.
2. **Untagged children of self processes** (112). These are processes whose parent PID is a
   self PID (including the supervisor and agent PIDs from `heartbeat.json`), started while
   that parent was alive. They are dropped recursively.
3. **Sysmon/ETW duplicate starts** (2,479). They are matched on PID + image name within 2 s,
   and the Sysmon record is kept. ETW starts without a pair are dropped too, because the
   model scores Sysmon-sourced starts only.
4. **Probe cadence** isn't used for gap detection.
5. **Both kit versions are recorded.**
6. **`git.exe` dominates.** Training uses at most 50 rows per image; test streams keep
   everything.

**Result:** 2,485 Sysmon process starts (884 distinct), all labelled benign as the
user-recorded ordinary use.

**Known limitations:**
- 756 starts have no parent name: Sysmon couldn't resolve the parents of long-running
  services. The live agent behaves the same way.
- The data includes the user's own evening testing.
- There's no integrity level in this recording.

## ATLASv2 (`tools/train/pdtrain/atlasv2.py`)

**What it is.** Two Windows 7 workstations (`h1`, `h2`) used by two experimenters: four
benign days, then one attack day with 10 multi-stage attack scenarios (`s1`–`s4` on h1,
`m1`–`m6` on both hosts). The 12.2 GB archive is streamed over HTTP ranges and never stored;
only the Sysmon Event Viewer XML exports are parsed, and only their process creates kept.

**Labels (fixed in code before any row was looked at by a model):**
- benign days → benign;
- attack day → **malicious** if and only if a REAPr `attack` label matches the process on
  host + PID + creation time (REAPr's `process_uuid` carries the PID and the FILETIME
  creation time; matched within 2 s);
- REAPr also marks long-running processes the attack only touched (`explorer.exe`,
  `lsass.exe`, `svchost.exe` …). Their starts are not attack starts, so they are excluded,
  as are `conhost.exe` and browsers (as everywhere in this pipeline);
- unmatched attack-day starts are the experimenters' ongoing activity → benign.

**Role.** Planned as the untouched final test, it became a training environment in v7
(training-plan D20) before any model scored it. Counts: 164,796 process starts; 159,377
benign-period, 5,098 attack-day background and 87 REAPr-matched attack starts; 234 excluded
(touched-only processes, `conhost.exe`, browsers).

**Caveats:** REAPr itself warns that the attacks are highly redundant across scenarios, so
recall is also reported over unique featurized rows. Windows 7 and 2022-era software differ
from the agent's Windows 10/11 targets.

## Environments (v7, `tools/train/pdtrain/loeo.py`)

From v7, rows are grouped into the environment they were recorded in, and each environment is
held out entirely in turn. Units are featurized rows de-duplicated *within* an environment.

| Environment | Sources | Observed host-hours | Benign / attack units |
|---|---|---|---|
| attack_range | Splunk attack_data | 194.2 | 270 / 5,328 |
| mordor | OTRF atomic + compound | 5.6 | 460 / 246 |
| botsv1 | BOTSv1 | 8.7 | 322 / 51 |
| officer_vm | the project owner's VM | 4.5 | 884 / 0 |
| optc | DARPA OpTC (7 ranges) | 818.6 | 5,229 / 0 |
| atlasv2 | ATLASv2 | 512.6 | 690 / 19 |

27 featurizer keys carry both labels somewhere (for example a user opening Word, which REAPr
counts as part of an attack on ATLASv2); they are never trained on. ATLASv2's 87 attack starts
are 32 distinct rows within ATLASv2 (19 after cross-source de-duplication), as REAPr's
redundancy warning predicts. A sealed agent recording from another machine (`officer_sealed`)
is reserved for a final test and never labelled or trained on.

## Labelling (`tools/train/pdtrain/label.py`, labeller v4)

**v4 (run v6)** adds 12 OS housekeeping binaries to the background list
(`usocoreworker`, `settingsynchost`, `cliprenew`, `chxsmartscreen`, `dxgiadaptercache`,
`wlrmdr`, `microsoftedgecp`, `raserver`, `upfc`, `windows.warp.jitservice`, `ielowutil`,
`officec2rclient`) and two agents to infrastructure (`windowsazurenetagent`,
`monitoringhost`), from the v5 error analysis. Decided after seeing test results.

Labels come from provenance and dataset documentation. **They never come from the engine's
detection rules**, which would make the evaluation circular.

- **BOTSv1:** a process is malicious if and only if it is, or descends from (Sysmon
  ProcessGuid → ParentProcessGuid), a documented attack root:
  - `php-cgi → cmd` and `3791.exe` on `we1149srv`;
  - `winword → cmd` on `we8105desk`.

  Everything else is benign.
- **Attack recordings (background subtraction):**
  - lab and cloud infrastructure (Splunk forwarder paths; Azure, Defender and Edge-update
    agents; `netsh trace` diagnostics in OTRF compound) is **benign/infrastructure**, and
    this overrides any inherited label;
  - OS housekeeping with OS-only lineage is **benign/background**;
  - `conhost.exe`, browsers, defensive tools (Raccine/YARA), interactive applications and
    Store apps outside an attack tree are **excluded**;
  - everything else is **malicious**.
- **Audit:** three assistant-review iterations of 100 rows each.
  - Malicious-label noise fell from ~25% (v1) through ~8% (v2) to ~2–3% (v3); benign
    errors were 0 of 40.
  - **The error analysis then found much higher noise among OTRF malicious rows:** about 17
    of the 25 lowest-scoring were Windows housekeeping. The background list doesn't cover
    every OS binary.
  - A 1,191-row stratified sample is written to `data/labelled/audit_sample.csv` for human
    review; **that review has not been done.**
- **Grouping:** malicious rows are grouped by parent ATT&CK technique from the dataset
  metadata, or by recording family. Benign rows are grouped by source and host.

## Known biases

- **Lab versus enterprise.** Almost all malicious rows, and most benign ones, come from lab
  VMs: Attack Range, Mordor/Azure. Realistic benign desktop activity is limited to one
  BOTSv1 desktop (4.3 observed host-hours).
- **Class balance is inverted.** The training pool is 97% malicious. Calibrated
  probabilities reflect that prevalence, not deployment.
- **Concentrated techniques.** A few techniques produce many near-duplicate rows (T1048 DNS
  exfiltration). Training caps each technique group at 300 rows.
- **Sysmon only.** The agent's ETW process starts carry no command line or user, so the
  data and the model describe Sysmon-sourced starts only.

## Personal data

BOTSv1 identities are fictional (Wayne Enterprises). Lab usernames and hostnames appear in
raw rows. The featurizer never uses user or host identity: it normalises profile paths,
reduces users to system/service/user/unknown, and scrubs harness and lab tokens before
training. No real personal data was collected for this work.

## Maintenance

- **Adding a source:** add a pin in `pdtrain/sources.py` and a reader that produces the
  standard row shape (see `pdtrain/normalize.py` and `pdtrain/optc.py`).
- **Version bumps:** change `LABELLER_VERSION` or `FEATURIZER_VERSION` on any rule change.
  Either bump invalidates trained bundles.
