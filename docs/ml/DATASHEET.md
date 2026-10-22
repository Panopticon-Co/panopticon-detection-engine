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
| [DARPA OpTC](https://github.com/FiveDirections/OpTC-data) | public domain (Distribution A) | — | **not obtained**: Google Drive quota (training-plan D3) | planned large benign false-positive test |

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

## Labelling (`tools/train/pdtrain/label.py`, labeller v3)

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
