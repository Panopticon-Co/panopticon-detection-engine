# eyedetect — Enterprise Cyber Threat Detection & Automated Response Engine

[![CI](https://github.com/Panopticon-Co/panopticon-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Panopticon-Co/panopticon-detection-engine/actions/workflows/ci.yml)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests: 151 Passed](https://img.shields.io/badge/Tests-151%20passed%2C%202%20skipped-success.svg)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-12%2F12%20Tactics%20Covered-orange.svg)](rules/)
[![Project Status](https://img.shields.io/badge/Status-Active%20Development-yellow.svg)](#project-status)

A detection and automated response system (EDR / XDR) built from scratch in Python to catch and stop cyber threats across endpoints, user identities, networks, and cloud environments.

---

## Project Status

> This is a working prototype under active development.
>
> * All 151 unit tests (plus 2 skipped) and the core detection rules pass.
> * Integrated with the team's C++ Windows kernel endpoint agent ([`officer` / `panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent)) via Panopticon Schema 0.3 (the ingestion adapter also accepts Schema 0.1 / 0.2).
> * Interfaces and detection rules are still evolving between milestones; environment-specific warnings may appear depending on the Python/OS setup.
> * This is a research and educational project, not a commercial product.
>
> Issues and suggestions are welcome via the issue tracker.

---

## C++ Endpoint Agent Integration (`officer` + `eyedetect`)

`eyedetect` connects directly to our team's Windows Endpoint Agent ([`officer` / `panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent), built in C++20).

```text
┌─────────────────────────────────────────────────────────────┐
│                 Windows Endpoint Host                       │
│                                                             │
│  ┌────────────────────────┐      Panopticon Schema 0.3      │
│  │   C++ Officer Agent    │ ─── (NDJSON Pipe Stream) ─────► │
│  │  (`officer-agent.exe`) │     (ETW Kernel + Sysmon)       │
│  └────────────────────────┘                                 │
│                                                             │
│                             ▼                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Python Detection Engine (`eyedetect`)        │ │
│  │                                                        │ │
│  │  1. `OfficerIngestionAdapter` (Schema 0.3 Normalizer)  │ │
│  │  2. `ProcessTree` Lineage Tracker                      │ │
│  │  3. `RuleEvaluator` (84+ Detection Rules)              │ │
│  │  4. `EntityRiskScorer` & MITRE ATT&CK Matrix           │ │
│  │  5. Active Response / Process Termination Playbooks    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Live Interactive Pipeline Demo
Run the live terminal visualizer to see real-time C++ kernel telemetry streaming into the detection engine and auto-remediation playbooks:
```bash
python scripts/demo_edr_pipeline.py
```

### Ingesting Live Telemetry from the C++ Agent:
```bash
# Ingest live C++ Officer agent telemetry stream
python src/main.py --rules rules --officer-ndjson samples/officer_live_sample.ndjson

# Or attach directly to the compiled officer-agent.exe binary
python src/main.py --rules rules --officer --officer-bin path/to/officer-agent.exe
```

> **Full Integration Specs**: See [**`docs/OFFICER_INTEGRATION.md`**](docs/OFFICER_INTEGRATION.md) for the complete data contract, field mappings, and developer architecture.

---

## How to Test & Verify

Follow these steps to set up, test, and evaluate `eyedetect` on any Windows, macOS, or Linux environment:

### Prerequisites
* Python 3.9, 3.10, 3.11, or newer installed.
* Git installed.

---

### Step 1: Clone the Repository
Open PowerShell or your system terminal and clone the repository:
```bash
git clone https://github.com/Panopticon-Co/panopticon-detection-engine.git
cd panopticon-detection-engine
```

---

### Step 2: Install Dependencies
Install the required lightweight packages:
```bash
pip install -r requirements.txt
```
*(Dependencies: `pydantic`, `pyyaml`, `pytest`)*

> **Windows Tip**: If `python` opens the Microsoft Store or shows an alias error, run using your direct Python path (e.g., `py -m pip install -r requirements.txt` or `& "C:\Users\<user>\anaconda3\python.exe"`).

---

### Step 3: Run the Automated Engine Test Suite
Run the automated test suite to verify math algorithms, deobfuscators, process trees, and detection logic:
```bash
pytest -v tests/
```
* **Expected Result**: `151 passed, 2 skipped` (across all test modules).

---

### Step 4: Run the Master Cyber Attack Simulation
Run the full-spectrum enterprise threat simulation to observe detection cards and automated auto-remediation playbooks in real time:
```bash
python src/main.py --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson
```
* **What You Will See**:
  * **Threat Detection Cards**: Clearly explains what the attacker attempted in human-readable terms.
  * **Automated Defense**: Real-time process termination, file quarantine to encrypted vaults, account lockouts, and cloud access key revocations.
  * **Executive Summary**: Final tally of intercepted attacks and containment actions.

---

### Step 5: Audit MITRE ATT&CK & Taxonomy Compliance
Generate full terminal heatmaps and audit scorecards verifying coverage across all 12 MITRE Enterprise tactics and 14 cybersecurity threat domains:
```bash
python src/main.py --mitre-matrix --audit-taxonomy
```

---

## Additional Dedicated Test Scenarios

### Identity & Active Directory UEBA Simulation
Simulate and detect account brute-force attacks, distributed password spraying, and Kerberoasting:
```bash
python src/main.py --rules rules --telemetry samples/identity_threat_simulation.ndjson
```

### Enterprise Multi-Hop Cross-Domain Lateral Movement
Simulate and track an attacker moving laterally from a phished laptop across servers to a Domain Controller and Cloud:
```bash
python src/main.py --rules rules --telemetry samples/enterprise_cloud_attack_simulation.ndjson
```

---

## Core Capabilities & Architecture

| Subsystem | Threat Vectors Detected | Automated Defense Action |
| :--- | :--- | :--- |
| **Endpoint / EDR** | Process Injection, BYOVD Drivers, LSASS Dumps, SAM Dumps, Wipers, LOLBAS | `KILL_PROCESS_TREE`, `QUARANTINE_FILE` |
| **C++ Agent Ingest** | Windows ETW Kernel Process Starts & Sysmon Event Subscriptions (Schema 0.3) | `KILL_PROCESS_TREE`, `QUARANTINE_FILE` |
| **Ransomware Shield** | Decoy Canary file tripwires, Mass extension changes | `ISOLATE_HOST`, `TERMINATE_PROCESS` |
| **Identity / ITDR** | Brute Force, Password Spraying, DCSync, Kerberoasting, Golden Ticket | `LOCK_USER_ACCOUNT`, `REVOKE_SESSIONS` |
| **Network / NDR** | C2 Periodic Beaconing (Jitter CV ≤ 0.22), DNS Tunneling, DGA, Port Scans | `BLOCK_FIREWALL_IP`, `ISOLATE_HOST` |
| **Cloud & Workload** | AWS IAM Backdoor Keys, S3 Public Leaks, Kubernetes Container Escape | `REVOKE_ACCESS_KEY`, `RESTRICT_BUCKET` |
| **Enterprise Graph** | Multi-hop lateral pivot chains across endpoints and cloud | `ENTERPRISE_ISOLATE_PIVOT_PATH` |

---

## Repository Structure
```text
eyedetect/
├── rules/                    # 84 YAML-based Sigma/Wazuh detection rules
│   ├── cloud/                # AWS, GCP, and Kubernetes rules
│   ├── identity/             # Active Directory & authentication rules
│   ├── network/              # DNS, C2, and port scanning rules
│   ├── persistence/          # Registry, services, and scheduled tasks
│   ├── privilege_escalation/ # UAC bypass, token impersonation, BYOVD
│   ├── process/              # Office spawns, LSASS dump, LOLBAS, injection
│   └── malware/              # Droppers, wipers, ransomware canaries
├── src/
│   ├── ingestion/            # Telemetry stream readers & C++ Officer adapter
│   │   ├── event_reader.py   # Streaming NDJSON reader
│   │   ├── officer_adapter.py# Panopticon Schema 0.3 ingestion adapter
│   │   └── live_stream.py    # Subprocess & live socket stream manager
│   ├── evaluator/            # Core matching & condition engine
│   ├── correlation/          # Process tree, graph correlation & risk scorer
│   ├── identity/             # ITDR & UEBA analytics
│   ├── network/              # Beaconing jitter & port scan detectors
│   ├── cloud/                # AWS, GCP & Kubernetes engines
│   ├── remediation/          # Automated process killing & quarantine
│   ├── threat_intel/         # In-memory IOC hash & IP blacklists
│   ├── alerting/             # Plain-English alert cards & active response
│   └── main.py               # Master CLI entrypoint
├── samples/                  # Attack simulations & live Officer NDJSON captures
└── tests/                    # 151 automated pytest unit tests (100% passing, +2 skipped)
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.
