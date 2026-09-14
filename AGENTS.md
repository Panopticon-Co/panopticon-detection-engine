# AGENTS.md — Panopticon Autonomous Agent Guidance & Execution Protocol

This document provides definitive instructions, architectural boundaries, and execution rules for **Antigravity (Enzo)**, **Claude Code**, and all autonomous AI coding agents operating on the **`panopticon-detection-engine`** repository.

---

## 1. Project Context & Ecosystem

* **Repository**: `Panopticon-Co/panopticon-detection-engine` (internal codebase: `eyedetect`).
* **Role**: The central analytical detection, correlation, and response engine for the **Panopticon EDR / XDR Platform**.
* **Organization Topology**:
  * 🛡️ **`panopticon-agent`** (C++20): Windows kernel ETW and Sysmon telemetry collector.
  * 🧠 **`panopticon-detection-engine`** (Python 3.10+): This repository. Evaluates 92 custom YAML detection rules (Sigma/Wazuh-inspired format, **not** Sigma-format), correlates process trees, and produces alerts.
  * 🏢 **`panopticon-manager`** (Python / FastAPI): Central management server. Vendors this repository as a git submodule at `vendor/eyedetect` to run server-side detection.
  * 🖥️ **`panopticon-console`** (Python / HTML5): Lightweight SOC analyst web dashboard that reads `alerts.ndjson`.

---

## 2. Telemetry Contract (Panopticon Schema 0.4)

* This engine ingests telemetry adhering to **Panopticon Schema 0.1, 0.2, 0.3, and 0.4** via `src/ingestion/officer_adapter.py` (`OfficerIngestionAdapter`). Schema 0.4 is the Linux agent's additive procfs extension; wire compatibility is unchanged for 0.1-0.3 producers.
* Supported Telemetry Families:
  1. **Process**: Process start, stop, command lines, parent lineage, and SHA-256 entity hashes (`proc_<sha256>`).
  2. **Network**: Outbound/inbound IP connections, destination ports, protocols (Sysmon Event ID 3).
  3. **File**: File creations, modifications, deletions (Sysmon Event IDs 11, 23, 26).
  4. **Registry**: Registry key creations, value modifications, deletions (Sysmon Event IDs 12, 13, 14).
  5. **Image Load**: Dynamic Link Libraries (DLLs) loaded into processes (Sysmon Event ID 7).
* **Rule**: Never break backward compatibility for Schema 0.1/0.2 when extending Schema 0.3 adapters.

---

## 3. Core Engine Architecture

```text
  [ Telemetry Input (NDJSON / Subprocess / Network Stream) ]
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 1. Ingestion & Normalizer (src/ingestion/officer_adapter.py)│
  │    • Maps Schema 0.3 JSON into internal lookup dictionary. │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 2. Pipeline Core & State (src/pipeline_core.py)             │
  │    • Stateful ProcessTree lineage tracking (GUID / PID).    │
  │    • CommandDeobfuscator (Base64, carets ^, backticks `).   │
  │    • ShannonEntropyCalculator & C2 Beaconing Detectors.     │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 3. Rule Evaluator (src/evaluator/engine.py)                 │
  │    • Evaluates 92 custom YAML MITRE-mapped rules (rules/*). │
  │    • Wazuh severity scoring (Levels 0–16).                  │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 4. Reliability & Alert Sink (src/reliability/)              │
  │    • Bounded Ingestion Queue (queue.py).                    │
  │    • SQLite Durable Alert Spool (spool.py / spool.db).      │
  │    • IncrementalAlertWriter (alert_sink.py -> alerts.ndjson)│
  └─────────────────────────────────────────────────────────────┘
```

---

## 4. Operational Modes & CLI Invocations

### Mode A: Standard Batch & Offline Evaluation
```bash
# Evaluate sample attack telemetry simulation
python src/main.py --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson

# Ingest raw pre-recorded Officer Schema 0.3 capture
python src/main.py --rules rules --officer-ndjson samples/officer_live_sample.ndjson
```

### Mode B: V2 Reliable Streaming Mode (Production Ingest)
```bash
python src/main.py --rules rules --officer-ndjson samples/officer_live_sample.ndjson \
  --reliable --spool-db spool/panopticon.db --output-file alerts.ndjson
```

### Mode C: Live Windows Subprocess Execution
```bash
python src/main.py --rules rules --officer --officer-bin path/to/officer-agent.exe --reliable
```

---

## 5. Agent Verification & Quality Protocol (Strict TDD)

Any AI agent modifying code in this repository **MUST** adhere to the following test protocol:

1. **Mandatory Test Execution**:
   Always run the full pytest suite before and after making changes:
   ```bash
   pytest -q tests/
   ```
   * **Target Quality Standard**: **152+ passed, 0 failures**.
2. **Deterministic Alert IDs**:
   All alerts must derive IDs deterministically via `Alert.from_detection_result` using SHA-256 hashes of `(rule_id, event_id, host_id, timestamp, evidence)` to prevent duplicate alerts during restarts.
3. **Safe Submodule Boundaries**:
   `panopticon-manager` vendors this repository at `vendor/eyedetect` and imports `from src.evaluator.engine import RuleEvaluator` and `from src.pipeline_core import DetectionRun`. Do not alter the constructor signature of `DetectionRun` without updating the manager's factory.
4. **Remediation Safety**:
   Active response playbooks (`KILL_PROCESS_TREE`, `QUARANTINE_FILE`, etc.) must remain safely simulated in development mode unless explicitly instructed.

---

## 6. Project Contacts & Maintainers

* **Aditya Singh** (`Adityasingh230058` / `heyworld`): Detection Engine Lead & Rulebase Architect.
* **Aryan Sokhi** (`sokhiaryan`): C++ Agent & Manager Server Lead.
* **Shreyas Tekawade** (`ShreyasTek1`): Pipeline Reliability & Console UI Lead.
* **Organization**: `https://github.com/Panopticon-Co`
