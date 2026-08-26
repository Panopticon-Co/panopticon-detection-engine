# 🛡️ Panopticon EDR Integration Guide: Officer (C++) ➔ eyedetect (Python)

---

## 📌 Overview for Teammates & Collaborators

This repository (`eyedetect`) is the **Central Detection, Correlation, and Automated Response Engine** for the Panopticon EDR / XDR Capstone Project.

It is designed to connect directly with the **Windows Kernel Telemetry Agent** ([`Panopticon-Co/panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent), internally named "Officer"), written in **C++20**.

---

## 🏗️ End-to-End Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  Windows Endpoint Host                                 │
│                                                                                        │
│   ┌────────────────────────────────────────┐                                           │
│   │    Sokhiaryan's C++ Endpoint Agent     │                                           │
│   │               (`officer`)              │                                           │
│   │  • ETW Kernel Process Trace Provider   │                                           │
│   │  • Sysmon Event Log Subscriptions      │                                           │
│   │  • CNG SHA-256 Entity Hashes (proc_*)  │                                           │
│   └───────────────────┬────────────────────┘                                           │
│                       │                                                                │
│                       │  Panopticon Schema 0.2 Stream                                  │
│                       │  (Unbuffered NDJSON Pipe / Named Pipe)                         │
│                       ▼                                                                │
│   ┌────────────────────────────────────────┐                                           │
│   │   Aditya's Python Detection Engine     │                                           │
│   │             (`eyedetect`)              │                                           │
│   │  • Officer Ingestion Adapter (v0.2)    │                                           │
│   │  • Stateful ProcessTree Tracker        │                                           │
│   │  • 84+ Wazuh/Sigma Rules Evaluator     │                                           │
│   │  • Entity Risk Scorer & MITRE Matrix   │                                           │
│   │  • Automated Process Kill / Quarantine │                                           │
│   └────────────────────────────────────────┘                                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔌 The Data Contract (Panopticon Schema 0.2)

The C++ agent emits single-line JSON objects matching this format:

```json
{
  "schema_version": "0.2",
  "event": {
    "id": "evt_7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    "category": "process",
    "type": "start",
    "timestamp": "2026-08-18T12:01:05.000Z"
  },
  "source": {
    "kind": "sysmon",
    "provider": "Microsoft-Windows-Sysmon",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "record_id": 202
  },
  "agent": {
    "id": "officer-agent-001",
    "version": "0.2.0"
  },
  "host": {
    "id": "OFFICER-WIN11-LAB",
    "hostname": "OFFICER-WIN11-LAB",
    "os": { "name": "Windows 11 Pro", "build": "26100" }
  },
  "user": {
    "name": "analyst",
    "domain": "LAB",
    "sid": "S-1-5-21-1000-1001"
  },
  "process": {
    "entity_id": "proc_8f14e45fceea167a5a36dedd4bea2543d3b76251b5c46e30ebdf0129f1234567",
    "pid": 4100,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -w hidden -enc SQBFAFgA...",
    "parent": {
      "entity_id": "proc_1111111111111111111111111111111111111111111111111111111111111111",
      "pid": 3000,
      "name": "winword.exe"
    },
    "hash": {
      "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  }
}
```

---

## ⚡ How to Run the Integrated EDR Pipeline

### Option 1: Run the Interactive Visual Demo (Recommended)
Run the live terminal visualizer to see the C++ telemetry streaming into the detection engine in real time:
```bash
python scripts/demo_edr_pipeline.py
```

### Option 2: Run Telemetry Ingestion from Officer NDJSON Logs
```bash
python src/main.py --rules rules --officer-ndjson samples/officer_live_sample.ndjson
```

### Option 3: Launch & Pipe Live `officer-agent.exe`
```bash
python src/main.py --rules rules --officer --officer-bin path/to/officer-agent.exe
```

---

## 🧪 Testing the Integration
Run the automated integration tests anytime:
```bash
pytest -v tests/test_officer_integration.py
```
*(Tests cover Schema 0.2 parsing, entity ID extraction, process tree ancestry tracking, and live threat detection using fixture/sample NDJSON — no C++ build required.)*

To additionally test against a real, compiled `officer-agent.exe` artifact (spawning it as a subprocess and reading its stdout, the same code path Option 3 above uses), set `OFFICER_AGENT_BIN` and run:
```bash
OFFICER_AGENT_BIN=/path/to/officer-agent.exe pytest -v tests/test_officer_artifact_integration.py
```
This proves the artifact-consumption boundary (the binary launches, the pipe is read, the process exits cleanly) works. It does **not** prove real ETW/Sysmon telemetry content is correct — that requires running on an elevated Windows session with Sysmon installed, which is validated separately on real hardware, not by this test.
