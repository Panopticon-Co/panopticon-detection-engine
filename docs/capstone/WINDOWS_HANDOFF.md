# Windows handoff: live verification for the capstone demo

You are an AI agent on the **Windows lab endpoint** for Panopticon&Co, a capstone EDR. The
Mac developer environment cannot run the Windows agent ("Officer"), Sysmon or ETW. Your job
is to **verify and report**, not to develop.

The full plan is `docs/plans/ml-integration-demo-plan.md` in `panopticon-detection-engine`;
read sections D and E. Send your report back to the Mac side.

## Ground rules (non-negotiable)

1. **Benign actions only.** Use exactly the commands below:
   - no real credential access;
   - no LSASS access;
   - no malware or downloaded payloads;
   - no Defender exclusions;
   - no disabling security controls.
2. **No code changes.** Do not edit, commit or push in any repo (agent, manager, engine,
   console, contracts). If something is broken, record it with evidence and stop that step.
3. **Do not start the agent with `--enable-response`** unless the owner tells you to.
   - Kill / quarantine / isolate commands must stay PENDING in the approval queue.
   - Never approve one.
4. **Record facts, not expectations.** Write "not observed" when something does not happen.
   Never edit outputs or substitute values from this document.
5. **Clean up after every scenario** (cleanup commands below), even if it failed.

## Topology and prerequisites

```
Windows VM: Sysmon (+ reference config) + officer-agent.exe --source all
   -> HTTPS/HTTP canonical endpoint records 1.0 -> manager POST /api/v2/endpoint/records
Manager host: FastAPI + SQLite + detection worker (vendored engine) -> alerts table + alerts.ndjson
Console: 127.0.0.1:8787 on the manager host (or tunnelled)
```

Check and record each of these:

| Check | How | Expected |
|---|---|---|
| Agent build | `officer-agent.exe --version` (or file hash) | Build from `panopticon-agent` `origin/main` @ `7de7a97`. Fallback: v0.3.0 `3339055`. Record which you used |
| Sysmon running | `sc query Sysmon64` (or `Sysmon`) | RUNNING |
| Sysmon config | `Sysmon64.exe -c` | Matches `panopticon-agent/docs/sysmon/officer-reference-config.xml`. Note whether RegistryEvent (EID 12/13) includes `\CurrentVersion\Run` and FileCreate (EID 11) includes the Startup folder |
| Triggers script | `panopticon-agent` branch `demo/windows-validation`, `tools/demo/demo-triggers.ps1` | present; if not, use the commands below |
| Manager reachable | `curl <manager>/healthz` and `/readyz` | 200 |
| Manager disk | on the manager host, `df -h` for the state dir | **Not** `/srv/panopticon-data` if it is still 100% full. Use `--state-dir` on a volume with space |
| Agent enrolled | manager `GET /api/v1/agents` (token from the owner) | your host listed |
| Clock | `w32tm /query /status` | within a few seconds of the manager |

If the agent cannot run or cannot reach the manager, record why, skip to "Report", and say
the demo falls back to the Mac replay.

## Part A: deterministic detections (always run)

For each scenario:
1. Note the wall-clock time.
2. Run the action from a **non-admin** PowerShell unless stated otherwise.
3. Wait up to 30 s.
4. Verify **independently of the UI**: `GET /api/v1/alerts?rule_id=<ID>` on the manager, or
   `Select-String <ID>` / `grep <ID>` on `$STATE_DIR/alerts.ndjson`.
5. Check the console at 127.0.0.1:8787 shows it.
6. Run cleanup.

| # | Action (exact) | Expected rule | Cleanup |
|---|---|---|---|
| 0 | `notepad.exe` (then close it); `whoami` (no arguments) | **no alert**: benign control | close notepad |
| 1 | `whoami /priv` | DET-PROC-008, level 10 | none |
| 2 | `schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f` | DET-PERS-002, level 10 | `schtasks /delete /tn PanopticonDemo /f` |
| 3 | `cmdkey /list` | DET-CRED-003, level 12; a TERMINATE_PROCESS recommendation **PENDING** in the approval queue (or REJECTED / fail-closed if the record lacks `start_time_ticks`; record which) | none. **Do not approve** |
| 4 | Start a local listener first: `python -m http.server 8080` in an empty temp folder, or skip the listener (the alert fires on the command line). Then `certutil -urlcache -split -f http://127.0.0.1:8080/demo.txt $env:TEMP\ct.txt` | DET-PROC-003, level 12 | `Remove-Item $env:TEMP\ct.txt -ErrorAction SilentlyContinue`; `certutil -urlcache * delete`; stop the listener |
| 5 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PanopticonDemo /t REG_SZ /d notepad.exe /f` | DET-PERS-001, level 12 (needs Sysmon EID 13) | `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PanopticonDemo /f` |
| 6 | In **one** PowerShell window, quickly: `whoami; ipconfig /all; net user; systeminfo` | DET-DISC-001, level 10 (3+ distinct discovery tools under one parent within 60 s) | none |
| 7 | `$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'Panopticon demo'")); powershell -NoProfile -EncodedCommand $b` | DET-PROC-011, level 11 (entropy threshold; it may not fire, so record the result) | none |

Optional, only if EID 11 is configured for the Startup folder:

| # | Action | Expected | Cleanup |
|---|---|---|---|
| 8 | `Copy-Item C:\Windows\System32\notepad.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\pdemo.exe"` | DET-PERS-007 | `Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\pdemo.exe"` |

For each scenario, also record:
- **Count of alerts.** One trigger may produce **two** alerts because ETW and Sysmon both
  report the start. This is a known issue; count them.
- **Latency.** Seconds from action to alert in the API.
- **Evidence fields.** Whether the alert shows `host_id`, process name, command line,
  `detection_source` and `evidence`.
- **Defender / AMSI.** Whether either blocked or warned (expected possibly for 4 and 7).

Repeat scenarios 0–4 a **second time** to confirm they are reproducible.

## Part B: ML integration (run only if the Mac side says Phases 1 and 3 are deployed)

Ask the owner whether the manager is running an engine pin that includes the ML stage and
whether the console renders ML. If not, skip Part B and say so.

1. **Manager environment** (on the manager host):
   - `PANOPTICON_MODEL_PATH=<path to the v7_v5 bundle directory>`. The bundle is copied
     out-of-band; it is not in git.
   - `PANOPTICON_ML_MODE=active`.
   - Optionally, `PANOPTICON_MODEL_SHA256` as provided by the owner.
   - Restart the manager.
2. **Model loaded.** `GET /metrics` (or the startup log) shows:
   - `ml_state` = active;
   - `ml_model_version` starting `v7_lgb_no_stats-`.
   Record the version and `artifact_sha256`. If the log says `ML stage DISABLED: …`, record
   the full message, then continue with Part A (rules must still work, which is itself an
   acceptance check).
3. **Inference on live telemetry.** Re-run scenarios 1, 3, 4 and 7. For each resulting rule
   alert, record its `ml` block:
   - `raw_score`;
   - `band` (null, alert or high);
   - `model_version`.
   Record any `ML-PROC-001` or `ML-PROC-002` alerts. Confirm they show:
   - `detection_source: "ml"`;
   - **no** `active_response`;
   - **no** MITRE tactic;
   - and that nothing for them appears in the approval queue.
4. **Benign baseline.** Use the VM normally for 10 minutes (open Edge, Explorer, Notepad,
   Settings). Count `ML-PROC-*` alerts and list their process names and scores. **Do not
   suppress or tune anything**; this is a disclosed false-positive measurement.
5. **Failure drill.**
   - Point `PANOPTICON_MODEL_PATH` at a copy of the bundle with one byte of `model.json`
     changed, and restart.
   - Expect `ML stage DISABLED` (hash mismatch).
   - Re-run scenarios 1 and 2; both rule alerts must still appear.
   - Restore the real path afterwards.
6. **ML ingestion counters** from `/metrics`, in particular:
   - `ml_scored`;
   - `ml_skipped_no_command_line` (expected large: ETW starts carry no command line);
   - `ml_errors` (expected 0).
   Note whether live Sysmon EID 1 records carry `command_line`.

## Things to note that the Mac side cannot observe

- whether canonical process records group discovery tools under one parent (scenario 6);
- whether EID 13 Run-key writes reach the manager (scenario 5);
- whether DET-CRED-003's kill is PENDING or fail-closed (`start_time_ticks` present?);
- end-to-end latency on real hardware (the Mac measured about 1 s with synthetic records);
- the Defender/AMSI interaction;
- the duplicate (twin) alert count per trigger;
- live ML score distribution and false positives (Part B).

## Report (return this to the Mac side as `WINDOWS_REPORT.md`)

```
Date/time, VM OS build, agent build (commit/hash), Sysmon version + config hash, manager pin, console branch
Prereq table: each check -> result
Part A table: # | fired? (rule ids) | alert count | latency s | in API? | in console? | evidence ok? | Defender note | cleanup done?
Second run of 0-4: same/different
Part B: model loaded? version, sha | per-scenario ml block | ML-PROC alerts (benign session) | failure drill result | counters
Blockers: exact error text, file/endpoint, what you tried
Anything you did not run, and why
```

Attach raw evidence where possible:
- the `alerts.ndjson` lines for each fired alert;
- the API JSON;
- console screenshots: real captures only, never recreated.
