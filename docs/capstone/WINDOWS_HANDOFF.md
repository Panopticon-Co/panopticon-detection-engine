# Windows handoff: live verification for the capstone demo

You are an AI agent on the **Windows lab endpoint** (and, where noted, the manager host) for
Panopticon&Co, a capstone EDR. The Mac developer environment cannot run the Windows agent
("Officer"), Sysmon or ETW. Your job is to **verify and report**, not to develop.

Background reading: `docs/plans/ml-integration-demo-plan.md` (sections D, E) in
`panopticon-detection-engine`. Your report goes back to the Mac side.

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
   - `demo_up.sh` prints a command that includes it; drop that flag.
   - Kill / quarantine / isolate commands must stay PENDING in the approval queue.
   - Never approve one.
4. **Record facts, not expectations.** Write "not observed" when something does not happen.
   The "predicted" values below are predictions; never copy them into your report as results.
5. **Clean up after every scenario** (cleanup commands below), even if it failed.

## What is already done and verified on the Mac (2026-10-30)

You are verifying these on real Windows telemetry.

| Item | Mac evidence |
|---|---|
| Engine ML stage, ported onto the manager's canonical-record pin | engine branch `ml/scoring-stage-canonical` @ `2730b45`: 538 passed, 15 skipped; rule-sourcing and dependency gates OK. Rules-only output byte-identical (`engine_oracle --check`: identical, on `ml/scoring-stage` @ `0dbd96a`) |
| Model | `v7_v5`, `model_version v7_lgb_no_stats-a4f71136`, `artifact_sha256 9b2837d10fb209c368fca9682fe44909a145a6a36bf8e0083224050edd875303`, thresholds alert 3.4809 / high 4.2005. LOEO re-run: macro recall 0.0838 (−0.211 vs rules), worst held-out 0.1156 FP/h (`docs/ml/MODEL_CARD.md`) |
| Manager | branch `ml/scoring-stage` @ `4e678cc`. Pin → `2730b45`; `?source=ml`; `"ml"` is record-only; ML state on `/api/v1/status` and `/metrics`. New tests pass. 8 other tests fail identically on the old pin (endpoint freshness ×4, legacy schema mirror, wave6 transport ×3) |
| Console | branch `ml/scoring-stage` @ `ffbf890`: "ML" source badge and filter, score chip on rule alerts, "ML triage" detail section. All console tests pass |
| Live prototype | `demo_up.sh` with the real model, then 232 corpus events over HTTP. Result: 30 alerts and 3 incidents; ML scored 32 starts (0.31 ms mean), 2 `ML-PROC-001` findings, 0 response actions from ML, 0 alerts on the benign host. Dashboard showed the ML rows and the detail section |
| Failure drill | Corrupted bundle: `ML stage DISABLED`, and rule alerts identical to rules-only (`scripts/ml_demo.py`, `test_ml_stage_path.py`) |

**Not pushed.** These branches are local to the Mac. Before you start, the owner must push:
- `panopticon-detection-engine` `ml/scoring-stage-canonical` (and `ml/scoring-stage`);
- `panopticon-manager` `ml/scoring-stage`;
- `panopticon-console` `ml/scoring-stage`.

They can also copy the checkouts across. If you cannot get these exact commits
(`git log -1` on each), run **Part A only** and say so.

## Topology and prerequisites

```
Windows VM: Sysmon (+ reference config) + officer-agent.exe --source all
   -> canonical endpoint records 1.0 -> manager POST /api/v2/endpoint/records
Manager host: FastAPI + SQLite + detection worker (vendored engine + ML stage) -> alerts table + alerts.ndjson
Console: 127.0.0.1:8787 on the manager host (or tunnelled: ssh -L 8787:127.0.0.1:8787 <host>)
```

**Manager host setup** (if you operate it; otherwise ask the owner to confirm each line):

```
cd panopticon-manager && git switch ml/scoring-stage && git submodule update --init vendor/eyedetect
# copy the bundle directory data/models/v7_v5 from the Mac (it is git-ignored) to e.g. /opt/panopticon/models/v7_v5
export PANOPTICON_MODEL_PATH=/opt/panopticon/models/v7_v5
export PANOPTICON_ML_MODE=active
tools/demo_up.sh --fresh --state-dir <a volume with free space>   # NOT /srv/panopticon-data if it is still 100% full
curl -s http://127.0.0.1:8000/metrics | grep panopticon_ml_enabled
#   expect: panopticon_ml_enabled{mode="active",version="v7_lgb_no_stats-a4f71136"} 1
```

**Bundle integrity check** on the manager host:

```
python vendor/eyedetect/scripts/ml_demo.py --model /opt/panopticon/models/v7_v5
```

It must:
- exit 0;
- print `artifact_sha256 9b2837d1…`;
- print a table matching `docs/capstone/ML_DEMO_EXPECTED.md`.

Any difference means the copy is wrong or the code differs. Record it.

Check and record each of these:

| Check | How | Expected |
|---|---|---|
| Agent build | `officer-agent.exe --version` (or file hash) | Built from `panopticon-agent` `origin/main` @ `7de7a97` (fallback v0.3.0 `3339055`); record which |
| Sysmon running | `sc query Sysmon64` (or `Sysmon`) | RUNNING |
| Sysmon config | `Sysmon64.exe -c` | Matches `panopticon-agent/docs/sysmon/officer-reference-config.xml`. Note whether RegistryEvent (EID 12/13) includes `\CurrentVersion\Run` and FileCreate (EID 11) the Startup folder |
| Triggers script | `panopticon-agent` branch `demo/windows-validation`, `tools/demo/demo-triggers.ps1` | present; otherwise use the commands below |
| Manager reachable | `curl <manager>/healthz` and `/readyz` | 200 |
| ML loaded | `curl <manager>/metrics` | `panopticon_ml_enabled{…} 1` (Part B only) |
| Agent enrolled | `GET /api/v1/agents` (analyst token from the owner) | your host listed |
| Clock | `w32tm /query /status` | within a few seconds of the manager |

If the agent cannot run or cannot reach the manager, record why, skip to "Report", and state
that the demo falls back to the Mac replay.

## Part A: deterministic detections (always run)

For each scenario:
1. Note the wall-clock time.
2. Run the action from a **non-admin** PowerShell unless stated otherwise.
3. Wait up to 30 s.
4. Verify **independently of the UI**: `GET /api/v1/alerts?rule_id=<ID>` on the manager, or
   `grep <ID> $STATE_DIR/alerts.ndjson`.
5. Check the console shows it.
6. Run cleanup.

| # | Action (exact) | Expected rule | Cleanup |
|---|---|---|---|
| 0 | `notepad.exe` (then close it); `whoami` (no arguments) | **no rule alert**: benign control (see Part B for ML) | close notepad |
| 1 | `whoami /priv` | DET-PROC-008, level 10 | none |
| 2 | `schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f` | DET-PERS-002, level 10 | `schtasks /delete /tn PanopticonDemo /f` |
| 3 | `cmdkey /list` | DET-CRED-003, level 12; a TERMINATE_PROCESS recommendation **PENDING** in the approval queue (or REJECTED / fail-closed if the record lacks `start_time_ticks`; record which) | none. **Do not approve** |
| 4 | Optional listener first: `python -m http.server 8080` in an empty temp folder (the alert fires on the command line either way). Then `certutil -urlcache -split -f http://127.0.0.1:8080/demo.txt $env:TEMP\ct.txt` | DET-PROC-003, level 12 | `Remove-Item $env:TEMP\ct.txt -ErrorAction SilentlyContinue`; `certutil -urlcache * delete`; stop the listener |
| 5 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PanopticonDemo /t REG_SZ /d notepad.exe /f` | DET-PERS-001, level 12 (needs Sysmon EID 13) | `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PanopticonDemo /f` |
| 6 | In **one** PowerShell window, quickly: `whoami; ipconfig /all; net user; systeminfo` | DET-DISC-001, level 10 (≥ 3 distinct discovery tools, one parent, 60 s) | none |
| 7 | `$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'Panopticon demo'")); powershell -NoProfile -EncodedCommand $b` | DET-PROC-011, level 11 (entropy threshold; may not fire, so record the result) | none |

Optional, only if EID 11 is configured for the Startup folder:

| # | Action | Expected | Cleanup |
|---|---|---|---|
| 8 | `Copy-Item C:\Windows\System32\notepad.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\pdemo.exe"` | DET-PERS-007 | `Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\pdemo.exe"` |

For each scenario, also record:
- **Count of alerts.** One trigger may produce **two** rule alerts because ETW and Sysmon both
  report the start. This is a known issue; count them.
- **Latency.** Seconds from action to alert in the API.
- **Evidence fields.** Whether the alert shows `host_id`, process name, command line,
  `detection_source` and `evidence`.
- **Defender / AMSI.** Whether either blocked or warned (expected possibly for 4 and 7).

Repeat scenarios 0–4 a **second time** to confirm they are reproducible.

## Part B: the ML stage on live telemetry (needs the commits above and the bundle)

1. **Model loaded.** `/metrics` shows `panopticon_ml_enabled{mode="active",version="v7_lgb_no_stats-a4f71136"} 1`.
   `GET /api/v1/status` → `detection_worker.ml.ml_state = "enabled"`. If the log says
   `ML stage DISABLED: …`, record the full line and do Part A anyway: rules must still work,
   which is itself an acceptance check.
2. **Live scores.** For each Part A scenario, record:
   - the `ml` block on its rule alert(s): `raw_score`, `band`;
   - any `ML-PROC-001`/`ML-PROC-002` alert (`GET /api/v1/alerts?source=ml`).

   Predicted from synthetic events on the Mac (`docs/capstone/ML_DEMO_EXPECTED.md`); **record
   the actual values, not these**:

   | # | Predicted raw score | Predicted band |
   |---|---|---|
   | 0 notepad | −0.78 | below |
   | 0 whoami | 3.27 | below |
   | 1 | 3.27 | below |
   | 2 | 3.28 | below |
   | 3 | 3.27 | below |
   | 4 certutil | 5.72 | **high → ML-PROC-002** |
   | 5 | 3.45 | below (threshold 3.48) |
   | 6 systeminfo | 3.27 | below |
   | 7 encoded PowerShell | 4.79 | **high → ML-PROC-002** |

   Live events carry the agent's real paths and parent images, so actual scores will differ.
   That difference is exactly what the Mac cannot measure.
3. **Policy on live data.** For every `ML-PROC-*` alert confirm:
   - `detection_source: "ml"`;
   - `active_response: null`;
   - no MITRE tactic;
   - **nothing for it in the approval queue** (`GET /api/v1/response-actions`);
   - the console shows an "ML" badge;
   - its detail has an "ML triage" section.
4. **Benign false-positive measurement.** Use the VM normally for 10 minutes (Edge, Explorer,
   Notepad, Settings, a few PowerShell commands such as `Get-Date`, `dir`).
   - Count `ML-PROC-*` alerts and list process name, parent and score.
   - **Do not tune or suppress anything.**
   - Known risk: on the Mac, almost any start whose parent is PowerShell scored 3.27, just
     under the 3.48 alert threshold. Report how many live PowerShell-spawned starts cross it.
5. **Failure drill.**
   - Copy the bundle, flip one byte in the copy's `model.json`, and point
     `PANOPTICON_MODEL_PATH` at the copy.
   - Restart (`tools/demo_up.sh --stop …`, then up).
   - Expect `/metrics` `panopticon_ml_enabled 0` and `status.detection_worker.ml.ml_state = "disabled"`.
   - Re-run scenarios 1 and 2; both rule alerts must appear.
   - Restore the real path afterwards.
6. **Counters** from `/metrics`, in particular:
   - `panopticon_ml_scored`;
   - `panopticon_ml_skipped_no_command_line` (expected large: ETW starts carry no command line);
   - `panopticon_ml_errors` (expected 0);
   - `panopticon_ml_latency_mean_ms` / `max_ms`.

   Note whether live Sysmon EID 1 records carry `command_line`. If ML scores **0** starts,
   check exactly that and report it.

## Things only this environment can establish

- Whether live canonical process records carry `command_line` and a parent name. On the Mac's
  canonical fixture the parent name was absent; the model tolerates it, but scores shift.
- Live ML score distribution and false-positive count (Part B 2 and 4).
- Whether discovery tools group under one parent on the canonical path (scenario 6).
- Whether EID 13 Run-key writes reach the manager (scenario 5).
- Whether DET-CRED-003's kill is PENDING or fail-closed (`start_time_ticks` present?).
- End-to-end latency on real hardware (the Mac measured about 1 s with synthetic records).
- Defender/AMSI interaction, and the twin-alert count per trigger.
- Whether the ML alert's `alert_id` is `ALT-…` on canonical records. This is expected: the
  canonical path re-derives per-record ids, so identify ML by `rule_id ML-PROC-*` and
  `detection_source ml`, not by id prefix.

## Report (return this to the Mac side as `WINDOWS_REPORT.md`)

```
Date/time, VM OS build, agent build (commit/hash), Sysmon version + config hash,
engine/manager/console commits actually running, bundle artifact_sha256 printed by ml_demo.py
Prereq table: each check -> result
Part A table: # | fired? (rule ids) | alert count | latency s | in API? | in console? | evidence ok? | Defender note | cleanup done?
Second run of 0-4: same/different
Part B: model loaded? | per-scenario actual raw_score/band vs predicted | ML-PROC alerts (with policy checks)
        | benign 10-min session: ML-PROC count + list | failure drill result | counters
Blockers: exact error text, file/endpoint, what you tried
Anything you did not run, and why
```

Attach raw evidence where possible:
- the `alerts.ndjson` lines for each fired alert;
- the API JSON;
- the `/metrics` ML lines;
- console screenshots: real captures only, never recreated.
