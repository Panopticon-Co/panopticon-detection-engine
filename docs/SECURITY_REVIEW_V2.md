# Security Review — V2 reliability

Focused review of the code added/changed for V2 in `panopticon-detection-engine`
(`src/reliability/*`, `src/pipeline_core.py`, the `src/main.py` V2 flags, the
`src/ingestion/live_stream.py` shutdown, deterministic ids in `src/alerting/
alert.py` + `src/correlation/risk_scorer.py`) and the `panopticon-console`
client de-dup. Not a V2 security architecture — just this cycle's diff.

**Result: no high or medium findings.** Notes and low-risk items below.

| Area | Finding |
|---|---|
| SQLite path handling | `--spool-db` (or a test path) → `Path(...).expanduser()`, parent `mkdir(parents=True)`. Repo-relative default (`spool/panopticon-v2.db`), git-ignored. `":memory:"` special-cased. No hardcoded user path in source or tests (tests use `tmp_path`). |
| SQLite permissions | File created by `sqlite3.connect` with the process umask — inherits the user's default. It contains alert payloads only (no secrets). Not world-readable on a normally-configured Windows profile. |
| SQL injection | All 26 `execute()` calls use `?` bind parameters. No f-string / concatenated SQL. `PRAGMA` values (`synchronous`, `busy_timeout`) cannot be bound — they are whitelisted / `int()`-cast in `AlertSpool.__init__` and are not CLI-exposed. |
| SQLite locking | WAL + `PRAGMA busy_timeout` (5s) so a concurrent writer waits rather than erroring. One connection per `AlertSpool` behind an `RLock`; `check_same_thread=False` is safe under that lock. `close()` runs `wal_checkpoint(TRUNCATE)`. |
| Concurrent file access | `IncrementalAlertWriter` is single-writer (the pipeline's one consumer thread) behind a `Lock`; append-only. The console only ever *reads* the file and tolerates a torn final line. Two engines pointed at one file is unsupported and undocumented as supported. |
| Subprocess lifecycle | `stream_from_officer_process` builds `["officer-agent.exe", "--source", <choice>]` — list form, **no `shell=True`**, `--source` from `argparse choices`. New in V2: `CREATE_NEW_PROCESS_GROUP` + `CTRL_BREAK_EVENT` for graceful stop, then `terminate()`/`kill()`. Live-verified: no orphan process. |
| Command construction | The only new subprocess call is `["logman", "stop", "Panopticon-Officer-Process", "-ets"]` — a fixed argument list, no interpolation, `capture_output=True`, `timeout=10`, `check=False`, Windows-only, best-effort. Session name is a module constant. |
| Command-line / path leakage | `_run_streaming_pipeline` prints the spool + sink **paths** (operator-facing, local). It does **not** print telemetry command lines. Alert *evidence* (which can contain attacker command lines) is written only to the NDJSON file the operator chose, exactly as V1 did. Health/metrics files contain counts + timestamps + paths, no evidence. |
| Queue exhaustion / resource | `BoundedEventQueue` is hard-capped (`deque` at capacity). Default policy `block` applies backpressure (no loss, no growth). `drop_*` policies count every drop into `events_failed` — never silent. `Metrics` latency buffer is a fixed 1024-sample ring. `AlertSpool` grows with delivered/dead tombstones (see limitations). |
| Malformed NDJSON | Officer stdout lines that don't parse are dropped by `OfficerIngestionAdapter.parse_line` (returns `None`) exactly as V1. The spool only ever receives `Alert` objects the engine built, so no malformed-payload ingress there; a payload row that somehow won't parse on read is quarantined to `dead`. |
| Partial records | `IncrementalAlertWriter._repair_torn_tail()` truncates a torn final line on open before appending; the console's reader skips a torn final line. A crash can lose at most the last in-flight record's file write — but it is still `pending` in the spool and re-delivered on restart. |
| Duplicate events / alerts | Spool PK on `alert_id` + `INSERT … ON CONFLICT DO NOTHING`; writer indexes existing `alert_id`s; alert ids are deterministic. Restart re-delivery reconciles instead of re-emitting. Console de-dups client-side as a third layer. |
| Crash recovery | `claim_deliverable` never mutates rows, so a crash mid-delivery re-offers the alert; `recover()` drains pending on start. At-least-once, documented. |
| Temporary files | `HealthState.write_json` writes `path + ".tmp"` then `os.replace` (atomic). Predictable sibling name — a minor symlink-preplacement risk **only** if `--health-file` points into a world-writable directory; for a local single-user tool this is acceptable. No other temp files. |
| Local spool contents | Alert payloads (rule id, title, evidence, MITRE mapping). Evidence can contain attacker-influenced strings but **no credentials or secrets** are ever put there by the engine. Same sensitivity class as `alerts.ndjson`, which already existed in V1. |
| Sensitive data in logs | Engine stdout prints alerts (V1 behaviour, unchanged) and the V2 result dict / health text (counts + timestamps + paths). No new secret-bearing output. `logman` output is captured and discarded. |
| Console rendering / XSS | Unchanged and already hardened: `app.js` writes every value via `textContent` / `createTextNode`; server sends `Content-Security-Policy: default-src 'none'; script-src 'self'; …` + `X-Content-Type-Options: nosniff`. The new `dedupe()` only compares `String(alert_id)` and never touches the DOM as HTML. |
| Shutdown races | `StreamingPipeline` uses `threading.Event` for stop; producer + consumer both check it; `queue.close()` releases all waiters; `_drain_spool()` is bounded and monotone (each attempt → delivered or dead). Health/metrics are snapshotted **before** the spool is closed (a use-after-close was found and fixed during development). `KeyboardInterrupt` takes the same path. |

## Low-risk items / recommendations

1. **`done`/`dead` tombstone growth** — `AlertSpool` keeps a payload-NULLed row
   per delivered alert (for dedup) and a full row per dead alert (for
   inspection). A long-lived spool file grows unboundedly. Add a
   `--spool-retain` / periodic prune before any long-running deployment.
2. **Predictable `*.tmp` name** in `HealthState.write_json` — fine locally;
   document that `--health-file` should live in a directory only the running
   user can write.
3. **`logman` availability** — the ETW safety net silently no-ops if `logman`
   is missing or the call times out. The graceful `CTRL_BREAK` path is the
   primary mechanism and does not depend on it.
4. **Two engines, one spool/file** — unsupported; the spool's single-connection
   + `RLock` model and the writer's single-writer assumption both break under
   it. Not a regression (V1 had the same file-clobber hazard) but worth a
   docs note if multi-instance ever comes up.
