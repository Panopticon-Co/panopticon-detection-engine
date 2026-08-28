# V2 — Reliability & Continuous Streaming

Status: **implemented, tested, and live-validated on elevated Windows x64 + Sysmon.**
Opt-in via `--reliable`. The default CLI path is byte-for-byte unchanged V1.

---

## 1. Architecture before V2

```
Officer (stdout / file)  ->  detection-engine (single for-loop)  ->  alerts.ndjson (one dump at stream end)  ->  console polls
```

Batch-oriented. The alert file was only written when the input stream ended;
there was no durable buffering, no restart-safe delivery, no backpressure, no
retry, no health/metrics, and (in `--officer` mode) `process.terminate()` left
the agent's ETW kernel trace session running.

## 2. Architecture after V2

```
Officer stdout (Schema 0.2 NDJSON, untouched)
   │  producer thread
   ▼
BoundedEventQueue                 src/reliability/queue.py
   │  bounded memory + explicit backpressure
   │  consumer thread
   ▼
DetectionRun.process_event        src/pipeline_core.py  (the V1 A–G detection logic, unchanged)
   │  → [Alert, ...]
   ▼
AlertSpool.persist(alert)         src/reliability/spool.py   SQLite (WAL), status=pending, BEFORE the file write
   ▼
IncrementalAlertWriter.write()    src/reliability/alert_sink.py   append + flush + fsync to alerts.ndjson
   │
   ├─ ok       → spool.mark_delivered(alert_id)
   └─ failure  → spool.mark_failed  → bounded-backoff retry (retry.py), or terminal 'dead'

HealthState (health.py) + Metrics (metrics.py) observe every stage.
StreamingPipeline (pipeline.py) owns the threads, shutdown, and recovery.
```

Wired into `src/main.py::_run_streaming_pipeline`, reached with `--reliable`.

## 3. Bounded ingestion queue

`BoundedEventQueue` — capacity-bounded FIFO, `deque` + `threading.Condition`.

| Concern | Behaviour |
|---|---|
| Capacity | `--queue-capacity` (default 1024). Backing deque hard-capped. |
| Overflow | `--queue-overflow` = `block` (default; producer waits — true backpressure) / `drop_newest` / `drop_oldest`. Every drop is counted and reported to the pipeline (`events_failed`), never silent. |
| Producer/consumer | Independent `put` / `get`; safe across threads. |
| Shutdown | `close()` unblocks every waiter; consumer drains, then `get()` returns `CLOSED`; a timed-out `get()` returns `EMPTY` (distinct from a `None` payload). |
| Schema 0.2 | Objects pass through untouched — the queue is generic over payload type. |

## 4. SQLite durable spool

`AlertSpool` — one local file (`--spool-db`, default `spool/panopticon-v2.db`), WAL mode, `busy_timeout`.

### SQLite schema (`spool_meta.schema_version = 1`)

```sql
CREATE TABLE spool_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    -- rows: schema_version, created_at

CREATE TABLE alerts (
    alert_id        TEXT PRIMARY KEY,   -- deterministic (see §6); the dedup key
    payload         TEXT,               -- Alert.to_dict() JSON, verbatim; NULLed once delivered
    rule_id         TEXT,               -- denormalised for inspection
    created_at      TEXT NOT NULL,      -- ISO-8601 UTC, when persisted
    status          TEXT NOT NULL,      -- 'pending' | 'delivered' | 'dead'
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    next_attempt_at TEXT,               -- ISO-8601 UTC; NULL = ready now
    last_error      TEXT,
    delivered_at    TEXT
);
CREATE INDEX ix_alerts_delivery ON alerts (status, next_attempt_at, created_at);
```

* **Migration**: `_MIGRATIONS` is an ordered list; index *i* upgrades a v*i* file
  to v*(i+1)*. A **newer** file raises `SpoolSchemaError` (never corrupted); a
  bare pre-existing db is migrated in place.
* **Transactions**: every write and state transition runs in `with self._conn`
  (BEGIN/COMMIT, rollback on exception).
* **Identity / dedup**: `alert_id` is the primary key; `persist()` is
  `INSERT … ON CONFLICT DO NOTHING` → reports `"new"` / `"duplicate"`.
* **Claiming** (`claim_deliverable`) never mutates rows, so a crash before the
  delivery ack simply re-offers them (at-least-once; dedup makes that safe).
* **Corrupt record**: a row whose payload will not parse is moved to `dead` on
  claim, not retried forever.
* **No coupling to the console** — the spool's only downstream is the NDJSON
  file, and that wiring lives in the pipeline, not the spool.

## 5. Retry lifecycle

`RetryPolicy` — bounded exponential backoff: `base_delay · factor^(n-1)`, capped
at `max_delay`, ± `jitter`. `--retry-max-attempts` (default 5),
`--retry-base-delay` (default 1.0s).

```
persist → pending
   deliver ok        → delivered            (terminal, payload NULLed, kept as dedup tombstone)
   deliver fails      → attempts++, last_error set
       attempts < max → pending, next_attempt_at = now + backoff   → "retry"
       attempts ≥ max → dead                (terminal, payload + error KEPT for inspection)
```

Retries are driven **continuously** while the stream idles (`_retry_ready`) and
**swept to completion** on shutdown (`_drain_spool`, guaranteed to terminate:
every attempt moves an alert toward delivered or dead). Delay is always
`≥ base_delay` once failing, so a permanently failing alert never hot-loops.
`requeue_dead(alert_id)` is the manual recovery lever.

## 6. Incremental alert output

`IncrementalAlertWriter` appends one `json.dumps(alert.to_dict()) + "\n"` per
alert, `flush()` + optional `os.fsync`. Output shape is identical to V1.

* **Torn-tail repair on open** — if the file does not end in `\n` (a half-written
  record from a crash), the partial tail is truncated back to the last newline
  *before* any append. A new record is never concatenated onto a broken one.
* **Cross-restart dedup** — on open the existing `alert_id`s are indexed;
  `write()` returns `False` for an id already in the file. Combined with
  **deterministic alert IDs** (`Alert.from_detection_result` now hashes
  `rule_id | event_id | host_id | timestamp | evidence-keys` into the existing
  `ALT-XXXXXXXX` format), re-processing the same event never produces a
  duplicate line.
* `--output-file` is honoured; if omitted in `--reliable` mode it defaults to
  `alerts.ndjson`.

## 7. Clean stream shutdown

`--max-events N` (hard cap on processed events) and `--duration SECONDS`
(wall-clock budget). An external stop event and `KeyboardInterrupt` take the
same path:

1. producer stops pulling from the source;
2. the queue is closed (waiters released);
3. the source generator is `close()`d → `stream_from_officer_process` sends the
   agent a console **CTRL_BREAK** so it tears down its ETW consumer + Sysmon
   subscription; escalates to `terminate()`/`kill()` only after 6s; runs
   `logman stop Panopticon-Officer-Process -ets` as a safety net if it had to
   escalate;
4. the queue is drained per `drain_on_shutdown` policy;
5. `_drain_spool()` delivers everything still `pending` (retries included);
6. the writer is flushed + fsync'd, the spool checkpointed and closed;
7. `HealthState` records `shutdown_reason` (`max_events` / `duration` /
   `stream_end` / `keyboard_interrupt`).

Indefinite interactive mode remains the default (no `--max-events`/`--duration`).

**Validated live**: 0 orphan `officer-agent.exe`, 0 orphan ETW sessions.

## 8. Health

`HealthState.snapshot()` / `render_text()` / `write_json()` (atomic temp+rename).
`--health-file` writes a JSON snapshot on exit. Fields: `engine_running`,
`ingestion_state`, `pid`, `uptime_seconds`, `queue.{depth,capacity,max_depth,
dropped_rejected}`, `spool.{pending,retry_waiting,failed,dead,delivered}`,
`counters.{events_received,events_processed,events_failed,alerts_generated,
alerts_persisted,alerts_delivered,alerts_failed,retry_attempts}`,
`last_event_processed_at`, `last_alert_persisted_at`, `last_error`,
`shutdown_reason`.

## 9. Metrics

`Metrics` — counters, gauges, a bounded latency summary, uptime. `--metrics-file`
writes Prometheus text-exposition format on exit (a plain string; **no server,
no client library**). Counters: `events_received/processed/failed`,
`alerts_generated/persisted/delivered/failed`, `retry_attempts`. Gauges:
`queue_depth/capacity`, `spool_pending/failed`.

## 10. Restart / recovery

On start, `StreamingPipeline.recover()` calls `claim_deliverable()` and
re-delivers every alert left `pending` by a prior crashed run **before** the
live stream is consumed. Because delivery dedup keys on `alert_id` in both the
spool (`persist` → `"duplicate"`, `already_delivered()`) and the writer (file
index), a recovered alert that had actually reached the file is reconciled
(`mark_delivered`) rather than re-emitted.

Proven by `tests/test_reliability_pipeline.py::test_recover_redelivers_pending_
alerts_without_double_emitting`, `test_full_run_after_restart_recovers_then_
streams`, and `tests/test_v2_pipeline_integration.py::test_restart_against_same_
spool_and_file_emits_no_duplicates` / `test_recovers_alerts_left_pending_by_a_crash`.

## 11. Console changes

`panopticon-console` (separate repo): `static/app.js` now de-duplicates by
`alert_id` before rendering and decides "new row flash" by whether an id was
seen on the previous poll. `read_alerts` / `/api/alerts` are unchanged — every
line still passes through untouched; de-dup is purely client-side. No
WebSockets/SSE — 3-second polling, as before.

## 12. Configuration reference

| Flag | Default | Meaning |
|---|---|---|
| `--reliable` | off | Enable the V2 streaming pipeline. |
| `--spool-db PATH` | `spool/panopticon-v2.db` | SQLite spool file (created if absent). |
| `--queue-capacity N` | 1024 | Bounded ingestion queue size. |
| `--queue-overflow` | `block` | `block` / `drop_newest` / `drop_oldest`. |
| `--max-events N` | — | Stop cleanly after N processed events. |
| `--duration SECONDS` | — | Stop cleanly after a wall-clock budget. |
| `--retry-max-attempts N` | 5 | Delivery attempts before an alert goes `dead`. |
| `--retry-base-delay S` | 1.0 | Base backoff seconds. |
| `--health-file PATH` | — | Write a JSON health snapshot on exit. |
| `--metrics-file PATH` | — | Write Prometheus-text metrics on exit. |

## 13. Troubleshooting

| Symptom | Check |
|---|---|
| Alerts not appearing in the console | Is the console's `--alerts-file` the engine's `--output-file`? In `--reliable` mode without `--output-file` the sink is `./alerts.ndjson`. |
| `SpoolSchemaError` on start | The `--spool-db` file was written by a newer build. Point at a fresh path or migrate. |
| Alerts stuck `pending` after a run | `spool_dead > 0` in health → inspect `AlertSpool.dead_alerts()`; `requeue_dead()` to retry. A non-zero `retry_waiting` at exit means backoff had not elapsed — re-running resumes them. |
| Orphan `Panopticon-Officer-Process` ETW session | Should not happen post-fix; if it does, `logman stop Panopticon-Officer-Process -ets`. |
| Duplicate lines in `alerts.ndjson` | Should not happen (deterministic ids + writer index). A line with no `alert_id` is exempt from dedup by design. |

## 14. Testing

* `pytest -v tests/` — full suite: **138 passed, 2 skipped** (was 55/2).
  New: `test_reliability_queue.py`, `test_reliability_retry.py`,
  `test_reliability_spool.py`, `test_reliability_alert_sink.py`,
  `test_reliability_metrics_health.py`, `test_reliability_pipeline.py`,
  `test_v2_pipeline_integration.py`.
* Agent (`panopticon-agent`): `ctest --test-dir build-officer-x64` → 7/7 passed;
  Schema 0.2 unchanged (no agent source touched).
* Console: 24 passed (incl. incremental / duplicate / torn-line cases).
* **Live Windows** (elevated x64 + Sysmon64): `--reliable --officer` for 20s,
  47 real ETW+Sysmon events → 4 real DET-PROC-011 alerts persisted + delivered
  incrementally, `--duration` clean stop, 0 orphan processes, 0 orphan ETW
  sessions, valid NDJSON, health/metrics files sane.

## 15. V1 vs V2 boundaries

**V2 adds** (all opt-in): bounded ingestion queue, SQLite durable alert spool,
delivery retry with persisted state + restart recovery, incremental append-safe
alert output, deterministic clean shutdown, local health + metrics, orphan-free
Officer/ETW teardown, client-side alert de-dup.

**V2 does NOT provide / deliberately excludes**: any cloud or backend service,
Kubernetes, Kafka/RabbitMQ/Redis or any message broker, a database *server*
(SQLite is a local file), an HTTP/REST API, multi-agent or horizontal scale,
real destructive remediation (still simulated), any Schema 0.2 change,
authentication/RBAC/TLS, guaranteed exactly-once or guaranteed delivery across
arbitrary failures beyond the implemented at-least-once + bounded-retry +
restart-recovery guarantees.

## 16. V3 extension points (identified, not implemented)

V3 will add Network, File, Registry and Image-Load telemetry. V2 was kept
family-agnostic where it was cheap to do so:

* **`BoundedEventQueue`** is generic over payload type — no process-only
  assumption.
* **`AlertSpool`** stores opaque alert payloads; it never inspects telemetry
  shape.
* **`StreamingPipeline`** takes `detection_fn: Callable[[dict], Iterable[Alert]]`
  and `source: Iterable[dict]` — neither cares what telemetry family the dict
  is. A V3 multi-family collector plugs in as the `source`; a V3 family-aware
  normalizer plugs in ahead of `DetectionRun.process_event`.
* **`_run_streaming_pipeline`**'s `detect()` already normalises Officer records
  just-in-time via `OfficerIngestionAdapter` — the natural seam for a
  `category`-dispatched normaliser.
* **Schema 0.2 is untouched.** V3 must version the contract additively
  (`schema_version` bump + optional per-family blocks); do **not** mutate 0.2.

No V3 collectors, no V3 schema, and no `event.category` handling are added in V2.
