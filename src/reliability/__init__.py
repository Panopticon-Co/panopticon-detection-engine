"""V2 reliability infrastructure for the eyedetect detection engine.

Turns the V1 batch pipeline into a reliable, restart-safe local stream without
changing Panopticon Schema 0.2 or the ``alerts.ndjson`` boundary the console
consumes.

    Officer / NDJSON stream
        -> BoundedEventQueue        (queue.py)     bounded memory + backpressure
        -> detection (V1 logic)
        -> AlertSpool               (spool.py)     durable SQLite, delivery state
        -> IncrementalAlertWriter   (alert_sink.py) append-safe alerts.ndjson
           success -> mark_delivered
           failure -> mark_failed -> retry (retry.py) or terminal 'dead'
        HealthState (health.py) + Metrics (metrics.py) observe every layer.

Standard library only: ``queue``/``threading``/``sqlite3``. No broker, no
server, no new third-party dependency.
"""

from src.reliability.queue import (
    CLOSED,
    EMPTY,
    BoundedEventQueue,
    OverflowPolicy,
    QueueClosed,
    QueueStats,
)
from src.reliability.retry import RetryPolicy
from src.reliability.spool import AlertSpool, SpooledAlert, SpoolStats, SpoolSchemaError
from src.reliability.metrics import Metrics
from src.reliability.health import HealthState
from src.reliability.alert_sink import IncrementalAlertWriter
from src.reliability.pipeline import PipelineResult, StreamingPipeline

__all__ = [
    "BoundedEventQueue",
    "OverflowPolicy",
    "QueueClosed",
    "QueueStats",
    "CLOSED",
    "EMPTY",
    "RetryPolicy",
    "AlertSpool",
    "SpooledAlert",
    "SpoolStats",
    "SpoolSchemaError",
    "Metrics",
    "HealthState",
    "IncrementalAlertWriter",
    "StreamingPipeline",
    "PipelineResult",
]
