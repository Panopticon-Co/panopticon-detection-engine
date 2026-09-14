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

from panopticon_detection.reliability.alert_sink import IncrementalAlertWriter
from panopticon_detection.reliability.health import HealthState
from panopticon_detection.reliability.metrics import Metrics
from panopticon_detection.reliability.pipeline import PipelineResult, StreamingPipeline
from panopticon_detection.reliability.queue import (
    CLOSED,
    EMPTY,
    BoundedEventQueue,
    OverflowPolicy,
    QueueClosed,
    QueueStats,
)
from panopticon_detection.reliability.retry import RetryPolicy
from panopticon_detection.reliability.spool import (
    AlertSpool,
    SpooledAlert,
    SpoolSchemaError,
    SpoolStats,
)

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
