"""Bounded retry policy for the V2 recovery path.

A deliberately small, pure-function implementation: given how many times an event
has already failed, decide whether to try again and, if so, how long to wait.

* **Bounded** -- after ``max_attempts`` the event is *not* discarded; the spool
  moves it to a terminal ``dead`` state so it stays durable and auditable.
* **No infinite hot loop** -- the delay is always ``>= base_delay`` once an
  attempt has failed, so a permanently failing event cannot spin the CPU.
* **Simple bounded exponential backoff** -- ``base_delay * factor**(attempts-1)``
  capped at ``max_delay``, with optional +/- jitter to avoid lockstep retries.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    """Immutable retry configuration.

    ``attempts`` in every method means "failed attempts so far" (0 before the
    first try, 1 after the first failure, ...).
    """

    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    factor: float = 2.0
    jitter: float = 0.1  # fraction of the computed delay, applied as +/-

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must be non-negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.factor < 1.0:
            raise ValueError("factor must be >= 1.0")
        if not (0.0 <= self.jitter < 1.0):
            raise ValueError("jitter must be in [0, 1)")

    def should_retry(self, attempts: int) -> bool:
        """True while the event still has retries left."""
        return attempts < self.max_attempts

    def is_exhausted(self, attempts: int) -> bool:
        """True once the event has used all its attempts (-> terminal 'dead')."""
        return attempts >= self.max_attempts

    def compute_delay(self, attempts: int, *, _rand: "random.Random | None" = None) -> float:
        """Seconds to wait before the next attempt, given ``attempts`` failures.

        Deterministic when ``jitter == 0``; ``_rand`` is injectable for tests.
        """
        if attempts <= 0:
            return 0.0
        raw = self.base_delay * (self.factor ** (attempts - 1))
        delay = min(raw, self.max_delay)
        if self.jitter:
            rnd = _rand or random
            spread = delay * self.jitter
            delay = max(0.0, delay + rnd.uniform(-spread, spread))
        return delay
