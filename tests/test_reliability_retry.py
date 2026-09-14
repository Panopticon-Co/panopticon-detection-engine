"""Tests for the bounded retry policy (src/reliability/retry.py)."""

import random

import pytest

from panopticon_detection.reliability.retry import RetryPolicy


def test_validates_construction():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay=5, max_delay=1)
    with pytest.raises(ValueError):
        RetryPolicy(factor=0.5)
    with pytest.raises(ValueError):
        RetryPolicy(jitter=1.0)


def test_should_retry_and_exhaustion_are_complementary():
    p = RetryPolicy(max_attempts=3)
    assert p.should_retry(0) and p.should_retry(2)
    assert not p.should_retry(3)
    assert p.is_exhausted(3) and p.is_exhausted(4)
    assert not p.is_exhausted(2)


def test_no_delay_before_first_attempt():
    p = RetryPolicy(base_delay=2.0, jitter=0.0)
    assert p.compute_delay(0) == 0.0


def test_exponential_backoff_is_bounded_by_max_delay():
    p = RetryPolicy(base_delay=1.0, factor=2.0, max_delay=10.0, jitter=0.0)
    assert p.compute_delay(1) == 1.0
    assert p.compute_delay(2) == 2.0
    assert p.compute_delay(3) == 4.0
    assert p.compute_delay(4) == 8.0
    assert p.compute_delay(5) == 10.0  # capped
    assert p.compute_delay(50) == 10.0  # still capped, never overflows


def test_delay_never_zero_once_failing_so_no_hot_loop():
    p = RetryPolicy(base_delay=0.5, jitter=0.0)
    for attempts in range(1, 10):
        assert p.compute_delay(attempts) >= 0.5


def test_jitter_stays_within_band_and_is_deterministic_with_seed():
    p = RetryPolicy(base_delay=4.0, factor=1.0, max_delay=4.0, jitter=0.25)
    rnd = random.Random(1234)
    seen = [p.compute_delay(1, _rand=rnd) for _ in range(200)]
    assert all(3.0 <= d <= 5.0 for d in seen)  # 4 +/- 25%
    rnd2 = random.Random(1234)
    seen2 = [p.compute_delay(1, _rand=rnd2) for _ in range(200)]
    assert seen == seen2
