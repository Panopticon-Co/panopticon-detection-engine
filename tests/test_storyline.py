"""Storyline risk index (L3): dedup, max + 0.2 * rest, ML cap, kill-chain bonus, prune."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from panopticon_detection.provenance.storyline import (
    RiskEvent,
    StorylineRiskIndex,
    kill_chain_run,
    rule_points,
)

T0 = datetime(2026, 1, 1, 10, 0, 0)


def _rule(rule, score, second, tactic=None, obj="o"):
    return RiskEvent(f"rule:{rule}", score, T0 + timedelta(seconds=second), tactic, obj)


def test_repeats_count_once_and_weak_hits_do_not_add_up():
    index = StorylineRiskIndex(threshold=100)
    for i in range(50):  # the same rule on the same object, fifty times
        assert index.add("h", "root", _rule("A", 40, i)) is None
    for i in range(5):  # five other weak rules
        assert index.add("h", "root", _rule(f"W{i}", 40 if i == 0 else 30, 60 + i, obj=f"x{i}")) is None
    breakdown = index.score(index.storylines[("h", "root")])
    assert breakdown["rules"] == pytest.approx(40 + 0.2 * (40 + 4 * 30)) and not breakdown["fires"]


def test_ml_and_rarity_cannot_decide_an_alert_alone():
    index = StorylineRiskIndex(threshold=100, ml_cap_fraction=0.4)
    for i in range(10):
        assert index.add("h", "r", RiskEvent(f"ml:ctx{i}", 90, T0 + timedelta(seconds=i), None, f"p{i}")) is None
    breakdown = index.score(index.storylines[("h", "r")])
    assert breakdown["ml_and_rarity"] == 40 and breakdown["score"] == 40


def test_rules_plus_capped_ml_fire_once():
    index = StorylineRiskIndex(threshold=100)
    assert index.add("h", "r", _rule("A", 70, 0, "Execution")) is None
    breach = index.add("h", "r", RiskEvent("ml:ctx", 100, T0 + timedelta(seconds=5), None, "p"))  # 100+14, ML capped
    assert breach is not None and breach["rules"] == 70 and breach["ml_and_rarity"] == 40
    assert index.add("h", "r", _rule("B", 90, 9)) is None  # one alert per storyline


def test_three_tactics_from_three_rules_fire_and_kill_chain_order_scores():
    index = StorylineRiskIndex(threshold=1000)
    index.add("h", "r", _rule("A", 10, 0, "Execution"))
    index.add("h", "r", _rule("B", 10, 1, "Persistence"))
    breach = index.add("h", "r", _rule("C", 10, 2, "Command and Control"))
    assert breach is not None and breach["kill_chain_run"] == 3 and breach["chain_bonus"] == 20
    events = [_rule("A", 1, 0, "Impact"), _rule("B", 1, 1, "Execution"), _rule("C", 1, 2, "Discovery")]
    assert kill_chain_run(events) == 2  # Impact first breaks the order


def test_window_and_prune():
    index = StorylineRiskIndex(threshold=100, window=timedelta(hours=1))
    index.add("h", "r", _rule("A", 70, 0))
    assert index.add("h", "r", _rule("B", 40, 7200)) is None  # A expired: 40 < 100
    assert index.prune(T0 + timedelta(hours=3)) == 1 and not index.storylines


def test_rule_points():
    assert rule_points(16, 1.0) == 100.0 and rule_points(12, 0.5) == 37.5 and rule_points(8, None) == 35.0
