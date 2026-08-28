"""The comparison, including the results we lose.

The assertions here are pinned to measured behaviour, not to hopes. Two of them
assert that governed selection is beaten, and they are not there for balance:
they are the tests that would catch a scenario quietly rigged in our favour.
"""

from __future__ import annotations

import pytest

from sim.report import compare, render_markdown
from sim.scenarios import (
    ALL_SCENARIOS,
    AUTHORITY_BLACKOUT,
    FLAPPY,
    PLAIN_FAILOVER,
    QUOTA_SQUEEZE,
    REGULATED,
)

SEEDS = range(3)


@pytest.fixture(scope="module")
def table():
    return compare(ALL_SCENARIOS, seeds=SEEDS)


def test_governed_never_violates_a_class_requirement_it_was_given(table):
    assert table.violations("governed") == 0


def test_the_baselines_do_violate_requirements_so_the_test_above_means_something(table):
    assert table.violations("greedy") > 0
    assert table.violations("static_priority") > 0
    assert table.violations("hysteresis") > 0


def test_governed_refuses_rather_than_paying_overage_on_a_spent_allowance():
    t = compare([QUOTA_SQUEEZE], seeds=SEEDS)
    assert t.cost("greedy") > 0
    assert t.cost("governed") == 0
    # And it pays for that with class-seconds it declined to serve.
    assert t.refused("governed") > t.refused("greedy")


def test_regulated_traffic_is_kept_off_forbidden_paths_at_the_price_of_service():
    t = compare([REGULATED], seeds=SEEDS)
    assert t.violations("greedy") > 0
    assert t.violations("governed") == 0
    assert t.refused("governed") > 0


def test_greedy_is_not_beaten_on_plain_failover_and_that_is_recorded():
    """The scenario governed selection is expected to lose, or at best tie."""

    t = compare([PLAIN_FAILOVER], seeds=SEEDS)
    assert t.downtime("greedy") + t.refused("greedy") <= t.downtime("governed") + t.refused(
        "governed"
    )


def test_governed_does_not_damp_flapping_any_better_than_greedy():
    """A real limitation: eligibility is not hysteresis, and does not pretend to be."""

    t = compare([FLAPPY], seeds=SEEDS)
    assert t.flaps("governed") >= t.flaps("hysteresis")


def test_hysteresis_baseline_actually_damps_flapping():
    t = compare([FLAPPY], seeds=SEEDS)
    assert t.flaps("hysteresis") < t.flaps("greedy")


def test_losing_the_authority_puts_the_site_on_the_floor_without_violating_anything():
    t = compare([AUTHORITY_BLACKOUT], seeds=SEEDS)
    assert t.degraded("governed") > 0
    assert t.violations("governed") == 0
    assert t.degraded("greedy") == 0


def test_the_report_renders_every_scenario_and_selector(table):
    rendered = render_markdown(table)
    for scenario in ALL_SCENARIOS:
        assert scenario.name in rendered
    for selector in ("greedy", "static_priority", "hysteresis", "governed"):
        assert selector in rendered
