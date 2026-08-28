from datetime import UTC, datetime
from random import Random

import pytest

from sim.links import GB, FiberModel, FsoModel, LteModel, SatelliteModel
from sim.run import link_up_at, run
from sim.scenarios import PLAIN_FAILOVER
from sim.selectors import Greedy

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
RNG = Random(1)


def quantities(observations):
    return {o.quantity for o in observations}


def test_fso_reports_visibility_and_goes_down_when_it_drops():
    model = FsoModel("fso0", visibility_m=8000.0)
    clear = model.step(T0, RNG)
    assert quantities(clear) == {"up", "visibility_m", "rtt_ms"}

    model.visibility_m = 100.0
    fog = model.step(T0, RNG)
    up = next(o for o in fog if o.quantity == "up")
    assert up.value == 0.0
    assert "rtt_ms" not in quantities(fog)


def test_a_dead_sensor_reports_nothing_at_all():
    model = FsoModel("fso0")
    model.sensor_failed = True
    assert model.step(T0, RNG) == ()


def test_weather_is_modelled_and_latency_is_measured():
    """Policy discriminates on source, so the models must not blur the two."""

    by_quantity = {o.quantity: o for o in FsoModel("fso0").step(T0, RNG)}
    assert by_quantity["visibility_m"].source == "model"
    assert by_quantity["rtt_ms"].source == "agent"


def test_quota_comes_from_the_operator_not_from_us():
    by_quantity = {o.quantity: o for o in LteModel("lte0").step(T0, RNG)}
    assert by_quantity["quota_used_pct"].source == "operator"


def test_lte_quota_is_consumed_only_when_the_link_carries_traffic():
    model = LteModel("lte0", quota_gb=10.0)
    assert model.quota_used_pct() == 0.0
    model.carry(GB)
    assert model.quota_used_pct() == pytest.approx(10.0)


def test_quota_saturates_rather_than_exceeding_a_hundred_percent():
    model = LteModel("lte0", quota_gb=1.0)
    model.carry(5 * GB)
    assert model.quota_used_pct() == 100.0


def test_satellite_obstruction_shows_up_as_latency_not_as_an_outage():
    model = SatelliteModel("sat0")
    clear = {o.quantity: o.value for o in model.step(T0, RNG)}
    model.obstructed = True
    obstructed = {o.quantity: o.value for o in model.step(T0, RNG)}
    assert obstructed["up"] == 1.0
    assert obstructed["rtt_ms"] > clear["rtt_ms"] + 300


def test_a_down_link_reports_only_its_liveness():
    model = FiberModel("fiber0")
    model.up = False
    assert quantities(model.step(T0, RNG)) == {"up"}


def test_events_are_applied_at_their_timestamp_not_before():
    result = run(PLAIN_FAILOVER, Greedy(), seed=1)
    assert link_up_at(result, 570, "fiber0") is True
    assert link_up_at(result, 630, "fiber0") is False


def test_a_run_is_reproducible_from_its_seed():
    a = run(PLAIN_FAILOVER, Greedy(), seed=7)
    b = run(PLAIN_FAILOVER, Greedy(), seed=7)
    assert [f["choices"] for f in a.frames] == [f["choices"] for f in b.frames]
