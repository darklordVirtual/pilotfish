"""Negative conformance: evidence that must never be treated as usable.

Every test here encodes a way the system previously failed open. A rule that
reads a measurement must exclude when the measurement is absent, and these are
the cases where a measurement was present but meaningless.
"""

from datetime import UTC, datetime, timedelta

import pytest

from pilotfish.core.models import (
    MAX_CLOCK_SKEW_S,
    EvidenceSnapshot,
    Link,
    Observation,
    TrafficClass,
)
from pilotfish.core.rules import EvidenceFreshnessRule, LinkDownRule, MaxRttRule, QuotaRule

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
BULK = TrafficClass("bulk")
REALTIME = TrafficClass("realtime", max_rtt_ms=100.0)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_measurement_cannot_be_constructed(bad):
    """NaN compares false against every threshold, so it must never reach a rule."""

    with pytest.raises(ValueError, match="finite"):
        Observation("f0", "up", bad, T0, "agent")


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_a_non_finite_policy_threshold_cannot_be_constructed(bad):
    with pytest.raises(ValueError, match="finite"):
        TrafficClass("realtime", max_rtt_ms=bad)
    with pytest.raises(ValueError, match="finite"):
        QuotaRule("R", "lte", bad)
    with pytest.raises(ValueError, match="finite"):
        EvidenceFreshnessRule("R", "fso", "visibility_m", bad)


def test_evidence_from_the_future_is_discarded_not_treated_as_fresh():
    """A clock running fast must not be able to switch abstention off."""

    future = T0 + timedelta(days=1)
    snapshot = EvidenceSnapshot(
        (
            Observation("fso0", "visibility_m", 9000.0, future, "model"),
            Observation("fso0", "up", 1.0, future, "agent"),
        )
    )
    as_of = snapshot.as_of(T0)
    assert as_of.latest("fso0", "visibility_m") is None

    rule = EvidenceFreshnessRule("R-FRESH", "fso", "visibility_m", 600.0)
    assert rule.evaluate(Link(id="fso0", type="fso"), BULK, as_of, T0) is not None
    assert LinkDownRule("R-DOWN").evaluate(Link(id="fso0", type="fso"), BULK, as_of, T0) is not None


def test_evidence_inside_the_skew_allowance_is_kept():
    """Small disagreement between two honest clocks is normal and must not exclude."""

    slightly_ahead = T0 + timedelta(seconds=MAX_CLOCK_SKEW_S - 1)
    snapshot = EvidenceSnapshot((Observation("f0", "up", 1.0, slightly_ahead, "agent"),))
    assert snapshot.as_of(T0).latest("f0", "up") is not None


def test_age_of_evidence_inside_the_allowance_is_never_negative():
    snapshot = EvidenceSnapshot(
        (Observation("f0", "rtt_ms", 5.0, T0 + timedelta(seconds=2), "agent"),)
    )
    assert snapshot.as_of(T0).age_s("f0", "rtt_ms", T0) == 0.0


def test_a_future_latency_reading_cannot_satisfy_a_latency_bound():
    snapshot = EvidenceSnapshot(
        (Observation("sat0", "rtt_ms", 5.0, T0 + timedelta(hours=1), "agent"),)
    )
    rule = MaxRttRule("R-RTT", "realtime")
    assert rule.evaluate(Link(id="sat0", type="satellite"), REALTIME, snapshot.as_of(T0), T0)


def test_an_offset_timezone_is_accepted_because_its_arithmetic_is_correct():
    """Aware, non-zero offset is fine. Only naive timestamps are ambiguous."""

    oslo = datetime(2026, 8, 28, 14, 0, tzinfo=__import__("datetime").timezone(timedelta(hours=2)))
    observation = Observation("f0", "up", 1.0, oslo, "agent")
    assert observation.age_s(T0) == 0.0
