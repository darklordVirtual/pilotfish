from datetime import UTC, datetime, timedelta

import pytest

from pilotfish.core.models import EvidenceSnapshot, Link, Observation

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def obs(link_id="lte0", quantity="rtt_ms", value=40.0, at=T0, source="agent"):
    return Observation(link_id=link_id, quantity=quantity, value=value, at=at, source=source)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        Observation(
            link_id="a",
            quantity="rtt_ms",
            value=1.0,
            at=datetime(2026, 8, 28, 12, 0),
            source="agent",
        )


def test_latest_wins_and_age_is_computed():
    snap = EvidenceSnapshot((obs(value=40.0), obs(value=10.0, at=T0 + timedelta(seconds=30))))
    assert snap.latest("lte0", "rtt_ms").value == 10.0
    assert snap.age_s("lte0", "rtt_ms", T0 + timedelta(seconds=90)) == 60.0
    assert snap.latest("lte0", "loss_pct") is None
    assert snap.age_s("lte0", "loss_pct", T0) is None


def test_hash_is_order_independent_and_content_sensitive():
    a, b = obs(value=1.0), obs(link_id="fiber0", value=2.0)
    assert EvidenceSnapshot((a, b)).hash() == EvidenceSnapshot((b, a)).hash()
    assert EvidenceSnapshot((a,)).hash() != EvidenceSnapshot((b,)).hash()


def test_link_defaults():
    link = Link(id="sat0", type="satellite")
    assert link.metered is False
    assert link.jurisdictions == ()
