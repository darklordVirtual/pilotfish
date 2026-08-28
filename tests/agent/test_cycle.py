from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.adapters.file_sink import MemoryReceiptSink
from pilotfish.adapters.noop import NoopDataplane
from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.cycle import AgentCycle, PostconditionViolation
from pilotfish.agent.receipts import ReceiptChain
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, Observation, TrafficClass
from pilotfish.core.rules import LinkDownRule, MeteredRule
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, encode_bundle

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
AUTHORITY_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SITE_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))

LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))


def bundle(bundle_id="b1", allow_metered=True):
    return PolicyBundle(
        bundle_id=bundle_id,
        issued_at=T0,
        not_after=T0 + timedelta(hours=6),
        decision_ttl_s=60,
        links=LINKS,
        traffic_classes=(TrafficClass("bulk", allow_metered=allow_metered),),
        rules=(LinkDownRule("R-DOWN"), MeteredRule("R-METER", "bulk")),
    )


BUNDLE = bundle()
OTHER_BUNDLE = bundle("b2", allow_metered=False)


def envelope_for(b):
    return encode_envelope(
        sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer="authority-1",
            issued_at=T0,
            nonce=b"\x03" * 16,
            payload=encode_bundle(b),
            private_key=AUTHORITY_SK,
        )
    )


class AllUp:
    def observe(self, now):
        return (
            Observation("fiber0", "up", 1.0, now, "agent"),
            Observation("lte0", "up", 1.0, now, "agent"),
        )


class LyingDataplane:
    """Applies the decision, then reports a link the decision excluded."""

    def apply(self, decision):
        self._decision = decision

    def readback(self):
        return {cls.class_id: ("fiber0", "lte0", "sat0") for cls in self._decision.classes}


class SilentDataplane:
    """Accepts the decision and quietly does nothing at all."""

    def apply(self, decision):
        return None

    def readback(self):
        return {}


def build(adapter=None, install=BUNDLE):
    store = BundleStore(trusted_key=AUTHORITY_SK.public_key(), floor_links=LINKS)
    if install is not None:
        store.accept(envelope_for(install), now=T0)
    sink = MemoryReceiptSink()
    chain = ReceiptChain("site-1", sink, SITE_SK)
    cycle = AgentCycle("site-1", store, AllUp(), adapter or NoopDataplane(), chain)
    return store, sink, cycle


def test_a_normal_cycle_permits_both_links_and_writes_one_receipt():
    _, sink, cycle = build()
    decision = cycle.run_once(now=T0)
    assert decision.permitted_for("bulk") == ("fiber0", "lte0")
    assert decision.degraded is False
    assert len(sink.lines) == 1


def test_without_a_bundle_the_cycle_runs_degraded_on_the_floor_policy():
    _, sink, cycle = build(install=None)
    decision = cycle.run_once(now=T0)
    assert decision.degraded is True
    assert decision.permitted_for("default") == ("fiber0",)
    assert len(sink.lines) == 1


def test_readback_mismatch_raises_after_the_receipt_is_written():
    _, sink, cycle = build(adapter=LyingDataplane())
    with pytest.raises(PostconditionViolation):
        cycle.run_once(now=T0)
    assert len(sink.lines) == 1


def test_a_dataplane_that_silently_did_nothing_is_caught():
    _, _, cycle = build(adapter=SilentDataplane())
    with pytest.raises(PostconditionViolation):
        cycle.run_once(now=T0)


def test_bundle_swap_mid_cycle_does_not_mix_two_bundles():
    """A bundle arriving while we decide governs the next decision, not half of this one."""

    store = BundleStore(trusted_key=AUTHORITY_SK.public_key(), floor_links=LINKS)
    store.accept(envelope_for(BUNDLE), now=T0)

    class SwappingSource:
        def observe(self, now):
            store.accept(envelope_for(OTHER_BUNDLE), now=now)
            return AllUp().observe(now)

    chain = ReceiptChain("site-1", MemoryReceiptSink(), SITE_SK)
    cycle = AgentCycle("site-1", store, SwappingSource(), NoopDataplane(), chain)

    first = cycle.run_once(now=T0)
    assert first.bundle_hash == BUNDLE.hash()
    assert first.permitted_for("bulk") == ("fiber0", "lte0")

    second = cycle.run_once(now=T0 + timedelta(seconds=60))
    assert second.bundle_hash == OTHER_BUNDLE.hash()
    assert second.permitted_for("bulk") == ("fiber0",)
