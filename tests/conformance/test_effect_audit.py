"""Negative conformance: the log must record the effect, not only the intent.

A decision receipt says what was authorised. On its own it cannot distinguish a
site that enforced its policy from one whose dataplane ignored it entirely, and
in the second case every signature in the log still verifies.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.adapters.file_sink import MemoryReceiptSink
from pilotfish.adapters.noop import NoopDataplane
from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.cycle import AgentCycle, PostconditionViolation
from pilotfish.agent.epoch import MemoryEpochStore
from pilotfish.agent.receipts import (
    KIND_DECISION,
    KIND_EFFECT,
    KIND_EXECUTION,
    OUTCOME_ENFORCED,
    OUTCOME_ENFORCEMENT_ERROR,
    OUTCOME_POSTCONDITION_FAILED,
    ReceiptChain,
    read_chain,
    state_hash,
    verify_chain,
)
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, Observation, TrafficClass
from pilotfish.core.rules import LinkDownRule
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, encode_bundle

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
AUTHORITY_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SITE_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))

BUNDLE = PolicyBundle(
    bundle_id="b1",
    authority_id="authority-1",
    sequence=1,
    issued_at=T0,
    not_after=T0 + timedelta(hours=6),
    decision_ttl_s=60,
    links=LINKS,
    traffic_classes=(TrafficClass("bulk"),),
    rules=(LinkDownRule("R-DOWN"),),
)


class AllUp:
    def observe(self, now):
        return tuple(Observation(link.id, "up", 1.0, now, "agent") for link in LINKS)


class LyingDataplane:
    def apply(self, decision):
        self._decision = decision

    def readback(self):
        return {cls.class_id: ("fiber0", "lte0", "sat0") for cls in self._decision.classes}


class BrokenDataplane:
    def apply(self, decision):
        raise OSError("netlink socket refused the rule")

    def readback(self):
        return {}


def build(adapter):
    store = BundleStore(
        trusted_key=AUTHORITY_SK.public_key(),
        expected_issuer="authority-1",
        site_id="site-1",
        signed_floor=_signed_floor(AUTHORITY_SK, LINKS, site_id="site-1"),
        now=T0,
        epoch_store=MemoryEpochStore(),
    )
    store.accept(
        encode_envelope(
            sign(
                msg_type=MSG_POLICY_BUNDLE,
                issuer="authority-1",
                issued_at=T0,
                nonce=b"\x01" * 16,
                payload=encode_bundle(BUNDLE),
                private_key=AUTHORITY_SK,
            )
        ),
        now=T0,
    )
    sink = MemoryReceiptSink()
    chain = ReceiptChain.recover(sink, SITE_SK, site_id="site-1")
    return sink, AgentCycle("site-1", store, AllUp(), adapter, chain)


def kinds(sink):
    return [r.kind for r in read_chain(sink, SITE_SK.public_key())]


def test_a_successful_cycle_records_authorised_attempted_and_verified():
    sink, cycle = build(NoopDataplane())
    cycle.run_once(now=T0)

    receipts = read_chain(sink, SITE_SK.public_key())
    assert [r.kind for r in receipts] == [KIND_DECISION, KIND_EXECUTION, KIND_EFFECT]
    assert receipts[-1].outcome == OUTCOME_ENFORCED
    assert receipts[-1].observed_state_hash == state_hash({"bulk": ("fiber0", "lte0")})
    verify_chain(receipts)


def test_a_dataplane_that_kept_a_forbidden_link_is_named_in_the_log():
    sink, cycle = build(LyingDataplane())
    with pytest.raises(PostconditionViolation):
        cycle.run_once(now=T0)

    receipts = read_chain(sink, SITE_SK.public_key())
    assert kinds(sink) == [KIND_DECISION, KIND_EXECUTION, KIND_EFFECT]
    assert receipts[-1].outcome == OUTCOME_POSTCONDITION_FAILED
    assert receipts[-1].observed_state_hash == state_hash({"bulk": ("fiber0", "lte0", "sat0")})
    assert "sat0" in receipts[-1].detail
    verify_chain(receipts)


def test_an_adapter_that_threw_is_recorded_before_the_exception_escapes():
    sink, cycle = build(BrokenDataplane())
    with pytest.raises(OSError):
        cycle.run_once(now=T0)

    receipts = read_chain(sink, SITE_SK.public_key())
    assert kinds(sink) == [KIND_DECISION, KIND_EXECUTION, KIND_EFFECT]
    assert receipts[-1].outcome == OUTCOME_ENFORCEMENT_ERROR
    assert "netlink" in receipts[-1].detail
    verify_chain(receipts)


def test_the_effect_receipt_carries_the_same_decision_it_reports_on():
    sink, cycle = build(NoopDataplane())
    decision = cycle.run_once(now=T0)
    receipts = read_chain(sink, SITE_SK.public_key())
    assert {r.decision.bundle_hash for r in receipts} == {decision.bundle_hash}


def _signed_floor(key, links, *, site_id, issuer="authority-1", now=None):
    """A floor configuration signed by the authority, as a real deployment would ship."""

    from pilotfish.authority.signer import BundleSigner, sign_floor
    from pilotfish.core.models import TrafficClass as _TC

    return sign_floor(
        BundleSigner(key, issuer),
        site_id=site_id,
        links=links,
        classes=(_TC("default", allow_metered=False),),
        now=now or T0,
    )
