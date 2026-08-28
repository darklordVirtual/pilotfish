from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.epoch import MemoryEpochStore
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import LinkDownRule
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_OBSERVATION_BATCH, MSG_POLICY_BUNDLE, encode_bundle
from pilotfish.sdk.errors import BundleExpired, BundleUnverified

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
PK = SK.public_key()
NONCE = b"\x02" * 16

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


def envelope_bytes(bundle=BUNDLE, key=SK, msg_type=MSG_POLICY_BUNDLE):
    return encode_envelope(
        sign(
            msg_type=msg_type,
            issuer="authority-1",
            issued_at=T0,
            nonce=NONCE,
            payload=encode_bundle(bundle),
            private_key=key,
        )
    )


def store():
    return BundleStore(
        trusted_key=PK,
        expected_issuer="authority-1",
        site_id="site-1",
        signed_floor=_signed_floor(SK, LINKS, site_id="site-1"),
        now=T0,
        epoch_store=MemoryEpochStore(),
    )


def test_a_good_bundle_is_installed_and_is_not_degraded():
    s = store()
    assert s.accept(envelope_bytes(), now=T0).bundle_id == "b1"
    bundle, degraded = s.current(now=T0 + timedelta(hours=1))
    assert (bundle.bundle_id, degraded) == ("b1", False)


def test_wrongly_signed_bundle_is_refused():
    with pytest.raises(BundleUnverified):
        store().accept(envelope_bytes(key=OTHER_SK), now=T0)


def test_a_bundle_arriving_in_the_wrong_message_type_is_refused():
    with pytest.raises(BundleUnverified):
        store().accept(envelope_bytes(msg_type=MSG_OBSERVATION_BATCH), now=T0)


def test_an_already_expired_bundle_is_never_installed():
    with pytest.raises(BundleExpired):
        store().accept(envelope_bytes(), now=BUNDLE.not_after + timedelta(seconds=1))


def test_expired_bundle_falls_to_degraded_floor_not_to_the_old_bundle():
    s = store()
    s.accept(envelope_bytes(), now=T0)
    bundle, degraded = s.current(now=BUNDLE.not_after + timedelta(seconds=1))
    assert degraded is True
    assert bundle.bundle_id == "floor"


def test_a_refused_bundle_does_not_displace_the_good_one():
    s = store()
    s.accept(envelope_bytes(), now=T0)
    with pytest.raises(BundleUnverified):
        s.accept(envelope_bytes(key=OTHER_SK), now=T0)
    bundle, degraded = s.current(now=T0)
    assert (bundle.bundle_id, degraded) == ("b1", False)


def test_no_bundle_at_all_is_degraded_from_the_start():
    bundle, degraded = store().current(now=T0)
    assert degraded is True
    assert bundle.bundle_id == "floor"


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
