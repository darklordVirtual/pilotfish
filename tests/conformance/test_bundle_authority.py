"""Negative conformance: authenticity is not freshness, and neither is authority.

A signature proves who wrote a bundle. It says nothing about whether that bundle
is the one currently in force, and an attacker who can replay an old but validly
signed policy can widen a permitted set without forging anything.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.epoch import MemoryEpochStore
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import LinkDownRule, MeteredRule
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, encode_bundle
from pilotfish.sdk.errors import BundleUnverified

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
AUTHORITY = "authority-1"
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))


def bundle(sequence: int, *, allow_metered: bool, authority_id: str = AUTHORITY) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=f"v{sequence}",
        authority_id=authority_id,
        sequence=sequence,
        issued_at=T0,
        not_after=T0 + timedelta(hours=6),
        decision_ttl_s=60,
        links=LINKS,
        traffic_classes=(TrafficClass("bulk", allow_metered=allow_metered),),
        rules=(LinkDownRule("R-DOWN"), MeteredRule("R-METER", "bulk")),
    )


def envelope(b: PolicyBundle, *, issuer: str = AUTHORITY, nonce: bytes | None = None) -> bytes:
    return encode_envelope(
        sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer=issuer,
            issued_at=T0,
            nonce=nonce or bytes([b.sequence]) * 16,
            payload=encode_bundle(b),
            private_key=SK,
        )
    )


def store() -> BundleStore:
    return BundleStore(
        trusted_key=SK.public_key(),
        expected_issuer=AUTHORITY,
        site_id="site-1",
        signed_floor=_signed_floor(SK, LINKS, site_id="site-1", issuer=AUTHORITY),
        now=T0,
        epoch_store=MemoryEpochStore(),
    )


def test_an_older_but_still_valid_bundle_cannot_replace_a_newer_one():
    """The rollback that motivated all of this: strict policy swapped for a loose one."""

    s = store()
    s.accept(envelope(bundle(2, allow_metered=False)), now=T0)
    with pytest.raises(BundleUnverified, match="sequence"):
        s.accept(envelope(bundle(1, allow_metered=True)), now=T0)
    assert s.current(T0)[0].bundle_id == "v2"


def test_reinstalling_the_same_sequence_is_refused():
    s = store()
    s.accept(envelope(bundle(2, allow_metered=False)), now=T0)
    with pytest.raises(BundleUnverified, match="sequence"):
        s.accept(envelope(bundle(2, allow_metered=True), nonce=b"\xaa" * 16), now=T0)


def test_a_bundle_from_an_unexpected_issuer_is_refused_even_with_a_trusted_key():
    s = store()
    with pytest.raises(BundleUnverified, match="issuer"):
        s.accept(envelope(bundle(1, allow_metered=True), issuer="attacker"), now=T0)


def test_a_bundle_naming_a_different_authority_inside_is_refused():
    s = store()
    with pytest.raises(BundleUnverified, match="authority"):
        s.accept(envelope(bundle(1, allow_metered=True, authority_id="other")), now=T0)


def test_replaying_the_exact_same_envelope_is_refused():
    s = store()
    blob = envelope(bundle(3, allow_metered=False))
    s.accept(blob, now=T0)
    with pytest.raises(BundleUnverified, match="nonce|replay"):
        s.accept(blob, now=T0)


def test_an_envelope_stamped_in_the_future_is_refused():
    s = store()
    b = bundle(1, allow_metered=True)
    blob = encode_envelope(
        sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer=AUTHORITY,
            issued_at=T0 + timedelta(hours=2),
            nonce=b"\x01" * 16,
            payload=encode_bundle(b),
            private_key=SK,
        )
    )
    with pytest.raises(BundleUnverified, match="future|skew"):
        s.accept(blob, now=T0)


def test_a_newer_sequence_is_accepted_and_takes_effect():
    s = store()
    s.accept(envelope(bundle(1, allow_metered=True)), now=T0)
    s.accept(envelope(bundle(2, allow_metered=False)), now=T0)
    assert s.current(T0)[0].bundle_id == "v2"


def test_bundle_hash_is_the_hash_of_the_wire_encoding():
    """No Python runtime semantics in the cryptographic contract."""

    import hashlib

    b = bundle(1, allow_metered=True)
    assert b.hash() == hashlib.sha256(encode_bundle(b)).hexdigest()


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
