"""Negative conformance: rollback protection must outlive the process.

A high-water mark held only in memory protects a bundle store for as long as
nobody restarts it, which is not a security property. An attacker who can cause
or wait for a restart gets the rollback back.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.epoch import FileEpochStore, MemoryEpochStore
from pilotfish.authority.signer import BundleSigner, sign_floor
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import LinkDownRule, MeteredRule
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, encode_bundle
from pilotfish.sdk.errors import BundleUnverified

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
AUTHORITY = "authority-1"
SITE = "site-1"
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))


def bundle(sequence: int, *, allow_metered: bool) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=f"v{sequence}",
        authority_id=AUTHORITY,
        sequence=sequence,
        issued_at=T0,
        not_after=T0 + timedelta(hours=6),
        decision_ttl_s=60,
        links=LINKS,
        traffic_classes=(TrafficClass("bulk", allow_metered=allow_metered),),
        rules=(LinkDownRule("R-DOWN"), MeteredRule("R-METER", "bulk")),
    )


def envelope(b: PolicyBundle) -> bytes:
    return encode_envelope(
        sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer=AUTHORITY,
            issued_at=T0,
            nonce=b.sequence.to_bytes(16, "big"),
            payload=encode_bundle(b),
            private_key=SK,
        )
    )


def floor() -> bytes:
    return sign_floor(
        BundleSigner(SK, AUTHORITY),
        site_id=SITE,
        links=LINKS,
        classes=(TrafficClass("bulk", allow_metered=False),),
        now=T0,
    )


def store(epochs) -> BundleStore:
    """A fresh process reading the same durable state, which is what a restart is."""

    return BundleStore(
        trusted_key=SK.public_key(),
        expected_issuer=AUTHORITY,
        site_id=SITE,
        signed_floor=floor(),
        now=T0,
        epoch_store=epochs,
    )


def test_rollback_is_refused_across_a_restart():
    """The case that motivated this file: restart, then replay an older policy."""

    epochs = MemoryEpochStore()
    store(epochs).accept(envelope(bundle(10, allow_metered=False)), now=T0)

    restarted = store(epochs)
    assert restarted.sequence == 10

    with pytest.raises(BundleUnverified, match="sequence"):
        restarted.accept(envelope(bundle(7, allow_metered=True)), now=T0)


def test_replaying_the_identical_envelope_is_refused_across_a_restart():
    epochs = MemoryEpochStore()
    blob = envelope(bundle(10, allow_metered=False))
    store(epochs).accept(blob, now=T0)
    with pytest.raises(BundleUnverified, match="sequence"):
        store(epochs).accept(blob, now=T0)


def test_a_newer_bundle_still_installs_after_a_restart():
    epochs = MemoryEpochStore()
    store(epochs).accept(envelope(bundle(10, allow_metered=False)), now=T0)
    restarted = store(epochs)
    restarted.accept(envelope(bundle(11, allow_metered=True)), now=T0)
    assert restarted.current(T0)[0].bundle_id == "v11"


def test_the_high_water_mark_survives_on_disk(tmp_path):
    path = tmp_path / "epoch"
    store(FileEpochStore(path)).accept(envelope(bundle(10, allow_metered=False)), now=T0)
    assert FileEpochStore(path).read() == 10
    with pytest.raises(BundleUnverified, match="sequence"):
        store(FileEpochStore(path)).accept(envelope(bundle(9, allow_metered=True)), now=T0)


def test_the_mark_is_committed_before_the_bundle_takes_effect(tmp_path):
    """If the commit fails, the bundle must not govern anything."""

    class RefusingStore(MemoryEpochStore):
        def commit(self, sequence: int) -> None:
            raise OSError("read-only filesystem")

    epochs = RefusingStore()
    s = store(epochs)
    with pytest.raises(OSError):
        s.accept(envelope(bundle(10, allow_metered=False)), now=T0)
    assert s.current(T0)[0].bundle_id == "floor"


def test_the_mark_never_moves_backwards_even_if_asked(tmp_path):
    epochs = FileEpochStore(tmp_path / "epoch")
    epochs.commit(10)
    epochs.commit(4)
    assert epochs.read() == 10


def test_an_unreadable_mark_is_fatal_rather_than_treated_as_zero(tmp_path):
    """Corruption must not silently reopen the whole rollback window."""

    path = tmp_path / "epoch"
    path.write_text("not a number")
    with pytest.raises(BundleUnverified, match="epoch|high-water"):
        store(FileEpochStore(path))
