"""Negative conformance: degraded behaviour is part of the authority contract.

If the floor policy is whatever the local process happened to construct, then
the most security-relevant mode the site has, the one it runs in precisely when
nobody can reach it, is the one mode nobody signed.
"""

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.authority.signer import BundleSigner, sign_floor
from pilotfish.core.bundle import floor_bundle, link_inventory_hash
from pilotfish.core.models import Link, TrafficClass
from pilotfish.sdk.errors import BundleUnverified

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
AUTHORITY = "authority-1"
SITE = "site-1"
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))
OTHER_LINKS = (*LINKS, Link(id="sat0", type="satellite", metered=True))


def floor_envelope(*, key=SK, site_id=SITE, links=LINKS, issuer=AUTHORITY) -> bytes:
    return sign_floor(
        BundleSigner(key, issuer),
        site_id=site_id,
        links=links,
        classes=(TrafficClass("default", allow_metered=False),),
        now=T0,
    )


def store(floor: bytes) -> BundleStore:
    return BundleStore(
        trusted_key=SK.public_key(),
        expected_issuer=AUTHORITY,
        site_id=SITE,
        signed_floor=floor,
        now=T0,
    )


def test_an_unsigned_floor_cannot_be_installed():
    with pytest.raises(BundleUnverified):
        store(b"\x00not an envelope at all")


def test_a_floor_signed_by_the_wrong_key_is_refused():
    with pytest.raises(BundleUnverified):
        store(floor_envelope(key=OTHER_SK))


def test_a_floor_issued_for_another_site_is_refused():
    with pytest.raises(BundleUnverified, match="site"):
        store(floor_envelope(site_id="site-2"))


def test_a_floor_bound_to_a_different_link_inventory_is_refused():
    """A site that grew a satellite link must not keep running last year's floor."""

    with pytest.raises(BundleUnverified, match="inventory|links"):
        BundleStore(
            trusted_key=SK.public_key(),
            expected_issuer=AUTHORITY,
            site_id=SITE,
            signed_floor=floor_envelope(links=LINKS),
            now=T0,
            floor_links=OTHER_LINKS,
        )


def test_a_verified_floor_governs_the_degraded_mode():
    s = store(floor_envelope())
    bundle, degraded = s.current(T0)
    assert degraded is True
    assert bundle.bundle_id == "floor"
    assert bundle.authority_id == AUTHORITY


def test_link_inventory_hash_is_order_independent_and_content_sensitive():
    a, b = LINKS
    assert link_inventory_hash((a, b)) == link_inventory_hash((b, a))
    assert link_inventory_hash(LINKS) != link_inventory_hash(OTHER_LINKS)


def test_the_unsigned_floor_helper_is_not_reachable_from_the_store():
    """floor_bundle() still exists for tests, but no store path constructs one."""

    import inspect

    source = inspect.getsource(BundleStore)
    assert "floor_bundle(" not in source


def test_the_floor_keeps_every_constraint_a_class_declares():
    """Degraded mode may be more restrictive than policy. It may never be less."""

    from pilotfish.core.decide import decide
    from pilotfish.core.models import EvidenceSnapshot, Observation

    health = TrafficClass(
        "health", max_rtt_ms=250.0, allowed_jurisdictions=("NO",), requires_encryption=True
    )
    links = (
        Link(id="fiber0", type="fiber", encrypted_below=True, jurisdictions=("NO",)),
        Link(id="sat0", type="satellite", jurisdictions=("US",)),
    )
    floor = floor_bundle(links, now=T0, traffic_classes=(health,))
    evidence = EvidenceSnapshot(
        tuple(Observation(link.id, "up", 1.0, T0, "agent") for link in links)
        + tuple(Observation(link.id, "rtt_ms", 20.0, T0, "agent") for link in links)
    )

    decision = decide(bundle=floor, evidence=evidence, now=T0, site_id=SITE, degraded=True)
    assert decision.permitted_for("health") == ("fiber0",)
    reasons = {e.rule_id for e in decision.classes[0].exclusions if e.link_id == "sat0"}
    assert {"FLOOR-JUR-health", "FLOOR-ENC-health"} <= reasons
