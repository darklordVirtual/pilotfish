"""The bundle store: the only place a site decides what policy it is under.

The rule that shapes this module: there is no code path returning an unverified
or expired bundle as current. Falling back means falling to the floor, never to
the last bundle the site happened to like. A stale bundle is the more dangerous
of the two, because it looks like governance while no longer being it.
"""

from __future__ import annotations

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from pilotfish.core.bundle import PolicyBundle, floor_bundle
from pilotfish.core.models import Link
from pilotfish.protocol.envelope import SignatureInvalid, decode_envelope, verify
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, decode_bundle
from pilotfish.sdk.errors import BundleExpired, BundleUnverified


class BundleStore:
    def __init__(self, *, trusted_key: Ed25519PublicKey, floor_links: tuple[Link, ...]) -> None:
        self._trusted_key = trusted_key
        self._floor = floor_bundle(floor_links)
        self._bundle: PolicyBundle | None = None

    def accept(self, envelope_bytes: bytes, now: datetime) -> PolicyBundle:
        """Verify and install a bundle. Raises rather than installing a doubtful one."""

        envelope = decode_envelope(envelope_bytes)
        if envelope.msg_type != MSG_POLICY_BUNDLE:
            raise BundleUnverified(f"expected {MSG_POLICY_BUNDLE}, got {envelope.msg_type}")
        try:
            verify(envelope, self._trusted_key)
        except SignatureInvalid as exc:
            raise BundleUnverified(str(exc)) from exc

        bundle = decode_bundle(envelope.payload)
        if now >= bundle.not_after:
            raise BundleExpired(f"bundle {bundle.bundle_id} expired at {bundle.not_after.isoformat()}")
        self._bundle = bundle
        return bundle

    def current(self, now: datetime) -> tuple[PolicyBundle, bool]:
        """Return the bundle in force and whether the site is running degraded."""

        if self._bundle is None or now >= self._bundle.not_after:
            return self._floor, True
        return self._bundle, False
