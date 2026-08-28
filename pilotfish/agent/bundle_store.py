"""The bundle store: the only place a site decides what policy it is under.

Three questions have to be answered before a bundle governs anything, and a
signature answers only the first:

1. Was this written by a key we trust, on behalf of the authority we answer to?
2. Is it current, rather than a correctly signed policy from some earlier epoch?
3. Is it inside its validity window?

Checking only the first is the classic mistake. An attacker who can replay an
old but validly signed bundle widens the permitted set without forging anything,
and every signature in the audit trail still verifies afterwards.

The other rule that shapes this module: there is no code path returning an
unverified, superseded or expired bundle as current. Falling back means falling
to the floor, never to the last bundle the site happened to like.
"""

from __future__ import annotations

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from pilotfish.core.bundle import PolicyBundle, floor_bundle
from pilotfish.core.models import MAX_CLOCK_SKEW_S, Link
from pilotfish.protocol.envelope import SignatureInvalid, decode_envelope, verify
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, decode_bundle
from pilotfish.sdk.errors import BundleExpired, BundleUnverified


class BundleStore:
    def __init__(
        self,
        *,
        trusted_key: Ed25519PublicKey,
        expected_issuer: str,
        floor_links: tuple[Link, ...],
    ) -> None:
        self._trusted_key = trusted_key
        self._expected_issuer = expected_issuer
        self._floor = floor_bundle(floor_links)
        self._bundle: PolicyBundle | None = None
        self._sequence = -1
        self._seen_nonces: set[bytes] = set()

    @property
    def sequence(self) -> int:
        """Highest bundle sequence ever accepted. Never decreases."""

        return self._sequence

    def accept(self, envelope_bytes: bytes, now: datetime) -> PolicyBundle:
        """Verify and install a bundle. Raises rather than installing a doubtful one."""

        envelope = decode_envelope(envelope_bytes)

        if envelope.msg_type != MSG_POLICY_BUNDLE:
            raise BundleUnverified(f"expected {MSG_POLICY_BUNDLE}, got {envelope.msg_type}")

        if envelope.issuer != self._expected_issuer:
            raise BundleUnverified(
                f"issuer {envelope.issuer!r} is not the authority this site answers to "
                f"({self._expected_issuer!r})"
            )

        if envelope.issued_at.timestamp() > now.timestamp() + MAX_CLOCK_SKEW_S:
            raise BundleUnverified(
                f"envelope is stamped in the future: {envelope.issued_at.isoformat()} "
                f"exceeds the skew allowance"
            )

        try:
            verify(envelope, self._trusted_key)
        except SignatureInvalid as exc:
            raise BundleUnverified(str(exc)) from exc

        # Only after the signature holds, so an unsigned message cannot consume a
        # nonce and lock out the genuine one that follows it.
        if envelope.nonce in self._seen_nonces:
            raise BundleUnverified("envelope nonce already seen: replay refused")

        bundle = decode_bundle(envelope.payload)

        if bundle.authority_id != self._expected_issuer:
            raise BundleUnverified(
                f"bundle names authority {bundle.authority_id!r}, expected "
                f"{self._expected_issuer!r}"
            )

        if bundle.sequence <= self._sequence:
            raise BundleUnverified(
                f"bundle sequence {bundle.sequence} does not supersede {self._sequence}: "
                f"rollback refused"
            )

        if now >= bundle.not_after:
            raise BundleExpired(
                f"bundle {bundle.bundle_id} expired at {bundle.not_after.isoformat()}"
            )

        self._seen_nonces.add(envelope.nonce)
        self._bundle = bundle
        self._sequence = bundle.sequence
        return bundle

    def current(self, now: datetime) -> tuple[PolicyBundle, bool]:
        """Return the bundle in force and whether the site is running degraded."""

        if self._bundle is None or now >= self._bundle.not_after:
            return self._floor, True
        return self._bundle, False
