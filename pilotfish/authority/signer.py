"""The authority side: turn a policy file into a signed bundle.

This is deliberately the smallest component in the system. The authority signs
and publishes; it does not decide anything in real time, and no site waits on it.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.core.bundle import PolicyBundle, floor_bundle, link_inventory_hash
from pilotfish.core.models import Link, TrafficClass
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import (
    MSG_FLOOR_CONFIG,
    MSG_POLICY_BUNDLE,
    decode_rule,
    encode_bundle,
    encode_floor_config,
)

NONCE_SIZE_BYTES = 16


def _fresh_nonce() -> bytes:
    """Return a fresh envelope nonce.

    Nonces are replay metadata, not test fixtures. Production callers therefore
    get unpredictable bytes by default. Tests or deterministic interoperability
    vectors may still pass an explicit nonce.
    """

    return secrets.token_bytes(NONCE_SIZE_BYTES)


class BundleSigner:
    def __init__(self, private_key: Ed25519PrivateKey, issuer: str) -> None:
        self._key = private_key
        self._issuer = issuer

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._key

    def publish(
        self,
        bundle: PolicyBundle,
        now: datetime,
        nonce: bytes | None = None,
    ) -> bytes:
        envelope = sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer=self._issuer,
            issued_at=now,
            nonce=_fresh_nonce() if nonce is None else nonce,
            payload=encode_bundle(bundle),
            private_key=self._key,
        )
        return encode_envelope(envelope)


def load_bundle_json(path: str | Path, *, now: datetime | None = None) -> PolicyBundle:
    """Read a declarative policy file.

    JSON rather than YAML so the authority needs no dependency a site does not
    already have, and so a policy file can be diffed and reviewed like code.
    """

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    issued = now or datetime.now(tz=UTC)
    return PolicyBundle(
        bundle_id=data["bundle_id"],
        authority_id=data["authority_id"],
        sequence=data["sequence"],
        issued_at=issued,
        not_after=issued + timedelta(seconds=data["validity_s"]),
        decision_ttl_s=data["decision_ttl_s"],
        links=tuple(
            Link(
                id=link["id"],
                type=link["type"],
                metered=link.get("metered", False),
                encrypted_below=link.get("encrypted_below", False),
                jurisdictions=tuple(link.get("jurisdictions", ())),
                owner=link.get("owner", ""),
            )
            for link in data["links"]
        ),
        traffic_classes=tuple(
            TrafficClass(
                id=c["id"],
                max_rtt_ms=c.get("max_rtt_ms"),
                allow_metered=c.get("allow_metered", True),
                allowed_jurisdictions=(
                    tuple(c["allowed_jurisdictions"]) if "allowed_jurisdictions" in c else None
                ),
                requires_encryption=c.get("requires_encryption", False),
            )
            for c in data["traffic_classes"]
        ),
        rules=tuple(decode_rule(rule) for rule in data["rules"]),
    )


def sign_floor(
    signer: BundleSigner,
    *,
    site_id: str,
    links: tuple[Link, ...],
    classes: tuple[TrafficClass, ...],
    now: datetime,
    nonce: bytes | None = None,
) -> bytes:
    """Sign the degraded-mode policy for one site.

    The floor is the mode a site runs in exactly when nobody can reach it, which
    makes it the last thing that should be whatever the local process happened to
    construct at start-up.

    V2 will replace the operator-visible degraded-mode concept with the single
    SURVIVAL execution model. Until that protocol migration lands, this function
    remains the V1 compatibility path.
    """

    floor = floor_bundle(links, now=now, authority_id=signer.issuer, traffic_classes=classes)
    payload = encode_floor_config(site_id, link_inventory_hash(links), floor)
    return encode_envelope(
        sign(
            msg_type=MSG_FLOOR_CONFIG,
            issuer=signer.issuer,
            issued_at=now,
            nonce=_fresh_nonce() if nonce is None else nonce,
            payload=payload,
            private_key=signer.private_key,
        )
    )
