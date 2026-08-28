"""The authority side: turn a policy file into a signed bundle.

This is deliberately the smallest component in the system. The authority signs
and publishes; it does not decide anything in real time, and no site waits on it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, TrafficClass
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, decode_rule, encode_bundle

DEFAULT_NONCE = b"\x00" * 16


class BundleSigner:
    def __init__(self, private_key: Ed25519PrivateKey, issuer: str) -> None:
        self._key = private_key
        self._issuer = issuer

    def publish(self, bundle: PolicyBundle, now: datetime, nonce: bytes = DEFAULT_NONCE) -> bytes:
        envelope = sign(
            msg_type=MSG_POLICY_BUNDLE,
            issuer=self._issuer,
            issued_at=now,
            nonce=nonce,
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
