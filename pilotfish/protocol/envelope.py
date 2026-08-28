"""The signed envelope.

Security sits in the message, not the channel. A bundle that is only valid while
a TLS session stands would be useless in exactly the situation this system exists
for: a site whose uplinks are the thing being governed, cut off from the
authority, needing to know whether the policy in its hand is genuine.

An envelope is therefore verifiable alone, on arrival by any route at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pilotfish.protocol.canonical import dumps, loads

NONCE_BYTES = 16


class SignatureInvalid(Exception):
    """The envelope did not verify under the given key."""


@dataclass(frozen=True, slots=True)
class Envelope:
    msg_type: str
    issuer: str
    issued_at: datetime
    nonce: bytes
    payload: bytes
    signature: bytes


def signing_input(
    *, msg_type: str, issuer: str, issued_at: datetime, nonce: bytes, payload: bytes
) -> bytes:
    """Canonical CBOR of the array the signature covers.

    Ordering is fixed by position rather than by map key so that the signed bytes
    cannot drift with a field rename.
    """

    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("issued_at must be timezone-aware UTC")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be exactly {NONCE_BYTES} bytes, got {len(nonce)}")
    return dumps([msg_type, issuer, int(issued_at.timestamp()), nonce, payload])


def sign(
    *,
    msg_type: str,
    issuer: str,
    issued_at: datetime,
    nonce: bytes,
    payload: bytes,
    private_key: Ed25519PrivateKey,
) -> Envelope:
    material = signing_input(
        msg_type=msg_type, issuer=issuer, issued_at=issued_at, nonce=nonce, payload=payload
    )
    return Envelope(
        msg_type=msg_type,
        issuer=issuer,
        issued_at=issued_at,
        nonce=nonce,
        payload=payload,
        signature=private_key.sign(material),
    )


def verify(envelope: Envelope, public_key: Ed25519PublicKey) -> None:
    """Raises :class:`SignatureInvalid`. There is no boolean variant on purpose."""

    material = signing_input(
        msg_type=envelope.msg_type,
        issuer=envelope.issuer,
        issued_at=envelope.issued_at,
        nonce=envelope.nonce,
        payload=envelope.payload,
    )
    try:
        public_key.verify(envelope.signature, material)
    except InvalidSignature as exc:
        raise SignatureInvalid(
            f"envelope {envelope.msg_type} from {envelope.issuer} did not verify"
        ) from exc


def encode_envelope(envelope: Envelope) -> bytes:
    return dumps(
        [
            envelope.msg_type,
            envelope.issuer,
            int(envelope.issued_at.timestamp()),
            envelope.nonce,
            envelope.payload,
            envelope.signature,
        ]
    )


def decode_envelope(data: bytes) -> Envelope:
    fields = loads(data)
    if not isinstance(fields, list) or len(fields) != 6:
        raise ValueError("malformed envelope")
    msg_type, issuer, issued_at, nonce, payload, signature = fields
    return Envelope(
        msg_type=msg_type,
        issuer=issuer,
        issued_at=datetime.fromtimestamp(issued_at, tz=UTC),
        nonce=nonce,
        payload=payload,
        signature=signature,
    )
