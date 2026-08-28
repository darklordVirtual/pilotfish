from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.protocol.canonical import dumps
from pilotfish.protocol.envelope import (
    SignatureInvalid,
    decode_envelope,
    encode_envelope,
    sign,
    verify,
)

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
NONCE = b"\x01" * 16


def make(payload=b"hello", key=SK):
    return sign(
        msg_type="POLICY_BUNDLE",
        issuer="authority-1",
        issued_at=T0,
        nonce=NONCE,
        payload=payload,
        private_key=key,
    )


def test_roundtrip_and_verify():
    verify(make(), SK.public_key())


def test_tampered_payload_fails_verification():
    with pytest.raises(SignatureInvalid):
        verify(replace(make(), payload=b"hellp"), SK.public_key())


def test_wrong_key_fails_verification():
    with pytest.raises(SignatureInvalid):
        verify(make(key=OTHER_SK), SK.public_key())


def test_tampered_issuer_fails_verification():
    with pytest.raises(SignatureInvalid):
        verify(replace(make(), issuer="authority-2"), SK.public_key())


def test_signing_input_is_stable_across_map_ordering():
    assert dumps({"b": 1, "a": 2}) == dumps({"a": 2, "b": 1})


def test_envelope_survives_encoding():
    original = make()
    assert decode_envelope(encode_envelope(original)) == original


def test_naive_timestamp_and_short_nonce_are_refused():
    with pytest.raises(ValueError):
        sign(
            msg_type="X",
            issuer="a",
            issued_at=datetime(2026, 8, 28, 12, 0),
            nonce=NONCE,
            payload=b"",
            private_key=SK,
        )
    with pytest.raises(ValueError):
        sign(
            msg_type="X",
            issuer="a",
            issued_at=T0,
            nonce=b"short",
            payload=b"",
            private_key=SK,
        )
