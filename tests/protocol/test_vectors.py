"""The frozen vectors are the specification; this module checks we still match them.

If a change here fails, the answer is almost never to regenerate the vector file.
It is that the wire format changed, which is a breaking change to every party
that ever verified one of our envelopes.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pilotfish.protocol.envelope import decode_envelope, encode_envelope, sign, signing_input, verify

VECTOR = json.loads((Path(__file__).parents[2] / "spec/vectors/envelope.json").read_text())


def _inputs():
    return {
        "msg_type": VECTOR["msg_type"],
        "issuer": VECTOR["issuer"],
        "issued_at": datetime.fromtimestamp(VECTOR["issued_at_unix"], tz=UTC),
        "nonce": bytes.fromhex(VECTOR["nonce_hex"]),
        "payload": bytes.fromhex(VECTOR["payload_hex"]),
    }


def test_signing_input_matches_the_frozen_vector():
    assert signing_input(**_inputs()).hex() == VECTOR["signing_input_hex"]


def test_signature_matches_the_frozen_vector():
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["private_key_hex"]))
    envelope = sign(**_inputs(), private_key=sk)
    assert envelope.signature.hex() == VECTOR["signature_hex"]


def test_encoded_envelope_matches_the_frozen_vector():
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["private_key_hex"]))
    assert encode_envelope(sign(**_inputs(), private_key=sk)).hex() == VECTOR["encoded_envelope_hex"]


def test_a_third_party_holding_only_the_public_key_can_verify_the_vector():
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(VECTOR["public_key_hex"]))
    verify(decode_envelope(bytes.fromhex(VECTOR["encoded_envelope_hex"])), pk)
