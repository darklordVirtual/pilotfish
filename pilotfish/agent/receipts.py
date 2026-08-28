"""The audit trail.

A receipt is one decision, chained to the previous receipt from the same site and
numbered contiguously. Together those two properties mean a verifier holding a
run of receipts can tell whether any were removed or reordered. Gaps become
visible rather than silent, which is the entire point of keeping them.

Nothing in this module touches the network. Delivery to the authority is a
separate, resumable job reading the same file, so an expensive uplink is never on
the critical path of recording what a site decided.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.core.decide import EligibilityDecision
from pilotfish.protocol.canonical import dumps
from pilotfish.protocol.envelope import NONCE_BYTES, encode_envelope, sign
from pilotfish.protocol.messages import MSG_DECISION_RECEIPT, encode_decision

GENESIS_HASH = "0" * 64


class ChainBroken(Exception):
    """A run of receipts is not a contiguous, correctly linked chain."""


@dataclass(frozen=True, slots=True)
class Receipt:
    site_id: str
    seq: int
    prev_hash: str
    decision: EligibilityDecision

    def hash(self) -> str:
        payload = dumps([self.site_id, self.seq, self.prev_hash, encode_decision(self.decision)])
        return hashlib.sha256(payload).hexdigest()


class ReceiptChain:
    """Produces signed, linked receipts and hands them to a sink."""

    def __init__(self, site_id: str, sink, private_key: Ed25519PrivateKey) -> None:
        self._site_id = site_id
        self._sink = sink
        self._key = private_key
        self._seq = 0
        self._prev_hash = GENESIS_HASH

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._prev_hash

    def record(self, decision: EligibilityDecision, now: datetime) -> Receipt:
        receipt = Receipt(
            site_id=self._site_id,
            seq=self._seq + 1,
            prev_hash=self._prev_hash,
            decision=decision,
        )
        envelope = sign(
            msg_type=MSG_DECISION_RECEIPT,
            issuer=self._site_id,
            issued_at=now,
            # Derived from the receipt hash rather than drawn at random: the chain
            # must be reproducible by a verifier holding only the receipts.
            nonce=bytes.fromhex(receipt.hash())[:NONCE_BYTES],
            payload=dumps(
                [receipt.site_id, receipt.seq, receipt.prev_hash, encode_decision(receipt.decision)]
            ),
            private_key=self._key,
        )
        self._sink.append(encode_envelope(envelope))
        self._seq = receipt.seq
        self._prev_hash = receipt.hash()
        return receipt


def verify_chain(receipts: list[Receipt]) -> None:
    """Raise :class:`ChainBroken` unless the receipts form one unbroken run."""

    expected_prev = GENESIS_HASH
    expected_seq = 1
    for receipt in receipts:
        if receipt.seq != expected_seq:
            raise ChainBroken(f"expected sequence {expected_seq}, found {receipt.seq}")
        if receipt.prev_hash != expected_prev:
            raise ChainBroken(f"receipt {receipt.seq} does not link to its predecessor")
        expected_prev = receipt.hash()
        expected_seq += 1
