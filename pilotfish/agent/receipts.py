"""The audit trail.

A receipt records one step in the life of a decision, chained to the previous
receipt from the same site and numbered contiguously. Together those properties
let a verifier holding a run of receipts confirm that none were removed or
reordered, and make gaps visible rather than silent.

Three kinds, because a decision receipt on its own answers only the first of
three separate questions:

- ``DECISION``: what was authorised.
- ``EXECUTION``: what was attempted against the dataplane.
- ``EFFECT``: what the dataplane was actually observed to hold afterwards, with
  a hash of that observed state.

A system that logs only the first can say a link was forbidden while the
forbidden link carried traffic all night, and every signature in its log still
verifies. That gap is the whole reason this file has three record types.

Nothing here touches the network. Delivery to the authority is a separate,
resumable job reading the same log.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pilotfish.core.decide import EligibilityDecision
from pilotfish.protocol.canonical import dumps, loads
from pilotfish.protocol.envelope import (
    NONCE_BYTES,
    SignatureInvalid,
    decode_envelope,
    encode_envelope,
    sign,
    verify,
)
from pilotfish.protocol.messages import MSG_DECISION_RECEIPT, decode_decision, encode_decision

GENESIS_HASH = "0" * 64

KIND_DECISION = "DECISION"
KIND_EXECUTION = "EXECUTION"
KIND_EFFECT = "EFFECT"

OUTCOME_ENFORCED = "ENFORCED"
OUTCOME_POSTCONDITION_FAILED = "POSTCONDITION_FAILED"
OUTCOME_ENFORCEMENT_ERROR = "ENFORCEMENT_ERROR"


@runtime_checkable
class ReadableSink(Protocol):
    """A receipt sink that can also be read back, which recovery requires."""

    def append(self, receipt_bytes: bytes) -> None: ...

    def read_all(self) -> list[bytes]: ...


class ChainBroken(Exception):
    """A run of receipts is not a contiguous, correctly linked, verifiable chain."""


def state_hash(state: Mapping[str, tuple[str, ...]]) -> str:
    """Hash of an observed dataplane state, so an effect receipt names what it saw."""

    rows = sorted([class_id, sorted(links)] for class_id, links in state.items())
    return hashlib.sha256(dumps(rows)).hexdigest()


@dataclass(frozen=True, slots=True)
class Receipt:
    site_id: str
    seq: int
    prev_hash: str
    kind: str
    decision: EligibilityDecision
    outcome: str = ""
    observed_state_hash: str = ""
    detail: str = ""

    def body(self) -> list[Any]:
        return [
            self.site_id,
            self.seq,
            self.prev_hash,
            self.kind,
            encode_decision(self.decision),
            self.outcome,
            self.observed_state_hash,
            self.detail,
        ]

    def hash(self) -> str:
        return hashlib.sha256(dumps(self.body())).hexdigest()


def _receipt_from_body(fields: list[Any]) -> Receipt:
    return Receipt(
        site_id=fields[0],
        seq=fields[1],
        prev_hash=fields[2],
        kind=fields[3],
        decision=decode_decision(fields[4]),
        outcome=fields[5],
        observed_state_hash=fields[6],
        detail=fields[7],
    )


def read_chain(sink: ReadableSink, public_key: Ed25519PublicKey) -> list[Receipt]:
    """Decode and verify every receipt in a log.

    A receipt that does not verify raises. Reading past it and keeping the rest
    would mean appending to a log we cannot vouch for.
    """

    receipts: list[Receipt] = []
    for index, line in enumerate(sink.read_all()):
        envelope = decode_envelope(line)
        try:
            verify(envelope, public_key)
        except SignatureInvalid as exc:
            raise ChainBroken(f"receipt {index + 1} does not verify: {exc}") from exc
        receipts.append(_receipt_from_body(loads(envelope.payload)))
    return receipts


class ReceiptChain:
    """Produces signed, linked receipts and hands them to a sink."""

    def __init__(
        self,
        site_id: str,
        sink: ReadableSink,
        private_key: Ed25519PrivateKey,
        *,
        seq: int = 0,
        prev_hash: str = GENESIS_HASH,
    ) -> None:
        self._site_id = site_id
        self._sink = sink
        self._key = private_key
        self._seq = seq
        self._prev_hash = prev_hash

    @classmethod
    def recover(
        cls, sink: ReadableSink, private_key: Ed25519PrivateKey, *, site_id: str
    ) -> ReceiptChain:
        """Resume an existing log, or start a new one if there is nothing there.

        Constructing a chain without this is how an audit trail silently restarts
        at sequence 1 while its predecessors are still sitting in the log.
        """

        receipts = read_chain(sink, private_key.public_key()) if hasattr(sink, "read_all") else []
        if not receipts:
            return cls(site_id, sink, private_key)

        foreign = {r.site_id for r in receipts} - {site_id}
        if foreign:
            raise ChainBroken(
                f"log belongs to site {sorted(foreign)}, refusing to append as {site_id!r}"
            )

        verify_chain(receipts)
        last = receipts[-1]
        return cls(site_id, sink, private_key, seq=last.seq, prev_hash=last.hash())

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._prev_hash

    def record(
        self,
        decision: EligibilityDecision,
        now: datetime,
        *,
        kind: str = KIND_DECISION,
        outcome: str = "",
        observed_state_hash: str = "",
        detail: str = "",
    ) -> Receipt:
        receipt = Receipt(
            site_id=self._site_id,
            seq=self._seq + 1,
            prev_hash=self._prev_hash,
            kind=kind,
            decision=decision,
            outcome=outcome,
            observed_state_hash=observed_state_hash,
            detail=detail,
        )
        envelope = sign(
            msg_type=MSG_DECISION_RECEIPT,
            issuer=self._site_id,
            issued_at=now,
            # Derived from the receipt hash rather than drawn at random: a
            # verifier holding only the log must be able to recompute it.
            nonce=bytes.fromhex(receipt.hash())[:NONCE_BYTES],
            payload=dumps(receipt.body()),
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
