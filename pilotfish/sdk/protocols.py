"""The four integration points.

Each is a protocol you implement, not a class you subclass. If you have a
telemetry source, a dataplane, somewhere to put receipts and somewhere to fetch
policy from, you have integrated Pilotfish.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, runtime_checkable

from pilotfish.core.decide import EligibilityDecision
from pilotfish.core.models import Observation


@runtime_checkable
class ObservationSource(Protocol):
    """Supplies measurements. Each one carries its own timestamp and source.

    Returning fewer observations than usual is a legitimate answer, and a better
    one than inventing a value: policy treats missing evidence as grounds for
    exclusion, which is the conservative direction.
    """

    def observe(self, now: datetime) -> tuple[Observation, ...]: ...


@runtime_checkable
class DataplaneAdapter(Protocol):
    """Applies a decision, and reports what is actually in force.

    ``readback`` is not decoration. Without it there is no postcondition, and a
    decision that was taken but never reached the dataplane is among the most
    common and least visible failures in this domain.
    """

    def apply(self, decision: EligibilityDecision) -> None: ...

    def readback(self) -> Mapping[str, tuple[str, ...]]:
        """Return the permitted link ids per class as the system currently has them."""
        ...


@runtime_checkable
class ReceiptSink(Protocol):
    """Where receipts go. Append-only, and never on the critical path of an uplink."""

    def append(self, receipt_bytes: bytes) -> None: ...


@runtime_checkable
class PolicyAuthorityClient(Protocol):
    """Fetches a policy bundle envelope, or ``None`` if the authority is unreachable.

    Unreachable is an ordinary condition, not an error: it is the normal state of
    a site whose uplinks are the thing being governed.
    """

    def fetch(self) -> bytes | None: ...
