"""Domain models for governed access-link selection.

Every object here is frozen and hashable. Timestamps are timezone-aware UTC
without exception: an observation whose age cannot be computed is worse than no
observation at all, because policy would silently treat it as fresh.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

import cbor2

LinkType = Literal["fiber", "lte", "satellite", "fso"]

#: Source of a measurement. Policy discriminates on this, so it is not free text
#: in practice even though the type does not constrain it.
ObservationSourceName = Literal["agent", "operator", "model"]


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC, got naive {value!r}")


@dataclass(frozen=True, slots=True)
class Link:
    """An access path, with the static properties policy can reason over.

    ``type`` is not a label. It carries the failure model: fiber fails rarely and
    totally, LTE degrades with load and quota, satellite has a latency floor and
    weather sensitivity, FSO fails fast and predictably with visibility.
    """

    id: str
    type: LinkType
    metered: bool = False
    encrypted_below: bool = False
    jurisdictions: tuple[str, ...] = ()
    owner: str = ""


@dataclass(frozen=True, slots=True)
class Observation:
    """One measurement, with the two fields that make it evidence rather than a number."""

    link_id: str
    quantity: str
    value: float
    at: datetime
    source: str

    def __post_init__(self) -> None:
        _require_utc(self.at, "Observation.at")

    def age_s(self, now: datetime) -> float:
        _require_utc(now, "now")
        return (now - self.at).total_seconds()


@dataclass(frozen=True, slots=True)
class TrafficClass:
    """What policy discriminates on.

    Named requirements rather than raw DSCP values, because the requirement is
    what a contract or a regulation is written in.
    """

    id: str
    max_rtt_ms: float | None = None
    allow_metered: bool = True
    allowed_jurisdictions: tuple[str, ...] | None = None
    requires_encryption: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """A set of observations with a hash that is independent of their ordering."""

    observations: tuple[Observation, ...] = field(default_factory=tuple)

    def latest(self, link_id: str, quantity: str) -> Observation | None:
        candidates = [
            o for o in self.observations if o.link_id == link_id and o.quantity == quantity
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda o: o.at)

    def age_s(self, link_id: str, quantity: str, now: datetime) -> float | None:
        observation = self.latest(link_id, quantity)
        return None if observation is None else observation.age_s(now)

    def hash(self) -> str:
        rows = sorted(
            (o.link_id, o.quantity, o.at.timestamp(), o.source, o.value) for o in self.observations
        )
        return hashlib.sha256(cbor2.dumps(rows, canonical=True)).hexdigest()
