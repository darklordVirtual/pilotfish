"""Domain models for governed access-link selection.

Every object here is frozen and hashable. Timestamps are timezone-aware UTC
without exception: an observation whose age cannot be computed is worse than no
observation at all, because policy would silently treat it as fresh.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal

import cbor2

LinkType = Literal["fiber", "lte", "satellite", "fso"]

#: Source of a measurement. Policy discriminates on this, so it is not free text
#: in practice even though the type does not constrain it.
ObservationSourceName = Literal["agent", "operator", "model"]


#: How far ahead of our own clock another party's timestamp may be before we stop
#: believing it. Honest clocks disagree by seconds; evidence dated further into
#: the future than this is not evidence, and treating it as fresh would switch
#: abstention off exactly when it is most needed.
MAX_CLOCK_SKEW_S = 120.0


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC, got naive {value!r}")


def _require_finite(value: float | None, field_name: str) -> None:
    """NaN compares false against every threshold, so it defeats every rule at once.

    A rule asking "is this over the limit" answers no for NaN, and a rule asking
    "is this under the limit" also answers no. Either way the link stays in the
    permitted set on the strength of a measurement that means nothing.
    """

    if value is None:
        return
    if not math.isfinite(value):
        raise ValueError(f"{field_name} must be finite, got {value!r}")


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
        _require_finite(self.value, "Observation.value")

    def age_s(self, now: datetime) -> float:
        """Age in seconds, floored at zero.

        A reading from slightly ahead of our clock is at most brand new; it is
        never negative, because a negative age would read as more recent than
        anything real and would outrank genuine measurements.
        """

        _require_utc(now, "now")
        return max(0.0, (now - self.at).total_seconds())


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

    def __post_init__(self) -> None:
        _require_finite(self.max_rtt_ms, "TrafficClass.max_rtt_ms")


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """A set of observations with a hash that is independent of their ordering."""

    observations: tuple[Observation, ...] = field(default_factory=tuple)

    def as_of(self, now: datetime) -> EvidenceSnapshot:
        """Drop evidence dated further ahead than the skew allowance.

        Dropping rather than clamping is deliberate. A discarded observation
        leaves the quantity missing, and missing evidence already excludes, so a
        clock running fast makes the permitted set smaller instead of larger.
        """

        _require_utc(now, "now")
        horizon = now.timestamp() + MAX_CLOCK_SKEW_S
        kept = tuple(o for o in self.observations if o.at.timestamp() <= horizon)
        return replace(self, observations=kept)

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
