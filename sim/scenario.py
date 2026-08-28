"""Scenarios: a site, its links, the traffic it carries, and what goes wrong."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from pilotfish.core.bundle import PolicyBundle
from sim.links import LinkFleet

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)

EVENT_KINDS = (
    "link_down",
    "link_up",
    "fog",
    "clear",
    "obstruct",
    "unobstruct",
    "sensor_fail",
    "sensor_recover",
    "authority_unreachable",
    "authority_reachable",
)


@dataclass(frozen=True, slots=True)
class Event:
    """Something that happens to the site at a given second into the run."""

    at_s: int
    kind: str
    target: str = ""

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind {self.kind!r}")


@dataclass
class Scenario:
    name: str
    site_id: str
    bundle: PolicyBundle
    fleet_factory: callable
    traffic_bytes_per_s: dict[str, int] = field(default_factory=dict)
    events: tuple[Event, ...] = ()
    duration_s: int = 3600
    step_s: int = 30

    def fleet(self) -> LinkFleet:
        return self.fleet_factory()

    def steps(self) -> int:
        return self.duration_s // self.step_s
