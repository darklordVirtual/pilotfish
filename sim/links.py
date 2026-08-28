"""Link failure models.

Each model produces observations, which is the only way the rest of the system
can learn anything about it. A model that stops reporting is therefore a
first-class scenario: it is what a dead sensor or a hung modem daemon looks like
from the agent's side, and the agent must handle it without being told.

Everything here is seeded. No model reads a global random source or a wall clock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from random import Random

from pilotfish.core.models import Observation

GB = 10**9


@dataclass
class LinkModel:
    """Base: a link that is up, silent, or dead, and reports what it knows."""

    link_id: str
    up: bool = True
    sensor_failed: bool = False
    bytes_carried: int = 0

    def carry(self, bytes_: int) -> None:
        self.bytes_carried += bytes_

    def step(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        if self.sensor_failed:
            return ()
        return self._observe(t, rng)

    def _observe(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        raise NotImplementedError

    def _liveness(self, t: datetime) -> Observation:
        return Observation(self.link_id, "up", 1.0 if self.up else 0.0, t, "agent")

    def cost_per_gb(self) -> float:
        return 0.0


@dataclass
class FiberModel(LinkModel):
    """Fails rarely and totally. When it is up it is simply better than everything else."""

    base_rtt_ms: float = 8.0

    def _observe(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        if not self.up:
            return (self._liveness(t),)
        rtt = self.base_rtt_ms + rng.uniform(-1.0, 2.0)
        return (
            self._liveness(t),
            Observation(self.link_id, "rtt_ms", rtt, t, "agent"),
        )


@dataclass
class LteModel(LinkModel):
    """Degrades with load and, more importantly here, runs out of allowance."""

    quota_gb: float = 10.0
    base_rtt_ms: float = 45.0
    congestion: float = 0.0
    cost_per_gb_over: float = 8.0

    def quota_used_pct(self) -> float:
        if self.quota_gb <= 0:
            return 100.0
        return min(100.0, 100.0 * (self.bytes_carried / GB) / self.quota_gb)

    def cost_per_gb(self) -> float:
        return self.cost_per_gb_over

    def _observe(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        if not self.up:
            return (self._liveness(t),)
        rtt = self.base_rtt_ms * (1.0 + self.congestion) + rng.uniform(-5.0, 15.0)
        return (
            self._liveness(t),
            Observation(self.link_id, "rtt_ms", rtt, t, "agent"),
            # Quota comes from the carrier, not from us. Policy cares about the
            # difference, so the simulator must not blur it.
            Observation(self.link_id, "quota_used_pct", self.quota_used_pct(), t, "operator"),
        )


@dataclass
class SatelliteModel(LinkModel):
    """A latency floor no engineering removes, plus weather-driven obstruction."""

    base_rtt_ms: float = 90.0
    obstructed: bool = False
    quota_gb: float = 50.0
    cost_per_gb_over: float = 3.0

    def quota_used_pct(self) -> float:
        if self.quota_gb <= 0:
            return 100.0
        return min(100.0, 100.0 * (self.bytes_carried / GB) / self.quota_gb)

    def cost_per_gb(self) -> float:
        return self.cost_per_gb_over

    def _observe(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        if not self.up:
            return (self._liveness(t),)
        penalty = 400.0 if self.obstructed else 0.0
        rtt = self.base_rtt_ms + penalty + rng.uniform(-5.0, 25.0)
        return (
            self._liveness(t),
            Observation(self.link_id, "rtt_ms", rtt, t, "agent"),
            Observation(self.link_id, "quota_used_pct", self.quota_used_pct(), t, "operator"),
        )


@dataclass
class FsoModel(LinkModel):
    """Fast, cheap and short-sighted: excellent until the visibility goes.

    The weather figure is modelled, not measured, which is exactly why policy
    treats its age as significant.
    """

    visibility_m: float = 8000.0
    base_rtt_ms: float = 3.0
    usable_visibility_m: float = 500.0

    def _observe(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        usable = self.up and self.visibility_m >= self.usable_visibility_m
        observations = [
            Observation(self.link_id, "up", 1.0 if usable else 0.0, t, "agent"),
            Observation(self.link_id, "visibility_m", self.visibility_m, t, "model"),
        ]
        if usable:
            observations.append(
                Observation(
                    self.link_id, "rtt_ms", self.base_rtt_ms + rng.uniform(0.0, 1.0), t, "agent"
                )
            )
        return tuple(observations)


@dataclass
class LinkFleet:
    """The models for one site, addressed by link id."""

    models: dict[str, LinkModel] = field(default_factory=dict)

    def step(self, t: datetime, rng: Random) -> tuple[Observation, ...]:
        out: list[Observation] = []
        for model in self.models.values():
            out.extend(model.step(t, rng))
        return tuple(out)

    def is_up(self, link_id: str) -> bool:
        model = self.models[link_id]
        if isinstance(model, FsoModel):
            return model.up and model.visibility_m >= model.usable_visibility_m
        return model.up
