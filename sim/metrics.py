"""What we measure, and who gets to decide whether something was a violation.

The violation oracle deliberately does not consult policy. It reads the true
simulated state of the link and the stated requirement of the traffic class. If
it asked the policy engine, a governed run could never violate anything by
construction, and the comparison would be worthless.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pilotfish.core.models import Link, TrafficClass
from sim.links import LinkFleet, LteModel, SatelliteModel


@dataclass(frozen=True, slots=True)
class Violation:
    at_s: int
    class_id: str
    link_id: str
    requirement: str


def check_violations(
    *,
    at_s: int,
    choices: dict[str, str | None],
    links: dict[str, Link],
    classes: dict[str, TrafficClass],
    fleet: LinkFleet,
    true_rtt: dict[str, float],
) -> list[Violation]:
    """Ground truth: was this choice allowed, given what was actually true?"""

    found: list[Violation] = []
    for class_id, link_id in choices.items():
        if link_id is None:
            continue
        link, tclass = links[link_id], classes[class_id]

        if not tclass.allow_metered and link.metered:
            found.append(
                Violation(at_s, class_id, link_id, "metered path used by a class that forbids it")
            )

        if tclass.allowed_jurisdictions is not None:
            outside = [j for j in link.jurisdictions if j not in tclass.allowed_jurisdictions]
            if outside or not link.jurisdictions:
                found.append(
                    Violation(at_s, class_id, link_id, "traffic left the permitted jurisdiction")
                )

        if tclass.requires_encryption and not link.encrypted_below:
            found.append(
                Violation(
                    at_s,
                    class_id,
                    link_id,
                    "unencrypted path used by a class that requires encryption",
                )
            )

        if tclass.max_rtt_ms is not None:
            actual = true_rtt.get(link_id)
            if actual is not None and actual > tclass.max_rtt_ms:
                found.append(Violation(at_s, class_id, link_id, "latency requirement missed"))

        model = fleet.models.get(link_id)
        if isinstance(model, (LteModel, SatelliteModel)) and model.quota_used_pct() >= 100.0:
            found.append(Violation(at_s, class_id, link_id, "carried over a spent allowance"))

    return found


@dataclass
class RunResult:
    """The measures that discriminate between selectors, plus the ones that do not."""

    scenario: str
    selector: str
    seed: int
    steps: int = 0
    step_s: int = 30
    violations: list[Violation] = field(default_factory=list)
    downtime_s: int = 0
    refused_s: int = 0
    degraded_s: int = 0
    flaps: int = 0
    cost: float = 0.0
    frames: list[dict] = field(default_factory=list)

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def unserved_s(self) -> int:
        """Class-seconds with no path: no link up, or none that policy allowed."""

        return self.downtime_s + self.refused_s

    @property
    def uptime_pct(self) -> float:
        total = self.steps * self.step_s
        return 100.0 if total == 0 else 100.0 * (total - self.downtime_s) / total

    def timeline_at(self, second: int) -> dict:
        index = min(second // self.step_s, len(self.frames) - 1)
        return self.frames[index]
