"""The decision function.

Pure by construction: bundle, evidence and clock in, decision out. No I/O, no
network, no hidden state, and no clock read inside. That purity is what lets the
simulator run millions of these and what makes every one of them reproducible
from its inputs alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import EvidenceSnapshot
from pilotfish.core.rules import Exclusion


@dataclass(frozen=True, slots=True)
class ClassEligibility:
    """The permitted set for one traffic class, and why the rest were removed."""

    class_id: str
    permitted: tuple[str, ...]
    exclusions: tuple[Exclusion, ...]


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    """One signed-in-transit decision, bound to the exact bundle and evidence behind it."""

    site_id: str
    decided_at: datetime
    valid_until: datetime
    bundle_hash: str
    evidence_hash: str
    degraded: bool
    classes: tuple[ClassEligibility, ...]

    def permitted_for(self, class_id: str) -> tuple[str, ...]:
        for cls in self.classes:
            if cls.class_id == class_id:
                return cls.permitted
        return ()


def decide(
    *,
    bundle: PolicyBundle,
    evidence: EvidenceSnapshot,
    now: datetime,
    site_id: str,
    degraded: bool = False,
) -> EligibilityDecision:
    """Every link starts as a candidate; rules take links out, never put them in."""

    # Discard evidence dated past the skew allowance before anything reads it, and
    # bind the receipt to the snapshot actually used rather than the one supplied.
    evidence = evidence.as_of(now)

    classes: list[ClassEligibility] = []
    for tclass in sorted(bundle.traffic_classes, key=lambda c: c.id):
        permitted: list[str] = []
        exclusions: list[Exclusion] = []
        for link in sorted(bundle.links, key=lambda link: link.id):
            reasons = [
                Exclusion(link_id=link.id, rule_id=rule.rule_id, reason=reason)
                for rule in bundle.rules
                if (reason := rule.evaluate(link, tclass, evidence, now)) is not None
            ]
            if reasons:
                exclusions.extend(reasons)
            else:
                permitted.append(link.id)
        classes.append(
            ClassEligibility(
                class_id=tclass.id,
                permitted=tuple(permitted),
                exclusions=tuple(sorted(exclusions, key=lambda e: (e.link_id, e.rule_id))),
            )
        )

    return EligibilityDecision(
        site_id=site_id,
        decided_at=now,
        valid_until=now + timedelta(seconds=bundle.decision_ttl_s),
        bundle_hash=bundle.hash(),
        evidence_hash=evidence.hash(),
        degraded=degraded,
        classes=tuple(classes),
    )
