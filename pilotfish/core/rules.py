"""Exclusion rules.

Rules only ever take links out of the candidate set. None of them can put a link
in. That is what makes a decision monotone and explainable: every link was a
candidate, these ones were removed, and here is the reason for each.

The other invariant, and the one that matters most in operations: a rule that
reads a measurement excludes when the measurement is absent. Absence of evidence
is never evidence of health.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from pilotfish.core.models import EvidenceSnapshot, Link, LinkType, TrafficClass


@dataclass(frozen=True, slots=True)
class Exclusion:
    """One link removed from one class's permitted set, with its reason."""

    link_id: str
    rule_id: str
    reason: str


@runtime_checkable
class Rule(Protocol):
    """Returns a reason when the link is excluded, or ``None`` when it does not apply."""

    rule_id: str

    def evaluate(
        self,
        link: Link,
        tclass: TrafficClass,
        evidence: EvidenceSnapshot,
        now: datetime,
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class LinkDownRule:
    """Excludes a link that is not observed to be up."""

    rule_id: str

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        observation = evidence.latest(link.id, "up")
        if observation is None:
            return "no liveness observation"
        if observation.value < 1.0:
            return "observed down"
        return None


@dataclass(frozen=True, slots=True)
class MaxRttRule:
    """Excludes a link that fails, or cannot be shown to meet, the class latency bound."""

    rule_id: str
    class_id: str

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if tclass.id != self.class_id or tclass.max_rtt_ms is None:
            return None
        observation = evidence.latest(link.id, "rtt_ms")
        if observation is None:
            return f"no latency measurement, class requires <= {tclass.max_rtt_ms} ms"
        if observation.value > tclass.max_rtt_ms:
            return f"rtt {observation.value} ms exceeds {tclass.max_rtt_ms} ms"
        return None


@dataclass(frozen=True, slots=True)
class MeteredRule:
    """Excludes metered links from a class that does not tolerate them."""

    rule_id: str
    class_id: str

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if tclass.id != self.class_id or tclass.allow_metered or not link.metered:
            return None
        return "link is metered and the class does not permit metered paths"


@dataclass(frozen=True, slots=True)
class QuotaRule:
    """Excludes a link type whose quota is spent, or whose quota is unknown."""

    rule_id: str
    link_type: LinkType
    threshold_pct: float

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if link.type != self.link_type:
            return None
        observation = evidence.latest(link.id, "quota_used_pct")
        if observation is None:
            return "quota consumption unknown"
        if observation.value >= self.threshold_pct:
            return f"quota at {observation.value}% of allowance"
        return None


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessRule:
    """Excludes a link type whose evidence has aged past what policy tolerates.

    This is where abstention lives. Nothing has to detect that the weather feed
    died: the permitted set contracts on its own as the last observation ages.
    """

    rule_id: str
    link_type: LinkType
    quantity: str
    max_age_s: float

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if link.type != self.link_type:
            return None
        age = evidence.age_s(link.id, self.quantity, now)
        if age is None:
            return f"no {self.quantity} observation at all"
        if age > self.max_age_s:
            return f"{self.quantity} evidence is stale: {age:.0f}s old, limit {self.max_age_s:.0f}s"
        return None


@dataclass(frozen=True, slots=True)
class JurisdictionRule:
    """Excludes a link crossing a jurisdiction the class does not permit."""

    rule_id: str
    class_id: str

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if tclass.id != self.class_id or tclass.allowed_jurisdictions is None:
            return None
        if not link.jurisdictions:
            return "link jurisdiction is undeclared"
        disallowed = [j for j in link.jurisdictions if j not in tclass.allowed_jurisdictions]
        if disallowed:
            return f"crosses disallowed jurisdiction {', '.join(sorted(disallowed))}"
        return None


@dataclass(frozen=True, slots=True)
class EncryptionRule:
    """Excludes an unencrypted link from a class that requires encryption below."""

    rule_id: str
    class_id: str

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if tclass.id != self.class_id or not tclass.requires_encryption:
            return None
        if not link.encrypted_below:
            return "class requires encryption below and the link does not provide it"
        return None


@dataclass(frozen=True, slots=True)
class DirectiveRule:
    """A time-bounded human override taking one link out.

    Separate from ordinary policy because it is an exceptional act, and it should
    read as one in the log.
    """

    rule_id: str
    link_id: str
    reason_text: str
    not_after: datetime

    def evaluate(
        self, link: Link, tclass: TrafficClass, evidence: EvidenceSnapshot, now: datetime
    ) -> str | None:
        if link.id != self.link_id or now >= self.not_after:
            return None
        return f"authority directive: {self.reason_text}"
