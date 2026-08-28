"""Policy bundles, including the floor policy used when there is no valid one."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import cbor2

from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import (
    LinkDownRule,
    LinkTypeRule,
    MeteredRule,
    Rule,
)

FLOOR_BUNDLE_ID = "floor"


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """A signed-in-transit, hashed-at-rest set of rules and the classes they bind to."""

    bundle_id: str
    issued_at: datetime
    not_after: datetime
    decision_ttl_s: int
    links: tuple[Link, ...]
    traffic_classes: tuple[TrafficClass, ...]
    rules: tuple[Rule, ...]

    def with_rules(self, rules: tuple[Rule, ...]) -> PolicyBundle:
        return replace(self, rules=tuple(rules))

    def hash(self) -> str:
        payload = [
            self.bundle_id,
            int(self.issued_at.timestamp()),
            int(self.not_after.timestamp()),
            self.decision_ttl_s,
            sorted(
                [
                    link.id,
                    link.type,
                    link.metered,
                    link.encrypted_below,
                    list(link.jurisdictions),
                    link.owner,
                ]
                for link in self.links
            ),
            sorted(
                [
                    c.id,
                    c.max_rtt_ms,
                    c.allow_metered,
                    None if c.allowed_jurisdictions is None else list(c.allowed_jurisdictions),
                    c.requires_encryption,
                ]
                for c in self.traffic_classes
            ),
            sorted([type(r).__name__, r.rule_id, repr(r)] for r in self.rules),
        ]
        return hashlib.sha256(cbor2.dumps(payload, canonical=True)).hexdigest()


def floor_bundle(links: tuple[Link, ...], *, now: datetime | None = None) -> PolicyBundle:
    """The conservative policy a site falls to when it has no valid bundle.

    It is deliberately dull: one class, liveness required, metered paths refused,
    and FSO refused outright since its evidence pipeline is exactly what is most
    likely to be missing at the same moment the authority is unreachable.
    """

    issued = now or datetime.fromtimestamp(0, tz=UTC)
    return PolicyBundle(
        bundle_id=FLOOR_BUNDLE_ID,
        issued_at=issued,
        not_after=issued + timedelta(days=3650),
        decision_ttl_s=60,
        links=links,
        traffic_classes=(TrafficClass(id="default", allow_metered=False),),
        rules=(
            LinkDownRule("FLOOR-DOWN"),
            MeteredRule("FLOOR-METER", class_id="default"),
            LinkTypeRule(
                "FLOOR-FSO",
                link_type="fso",
                reason_text="floor policy refuses free-space optics without an authority",
            ),
        ),
    )
