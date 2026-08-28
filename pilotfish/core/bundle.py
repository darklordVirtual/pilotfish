"""Policy bundles, including the floor policy used when there is no valid one."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

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
    """A signed-in-transit, hashed-at-rest set of rules and the classes they bind to.

    ``authority_id`` and ``sequence`` exist because a signature answers only one
    of the three questions that matter. It says who wrote this. It does not say
    whether they are the authority this site answers to, and it does not say
    whether this is the policy currently in force rather than one from last year
    that happens to still be inside its validity window.
    """

    bundle_id: str
    authority_id: str
    sequence: int
    issued_at: datetime
    not_after: datetime
    decision_ttl_s: int
    links: tuple[Link, ...]
    traffic_classes: tuple[TrafficClass, ...]
    rules: tuple[Rule, ...]

    def with_rules(self, rules: tuple[Rule, ...]) -> PolicyBundle:
        return replace(self, rules=tuple(rules))

    def hash(self) -> str:
        """The hash of the wire encoding, and nothing else.

        This is deliberately not computed from Python objects. A Rust agent has
        no ``repr()``, and a cryptographic contract that only one runtime can
        reproduce is not a contract.
        """

        from pilotfish.protocol.messages import encode_bundle

        return hashlib.sha256(encode_bundle(self)).hexdigest()


def floor_bundle(links: tuple[Link, ...], *, now: datetime | None = None) -> PolicyBundle:
    """The conservative policy a site falls to when it has no valid bundle.

    It is deliberately dull: one class, liveness required, metered paths refused,
    and FSO refused outright since its evidence pipeline is exactly what is most
    likely to be missing at the same moment the authority is unreachable.
    """

    issued = now or datetime.fromtimestamp(0, tz=UTC)
    return PolicyBundle(
        bundle_id=FLOOR_BUNDLE_ID,
        authority_id=FLOOR_BUNDLE_ID,
        sequence=0,
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
