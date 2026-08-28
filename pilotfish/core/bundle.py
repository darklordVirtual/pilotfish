"""Policy bundles, including the floor policy used when there is no valid one."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import (
    EncryptionRule,
    JurisdictionRule,
    LinkDownRule,
    LinkTypeRule,
    MaxRttRule,
    MeteredRule,
    Rule,
)
from pilotfish.protocol.canonical import dumps

FLOOR_BUNDLE_ID = "floor"


def link_inventory_hash(links: tuple[Link, ...]) -> str:
    """Identity of the link inventory a floor policy was written against.

    A floor bound to an inventory cannot survive the site quietly growing a
    satellite dish: the new link is not in the hash, so the old floor stops
    applying instead of silently governing a topology nobody reviewed.
    """

    rows = sorted(
        [link.id, link.type, link.metered, link.encrypted_below, list(link.jurisdictions)]
        for link in links
    )
    return hashlib.sha256(dumps(rows)).hexdigest()


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


def _floor_class_rules(classes: tuple[TrafficClass, ...]) -> tuple[Rule, ...]:
    """Every constraint a class declares, kept.

    The floor refuses metered paths and free-space optics on top of this. What it
    must never do is drop a class's own requirements: a degraded mode that
    forgets a jurisdiction or an encryption rule is not fail-closed, it is
    fail-open with a reassuring name, and it takes effect exactly when nobody is
    watching.
    """

    rules: list[Rule] = []
    for tclass in classes:
        rules.append(MeteredRule(f"FLOOR-METER-{tclass.id}", class_id=tclass.id))
        if tclass.max_rtt_ms is not None:
            rules.append(MaxRttRule(f"FLOOR-RTT-{tclass.id}", class_id=tclass.id))
        if tclass.allowed_jurisdictions is not None:
            rules.append(JurisdictionRule(f"FLOOR-JUR-{tclass.id}", class_id=tclass.id))
        if tclass.requires_encryption:
            rules.append(EncryptionRule(f"FLOOR-ENC-{tclass.id}", class_id=tclass.id))
    return tuple(rules)


def floor_bundle(
    links: tuple[Link, ...],
    *,
    now: datetime | None = None,
    authority_id: str = FLOOR_BUNDLE_ID,
    traffic_classes: tuple[TrafficClass, ...] | None = None,
) -> PolicyBundle:
    """The conservative policy a site falls to when it has no valid bundle.

    It is deliberately dull: liveness required, metered paths refused, and FSO
    refused outright since its evidence pipeline is exactly what is most likely
    to be missing at the same moment the authority is unreachable.

    Constructing one locally is fine for tests and for the authority that is
    about to sign it. A site never builds its own: see
    :func:`pilotfish.authority.signer.sign_floor` and ``BundleStore``.
    """

    issued = now or datetime.fromtimestamp(0, tz=UTC)
    classes = traffic_classes or (TrafficClass(id="default", allow_metered=False),)
    return PolicyBundle(
        bundle_id=FLOOR_BUNDLE_ID,
        authority_id=authority_id,
        sequence=0,
        issued_at=issued,
        not_after=issued + timedelta(days=3650),
        decision_ttl_s=60,
        links=links,
        traffic_classes=classes,
        rules=(
            LinkDownRule("FLOOR-DOWN"),
            LinkTypeRule(
                "FLOOR-FSO",
                link_type="fso",
                reason_text="floor policy refuses free-space optics without an authority",
            ),
            *_floor_class_rules(classes),
        ),
    )
