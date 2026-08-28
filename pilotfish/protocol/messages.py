"""Codecs for the four protocol messages.

Rules encode as a tagged array whose first element names the kind. An unknown
kind is fatal on decode. A site that silently dropped a rule it did not
understand would compute a wider permitted set than the authority intended, and
would do it quietly, which is the worst way for a governance system to fail.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import ClassEligibility, EligibilityDecision
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import (
    DirectiveRule,
    EncryptionRule,
    EvidenceFreshnessRule,
    Exclusion,
    JurisdictionRule,
    LinkDownRule,
    LinkTypeRule,
    MaxRttRule,
    MeteredRule,
    QuotaRule,
    Rule,
)
from pilotfish.protocol.canonical import dumps, loads

MSG_POLICY_BUNDLE = "POLICY_BUNDLE"
MSG_OBSERVATION_BATCH = "OBSERVATION_BATCH"
MSG_DECISION_RECEIPT = "DECISION_RECEIPT"
MSG_AUTHORITY_DIRECTIVE = "AUTHORITY_DIRECTIVE"

MSG_TYPES = (
    MSG_POLICY_BUNDLE,
    MSG_OBSERVATION_BATCH,
    MSG_DECISION_RECEIPT,
    MSG_AUTHORITY_DIRECTIVE,
)


class UnknownRuleKind(ValueError):
    """A rule kind this implementation cannot evaluate. Never ignored."""


def _ts(value: datetime) -> int:
    return int(value.timestamp())


def _dt(value: int | float) -> datetime:
    return datetime.fromtimestamp(value, tz=UTC)


# --- rules ------------------------------------------------------------------


def encode_rule(rule: Rule) -> list[Any]:
    match rule:
        case LinkDownRule():
            return ["down", rule.rule_id]
        case MaxRttRule():
            return ["max_rtt", rule.rule_id, rule.class_id]
        case MeteredRule():
            return ["metered", rule.rule_id, rule.class_id]
        case QuotaRule():
            return ["quota", rule.rule_id, rule.link_type, rule.threshold_pct]
        case EvidenceFreshnessRule():
            return ["freshness", rule.rule_id, rule.link_type, rule.quantity, rule.max_age_s]
        case JurisdictionRule():
            return ["jurisdiction", rule.rule_id, rule.class_id]
        case EncryptionRule():
            return ["encryption", rule.rule_id, rule.class_id]
        case LinkTypeRule():
            return ["link_type", rule.rule_id, rule.link_type, rule.reason_text]
        case DirectiveRule():
            return ["directive", rule.rule_id, rule.link_id, rule.reason_text, _ts(rule.not_after)]
        case _:
            raise UnknownRuleKind(f"cannot encode rule of type {type(rule).__name__}")


_RULE_DECODERS = {
    "down": lambda f: LinkDownRule(f[0]),
    "max_rtt": lambda f: MaxRttRule(f[0], f[1]),
    "metered": lambda f: MeteredRule(f[0], f[1]),
    "quota": lambda f: QuotaRule(f[0], f[1], f[2]),
    "freshness": lambda f: EvidenceFreshnessRule(f[0], f[1], f[2], f[3]),
    "jurisdiction": lambda f: JurisdictionRule(f[0], f[1]),
    "encryption": lambda f: EncryptionRule(f[0], f[1]),
    "link_type": lambda f: LinkTypeRule(f[0], f[1], f[2]),
    "directive": lambda f: DirectiveRule(f[0], f[1], f[2], _dt(f[3])),
}


def decode_rule(fields: list[Any]) -> Rule:
    kind, *rest = fields
    decoder = _RULE_DECODERS.get(kind)
    if decoder is None:
        raise UnknownRuleKind(f"unknown rule kind {kind!r}; refusing to decode a partial policy")
    return decoder(rest)


# --- links and classes ------------------------------------------------------


def _encode_link(link: Link) -> list[Any]:
    return [
        link.id,
        link.type,
        link.metered,
        link.encrypted_below,
        list(link.jurisdictions),
        link.owner,
    ]


def _decode_link(f: list[Any]) -> Link:
    return Link(
        id=f[0],
        type=f[1],
        metered=f[2],
        encrypted_below=f[3],
        jurisdictions=tuple(f[4]),
        owner=f[5],
    )


def _encode_class(c: TrafficClass) -> list[Any]:
    return [
        c.id,
        c.max_rtt_ms,
        c.allow_metered,
        None if c.allowed_jurisdictions is None else list(c.allowed_jurisdictions),
        c.requires_encryption,
    ]


def _decode_class(f: list[Any]) -> TrafficClass:
    return TrafficClass(
        id=f[0],
        max_rtt_ms=f[1],
        allow_metered=f[2],
        allowed_jurisdictions=None if f[3] is None else tuple(f[3]),
        requires_encryption=f[4],
    )


# --- POLICY_BUNDLE ----------------------------------------------------------


def encode_bundle(bundle: PolicyBundle) -> bytes:
    return dumps(
        [
            bundle.bundle_id,
            bundle.authority_id,
            bundle.sequence,
            _ts(bundle.issued_at),
            _ts(bundle.not_after),
            bundle.decision_ttl_s,
            [_encode_link(link) for link in bundle.links],
            [_encode_class(c) for c in bundle.traffic_classes],
            [encode_rule(r) for r in bundle.rules],
        ]
    )


def decode_bundle(payload: bytes) -> PolicyBundle:
    f = loads(payload)
    return PolicyBundle(
        bundle_id=f[0],
        authority_id=f[1],
        sequence=f[2],
        issued_at=_dt(f[3]),
        not_after=_dt(f[4]),
        decision_ttl_s=f[5],
        links=tuple(_decode_link(x) for x in f[6]),
        traffic_classes=tuple(_decode_class(x) for x in f[7]),
        rules=tuple(decode_rule(x) for x in f[8]),
    )


# --- DECISION_RECEIPT payload ----------------------------------------------


def encode_decision(decision: EligibilityDecision) -> bytes:
    return dumps(
        [
            decision.site_id,
            _ts(decision.decided_at),
            _ts(decision.valid_until),
            decision.bundle_hash,
            decision.evidence_hash,
            decision.degraded,
            [
                [
                    cls.class_id,
                    list(cls.permitted),
                    [[e.link_id, e.rule_id, e.reason] for e in cls.exclusions],
                ]
                for cls in decision.classes
            ],
        ]
    )


def decode_decision(payload: bytes) -> EligibilityDecision:
    f = loads(payload)
    return EligibilityDecision(
        site_id=f[0],
        decided_at=_dt(f[1]),
        valid_until=_dt(f[2]),
        bundle_hash=f[3],
        evidence_hash=f[4],
        degraded=f[5],
        classes=tuple(
            ClassEligibility(
                class_id=c[0],
                permitted=tuple(c[1]),
                exclusions=tuple(Exclusion(e[0], e[1], e[2]) for e in c[2]),
            )
            for c in f[6]
        ),
    )


# --- OBSERVATION_BATCH ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObservationBatch:
    """Telemetry. Droppable by design when the uplink is expensive."""

    site_id: str
    observations: tuple[Observation, ...]

    def as_snapshot(self) -> EvidenceSnapshot:
        return EvidenceSnapshot(self.observations)


def encode_observation_batch(batch: ObservationBatch) -> bytes:
    return dumps(
        [
            batch.site_id,
            [[o.link_id, o.quantity, o.value, _ts(o.at), o.source] for o in batch.observations],
        ]
    )


def decode_observation_batch(payload: bytes) -> ObservationBatch:
    f = loads(payload)
    return ObservationBatch(
        site_id=f[0],
        observations=tuple(Observation(o[0], o[1], o[2], _dt(o[3]), o[4]) for o in f[1]),
    )


# --- AUTHORITY_DIRECTIVE ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorityDirective:
    """A time-bounded human override taking one link out."""

    directive_id: str
    site_id: str
    link_id: str
    reason: str
    not_after: datetime

    def to_rule(self) -> DirectiveRule:
        return DirectiveRule(
            rule_id=self.directive_id,
            link_id=self.link_id,
            reason_text=self.reason,
            not_after=self.not_after,
        )


def encode_directive(directive: AuthorityDirective) -> bytes:
    return dumps(
        [
            directive.directive_id,
            directive.site_id,
            directive.link_id,
            directive.reason,
            _ts(directive.not_after),
        ]
    )


def decode_directive(payload: bytes) -> AuthorityDirective:
    f = loads(payload)
    return AuthorityDirective(
        directive_id=f[0], site_id=f[1], link_id=f[2], reason=f[3], not_after=_dt(f[4])
    )
