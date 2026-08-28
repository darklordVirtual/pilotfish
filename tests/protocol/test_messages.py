from datetime import UTC, datetime, timedelta

import pytest

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import decide
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import (
    EncryptionRule,
    EvidenceFreshnessRule,
    JurisdictionRule,
    LinkDownRule,
    LinkTypeRule,
    MaxRttRule,
    MeteredRule,
    QuotaRule,
)
from pilotfish.protocol.messages import (
    AuthorityDirective,
    ObservationBatch,
    UnknownRuleKind,
    decode_bundle,
    decode_decision,
    decode_directive,
    decode_observation_batch,
    decode_rule,
    encode_bundle,
    encode_decision,
    encode_directive,
    encode_observation_batch,
)

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
CLASS_BULK = TrafficClass("bulk")
EMPTY = EvidenceSnapshot(())

LINKS = (
    Link(id="fiber0", type="fiber", encrypted_below=True, jurisdictions=("NO",), owner="telenor"),
    Link(id="lte0", type="lte", metered=True),
    Link(id="fso0", type="fso"),
)

BUNDLE = PolicyBundle(
    bundle_id="b1",
    issued_at=T0,
    not_after=T0 + timedelta(hours=24),
    decision_ttl_s=120,
    links=LINKS,
    traffic_classes=(
        CLASS_BULK,
        TrafficClass("health", allowed_jurisdictions=("NO",), requires_encryption=True),
    ),
    rules=(
        LinkDownRule("R-DOWN"),
        MaxRttRule("R-RTT", "bulk"),
        MeteredRule("R-METER", "bulk"),
        QuotaRule("R-QUOTA", "lte", 90.0),
        EvidenceFreshnessRule("R-FRESH", "fso", "visibility_m", 600.0),
        JurisdictionRule("R-JUR", "health"),
        EncryptionRule("R-ENC", "health"),
        LinkTypeRule("R-NOFSO", "fso", "not permitted for this site"),
    ),
)

SNAP = EvidenceSnapshot(
    (
        Observation("fiber0", "up", 1.0, T0, "agent"),
        Observation("lte0", "quota_used_pct", 12.5, T0, "operator"),
    )
)
DECISION = decide(bundle=BUNDLE, evidence=SNAP, now=T0, site_id="site-1")
BATCH = ObservationBatch(site_id="site-1", observations=SNAP.observations)
DIRECTIVE = AuthorityDirective(
    "D-1", "site-1", "lte0", "carrier maintenance", T0 + timedelta(hours=2)
)


@pytest.mark.parametrize(
    "obj,enc,dec",
    [
        (BUNDLE, encode_bundle, decode_bundle),
        (DECISION, encode_decision, decode_decision),
        (BATCH, encode_observation_batch, decode_observation_batch),
        (DIRECTIVE, encode_directive, decode_directive),
    ],
)
def test_message_roundtrip_is_lossless(obj, enc, dec):
    assert dec(enc(obj)) == obj


def test_bundle_hash_survives_the_wire():
    assert decode_bundle(encode_bundle(BUNDLE)).hash() == BUNDLE.hash()


def test_unknown_rule_kind_is_fatal_not_skipped():
    with pytest.raises(UnknownRuleKind):
        decode_rule(["telepathy", "R-X", "bulk"])


def test_directive_converts_to_a_rule_that_excludes_only_its_link():
    rule = DIRECTIVE.to_rule()
    assert rule.evaluate(Link(id="lte0", type="lte"), CLASS_BULK, EMPTY, T0) is not None
    assert rule.evaluate(Link(id="fiber0", type="fiber"), CLASS_BULK, EMPTY, T0) is None


def test_expired_directive_stops_excluding():
    rule = DIRECTIVE.to_rule()
    assert (
        rule.evaluate(Link(id="lte0", type="lte"), CLASS_BULK, EMPTY, T0 + timedelta(hours=3))
        is None
    )
