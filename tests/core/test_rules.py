from datetime import UTC, datetime, timedelta

from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import (
    EncryptionRule,
    EvidenceFreshnessRule,
    JurisdictionRule,
    LinkDownRule,
    MaxRttRule,
    MeteredRule,
    QuotaRule,
)

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
CLASS_BULK = TrafficClass("bulk")
EMPTY = EvidenceSnapshot(())


def test_freshness_rule_excludes_when_evidence_is_stale():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    link = Link(id="fso0", type="fso")
    snap = EvidenceSnapshot((Observation("fso0", "visibility_m", 3000.0, T0, "model"),))
    assert rule.evaluate(link, CLASS_BULK, snap, T0 + timedelta(seconds=300)) is None
    assert "stale" in rule.evaluate(link, CLASS_BULK, snap, T0 + timedelta(seconds=900))


def test_freshness_rule_excludes_when_evidence_is_missing_entirely():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    assert rule.evaluate(Link(id="fso0", type="fso"), CLASS_BULK, EMPTY, T0) is not None


def test_freshness_rule_ignores_other_link_types():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    assert rule.evaluate(Link(id="f0", type="fiber"), CLASS_BULK, EMPTY, T0) is None


def test_metered_rule_only_binds_its_own_class():
    rule = MeteredRule("R-METER", class_id="realtime")
    lte = Link(id="lte0", type="lte", metered=True)
    assert rule.evaluate(lte, TrafficClass("realtime", allow_metered=False), EMPTY, T0) is not None
    assert rule.evaluate(lte, TrafficClass("bulk", allow_metered=False), EMPTY, T0) is None


def test_metered_rule_leaves_unmetered_links_alone():
    rule = MeteredRule("R-METER", class_id="realtime")
    fiber = Link(id="f0", type="fiber", metered=False)
    assert rule.evaluate(fiber, TrafficClass("realtime", allow_metered=False), EMPTY, T0) is None


def test_link_down_rule_excludes_on_missing_and_on_down():
    rule = LinkDownRule("R-DOWN")
    link = Link(id="f0", type="fiber")
    assert rule.evaluate(link, CLASS_BULK, EMPTY, T0) is not None
    down = EvidenceSnapshot((Observation("f0", "up", 0.0, T0, "agent"),))
    up = EvidenceSnapshot((Observation("f0", "up", 1.0, T0, "agent"),))
    assert rule.evaluate(link, CLASS_BULK, down, T0) is not None
    assert rule.evaluate(link, CLASS_BULK, up, T0) is None


def test_max_rtt_rule_needs_a_measurement_to_admit():
    rule = MaxRttRule("R-RTT", class_id="realtime")
    realtime = TrafficClass("realtime", max_rtt_ms=100.0)
    link = Link(id="sat0", type="satellite")
    assert rule.evaluate(link, realtime, EMPTY, T0) is not None
    slow = EvidenceSnapshot((Observation("sat0", "rtt_ms", 600.0, T0, "agent"),))
    fast = EvidenceSnapshot((Observation("sat0", "rtt_ms", 40.0, T0, "agent"),))
    assert rule.evaluate(link, realtime, slow, T0) is not None
    assert rule.evaluate(link, realtime, fast, T0) is None


def test_quota_rule_excludes_over_threshold_and_when_unmeasured():
    rule = QuotaRule("R-QUOTA", link_type="lte", threshold_pct=90.0)
    lte = Link(id="lte0", type="lte", metered=True)
    assert rule.evaluate(lte, CLASS_BULK, EMPTY, T0) is not None
    over = EvidenceSnapshot((Observation("lte0", "quota_used_pct", 95.0, T0, "operator"),))
    under = EvidenceSnapshot((Observation("lte0", "quota_used_pct", 10.0, T0, "operator"),))
    assert rule.evaluate(lte, CLASS_BULK, over, T0) is not None
    assert rule.evaluate(lte, CLASS_BULK, under, T0) is None


def test_jurisdiction_and_encryption_rules():
    juris = JurisdictionRule("R-JUR", class_id="health")
    health = TrafficClass("health", allowed_jurisdictions=("NO",))
    assert juris.evaluate(Link(id="s0", type="satellite", jurisdictions=("US",)), health, EMPTY, T0)
    assert (
        juris.evaluate(Link(id="f0", type="fiber", jurisdictions=("NO",)), health, EMPTY, T0)
        is None
    )

    enc = EncryptionRule("R-ENC", class_id="health")
    health_enc = TrafficClass("health", requires_encryption=True)
    assert enc.evaluate(Link(id="f0", type="fiber", encrypted_below=False), health_enc, EMPTY, T0)
    assert (
        enc.evaluate(Link(id="f0", type="fiber", encrypted_below=True), health_enc, EMPTY, T0)
        is None
    )
