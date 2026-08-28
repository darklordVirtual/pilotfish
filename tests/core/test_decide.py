from datetime import UTC, datetime, timedelta

from pilotfish.core.bundle import PolicyBundle, floor_bundle
from pilotfish.core.decide import decide
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import EvidenceFreshnessRule, LinkDownRule, MeteredRule

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)

LINKS = (
    Link(id="fiber0", type="fiber"),
    Link(id="fso0", type="fso"),
    Link(id="lte0", type="lte", metered=True),
)

BUNDLE = PolicyBundle(
    bundle_id="b1",
    issued_at=T0,
    not_after=T0 + timedelta(hours=24),
    decision_ttl_s=120,
    links=LINKS,
    traffic_classes=(TrafficClass("bulk"),),
    rules=(
        LinkDownRule("R-DOWN"),
        EvidenceFreshnessRule(
            "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
        ),
    ),
)


def up(link_id, at=T0):
    return Observation(link_id, "up", 1.0, at, "agent")


SNAP = EvidenceSnapshot(
    (up("fiber0"), up("fso0"), up("lte0"), Observation("fso0", "visibility_m", 4000.0, T0, "model"))
)
SNAP_FOG = EvidenceSnapshot(
    (
        up("fiber0"),
        up("fso0"),
        up("lte0"),
        Observation("fso0", "visibility_m", 4000.0, T0 - timedelta(hours=2), "model"),
    )
)


def test_every_link_is_a_candidate_and_exclusions_carry_rule_ids():
    decision = decide(bundle=BUNDLE, evidence=SNAP_FOG, now=T0, site_id="site-1")
    bulk = decision.classes[0]
    assert "fso0" not in bulk.permitted
    assert set(bulk.permitted) == {"fiber0", "lte0"}
    assert any(e.link_id == "fso0" and e.rule_id == "R-FSO-FRESH" for e in bulk.exclusions)


def test_decision_binds_bundle_and_evidence_hashes():
    decision = decide(bundle=BUNDLE, evidence=SNAP, now=T0, site_id="site-1")
    assert decision.bundle_hash == BUNDLE.hash()
    assert decision.evidence_hash == SNAP.hash()
    assert decision.valid_until == T0 + timedelta(seconds=BUNDLE.decision_ttl_s)
    assert decision.degraded is False


def test_degraded_flag_is_carried_not_inferred():
    decision = decide(bundle=floor_bundle(LINKS), evidence=SNAP, now=T0, site_id="s", degraded=True)
    assert decision.degraded is True


def test_floor_policy_refuses_metered_and_fso():
    decision = decide(bundle=floor_bundle(LINKS), evidence=SNAP, now=T0, site_id="s", degraded=True)
    assert decision.permitted_for("default") == ("fiber0",)


def test_permitted_for_unknown_class_is_empty_not_an_error():
    decision = decide(bundle=BUNDLE, evidence=SNAP, now=T0, site_id="s")
    assert decision.permitted_for("nonexistent") == ()


def test_a_link_excluded_by_two_rules_reports_both():
    bundle = BUNDLE.with_rules(BUNDLE.rules + (MeteredRule("R-METER", class_id="bulk"),))
    strict = PolicyBundle(
        bundle_id="b2",
        issued_at=T0,
        not_after=T0 + timedelta(hours=1),
        decision_ttl_s=60,
        links=LINKS,
        traffic_classes=(TrafficClass("bulk", allow_metered=False),),
        rules=bundle.rules,
    )
    decision = decide(bundle=strict, evidence=SNAP_FOG, now=T0, site_id="s")
    lte_reasons = [e for e in decision.classes[0].exclusions if e.link_id == "lte0"]
    assert [e.rule_id for e in lte_reasons] == ["R-METER"]
