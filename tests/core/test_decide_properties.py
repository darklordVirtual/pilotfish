"""Property tests for the two invariants the whole design rests on.

Monotonicity: adding rules can only shrink a permitted set. If this ever fails,
some rule has learned to admit a link, and the decision stops being explainable.

Determinism: the same inputs give a bit-identical decision. Without this the
receipts chain proves nothing, because a verifier could not recompute.

The value strategy excludes NaN and infinity because the model layer now refuses
to construct them at all; the negative conformance tests cover that boundary
directly. Timestamps deliberately range into the future.
"""

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import decide
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
LINK_IDS = ["fiber0", "lte0", "sat0", "fso0"]
LINKS = (
    Link(id="fiber0", type="fiber", encrypted_below=True, jurisdictions=("NO",)),
    Link(id="lte0", type="lte", metered=True, jurisdictions=("NO",)),
    Link(id="sat0", type="satellite", metered=True, jurisdictions=("US",)),
    Link(id="fso0", type="fso"),
)
CLASSES = (
    TrafficClass("bulk"),
    TrafficClass("realtime", max_rtt_ms=100.0, allow_metered=False),
    TrafficClass("health", allowed_jurisdictions=("NO",), requires_encryption=True),
)

BUNDLE = PolicyBundle(
    bundle_id="b1",
    issued_at=T0,
    not_after=T0 + timedelta(hours=24),
    decision_ttl_s=120,
    links=LINKS,
    traffic_classes=CLASSES,
    rules=(LinkDownRule("R-DOWN"),),
)


@st.composite
def evidence_snapshots(draw):
    observations = draw(
        st.lists(
            st.builds(
                Observation,
                link_id=st.sampled_from(LINK_IDS),
                quantity=st.sampled_from(["up", "rtt_ms", "quota_used_pct", "visibility_m"]),
                value=st.floats(min_value=0.0, max_value=1000.0, allow_nan=False),
                # Deliberately reaches into the future as well: evidence dated
                # ahead of the clock must never widen a permitted set.
                at=st.integers(min_value=-3600, max_value=3600).map(
                    lambda offset: T0 + timedelta(seconds=offset)
                ),
                source=st.sampled_from(["agent", "operator", "model"]),
            ),
            max_size=12,
        )
    )
    return EvidenceSnapshot(tuple(observations))


extra_rules = st.lists(
    st.one_of(
        st.builds(
            MaxRttRule, rule_id=st.just("X-RTT"), class_id=st.sampled_from(["bulk", "realtime"])
        ),
        st.builds(
            MeteredRule, rule_id=st.just("X-METER"), class_id=st.sampled_from(["bulk", "health"])
        ),
        st.builds(
            QuotaRule,
            rule_id=st.just("X-QUOTA"),
            link_type=st.sampled_from(["lte", "satellite"]),
            threshold_pct=st.floats(min_value=1.0, max_value=99.0),
        ),
        st.builds(
            EvidenceFreshnessRule,
            rule_id=st.just("X-FRESH"),
            link_type=st.sampled_from(["fso", "satellite"]),
            quantity=st.just("visibility_m"),
            max_age_s=st.floats(min_value=1.0, max_value=600.0),
        ),
        st.builds(JurisdictionRule, rule_id=st.just("X-JUR"), class_id=st.just("health")),
        st.builds(EncryptionRule, rule_id=st.just("X-ENC"), class_id=st.just("health")),
    ),
    max_size=4,
)


@settings(max_examples=200, deadline=None)
@given(evidence=evidence_snapshots(), extra=extra_rules)
def test_more_rules_never_grow_the_permitted_set(evidence, extra):
    base = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    wider = decide(
        bundle=BUNDLE.with_rules(BUNDLE.rules + tuple(extra)),
        evidence=evidence,
        now=T0,
        site_id="s",
    )
    for cls in base.classes:
        assert set(wider.permitted_for(cls.class_id)) <= set(cls.permitted)


@settings(max_examples=100, deadline=None)
@given(evidence=evidence_snapshots())
def test_decision_is_deterministic(evidence):
    a = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    b = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    assert a == b


@settings(max_examples=100, deadline=None)
@given(evidence=evidence_snapshots())
def test_a_permitted_link_never_appears_in_its_own_exclusions(evidence):
    decision = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    for cls in decision.classes:
        excluded = {e.link_id for e in cls.exclusions}
        assert excluded.isdisjoint(set(cls.permitted))
