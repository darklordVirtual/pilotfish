from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.authority.signer import BundleSigner, load_bundle_json
from pilotfish.cli import main
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import decide
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import LinkDownRule

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))
POLICY = Path(__file__).parents[2] / "examples/policy.json"

BUNDLE = PolicyBundle(
    bundle_id="b1",
    authority_id="authority-1",
    sequence=1,
    issued_at=T0,
    not_after=T0 + timedelta(hours=6),
    decision_ttl_s=60,
    links=LINKS,
    traffic_classes=(TrafficClass("bulk"),),
    rules=(LinkDownRule("R-DOWN"),),
)


def test_published_bundle_verifies_and_round_trips():
    blob = BundleSigner(SK, "authority-1").publish(BUNDLE, now=T0)
    store = BundleStore(
        trusted_key=SK.public_key(),
        expected_issuer="authority-1",
        site_id="site-1",
        signed_floor=_signed_floor(SK, LINKS, site_id="site-1"),
        now=T0,
    )
    assert store.accept(blob, now=T0).hash() == BUNDLE.hash()


def test_policy_file_parses_into_the_expected_shape():
    bundle = load_bundle_json(POLICY, now=T0)
    assert bundle.bundle_id == "site-north-v3"
    assert {link.id for link in bundle.links} == {"fiber0", "lte0", "sat0", "fso0"}
    assert {c.id for c in bundle.traffic_classes} == {"bulk", "realtime", "health"}
    assert {r.rule_id for r in bundle.rules} == {
        "R-DOWN",
        "R-RTT-REALTIME",
        "R-RTT-HEALTH",
        "R-METER-BULK",
        "R-QUOTA-LTE",
        "R-QUOTA-SAT",
        "R-FSO-WEATHER",
        "R-JUR-HEALTH",
        "R-ENC-HEALTH",
    }


def test_the_example_policy_produces_the_decisions_it_claims_to():
    """Health traffic must not reach a satellite path that transits another jurisdiction."""

    bundle = load_bundle_json(POLICY, now=T0)
    evidence = EvidenceSnapshot(
        tuple(Observation(link.id, "up", 1.0, T0, "agent") for link in bundle.links)
        + (
            Observation("fiber0", "rtt_ms", 8.0, T0, "agent"),
            Observation("lte0", "rtt_ms", 45.0, T0, "agent"),
            Observation("sat0", "rtt_ms", 90.0, T0, "agent"),
            Observation("fso0", "rtt_ms", 3.0, T0, "agent"),
            Observation("lte0", "quota_used_pct", 20.0, T0, "operator"),
            Observation("sat0", "quota_used_pct", 5.0, T0, "operator"),
            Observation("fso0", "visibility_m", 8000.0, T0, "model"),
        )
    )
    decision = decide(bundle=bundle, evidence=evidence, now=T0, site_id="site-north")

    assert "sat0" not in decision.permitted_for("health")
    assert decision.permitted_for("bulk") == ("fiber0", "fso0")
    assert set(decision.permitted_for("realtime")) == {"fiber0", "fso0", "lte0", "sat0"}


def test_stale_weather_removes_fso_without_anything_detecting_the_outage():
    bundle = load_bundle_json(POLICY, now=T0)
    later = T0 + timedelta(minutes=30)
    evidence = EvidenceSnapshot(
        tuple(Observation(link.id, "up", 1.0, later, "agent") for link in bundle.links)
        + (Observation("fso0", "visibility_m", 8000.0, T0, "model"),)
    )
    decision = decide(bundle=bundle, evidence=evidence, now=later, site_id="site-north")
    assert "fso0" not in decision.permitted_for("bulk")


def test_cli_keygen_sign_and_verify_round_trip(tmp_path, capsys):
    key = tmp_path / "authority.key"
    out = tmp_path / "bundle.cbor"
    assert main(["keygen", "--out", str(key)]) == 0
    assert main(["sign-bundle", str(POLICY), "--key", str(key), "--out", str(out)]) == 0
    assert main(["verify-bundle", str(out), "--key", str(key) + ".pub"]) == 0
    assert "verified bundle site-north-v3" in capsys.readouterr().out


def test_cli_verify_refuses_a_bundle_signed_by_someone_else(tmp_path):
    key, other, out = tmp_path / "a.key", tmp_path / "b.key", tmp_path / "bundle.cbor"
    main(["keygen", "--out", str(key)])
    main(["keygen", "--out", str(other)])
    main(["sign-bundle", str(POLICY), "--key", str(key), "--out", str(out)])
    assert main(["verify-bundle", str(out), "--key", str(other) + ".pub"]) == 1


def _signed_floor(key, links, *, site_id, issuer="authority-1", now=None):
    """A floor configuration signed by the authority, as a real deployment would ship."""

    from pilotfish.authority.signer import BundleSigner, sign_floor
    from pilotfish.core.models import TrafficClass as _TC

    return sign_floor(
        BundleSigner(key, issuer),
        site_id=site_id,
        links=links,
        classes=(_TC("default", allow_metered=False),),
        now=now or T0,
    )
