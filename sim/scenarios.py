"""The scenarios the comparison runs on.

Four situations, chosen so that the hypothesis can lose. Plain failover is here
precisely because governed selection is expected to do no better on it, and
quite possibly worse.
"""

from __future__ import annotations

from datetime import timedelta

from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import Link, TrafficClass
from pilotfish.core.rules import (
    EncryptionRule,
    EvidenceFreshnessRule,
    JurisdictionRule,
    LinkDownRule,
    MaxRttRule,
    MeteredRule,
    QuotaRule,
)
from sim.links import FiberModel, FsoModel, LinkFleet, LteModel, SatelliteModel
from sim.scenario import T0, Event, Scenario

MB = 10**6

LINKS = (
    Link(id="fiber0", type="fiber", encrypted_below=True, jurisdictions=("NO",), owner="local-isp"),
    Link(id="lte0", type="lte", metered=True, jurisdictions=("NO",), owner="mno-a"),
    Link(id="sat0", type="satellite", metered=True, jurisdictions=("NO", "US"), owner="leo"),
    Link(id="fso0", type="fso", encrypted_below=True, jurisdictions=("NO",), owner="self"),
)

CLASSES = (
    TrafficClass("bulk", allow_metered=False),
    TrafficClass("realtime", max_rtt_ms=120.0),
    TrafficClass(
        "health",
        max_rtt_ms=250.0,
        allowed_jurisdictions=("NO",),
        requires_encryption=True,
    ),
)

RULES = (
    LinkDownRule("R-DOWN"),
    MaxRttRule("R-RTT-REALTIME", "realtime"),
    MaxRttRule("R-RTT-HEALTH", "health"),
    MeteredRule("R-METER-BULK", "bulk"),
    QuotaRule("R-QUOTA-LTE", "lte", 90.0),
    QuotaRule("R-QUOTA-SAT", "satellite", 95.0),
    EvidenceFreshnessRule("R-FSO-WEATHER", "fso", "visibility_m", 600.0),
    JurisdictionRule("R-JUR-HEALTH", "health"),
    EncryptionRule("R-ENC-HEALTH", "health"),
)


def bundle(validity_s: int = 1800, decision_ttl_s: int = 120) -> PolicyBundle:
    return PolicyBundle(
        bundle_id="sim-policy",
        authority_id="authority-1",
        sequence=1,
        issued_at=T0,
        not_after=T0 + timedelta(seconds=validity_s),
        decision_ttl_s=decision_ttl_s,
        links=LINKS,
        traffic_classes=CLASSES,
        rules=RULES,
    )


def fleet(quota_gb: float = 10.0) -> LinkFleet:
    return LinkFleet(
        {
            "fiber0": FiberModel("fiber0"),
            "lte0": LteModel("lte0", quota_gb=quota_gb),
            "sat0": SatelliteModel("sat0"),
            "fso0": FsoModel("fso0"),
        }
    )


TRAFFIC = {"bulk": 2 * MB, "realtime": 200_000, "health": 100_000}


PLAIN_FAILOVER = Scenario(
    name="plain-failover",
    site_id="sim-site",
    bundle=bundle(),
    fleet_factory=lambda: fleet(quota_gb=1000.0),
    traffic_bytes_per_s=TRAFFIC,
    events=(
        Event(600, "link_down", "fiber0"),
        Event(1800, "link_up", "fiber0"),
    ),
    duration_s=3600,
    step_s=30,
)

QUOTA_SQUEEZE = Scenario(
    name="quota-squeeze",
    site_id="sim-site",
    bundle=bundle(),
    fleet_factory=lambda: fleet(quota_gb=2.0),
    traffic_bytes_per_s=TRAFFIC,
    events=(
        Event(300, "link_down", "fiber0"),
        Event(900, "fog", "fso0"),
        Event(3000, "link_up", "fiber0"),
    ),
    duration_s=3600,
    step_s=30,
)

REGULATED = Scenario(
    name="regulated-health-traffic",
    site_id="sim-site",
    bundle=bundle(),
    fleet_factory=lambda: fleet(quota_gb=1000.0),
    traffic_bytes_per_s=TRAFFIC,
    events=(
        Event(600, "link_down", "fiber0"),
        Event(600, "fog", "fso0"),
        Event(2400, "clear", "fso0"),
        Event(3000, "link_up", "fiber0"),
    ),
    duration_s=3600,
    step_s=30,
)

FLAPPY = Scenario(
    name="flapping-fso",
    site_id="sim-site",
    bundle=bundle(),
    fleet_factory=lambda: fleet(quota_gb=1000.0),
    traffic_bytes_per_s=TRAFFIC,
    events=tuple(
        Event(at, "fog" if (at // 120) % 2 == 0 else "clear", "fso0")
        for at in range(120, 3600, 120)
    ),
    duration_s=3600,
    step_s=30,
)

AUTHORITY_BLACKOUT = Scenario(
    name="authority-blackout",
    site_id="sim-site",
    bundle=bundle(validity_s=900),
    fleet_factory=lambda: fleet(quota_gb=1000.0),
    traffic_bytes_per_s=TRAFFIC,
    events=(
        Event(600, "authority_unreachable", ""),
        Event(1200, "link_down", "fiber0"),
        Event(2400, "link_up", "fiber0"),
        Event(3000, "authority_reachable", ""),
    ),
    duration_s=3600,
    step_s=30,
)

ALL_SCENARIOS = (PLAIN_FAILOVER, QUOTA_SQUEEZE, REGULATED, FLAPPY, AUTHORITY_BLACKOUT)
