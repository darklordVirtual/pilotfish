from datetime import timedelta

from pilotfish.core.models import EvidenceSnapshot, Observation
from sim.scenario import T0
from sim.scenarios import CLASSES, LINKS, bundle
from sim.selectors import Governed, Greedy, Hysteresis, SelectorContext, StaticPriority

LINK_MAP = {link.id: link for link in LINKS}
CLASS_MAP = {c.id: c for c in CLASSES}


def context(now=T0, rtts=None, down=(), authority=True):
    rtts = rtts or {"fiber0": 8.0, "lte0": 45.0, "sat0": 90.0, "fso0": 3.0}
    observations = []
    for link_id in LINK_MAP:
        observations.append(
            Observation(link_id, "up", 0.0 if link_id in down else 1.0, now, "agent")
        )
        if link_id not in down:
            observations.append(Observation(link_id, "rtt_ms", rtts[link_id], now, "agent"))
    observations.append(Observation("fso0", "visibility_m", 8000.0, now, "model"))
    observations.append(Observation("lte0", "quota_used_pct", 5.0, now, "operator"))
    observations.append(Observation("sat0", "quota_used_pct", 5.0, now, "operator"))
    return SelectorContext(
        now=now,
        evidence=EvidenceSnapshot(tuple(observations)),
        links=LINK_MAP,
        classes=CLASS_MAP,
        authority_reachable=authority,
    )


def test_greedy_takes_the_lowest_latency_link_regardless_of_anything_else():
    assert Greedy()(context())["bulk"] == "fso0"


def test_greedy_returns_nothing_when_every_link_is_down():
    assert Greedy()(context(down=tuple(LINK_MAP)))["bulk"] is None


def test_static_priority_walks_its_list():
    selector = StaticPriority(("fiber0", "lte0", "sat0", "fso0"))
    assert selector(context())["bulk"] == "fiber0"
    assert selector(context(down=("fiber0",)))["bulk"] == "lte0"


def test_hysteresis_holds_its_choice_until_the_dwell_time_passes():
    selector = Hysteresis(dwell_s=300.0)
    assert (
        selector(context(rtts={"fiber0": 8.0, "lte0": 45.0, "sat0": 90.0, "fso0": 3.0}))["bulk"]
        == "fso0"
    )

    better_fiber = {"fiber0": 1.0, "lte0": 45.0, "sat0": 90.0, "fso0": 3.0}
    assert selector(context(now=T0 + timedelta(seconds=60), rtts=better_fiber))["bulk"] == "fso0"
    assert selector(context(now=T0 + timedelta(seconds=400), rtts=better_fiber))["bulk"] == "fiber0"


def test_hysteresis_moves_immediately_when_the_held_link_dies():
    selector = Hysteresis(dwell_s=300.0)
    selector(context())
    assert selector(context(now=T0 + timedelta(seconds=30), down=("fso0",)))["bulk"] == "fiber0"


def test_governed_keeps_bulk_off_metered_links_even_when_they_are_fastest():
    selector = Governed(bundle(), site_id="sim-site")
    fast_lte = {"fiber0": 80.0, "lte0": 5.0, "sat0": 90.0, "fso0": 60.0}
    choices = selector(context(rtts=fast_lte))
    assert choices["bulk"] != "lte0"
    assert choices["realtime"] == "lte0"


def test_governed_writes_one_receipt_per_decision():
    selector = Governed(bundle(), site_id="sim-site")
    selector(context())
    selector(context(now=T0 + timedelta(seconds=30)))
    assert len(selector.receipts) == 2


def test_governed_without_an_authority_falls_to_the_floor_policy():
    selector = Governed(bundle(), site_id="sim-site")
    choices = selector(context(authority=False))
    assert selector.last_degraded is True
    # The floor refuses metered paths and free-space optics outright.
    assert choices["bulk"] == "fiber0"
