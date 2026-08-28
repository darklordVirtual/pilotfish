"""The event loop.

Deterministic given a seed: one seeded generator per run, no global randomness,
no wall-clock reads. Time advances in fixed steps so two selectors face exactly
the same world, which is the only way the comparison means anything.
"""

from __future__ import annotations

from datetime import timedelta
from random import Random

from pilotfish.core.models import EvidenceSnapshot
from sim.links import LteModel, SatelliteModel
from sim.metrics import RunResult, check_violations
from sim.scenario import T0, Scenario
from sim.selectors import SelectorContext

FOG_VISIBILITY_M = 80.0
CLEAR_VISIBILITY_M = 8000.0


def _apply_event(fleet, event, authority) -> bool:
    """Apply one event and return whether the authority is reachable afterwards."""

    model = fleet.models.get(event.target)
    match event.kind:
        case "link_down":
            model.up = False
        case "link_up":
            model.up = True
        case "fog":
            model.visibility_m = FOG_VISIBILITY_M
        case "clear":
            model.visibility_m = CLEAR_VISIBILITY_M
        case "obstruct":
            model.obstructed = True
        case "unobstruct":
            model.obstructed = False
        case "sensor_fail":
            model.sensor_failed = True
        case "sensor_recover":
            model.sensor_failed = False
        case "authority_unreachable":
            return False
        case "authority_reachable":
            return True
    return authority


def run(scenario: Scenario, selector, seed: int = 0) -> RunResult:
    rng = Random(seed)
    fleet = scenario.fleet()
    links = {link.id: link for link in scenario.bundle.links}
    classes = {c.id: c for c in scenario.bundle.traffic_classes}
    if hasattr(selector, "reset"):
        selector.reset()

    result = RunResult(
        scenario=scenario.name,
        selector=getattr(selector, "name", type(selector).__name__),
        seed=seed,
        step_s=scenario.step_s,
    )
    previous: dict[str, str | None] = {}
    authority_reachable = True

    for index in range(scenario.steps()):
        at_s = index * scenario.step_s
        now = T0 + timedelta(seconds=at_s)

        for event in scenario.events:
            if event.at_s == at_s:
                authority_reachable = _apply_event(fleet, event, authority_reachable)

        evidence = EvidenceSnapshot(fleet.step(now, rng))

        ctx = SelectorContext(
            now=now,
            evidence=evidence,
            links=links,
            classes=classes,
            authority_reachable=authority_reachable,
        )
        choices = selector(ctx)

        # True latency, known to the oracle but never to the selector.
        true_rtt = {}
        for link_id, model in fleet.models.items():
            base = getattr(model, "base_rtt_ms", None)
            if base is None:
                continue
            if isinstance(model, SatelliteModel) and model.obstructed:
                base += 400.0
            true_rtt[link_id] = base

        result.violations.extend(
            check_violations(
                at_s=at_s,
                choices=choices,
                links=links,
                classes=classes,
                fleet=fleet,
                true_rtt=true_rtt,
            )
        )

        for class_id, link_id in choices.items():
            # Two different failures that must never be reported as one number:
            # nothing was available, versus nothing was allowed.
            if link_id is None:
                result.refused_s += scenario.step_s
                continue
            if not fleet.is_up(link_id):
                result.downtime_s += scenario.step_s
                continue
            carried = scenario.traffic_bytes_per_s.get(class_id, 0) * scenario.step_s
            model = fleet.models[link_id]
            before_pct = (
                model.quota_used_pct() if isinstance(model, (LteModel, SatelliteModel)) else 0.0
            )
            model.carry(carried)
            if isinstance(model, (LteModel, SatelliteModel)) and before_pct >= 100.0:
                result.cost += (carried / 10**9) * model.cost_per_gb()

        for class_id, link_id in choices.items():
            if class_id in previous and previous[class_id] != link_id:
                result.flaps += 1
        previous = dict(choices)

        if getattr(selector, "last_degraded", False):
            result.degraded_s += scenario.step_s

        result.frames.append(
            {
                "at_s": at_s,
                "choices": dict(choices),
                "up": {link_id: fleet.is_up(link_id) for link_id in fleet.models},
                "authority_reachable": authority_reachable,
            }
        )
        result.steps += 1

    return result


def link_up_at(result: RunResult, second: int, link_id: str) -> bool:
    return bool(result.timeline_at(second)["up"][link_id])
