"""Dataplane adapters that do not touch a dataplane.

``NoopDataplane`` remembers what it was told and reports it back honestly, which
makes it the right adapter for the simulator and for a site running in
observation mode before anyone trusts it with real routing.
"""

from __future__ import annotations

from collections.abc import Mapping

from pilotfish.core.decide import EligibilityDecision


class NoopDataplane:
    """Accepts every decision and reports exactly what it accepted."""

    def __init__(self) -> None:
        self._state: dict[str, tuple[str, ...]] = {}
        self.applied: list[EligibilityDecision] = []

    def apply(self, decision: EligibilityDecision) -> None:
        self.applied.append(decision)
        self._state = {cls.class_id: cls.permitted for cls in decision.classes}

    def readback(self) -> Mapping[str, tuple[str, ...]]:
        return dict(self._state)
