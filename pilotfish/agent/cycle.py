"""One turn of the agent.

The order of operations is the design, so it is worth stating plainly:

1. Pin the bundle. Everything below uses that one object, so a bundle arriving
   mid-cycle governs the next decision and never half of this one.
2. Collect evidence.
3. Decide.
4. Record the receipt.
5. Enforce.
6. Read back and compare.

Step 4 precedes step 5 deliberately. If enforcement blows up, the record of what
was decided has already survived, and an operator can see the gap between what
the site intended and what its dataplane did. The reverse order would lose
exactly the evidence needed to diagnose the failure.
"""

from __future__ import annotations

from datetime import datetime

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.receipts import ReceiptChain
from pilotfish.core.decide import EligibilityDecision, decide
from pilotfish.core.models import EvidenceSnapshot
from pilotfish.sdk.errors import EnforcementFailed
from pilotfish.sdk.protocols import DataplaneAdapter, ObservationSource


class PostconditionViolation(EnforcementFailed):
    """The dataplane does not hold what was decided.

    This is the failure that is otherwise invisible: the decision was taken, the
    receipt says so, and the packets went somewhere else entirely.
    """


class AgentCycle:
    def __init__(
        self,
        site_id: str,
        store: BundleStore,
        source: ObservationSource,
        adapter: DataplaneAdapter,
        chain: ReceiptChain,
    ) -> None:
        self._site_id = site_id
        self._store = store
        self._source = source
        self._adapter = adapter
        self._chain = chain

    def run_once(self, now: datetime) -> EligibilityDecision:
        bundle, degraded = self._store.current(now)

        evidence = EvidenceSnapshot(tuple(self._source.observe(now)))

        decision = decide(
            bundle=bundle,
            evidence=evidence,
            now=now,
            site_id=self._site_id,
            degraded=degraded,
        )

        self._chain.record(decision, now=now)

        self._adapter.apply(decision)
        self._check_postcondition(decision)
        return decision

    def _check_postcondition(self, decision: EligibilityDecision) -> None:
        actual = self._adapter.readback()
        for cls in decision.classes:
            in_force = tuple(actual.get(cls.class_id, ()))
            surplus = set(in_force) - set(cls.permitted)
            if surplus:
                raise PostconditionViolation(
                    f"class {cls.class_id}: dataplane holds {sorted(surplus)}, "
                    f"which policy excluded"
                )
            if not in_force and cls.permitted:
                raise PostconditionViolation(
                    f"class {cls.class_id}: decision permitted {list(cls.permitted)} "
                    f"but the dataplane holds nothing"
                )
