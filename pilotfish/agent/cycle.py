"""One turn of the agent.

The order of operations is the design, so it is worth stating plainly:

1. Pin the bundle. Everything below uses that one object, so a bundle arriving
   mid-cycle governs the next decision and never half of this one.
2. Collect evidence.
3. Decide, and record what was authorised.
4. Record that enforcement is being attempted.
5. Enforce.
6. Read back, and record what the dataplane was actually observed to hold.

Steps 3 to 6 exist as three separate receipts because they answer three
different questions, and a log that answers only the first is the failure this
whole layer exists to prevent: a site can report that a link was forbidden while
that link carried traffic all night, with every signature still verifying.

Recording precedes acting throughout. If enforcement throws, the record of what
was intended and attempted has already survived, and the exception is re-raised
only after the effect receipt is written.
"""

from __future__ import annotations

from datetime import datetime

from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.receipts import (
    KIND_EFFECT,
    KIND_EXECUTION,
    OUTCOME_ENFORCED,
    OUTCOME_ENFORCEMENT_ERROR,
    OUTCOME_POSTCONDITION_FAILED,
    ReceiptChain,
    state_hash,
)
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
        self._chain.record(decision, now=now, kind=KIND_EXECUTION)

        try:
            self._adapter.apply(decision)
        except Exception as exc:
            self._chain.record(
                decision,
                now=now,
                kind=KIND_EFFECT,
                outcome=OUTCOME_ENFORCEMENT_ERROR,
                detail=f"{type(exc).__name__}: {exc}",
            )
            raise

        actual = dict(self._adapter.readback())
        complaint = self._postcondition_complaint(decision, actual)
        self._chain.record(
            decision,
            now=now,
            kind=KIND_EFFECT,
            outcome=OUTCOME_POSTCONDITION_FAILED if complaint else OUTCOME_ENFORCED,
            observed_state_hash=state_hash(actual),
            detail=complaint,
        )
        if complaint:
            raise PostconditionViolation(complaint)
        return decision

    def _postcondition_complaint(
        self, decision: EligibilityDecision, actual: dict[str, tuple[str, ...]]
    ) -> str:
        for cls in decision.classes:
            in_force = tuple(actual.get(cls.class_id, ()))
            surplus = set(in_force) - set(cls.permitted)
            if surplus:
                return (
                    f"class {cls.class_id}: dataplane holds {sorted(surplus)}, "
                    f"which policy excluded"
                )
            if not in_force and cls.permitted:
                return (
                    f"class {cls.class_id}: decision permitted {list(cls.permitted)} "
                    f"but the dataplane holds nothing"
                )
        return ""
