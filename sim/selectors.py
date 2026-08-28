"""The selectors under comparison.

Three baselines and the governed path. The baselines are not straw men: greedy,
a static priority list and hysteresis-damped failover are what people actually
run, and on plain uptime they are hard to beat.

Every selector sees the same thing the agent sees, which is observations, never
the simulator's private truth.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.adapters.file_sink import MemoryReceiptSink
from pilotfish.adapters.noop import NoopDataplane
from pilotfish.agent.bundle_store import BundleStore
from pilotfish.agent.cycle import AgentCycle
from pilotfish.agent.epoch import MemoryEpochStore
from pilotfish.agent.receipts import ReceiptChain
from pilotfish.authority.signer import BundleSigner, sign_floor
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.models import EvidenceSnapshot, Link, TrafficClass
from pilotfish.protocol.envelope import encode_envelope, sign
from pilotfish.protocol.messages import MSG_POLICY_BUNDLE, encode_bundle

SITE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))
AUTHORITY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(160, 192)))


@dataclass(frozen=True, slots=True)
class SelectorContext:
    now: datetime
    evidence: EvidenceSnapshot
    links: dict[str, Link]
    classes: dict[str, TrafficClass]
    authority_reachable: bool


def _observed_up(evidence: EvidenceSnapshot, link_id: str) -> bool:
    observation = evidence.latest(link_id, "up")
    return observation is not None and observation.value >= 1.0


def _observed_rtt(evidence: EvidenceSnapshot, link_id: str) -> float:
    observation = evidence.latest(link_id, "rtt_ms")
    return float("inf") if observation is None else observation.value


def _best_by_rtt(evidence: EvidenceSnapshot, candidates: list[str]) -> str | None:
    live = [link_id for link_id in candidates if _observed_up(evidence, link_id)]
    if not live:
        return None
    return min(live, key=lambda link_id: (_observed_rtt(evidence, link_id), link_id))


class Greedy:
    """Always take the lowest observed latency that is up."""

    name = "greedy"

    def reset(self) -> None:
        return None

    def __call__(self, ctx: SelectorContext) -> dict[str, str | None]:
        best = _best_by_rtt(ctx.evidence, sorted(ctx.links))
        return {class_id: best for class_id in ctx.classes}


class StaticPriority:
    """Walk a fixed list and take the first link that is up."""

    def __init__(self, order: tuple[str, ...]) -> None:
        self._order = order
        self.name = "static_priority"

    def reset(self) -> None:
        return None

    def __call__(self, ctx: SelectorContext) -> dict[str, str | None]:
        chosen = next(
            (link_id for link_id in self._order if _observed_up(ctx.evidence, link_id)), None
        )
        return {class_id: chosen for class_id in ctx.classes}


class Hysteresis:
    """Greedy, but refuse to move again until the dwell time has passed."""

    def __init__(self, dwell_s: float = 300.0) -> None:
        self._dwell_s = dwell_s
        self.name = "hysteresis"
        self._current: str | None = None
        self._since: datetime | None = None

    def reset(self) -> None:
        self._current = None
        self._since = None

    def __call__(self, ctx: SelectorContext) -> dict[str, str | None]:
        best = _best_by_rtt(ctx.evidence, sorted(ctx.links))
        held_is_live = self._current is not None and _observed_up(ctx.evidence, self._current)

        if self._current is None or not held_is_live:
            self._current, self._since = best, ctx.now
        elif best != self._current:
            elapsed = (ctx.now - self._since).total_seconds() if self._since else float("inf")
            if elapsed >= self._dwell_s:
                self._current, self._since = best, ctx.now

        return {class_id: self._current for class_id in ctx.classes}


class Governed:
    """Run the real agent, then choose on latency inside the permitted set.

    This is the shipping decision path, not a reimplementation of it: the same
    ``AgentCycle``, the same bundle store, the same receipts. What the simulator
    swaps in is the evidence source and the dataplane, which is exactly what an
    integrator swaps.
    """

    name = "governed"

    def __init__(self, bundle: PolicyBundle, site_id: str = "sim-site") -> None:
        self._bundle = bundle
        self._site_id = site_id
        self._validity_s = (bundle.not_after - bundle.issued_at).total_seconds()
        self.reset()

    def _publish(self, now: datetime) -> bytes:
        """The authority reissues on a cadence; a site out of contact ages out of its bundle.

        Each publication carries a higher sequence and a fresh nonce, because a
        store that refuses rollback and replay would otherwise refuse the
        authority's own routine refresh.
        """

        self._epoch += 1
        fresh = replace(
            self._bundle,
            sequence=self._epoch,
            issued_at=now,
            not_after=now + timedelta(seconds=self._validity_s),
        )
        return encode_envelope(
            sign(
                msg_type=MSG_POLICY_BUNDLE,
                issuer="authority-1",
                issued_at=now,
                nonce=self._epoch.to_bytes(16, "big"),
                payload=encode_bundle(fresh),
                private_key=AUTHORITY_KEY,
            )
        )

    def reset(self) -> None:
        self._store = BundleStore(
            trusted_key=AUTHORITY_KEY.public_key(),
            expected_issuer="authority-1",
            site_id=self._site_id,
            signed_floor=sign_floor(
                BundleSigner(AUTHORITY_KEY, "authority-1"),
                site_id=self._site_id,
                links=self._bundle.links,
                classes=self._bundle.traffic_classes,
                now=self._bundle.issued_at,
            ),
            now=self._bundle.issued_at,
            epoch_store=MemoryEpochStore(),
        )
        self._sink = MemoryReceiptSink()
        self._chain = ReceiptChain(self._site_id, self._sink, SITE_KEY)
        self._adapter = NoopDataplane()
        self._epoch = 0
        self.last_degraded = True

    @property
    def receipts(self) -> list[bytes]:
        return list(self._sink.lines)

    def __call__(self, ctx: SelectorContext) -> dict[str, str | None]:
        if ctx.authority_reachable:
            self._store.accept(self._publish(ctx.now), now=ctx.now)

        class Snapshot:
            def observe(self, now):
                return ctx.evidence.observations

        cycle = AgentCycle(self._site_id, self._store, Snapshot(), self._adapter, self._chain)
        decision = cycle.run_once(now=ctx.now)
        self.last_degraded = decision.degraded

        choices: dict[str, str | None] = {}
        for class_id in ctx.classes:
            permitted = decision.permitted_for(class_id)
            if not permitted and decision.classes:
                # The floor policy names its own class; map the site's traffic on
                # to whatever the bundle in force actually decided.
                permitted = decision.classes[0].permitted
            choices[class_id] = _best_by_rtt(ctx.evidence, list(permitted))
        return choices
