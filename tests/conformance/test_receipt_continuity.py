"""Negative conformance: an audit trail that restarts is not an audit trail.

A chain whose sequence returns to 1 after a process restart cannot distinguish
"the agent was restarted" from "somebody deleted the middle of the log". Both
look identical to a verifier, which is precisely what the chain exists to
prevent.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.adapters.file_sink import MemoryReceiptSink
from pilotfish.agent.receipts import ChainBroken, ReceiptChain, read_chain, verify_chain
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import decide
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import LinkDownRule

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
OTHER_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
LINKS = (Link(id="fiber0", type="fiber"),)

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


def decision(offset_s=0):
    now = T0 + timedelta(seconds=offset_s)
    evidence = EvidenceSnapshot((Observation("fiber0", "up", 1.0, now, "agent"),))
    return decide(bundle=BUNDLE, evidence=evidence, now=now, site_id="site-1")


def test_a_restarted_agent_continues_the_chain_instead_of_starting_over():
    sink = MemoryReceiptSink()
    first = ReceiptChain.recover(sink, SK, site_id="site-1")
    assert [first.record(decision(i * 60), now=T0).seq for i in range(3)] == [1, 2, 3]

    second = ReceiptChain.recover(sink, SK, site_id="site-1")
    resumed = second.record(decision(300), now=T0)
    assert resumed.seq == 4
    assert resumed.prev_hash == first.head[1]

    verify_chain(read_chain(sink, SK.public_key()))


def test_recovery_refuses_a_log_belonging_to_another_site():
    sink = MemoryReceiptSink()
    ReceiptChain.recover(sink, SK, site_id="site-1").record(decision(), now=T0)
    with pytest.raises(ChainBroken, match="site"):
        ReceiptChain.recover(sink, SK, site_id="site-2")


def test_recovery_refuses_a_log_signed_by_a_different_key():
    """A log we cannot verify is not a log we may append to."""

    sink = MemoryReceiptSink()
    ReceiptChain.recover(sink, OTHER_SK, site_id="site-1").record(decision(), now=T0)
    with pytest.raises(ChainBroken):
        ReceiptChain.recover(sink, SK, site_id="site-1")


def test_recovery_refuses_a_log_with_a_hole_in_it():
    sink = MemoryReceiptSink()
    chain = ReceiptChain.recover(sink, SK, site_id="site-1")
    for i in range(3):
        chain.record(decision(i * 60), now=T0)

    del sink.lines[1]
    with pytest.raises(ChainBroken):
        ReceiptChain.recover(sink, SK, site_id="site-1")


def test_an_empty_log_starts_at_genesis():
    chain = ReceiptChain.recover(MemoryReceiptSink(), SK, site_id="site-1")
    assert chain.head[0] == 0
