from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pilotfish.adapters.file_sink import FileReceiptSink, MemoryReceiptSink
from pilotfish.agent.receipts import GENESIS_HASH, ChainBroken, ReceiptChain, verify_chain
from pilotfish.core.bundle import PolicyBundle
from pilotfish.core.decide import decide
from pilotfish.core.models import EvidenceSnapshot, Link, Observation, TrafficClass
from pilotfish.core.rules import LinkDownRule
from pilotfish.protocol.envelope import decode_envelope, verify

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
LINKS = (Link(id="fiber0", type="fiber"), Link(id="lte0", type="lte", metered=True))

BUNDLE = PolicyBundle(
    bundle_id="b1",
    issued_at=T0,
    not_after=T0 + timedelta(hours=6),
    decision_ttl_s=60,
    links=LINKS,
    traffic_classes=(TrafficClass("bulk"),),
    rules=(LinkDownRule("R-DOWN"),),
)


def snapshot(fiber_up=1.0, at=T0):
    return EvidenceSnapshot(
        (
            Observation("fiber0", "up", fiber_up, at, "agent"),
            Observation("lte0", "up", 1.0, at, "agent"),
        )
    )


def decision_at(offset_s, fiber_up=1.0):
    now = T0 + timedelta(seconds=offset_s)
    return decide(bundle=BUNDLE, evidence=snapshot(fiber_up, now), now=now, site_id="site-1")


def build(n=3):
    sink = MemoryReceiptSink()
    chain = ReceiptChain("site-1", sink, SK)
    receipts = [
        chain.record(decision_at(i * 60, fiber_up=float(i % 2)), now=T0 + timedelta(seconds=i * 60))
        for i in range(n)
    ]
    return sink, chain, receipts


def test_chain_links_and_numbers_are_contiguous():
    _, _, (r1, r2, r3) = build()
    assert [r.seq for r in (r1, r2, r3)] == [1, 2, 3]
    assert r1.prev_hash == GENESIS_HASH
    assert r2.prev_hash == r1.hash()
    assert r3.prev_hash == r2.hash()
    verify_chain([r1, r2, r3])


def test_a_removed_receipt_breaks_the_chain():
    _, _, (r1, _, r3) = build()
    with pytest.raises(ChainBroken):
        verify_chain([r1, r3])


def test_reordering_breaks_the_chain():
    _, _, (r1, r2, r3) = build()
    with pytest.raises(ChainBroken):
        verify_chain([r1, r3, r2])


def test_every_written_receipt_verifies_under_the_site_key():
    sink, _, _ = build()
    for line in sink.lines:
        verify(decode_envelope(line), SK.public_key())


def test_file_sink_is_append_only(tmp_path):
    sink = FileReceiptSink(tmp_path / "receipts.log")
    sink.append(b"a")
    sink.append(b"b")
    assert (tmp_path / "receipts.log").read_bytes().count(b"\n") == 2
    assert sink.read_all() == [b"a", b"b"]


def test_a_torn_final_line_is_dropped_and_the_rest_still_reads(tmp_path):
    path = tmp_path / "receipts.log"
    sink = FileReceiptSink(path)
    sink.append(b"a")
    with path.open("ab") as handle:
        handle.write(b"dGhpcyBpcyB0")  # a line cut off mid-write
    assert sink.read_all() == [b"a"]
