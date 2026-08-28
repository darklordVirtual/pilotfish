# Pilotfish Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure decision core, the signed message protocol, the SDK integration surface, a working site agent, and a simulation rig that compares governed link eligibility against the three baselines people actually run.

**Architecture:** A pure function maps a verified policy bundle plus a timestamped evidence snapshot to an `EligibilityDecision` that names the permitted links per traffic class and the reason each excluded link was excluded. A site agent wraps that function with I/O: bundle verification, evidence collection, dataplane enforcement with readback, and a hash-chained receipt log. The same pure function drives the simulator, so simulated and production decisions are the same code.

**Tech Stack:** Python 3.12, `cbor2` for canonical encoding, `cryptography` for Ed25519, `pytest` and `hypothesis` for tests, `ruff` and `mypy` for gates.

**Spec:** `docs/superpowers/specs/2026-08-28-pilotfish-design.md`

## Global Constraints

- Python 3.12 floor. No runtime dependency beyond `cbor2` and `cryptography`.
- The decision function is pure: no I/O, no network, no clock reads inside it. `now` is always an explicit parameter.
- Rules only exclude. No rule may add a link to a permitted set.
- Bundle verification has no skip flag and no bypass parameter.
- Every decision carries `bundle_hash`, `evidence_hash` and a `degraded` flag.
- Canonical CBOR everywhere on the wire: deterministic encoding, sorted map keys.
- All timestamps are timezone-aware UTC. Naive datetimes are rejected at construction.
- Licence: BUSL-1.1.

---

### Task 1: Project scaffold and domain models

**Files:**
- Create: `pyproject.toml`, `README.md`, `LICENSE`, `.gitignore`, `NEGATIVE_RESULTS.md`
- Create: `pilotfish/__init__.py`, `pilotfish/core/__init__.py`, `pilotfish/core/models.py`
- Test: `tests/core/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `LinkType = Literal["fiber","lte","satellite","fso"]`; frozen dataclasses `Link(id, type, metered=False, encrypted_below=False, jurisdictions=(), owner="")`, `Observation(link_id, quantity, value, at, source)`, `TrafficClass(id, max_rtt_ms=None, allow_metered=True, allowed_jurisdictions=None, requires_encryption=False)`, `EvidenceSnapshot(observations)` with `latest(link_id, quantity) -> Observation | None`, `age_s(link_id, quantity, now) -> float | None`, and `hash() -> str` (hex sha256 over canonical CBOR).

- [ ] **Step 1: Write the failing test**

```python
from datetime import UTC, datetime, timedelta
import pytest
from pilotfish.core.models import EvidenceSnapshot, Link, Observation

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def obs(link_id="lte0", quantity="rtt_ms", value=40.0, at=T0, source="agent"):
    return Observation(link_id=link_id, quantity=quantity, value=value, at=at, source=source)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        Observation(
            link_id="a",
            quantity="rtt_ms",
            value=1.0,
            at=datetime(2026, 8, 28, 12, 0),
            source="agent",
        )


def test_latest_wins_and_age_is_computed():
    snap = EvidenceSnapshot((obs(value=40.0), obs(value=10.0, at=T0 + timedelta(seconds=30))))
    assert snap.latest("lte0", "rtt_ms").value == 10.0
    assert snap.age_s("lte0", "rtt_ms", T0 + timedelta(seconds=90)) == 60.0
    assert snap.latest("lte0", "loss_pct") is None


def test_hash_is_order_independent_and_content_sensitive():
    a, b = obs(value=1.0), obs(link_id="fiber0", value=2.0)
    assert EvidenceSnapshot((a, b)).hash() == EvidenceSnapshot((b, a)).hash()
    assert EvidenceSnapshot((a,)).hash() != EvidenceSnapshot((b,)).hash()


def test_link_defaults():
    link = Link(id="sat0", type="satellite")
    assert link.metered is False and link.jurisdictions == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/core/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish'`

- [ ] **Step 3: Write the scaffold and the models**

`pyproject.toml` declares the package, the two runtime dependencies, and dev extras (`pytest`, `hypothesis`, `ruff`, `mypy`). `EvidenceSnapshot.hash()` sorts observations by `(link_id, quantity, at, source)` before encoding so ordering cannot change the hash. Post-init validation raises `ValueError` for naive datetimes.

```python
def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware UTC")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/core/test_models.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml README.md LICENSE .gitignore NEGATIVE_RESULTS.md pilotfish tests
git commit -m "feat(core): domain models with UTC-checked timestamps and evidence hashing"
```

---

### Task 2: Exclusion rules

**Files:**
- Create: `pilotfish/core/rules.py`
- Test: `tests/core/test_rules.py`

**Interfaces:**
- Consumes: Task 1 models.
- Produces: `Exclusion(link_id, rule_id, reason)`; a `Rule` protocol with `rule_id: str` and `evaluate(link, tclass, evidence, now) -> str | None` returning a reason when the link is excluded; concrete rules `LinkDownRule(rule_id)`, `MaxRttRule(rule_id, class_id)`, `MeteredRule(rule_id, class_id)`, `QuotaRule(rule_id, link_type, threshold_pct)`, `EvidenceFreshnessRule(rule_id, link_type, quantity, max_age_s)`, `JurisdictionRule(rule_id, class_id)`, `EncryptionRule(rule_id, class_id)`, `DirectiveRule(rule_id, link_id, reason_text, not_after)`.

- [ ] **Step 1: Write the failing test**

```python
def test_freshness_rule_excludes_when_evidence_is_stale():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    link = Link(id="fso0", type="fso")
    snap = EvidenceSnapshot((Observation("fso0", "visibility_m", 3000.0, T0, "model"),))
    assert rule.evaluate(link, CLASS_BULK, snap, T0 + timedelta(seconds=300)) is None
    assert "stale" in rule.evaluate(link, CLASS_BULK, snap, T0 + timedelta(seconds=900))


def test_freshness_rule_excludes_when_evidence_is_missing_entirely():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    assert (
        rule.evaluate(Link(id="fso0", type="fso"), CLASS_BULK, EvidenceSnapshot(()), T0) is not None
    )


def test_freshness_rule_ignores_other_link_types():
    rule = EvidenceFreshnessRule(
        "R-FSO-FRESH", link_type="fso", quantity="visibility_m", max_age_s=600
    )
    assert rule.evaluate(Link(id="f0", type="fiber"), CLASS_BULK, EvidenceSnapshot(()), T0) is None


def test_metered_rule_only_binds_its_own_class():
    rule = MeteredRule("R-METER", class_id="realtime")
    lte = Link(id="lte0", type="lte", metered=True)
    assert (
        rule.evaluate(lte, TrafficClass("realtime", allow_metered=False), EvidenceSnapshot(()), T0)
        is not None
    )
    assert (
        rule.evaluate(lte, TrafficClass("bulk", allow_metered=False), EvidenceSnapshot(()), T0)
        is None
    )
```

Missing evidence excluding rather than admitting is the single most important behaviour in this file: absence of evidence is never evidence of health.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/core/test_rules.py -v`
Expected: FAIL with `ImportError: cannot import name 'EvidenceFreshnessRule'`

- [ ] **Step 3: Implement the rules**

Each rule returns `None` when it does not apply, or a human-readable reason string when it excludes. Every rule that reads a measurement excludes when the measurement is absent.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/core/test_rules.py -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/core/rules.py tests/core/test_rules.py
git commit -m "feat(core): exclusion rules; missing evidence excludes"
```

---

### Task 3: Policy bundle and the pure decision function

**Files:**
- Create: `pilotfish/core/bundle.py`, `pilotfish/core/decide.py`
- Test: `tests/core/test_decide.py`, `tests/core/test_decide_properties.py`

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: `PolicyBundle(bundle_id, issued_at, not_after, decision_ttl_s, links, traffic_classes, rules)` with `hash() -> str`; `FLOOR_BUNDLE` built by `floor_bundle(links) -> PolicyBundle`; `ClassEligibility(class_id, permitted, exclusions)`; `EligibilityDecision(site_id, decided_at, valid_until, bundle_hash, evidence_hash, degraded, classes)` with `permitted_for(class_id) -> tuple[str, ...]`; `decide(*, bundle, evidence, now, site_id, degraded=False) -> EligibilityDecision`.

- [ ] **Step 1: Write the failing tests**

```python
def test_every_link_is_a_candidate_and_exclusions_carry_rule_ids():
    decision = decide(bundle=BUNDLE, evidence=SNAP_FOG, now=T0, site_id="site-1")
    fso = decision.classes[0]
    assert "fso0" not in fso.permitted
    assert any(e.link_id == "fso0" and e.rule_id == "R-FSO-FRESH" for e in fso.exclusions)


def test_decision_binds_bundle_and_evidence_hashes():
    decision = decide(bundle=BUNDLE, evidence=SNAP, now=T0, site_id="site-1")
    assert decision.bundle_hash == BUNDLE.hash()
    assert decision.evidence_hash == SNAP.hash()
    assert decision.valid_until == T0 + timedelta(seconds=BUNDLE.decision_ttl_s)


def test_degraded_flag_is_carried_not_inferred():
    assert (
        decide(
            bundle=floor_bundle(LINKS), evidence=SNAP, now=T0, site_id="s", degraded=True
        ).degraded
        is True
    )
```

```python
# tests/core/test_decide_properties.py
@given(evidence=evidence_snapshots(), extra=rule_lists())
def test_more_rules_never_grow_the_permitted_set(evidence, extra):
    base = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    wider = decide(
        bundle=BUNDLE.with_rules(BUNDLE.rules + extra), evidence=evidence, now=T0, site_id="s"
    )
    for cls in base.classes:
        assert set(wider.permitted_for(cls.class_id)) <= set(cls.permitted)


@given(evidence=evidence_snapshots())
def test_decision_is_deterministic(evidence):
    a = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    b = decide(bundle=BUNDLE, evidence=evidence, now=T0, site_id="s")
    assert a == b
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/core/test_decide.py tests/core/test_decide_properties.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.core.decide'`

- [ ] **Step 3: Implement the bundle and the decision function**

`decide` starts from all links as candidates for each class, applies every rule, collects exclusions sorted by `(link_id, rule_id)` for determinism, and returns the frozen decision. `floor_bundle` builds the conservative degraded-mode policy: unmetered, non-FSO links only, evidence freshness required.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/core -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/core/bundle.py pilotfish/core/decide.py tests/core
git commit -m "feat(core): pure eligibility decision, monotone and deterministic"
```

---

### Task 4: Canonical encoding and the signed envelope

**Files:**
- Create: `pilotfish/protocol/__init__.py`, `pilotfish/protocol/canonical.py`, `pilotfish/protocol/envelope.py`
- Create: `spec/protocol.md`, `spec/vectors/envelope.json`
- Test: `tests/protocol/test_envelope.py`, `tests/protocol/test_vectors.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `dumps(obj) -> bytes` and `loads(data) -> object` (canonical CBOR); `Envelope(msg_type, issuer, issued_at, nonce, payload, signature)`; `sign(msg_type, issuer, issued_at, nonce, payload, private_key) -> Envelope`; `verify(envelope, public_key) -> None` raising `SignatureInvalid`; `signing_input(...) -> bytes`.

- [ ] **Step 1: Write the failing test**

```python
def test_roundtrip_and_verify():
    env = sign(
        msg_type="POLICY_BUNDLE",
        issuer="authority-1",
        issued_at=T0,
        nonce=b"\x01" * 16,
        payload=b"hello",
        private_key=SK,
    )
    verify(env, SK.public_key())


def test_tampered_payload_fails_verification():
    env = sign(
        msg_type="POLICY_BUNDLE",
        issuer="authority-1",
        issued_at=T0,
        nonce=b"\x01" * 16,
        payload=b"hello",
        private_key=SK,
    )
    with pytest.raises(SignatureInvalid):
        verify(replace(env, payload=b"hellp"), SK.public_key())


def test_signing_input_is_stable_across_map_ordering():
    assert dumps({"b": 1, "a": 2}) == dumps({"a": 2, "b": 1})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/protocol -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.protocol'`

- [ ] **Step 3: Implement encoding, envelope, and freeze the test vectors**

`signing_input` is canonical CBOR of the array `[msg_type, issuer, int(issued_at.timestamp()), nonce, payload]`. `spec/vectors/envelope.json` holds a fixed key, fixed nonce, fixed payload and the expected signing input and signature as hex. `spec/protocol.md` states the encoding rules normatively.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/protocol -v`
Expected: all passed, including the vector test that reads `spec/vectors/envelope.json`

- [ ] **Step 5: Commit**

```bash
git add pilotfish/protocol spec tests/protocol
git commit -m "feat(protocol): canonical CBOR and Ed25519 signed envelope with frozen vectors"
```

---

### Task 5: The four messages

**Files:**
- Create: `pilotfish/protocol/messages.py`
- Test: `tests/protocol/test_messages.py`

**Interfaces:**
- Consumes: Tasks 3 and 4.
- Produces: `encode_bundle(bundle) -> bytes` / `decode_bundle(payload) -> PolicyBundle`; `encode_decision(decision) -> bytes` / `decode_decision(payload) -> EligibilityDecision`; `ObservationBatch(site_id, observations)` with encode/decode; `AuthorityDirective(directive_id, site_id, link_id, reason, not_after)` with encode/decode and `to_rule() -> DirectiveRule`; `MSG_TYPES` naming the four constants.

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.parametrize("obj,enc,dec", CASES)
def test_message_roundtrip_is_lossless(obj, enc, dec):
    assert dec(enc(obj)) == obj


def test_directive_converts_to_a_rule_that_excludes_only_its_link():
    d = AuthorityDirective("D-1", "site-1", "lte0", "carrier maintenance", T0 + timedelta(hours=2))
    rule = d.to_rule()
    assert (
        rule.evaluate(Link(id="lte0", type="lte"), CLASS_BULK, EvidenceSnapshot(()), T0) is not None
    )
    assert rule.evaluate(Link(id="f0", type="fiber"), CLASS_BULK, EvidenceSnapshot(()), T0) is None


def test_expired_directive_stops_excluding():
    d = AuthorityDirective("D-1", "site-1", "lte0", "maintenance", T0 + timedelta(hours=2))
    assert (
        d.to_rule().evaluate(
            Link(id="lte0", type="lte"), CLASS_BULK, EvidenceSnapshot(()), T0 + timedelta(hours=3)
        )
        is None
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/protocol/test_messages.py -v`
Expected: FAIL with `ImportError: cannot import name 'encode_bundle'`

- [ ] **Step 3: Implement the codecs**

Rules encode as a tagged array `[kind, rule_id, *fields]` with a registry mapping kind to constructor, so an unknown rule kind raises rather than being silently dropped.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/protocol -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/protocol/messages.py tests/protocol/test_messages.py
git commit -m "feat(protocol): the four message codecs; unknown rule kinds are fatal"
```

---

### Task 6: Bundle verification, expiry and the degraded floor

**Files:**
- Create: `pilotfish/agent/__init__.py`, `pilotfish/agent/bundle_store.py`
- Test: `tests/agent/test_bundle_store.py`

**Interfaces:**
- Consumes: Tasks 3, 4, 5.
- Produces: `BundleStore(trusted_key, floor_links)` with `accept(envelope_bytes, now) -> PolicyBundle` raising `BundleUnverified` or `BundleExpired`, and `current(now) -> tuple[PolicyBundle, bool]` returning the active bundle and the degraded flag.

- [ ] **Step 1: Write the failing test**

```python
def test_unsigned_or_wrongly_signed_bundle_is_refused():
    store = BundleStore(trusted_key=PK, floor_links=LINKS)
    with pytest.raises(BundleUnverified):
        store.accept(sign_with(OTHER_SK, BUNDLE), now=T0)


def test_expired_bundle_falls_to_degraded_floor_not_to_the_old_bundle():
    store = BundleStore(trusted_key=PK, floor_links=LINKS)
    store.accept(sign_with(SK, BUNDLE), now=T0)
    bundle, degraded = store.current(now=BUNDLE.not_after + timedelta(seconds=1))
    assert degraded is True
    assert bundle.bundle_id == "floor"


def test_no_bundle_at_all_is_degraded_from_the_start():
    _, degraded = BundleStore(trusted_key=PK, floor_links=LINKS).current(now=T0)
    assert degraded is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/agent/test_bundle_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.agent'`

- [ ] **Step 3: Implement the store**

There is no code path that returns an unverified or expired bundle as current. Falling back means falling to the floor, never to the last good bundle.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/agent -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/agent tests/agent
git commit -m "feat(agent): fail-closed bundle store with degraded floor policy"
```

---

### Task 7: SDK surface and typed errors

**Files:**
- Create: `pilotfish/sdk/__init__.py`, `pilotfish/sdk/protocols.py`, `pilotfish/sdk/errors.py`
- Test: `tests/sdk/test_public_api.py`

**Interfaces:**
- Consumes: Tasks 1, 3.
- Produces: runtime-checkable protocols `ObservationSource.observe(now) -> tuple[Observation, ...]`, `DataplaneAdapter.apply(decision) -> None` and `DataplaneAdapter.readback() -> Mapping[str, tuple[str, ...]]`, `ReceiptSink.append(receipt_bytes) -> None`, `PolicyAuthorityClient.fetch() -> bytes | None`; errors `PilotfishError`, `BundleUnverified`, `BundleExpired`, `EvidenceStale`, `EnforcementFailed`; `PUBLIC_API` frozenset snapshot.

- [ ] **Step 1: Write the failing test**

```python
def test_public_api_snapshot_is_unchanged():
    import pilotfish.sdk as sdk

    assert {n for n in dir(sdk) if not n.startswith("_")} == sdk.PUBLIC_API


def test_enforcement_failed_is_the_only_operational_fault():
    assert issubclass(EnforcementFailed, PilotfishError)
    for cls in (BundleUnverified, BundleExpired, EvidenceStale):
        assert issubclass(cls, PilotfishError)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/sdk -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.sdk'`

- [ ] **Step 3: Implement the SDK surface**

`pilotfish/sdk/__init__.py` re-exports the four protocols, the five errors, the models a consumer needs, and `decide`. Nothing else. `PUBLIC_API` is the literal frozenset of those names, so widening the surface fails the test until it is done deliberately.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/sdk -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/sdk tests/sdk
git commit -m "feat(sdk): four integration protocols, typed errors, frozen public API"
```

---

### Task 8: Hash-chained receipts

**Files:**
- Create: `pilotfish/agent/receipts.py`, `pilotfish/adapters/__init__.py`, `pilotfish/adapters/file_sink.py`
- Test: `tests/agent/test_receipts.py`

**Interfaces:**
- Consumes: Tasks 3, 4, 5, 7.
- Produces: `Receipt(site_id, seq, prev_hash, decision, degraded)` with `hash() -> str`; `ReceiptChain(site_id, sink, private_key)` with `record(decision, now) -> Receipt`; `verify_chain(receipts) -> None` raising `ChainBroken`; `FileReceiptSink(path)` implementing `ReceiptSink` with append-only writes.

- [ ] **Step 1: Write the failing test**

```python
def test_chain_links_and_numbers_are_contiguous():
    chain = ReceiptChain("site-1", sink, SK)
    r1 = chain.record(DECISION_A, now=T0)
    r2 = chain.record(DECISION_B, now=T1)
    assert (r1.seq, r2.seq) == (1, 2)
    assert r2.prev_hash == r1.hash()
    verify_chain([r1, r2])


def test_a_removed_receipt_breaks_the_chain():
    r1, r2, r3 = build_three()
    with pytest.raises(ChainBroken):
        verify_chain([r1, r3])


def test_sink_is_append_only():
    sink = FileReceiptSink(tmp_path / "receipts.log")
    sink.append(b"a")
    sink.append(b"b")
    assert (tmp_path / "receipts.log").read_bytes().count(b"\n") == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/agent/test_receipts.py -v`
Expected: FAIL with `ImportError: cannot import name 'ReceiptChain'`

- [ ] **Step 3: Implement receipts and the file sink**

Each line in the sink is one base64 envelope, so a partially written tail can be detected and the rest of the chain still verified. No network I/O anywhere in this module.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/agent -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/agent/receipts.py pilotfish/adapters tests/agent/test_receipts.py
git commit -m "feat(agent): hash-chained append-only decision receipts"
```

---

### Task 9: The agent cycle with postcondition readback

**Files:**
- Create: `pilotfish/agent/cycle.py`, `pilotfish/adapters/noop.py`
- Test: `tests/agent/test_cycle.py`

**Interfaces:**
- Consumes: Tasks 6, 7, 8.
- Produces: `AgentCycle(site_id, store, source, adapter, chain)` with `run_once(now) -> EligibilityDecision`; `NoopDataplane()` implementing `DataplaneAdapter`; `PostconditionViolation(EnforcementFailed)`.

- [ ] **Step 1: Write the failing test**

```python
def test_readback_mismatch_raises_after_the_receipt_is_written():
    adapter = LyingDataplane()  # applies, then reports a link that was excluded
    cycle = AgentCycle("site-1", store, source, adapter, chain)
    with pytest.raises(PostconditionViolation):
        cycle.run_once(now=T0)
    assert len(sink.lines) == 1  # the decision is on the record regardless


def test_bundle_swap_mid_cycle_does_not_mix_two_bundles():
    source = SwappingSource(
        store, new_bundle_envelope=OTHER_BUNDLE_BYTES
    )  # accepts a new bundle during observe()
    decision = AgentCycle("site-1", store, source, NoopDataplane(), chain).run_once(now=T0)
    assert decision.bundle_hash in (BUNDLE.hash(), OTHER_BUNDLE.hash())
    assert decision.bundle_hash == store.decided_against_hash
```

The second test is the analogue of REMORA's policy-change-under-review case: the cycle pins the bundle once at the top and uses that pinned object throughout, so a bundle arriving mid-cycle applies to the next decision, never half of this one.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/agent/test_cycle.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.agent.cycle'`

- [ ] **Step 3: Implement the cycle**

Order is fixed: pin the bundle, collect evidence, decide, record the receipt, enforce, read back, compare. The receipt is written before enforcement so that an enforcement fault cannot erase the evidence of what was decided.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/agent -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/agent/cycle.py pilotfish/adapters/noop.py tests/agent/test_cycle.py
git commit -m "feat(agent): decision cycle with pinned bundle and postcondition readback"
```

---

### Task 10: Authority: bundle signing and publication

**Files:**
- Create: `pilotfish/authority/__init__.py`, `pilotfish/authority/signer.py`, `pilotfish/cli.py`
- Test: `tests/authority/test_signer.py`

**Interfaces:**
- Consumes: Tasks 3, 4, 5.
- Produces: `BundleSigner(private_key, issuer)` with `publish(bundle, now) -> bytes`; `load_bundle_yaml(path) -> PolicyBundle` reading a declarative policy file; CLI `pilotfish sign-bundle <policy.json> --key <path> --out <file>` and `pilotfish verify-bundle <file> --key <pub>`.

- [ ] **Step 1: Write the failing test**

```python
def test_published_bundle_verifies_and_round_trips():
    blob = BundleSigner(SK, "authority-1").publish(BUNDLE, now=T0)
    store = BundleStore(trusted_key=SK.public_key(), floor_links=LINKS)
    assert store.accept(blob, now=T0).hash() == BUNDLE.hash()


def test_policy_file_parses_into_the_same_bundle_shape():
    bundle = load_bundle_json(FIXTURE_POLICY)
    assert {r.rule_id for r in bundle.rules} == {"R-DOWN", "R-FSO-FRESH", "R-QUOTA", "R-METER"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/authority -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pilotfish.authority'`

- [ ] **Step 3: Implement the signer, the policy file reader and the CLI**

The policy file is JSON so it needs no dependency. A realistic fixture policy ships in `examples/policy.json` and is the one the simulator uses.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/authority -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add pilotfish/authority pilotfish/cli.py examples tests/authority
git commit -m "feat(authority): bundle signing, declarative policy files, CLI"
```

---

### Task 11: Link failure models and the simulator

**Files:**
- Create: `sim/__init__.py`, `sim/links.py`, `sim/scenario.py`, `sim/run.py`
- Test: `tests/sim/test_links.py`, `tests/sim/test_scenario.py`

**Interfaces:**
- Consumes: Tasks 1, 3, 7.
- Produces: `LinkModel.step(t, rng) -> tuple[Observation, ...]` with `FiberModel`, `LteModel(quota_gb)`, `SatelliteModel`, `FsoModel(weather)`; `Scenario(site_id, links, models, classes, traffic, events, duration_s, step_s)`; `Event(at, kind, target)`; `run(scenario, selector, seed) -> RunResult` where `RunResult` carries `violations`, `cost`, `flaps`, `downtime_s`, `degraded_s`.

- [ ] **Step 1: Write the failing test**

```python
def test_fso_degrades_with_visibility_and_stops_reporting_when_the_sensor_dies():
    model = FsoModel(visibility_m=200.0)
    assert model.step(T0, rng)[0].value == pytest.approx(200.0)
    model.sensor_failed = True
    assert model.step(T0, rng) == ()


def test_lte_quota_is_consumed_only_when_the_link_carries_traffic():
    model = LteModel(quota_gb=10.0)
    model.carry(bytes_=10**9)
    assert model.quota_used_pct() == pytest.approx(10.0)


def test_events_are_applied_at_their_timestamp_not_before():
    result = run(SCENARIO_WITH_CUT_AT_60S, selector=greedy, seed=1)
    assert result.timeline_at(59).link_up("fiber0") is True
    assert result.timeline_at(61).link_up("fiber0") is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/sim -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sim'`

- [ ] **Step 3: Implement the models and the event loop**

The loop is deterministic given a seed: one seeded `random.Random` per run, no global randomness, no wall-clock reads. Time advances in fixed `step_s` increments so runs are reproducible and comparable across selectors.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/sim -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add sim tests/sim
git commit -m "feat(sim): seeded link failure models and deterministic event loop"
```

---

### Task 12: Baselines, metrics and the comparison report

**Files:**
- Create: `sim/selectors.py`, `sim/metrics.py`, `sim/report.py`, `sim/scenarios/*.json`
- Modify: `NEGATIVE_RESULTS.md`
- Test: `tests/sim/test_selectors.py`, `tests/sim/test_comparison.py`

**Interfaces:**
- Consumes: Task 11 and the decision core.
- Produces: selectors `greedy(state)`, `static_priority(order)(state)`, `hysteresis(dwell_s)(state)`, `governed(store, chain)(state)`, each returning a link id per traffic class; `compare(scenarios, selectors, seeds) -> ComparisonTable`; `render_markdown(table) -> str`.

- [ ] **Step 1: Write the failing test**

```python
def test_governed_never_violates_a_class_requirement_it_was_given():
    table = compare([QUOTA_SCENARIO, REGULATED_SCENARIO], SELECTORS, seeds=range(5))
    assert table.violations("governed") == 0


def test_greedy_beats_governed_on_uptime_somewhere_and_that_is_recorded():
    table = compare([PLAIN_FAILOVER_SCENARIO], SELECTORS, seeds=range(5))
    assert table.downtime("greedy") <= table.downtime("governed")


def test_hysteresis_baseline_actually_damps_flapping():
    table = compare([FLAPPY_SCENARIO], SELECTORS, seeds=range(5))
    assert table.flaps("hysteresis") < table.flaps("greedy")
```

The second test asserts the outcome we expect to lose on. If it ever fails, the honest reading is that the scenario is not a fair one, not that governed selection got better.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/sim/test_comparison.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sim.selectors'`

- [ ] **Step 3: Implement the selectors, metrics and the report**

The `governed` selector runs the real `AgentCycle` against a simulated dataplane, so the comparison exercises the shipping decision path rather than a reimplementation of it. `render_markdown` writes the comparison table used in the results document.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest -q`
Expected: whole suite passes

- [ ] **Step 5: Record the result honestly**

Write the measured comparison into `NEGATIVE_RESULTS.md`, including any scenario where governed selection lost, with the numbers as measured and no rounding in our favour.

- [ ] **Step 6: Commit**

```bash
git add sim tests/sim NEGATIVE_RESULTS.md
git commit -m "feat(sim): baselines, metrics and the governed-vs-greedy comparison"
```

---

## Self-review notes

Spec coverage checked section by section. Section 3 planes map to Tasks 3, 6, 9 and 10. Section 4's five objects are Tasks 1 to 3. Section 5's four messages are Tasks 4 and 5, with the normative document and vectors in Task 4. Section 6's four SDK protocols are Task 7, with adapters in Tasks 8, 9 and 12. Section 7's rig is Tasks 11 and 12, including the falsification requirement. Section 8's three test layers appear as unit tests throughout, property tests in Task 3, and vector-based contract tests in Task 4; the bundle-swap contract test is in Task 9.

Two spec items are deliberately deferred past this plan and are not gaps in it: the QUIC/HTTP3 transport binding, since every message is self-standing and the file-based path exercises the same envelope, and the `ip rule` and mwan3 adapters, which need a Linux host to test honestly and would otherwise ship as untested code.
