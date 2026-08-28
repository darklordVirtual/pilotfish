# Pilotfish

Evidence-bound bearer assurance for resilient communications.

Pilotfish separates two questions that are often collapsed into one:

1. **Is this communications bearer operationally eligible for this traffic now?**
2. **Which eligible bearer should the local dataplane use?**

The first is a policy, trust and evidence problem. The second is a local scheduling problem. Pilotfish owns the first and verifies the result of the second; it does not forward packets itself.

## V2 direction: SURVIVAL

Pilotfish is being evolved from governed access-link selection into a technology-neutral bearer-assurance architecture for critical communications.

The V2 target has one operational mode:

> **SURVIVAL**

A field node is expected to remain locally decision-capable when central authority, management paths, individual bearers, sensors or remote services disappear. The runtime is deterministic and does not depend on an LLM, generative model, cloud inference service or synchronous central controller.

The design rule is simple:

> **Available is not the same as eligible.**

A bearer may be technically healthy and still be excluded because current policy, trust state, evidence freshness or another hard operational constraint does not permit its use for the relevant traffic class.

The normative V2 architectural targets are documented in:

- [`docs/SURVIVAL_INVARIANTS.md`](docs/SURVIVAL_INVARIANTS.md)
- [`docs/ARCHITECTURE_V2.md`](docs/ARCHITECTURE_V2.md)
- [`docs/PEACETIME_EVOLUTION.md`](docs/PEACETIME_EVOLUTION.md)

These documents describe the target architecture. They are not a claim that the current 0.1 implementation already satisfies every V2 invariant.

## Current implementation

The current implementation is an early V1 research prototype for governed link eligibility.

Link selection today is commonly treated as metric optimisation: choose the path with the best measured latency or loss, with hysteresis to reduce flapping. That is incomplete whenever something other than a metric constrains the choice: a quota, a contractual requirement, a security requirement, a jurisdiction constraint, or an FSO path whose environmental evidence has gone stale.

Pilotfish makes those constraints first-class, evidence-bound and auditable while leaving frequent metric scheduling local and cheap.

### Current three-plane design

- **Authority.** Central. Owns policy, signs bundles and publishes them. It takes no real-time forwarding decision and is not required for each local choice.
- **Decision.** Local. Evaluates a verified bundle against timestamped evidence and produces the permitted set per traffic class, including exclusion reasons.
- **Execution.** Local. A scheduler chooses inside the permitted set; an adapter applies the result and reads back what the dataplane actually holds.

Two current properties are intentionally carried into V2:

**Evidence has an age.** A measurement is not just a number. It has a timestamp and a source. Required evidence that becomes stale contracts the permitted set. Missing evidence is never treated as evidence of health.

**Decision is not effect.** A valid decision does not prove the dataplane enforced it. Pilotfish keeps decision, execution and observed effect distinct so a silent enforcement failure is not recorded as success.

## What V2 changes

V2 generalises `Link` into a technology-neutral `Bearer` and separates four concerns explicitly:

```text
signed authority
      ↓
evidence assurance
      ↓
bearer eligibility
      ↓
stability / scheduling
      ↓
existing dataplane
      ↓
authoritative readback
      ↓
effect verification
```

Local autonomy is bounded: a node may remove actions from its authorised set as evidence worsens, but it may not invent new authority to restore connectivity.

Self-healing therefore means recomputing eligibility, selecting another already-authorised bearer, reconciling the dataplane, recovering durable state and continuing without central control. It does not mean online self-modification.

## Peacetime improvement, frozen field runtime

Pilotfish deliberately separates engineering-time self-improvement from field adaptation.

During controlled development, telemetry, receipts, simulation, counterfactual replay and REMORA-style falsification may be used to propose better policies, thresholds, schedulers or code. LLMs or optimisation tools may assist that engineering loop.

A candidate improvement does not deploy itself. It must pass replay, simulation, negative conformance, security testing and signed promotion before becoming a new SURVIVAL release.

The deployed runtime adapts decisions to the world while executing a previously verified implementation and authority envelope.

## What this is not

Pilotfish does not:

- forward packets;
- implement a radio waveform;
- replace a routing or multipath protocol;
- require a central decision service;
- require an LLM in the field;
- use online learning to widen its authority; or
- claim that signing a decision proves successful enforcement.

The intended role is an assurance layer above heterogeneous communications transports and below mission or service policy.

## Status

Early, and intentionally conservative about claims.

The V1 decision core, protocol, local agent and simulator are implemented and tested. Real dataplane adapters that would make the system useful on a production router are not yet implemented; current adapters are deliberately limited because an untested enforcement layer would undermine the postcondition guarantee.

The current normative V1 wire protocol remains in [`spec/protocol.md`](spec/protocol.md). V2 is a target architecture and will become normative only as implementation, tests and conformance vectors catch up.

The simulator exists to falsify the hypothesis as much as to support it. [`NEGATIVE_RESULTS.md`](NEGATIVE_RESULTS.md) records measured losses and limitations rather than hiding them.

## Licence

BUSL-1.1, source-available. See `LICENSE`.
