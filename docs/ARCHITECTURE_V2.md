# Pilotfish V2 architecture

Status: target architecture for the next major design iteration.

Pilotfish V2 is a deterministic bearer-assurance system for critical communications. Its purpose is not to forward packets or replace an existing routing, multipath or radio stack. Its purpose is to determine which communication bearers are operationally eligible for a traffic class under current authority, evidence and constraints, then verify that the local dataplane actually enforced the resulting decision.

The design assumes hostile conditions: central services may disappear, bearers may fail independently, evidence may become stale, components may restart, and the communications path under governance may be the only path available to recover connectivity.

## 1. Operating model

Pilotfish has one operational mode: `SURVIVAL`.

There is no operator transition between normal, degraded, emergency or offline modes. Those labels encourage multiple execution contracts. V2 instead keeps one contract and changes only the inputs and admissible action set.

The normative runtime invariants are defined in [`SURVIVAL_INVARIANTS.md`](SURVIVAL_INVARIANTS.md).

## 2. Non-goals

Pilotfish V2 does not:

- forward packets;
- implement a radio waveform;
- replace BGP, OSPF, MANET routing, MPTCP, MPQUIC, ATSSS, RAW or an SD-WAN dataplane;
- require a generative AI model at runtime;
- use online learning to modify fielded decision semantics; or
- claim that a signed decision proves the dataplane complied.

Pilotfish supplies a policy- and evidence-bounded eligible bearer set to an existing local scheduler/dataplane and verifies the resulting effect.

## 3. System shape

```text
                   PEACETIME EVOLUTION PLANE
            replay / simulation / falsification / REMORA
                              │
                      signed promotion
                              │
                              ▼
                  VERIFIED SURVIVAL RELEASE
                              │
══════════════════════════════╪══════════════════════════════
                              │
                     FIELD SURVIVAL NODE
                              │
       ┌──────────────────────┴──────────────────────┐
       │                                             │
       │  sensors / local state / signed authority  │
       │                  │                          │
       │                  ▼                          │
       │          Evidence Assurance                 │
       │                  │                          │
       │                  ▼                          │
       │          Bearer Eligibility                 │
       │                  │                          │
       │          eligible bearer set                │
       │                  ▼                          │
       │          Stability Controller               │
       │                  │                          │
       │                  ▼                          │
       │             Scheduler                       │
       │                  │                          │
       │                  ▼                          │
       │         Dataplane Enforcement               │
       │                  │                          │
       │                  ▼                          │
       │       Authoritative Local Readback           │
       │                  │                          │
       │                  ▼                          │
       │           Effect Verification               │
       │                  │                          │
       │            repair if needed                 │
       │                  └───────────────↺          │
       └─────────────────────────────────────────────┘
                    │          │          │
                    ▼          ▼          ▼
                 bearer A   bearer B   bearer C
```

## 4. Bearer, not link

V1 models a fixed set of access-link technologies. V2 generalises the domain to a `Bearer`.

A bearer is any locally addressable communications transport or path that the dataplane can select or exclude.

The core protocol should not require knowledge of the underlying technology. Technology-specific capabilities belong in profiles and evidence.

A future bearer model should support at least:

```text
bearer_id
bearer_type / profile
capabilities
static trust attributes
static policy attributes
required evidence properties
local enforcement identity
```

Profiles may represent optical, cellular, satellite, wired, microwave, radio, mesh or future transports without changing the core eligibility semantics.

## 5. Evidence is a security boundary

V1 already treats a measurement as a value with a timestamp and source. V2 strengthens this into explicit evidence assurance.

A bearer property used in a hard eligibility decision should eventually carry enough information to answer:

- what property is asserted;
- which bearer or path the assertion describes;
- who or what observed it;
- when it was observed;
- when it expires;
- which method or profile produced it;
- what trust or assurance class applies; and
- whether the assertion can be authenticated or attested.

A future normative evidence record should therefore evolve beyond free-text `source` and include a stable source identity and trust semantics.

Loss of acceptable evidence contracts eligibility. It never widens it.

## 6. Eligibility before optimisation

Pilotfish MUST NOT collapse safety, security, reliability and performance into a single scalar score.

The decision pipeline is ordered:

```text
SIGNED AUTHORITY BOUNDARY
          ↓
HARD POLICY / TRUST CONSTRAINTS
          ↓
EVIDENCE SUFFICIENCY
          ↓
ELIGIBLE BEARER SET
          ↓
STABILITY POLICY
          ↓
PERFORMANCE / COST OPTIMISATION
```

A low-latency bearer cannot compensate for violation of a hard constraint.

The output of the eligibility engine is a set, not a winner. Selection within that set belongs to the stability/scheduling layer.

## 7. Stability is a separate control problem

V1 simulation showed that eligibility alone does not eliminate flapping. V2 therefore treats stability as an explicit component below eligibility.

Candidate mechanisms include:

- minimum dwell time;
- switching hysteresis;
- persistent-condition windows;
- switching penalties;
- confidence margins;
- make-before-break where the dataplane supports it; and
- path stickiness where it does not violate a hard constraint.

A hard eligibility removal bypasses performance hysteresis. Stability may delay optimisation; it may not preserve a prohibited bearer.

## 8. Local autonomous authority

A field node receives a signed authority envelope defining the maximum action space it may exercise.

Local autonomy is monotone in the conservative direction:

```text
local_eligible(t) ⊆ authorised_bearers
```

The node may autonomously remove a bearer because evidence expired, a trust condition changed, the bearer failed, or a hard policy constraint became active.

It may not add unknown or unauthorised bearers to recover connectivity.

This property is the V2 replacement for an operator-visible degraded mode.

## 9. Authority loss is ordinary

The authority plane signs and publishes; it does not participate in real-time bearer selection.

A node that loses contact with authority continues to execute the same SURVIVAL control loop using its durable signed authority state and current local evidence.

Where centrally sourced evidence expires, eligibility may contract naturally. The control contract does not change.

The V1 signed floor concept should evolve into a signed survivability envelope rather than a separate operational mode.

## 10. Decision, execution, effect

Pilotfish keeps three distinct claims:

```text
DECISION  what the control system authorised or selected
EXECUTION what the node attempted to configure
EFFECT    what the local dataplane was observed to hold afterwards
```

A mismatch between intended and observed state is a control-loop input.

The system should retry or reconcile safely, verify again, and if enforcement cannot be proven, remove or quarantine the failing local path where policy permits that response.

A cryptographically valid audit trail containing an incorrect dataplane state is not success.

## 11. Self-healing scope

The SURVIVAL runtime is expected to heal within its authority envelope.

It may:

- recompute eligibility after evidence or bearer changes;
- select another authorised bearer;
- retry idempotent enforcement;
- reconcile desired and observed state;
- invalidate stale evidence;
- recover durable anti-rollback and receipt state;
- resume after restart; and
- continue while remote management is unreachable.

It may not:

- generate new execution rules;
- rewrite protocol semantics;
- add new trust roots;
- authorise an unknown bearer; or
- deploy unvalidated code to itself.

## 12. Runtime has no LLM dependency

REMORA informs the architecture, not the field dependency graph.

The deployed node uses deterministic state machines, cryptographic verification, bounded policy evaluation, explicit evidence and local control loops.

LLMs or other learning systems may be used in the peacetime engineering lifecycle to analyse traces, generate candidate changes or help discover failure cases. Such candidates must pass the promotion pipeline defined in [`PEACETIME_EVOLUTION.md`](PEACETIME_EVOLUTION.md).

## 13. V2 trust and key-management work

The current implementation proves message signing and rollback concepts but does not yet define a complete operational key lifecycle.

V2 needs normative handling for:

- key identifiers;
- enrolment;
- rotation;
- revocation;
- authority replacement;
- device compromise recovery;
- trust-domain federation;
- durable trust-store recovery; and
- hardware-backed key profiles where available.

These capabilities should be layered so that Pilotfish can integrate with externally approved communications-security systems rather than claiming to replace them.

## 14. Test and falsification strategy

Pilotfish should be evaluated against strong simpler baselines rather than against deliberately weak alternatives.

At minimum:

```text
static priority
greedy metric selection
hysteresis-based selection
weighted policy selection
multipath / local-repair baseline where practical
```

V2 metrics should include:

- forbidden-bearer use;
- false refusal / unserved traffic;
- switching latency;
- flapping;
- time operating without fresh remote authority;
- stale-evidence acceptance;
- incorrect trust acceptance;
- execution/effect mismatch;
- restart recovery correctness;
- policy rollback acceptance; and
- deterministic decision reproduction.

A result in which Pilotfish loses on availability or cost must be recorded alongside any gain in safety or policy compliance.

## 15. Implementation sequence

### V2.1 — semantic hardening

- retain the V1 protocol as the compatibility baseline;
- fix nonce generation and add negative replay tests;
- introduce the SURVIVAL invariants;
- specify bearer terminology and migration from `Link`;
- specify the authority-envelope model;
- define the separation between eligibility and stability.

### V2.2 — evidence assurance

- stable evidence-source identity;
- expiry and assurance profiles;
- trust semantics;
- source-authentication hooks;
- negative tests for stale, conflicting and untrusted evidence.

### V2.3 — stable autonomous control

- explicit stability controller;
- deterministic selection policy;
- failover and recovery bounds;
- fault-injection and restart tests.

### V2.4 — real dataplane

- Linux network-namespace testbed;
- policy-routing / nftables adapter;
- authoritative readback;
- reproducible multi-bearer emulation with `tc/netem`;
- execution/effect fault injection.

### V2.5 — protocol independence

- independent implementation, preferably in Rust;
- frozen cross-language wire vectors;
- Python ↔ Rust verification;
- parser and protocol fuzzing.

### V2.6 — critical-communications profile

- complete threat model;
- key lifecycle;
- signed release manifests;
- reproducible benchmark corpus;
- implementation profiles for multiple heterogeneous bearers;
- public conformance report that distinguishes proven, observed and unproven claims.

## 16. Definition of success

Pilotfish V2 should not call itself superior because it is more complex.

The target is to demonstrate a bounded domain in which it provides stronger guarantees than ordinary metric-based or priority-based bearer selection.

The minimum intended invariants are:

```text
forbidden bearer transitions = 0
fail-open from missing required evidence = 0
local authority widening = 0
accepted signed-policy rollback = 0
silent decision/effect mismatch = 0
security-state loss on restart = 0
deterministic decision reproduction = 100%
```

False refusal, switching latency, flapping and resource cost remain measured trade-offs and must not be hidden.

That is the standard V2 should be held to.