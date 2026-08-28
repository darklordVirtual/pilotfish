# Pilotfish SURVIVAL invariants

Status: V2 architectural target. Normative for the V2 design; not yet a claim that the current 0.1 implementation satisfies every invariant.

Pilotfish has one operational mode: `SURVIVAL`.

`SURVIVAL` is not an emergency fallback. It is the normal execution model. A node is expected to continue making local, deterministic communications decisions when central authority, management systems, individual bearers, sensors, or network paths are unavailable.

The implementation may expose internal state for diagnosis, but operators do not switch Pilotfish between `normal`, `degraded`, `offline`, or `emergency` modes. Those conditions are inputs to the same control loop.

## 1. Runtime invariants

### S-01. One operational mode

A deployed node MUST operate in `SURVIVAL` from startup until shutdown.

Loss of authority, evidence, a bearer, a sensor, or a management channel MUST NOT require an operator-visible mode transition in order for the node to remain correct.

### S-02. Local decision sovereignty

Correct local operation MUST NOT depend on a synchronous request to a central controller, cloud service, model endpoint, or other remote decision service.

A remote authority MAY provision signed policy and trust material. It MUST NOT sit on the critical path of a bearer decision.

### S-03. Deterministic runtime

The field decision path MUST be deterministic and reproducible from its explicit inputs.

The runtime decision path MUST NOT require an LLM, generative model, remote inference API, or online self-modification.

Given the same policy, trusted evidence, durable state and clock input, the decision engine MUST produce the same eligibility result.

### S-04. Available is not eligible

Physical or protocol availability MUST NOT imply operational eligibility.

A bearer that is reachable, low-latency or otherwise technically healthy MUST still be excluded when current policy, trust, evidence or operational constraints do not permit its use for the relevant traffic class.

### S-05. Local authority may contract, never expand

A node MAY autonomously reduce its permitted action space when evidence becomes stale, unavailable or adverse.

A node MUST NOT autonomously add a bearer, traffic permission, trust relationship or authority that was not already permitted by its active signed authority envelope.

In set form, if `A` is the centrally authorised bearer set and `L(t)` is the locally eligible set at time `t`, then:

`L(t) ⊆ A`

must hold for every local decision.

### S-06. Absence of evidence is not evidence of safety

Missing, unverifiable, expired or future-invalid evidence MUST NOT be interpreted as a positive observation.

Where a property is required to establish eligibility, loss of acceptable evidence MUST contract the eligible set.

### S-07. Hard constraints dominate optimisation

No performance, bandwidth, latency, cost, energy or convenience score may compensate for violation of a hard policy, trust, security or operational constraint.

Eligibility and optimisation MUST remain separate stages.

### S-08. Safety dominates stability

Stability mechanisms such as hysteresis, minimum dwell time, stickiness and switching cost MAY delay changes made only for performance reasons.

They MUST NOT delay removal of a bearer that has become ineligible under a hard constraint.

### S-09. Decision, execution and effect are distinct

A valid decision is not proof that the dataplane applied it.

An execution attempt is not proof that the intended communications state exists.

Pilotfish MUST preserve separate evidence for:

1. what was permitted or selected;
2. what enforcement was attempted; and
3. what state was authoritatively observed after enforcement.

An effect mismatch MUST enter the self-healing loop rather than being treated as success.

### S-10. Restart does not erase security state

Restart, process replacement or power loss MUST NOT reset rollback protection, receipt continuity, accepted authority epochs, or other durable security state to an unsafe default.

If durable state required for safe recovery is unreadable or internally inconsistent, the node MUST fail in the conservative direction.

### S-11. Component failure must not become system failure by default

Loss of one bearer, sensor, evidence source, management path or authority connection MUST trigger local recomputation and repair where another policy-permitted path remains.

The system MUST be designed to continue useful operation within its remaining authorised envelope.

### S-12. Self-healing is bounded by authority

The runtime MAY autonomously:

- recompute eligibility;
- select another already-authorised bearer;
- retry enforcement safely;
- reconcile the dataplane;
- invalidate stale evidence;
- recover durable state;
- quarantine a failing local adapter or evidence source; and
- resume operation after restart.

The runtime MUST NOT use self-healing as justification to widen authority.

## 2. The continuous control loop

The target runtime is a closed local loop:

```text
SENSE
  ↓
VERIFY EVIDENCE
  ↓
COMPUTE ELIGIBLE BEARERS
  ↓
APPLY HARD CONSTRAINTS
  ↓
STABILISE / SELECT
  ↓
ENFORCE
  ↓
READ BACK ACTUAL STATE
  ↓
VERIFY EFFECT
  ↓
REPAIR OR CONTINUE
  ↺
```

The loop never changes operating mode. The inputs and admissible action set change; the execution contract does not.

## 3. Correctness criterion

For V2, a communications decision is `correct` only when it is all of the following:

```text
authorised
AND evidence-supported
AND currently valid
AND locally enforceable
AND stable under the applicable switching rules
AND effect-verified
```

A fast decision that violates one of these conditions is not correct.

## 4. Relationship to REMORA

Pilotfish inherits REMORA principles as deterministic systems properties rather than as an AI dependency:

- explicit authority boundaries;
- evidence provenance and freshness;
- monotonic narrowing under uncertainty;
- abstention by removing unsupported actions;
- bounded execution;
- separation of attempted execution from verified effect;
- durable audit evidence; and
- negative conformance testing.

No LLM is required in the deployed SURVIVAL runtime.

## 5. Conformance direction

A V2 implementation should eventually prove at least these negative properties:

- no forbidden bearer use;
- no fail-open transition caused by missing evidence;
- no policy widening during authority loss;
- no accepted stale-policy rollback;
- no silent execution/effect mismatch;
- no security-state reset on restart;
- no stability hold that preserves a now-forbidden bearer; and
- no autonomous addition of unknown authority.

These are protocol and system invariants, not performance claims.