# Pilotfish: governed access-link selection and traffic routing

Design specification, 2026-08-28.

## 1. Purpose

Pilotfish applies REMORA's governance model to a different domain: choosing how a
site reaches the internet (fiber, LTE, satellite, free-space optics) and which of
those paths a given class of traffic is permitted to use.

The premise is that link selection today is a metric optimisation. Systems pick the
path with the best measured latency or loss, with some hysteresis to stop it
flapping. That is a good answer to the wrong question in every case where something
other than a metric constrains the choice: a metered LTE plan with a monthly cap, a
contractual SLA, traffic that may not cross an unencrypted or foreign path, an FSO
hop whose weather evidence has gone stale. Those constraints are invisible to a
metric and are usually encoded as static failover priority lists that nobody can
audit and that silently stop matching the contract.

Pilotfish makes the constraint side of that decision a first-class, evidence-bound,
auditable object, and leaves the metric side alone.

Non-goals: Pilotfish does not forward packets, does not replace a dataplane, and
does not attempt to be an SD-WAN product. It does not speak BGP and does not
negotiate routes with peers.

## 2. Deployment shape

A central policy authority serves a fleet of sites. Sites hold local decision
authority and continue to operate correctly while the authority is unreachable,
which is the normal condition for a device whose uplinks are the thing being
governed.

## 3. Architecture

Three planes with a hard boundary between them.

### 3.1 Authority plane

Central, one process. It owns the policy, signs it into a policy bundle with a
bundle hash, and publishes it. It takes no real-time decisions. No site is ever
required to reach it in order to route a packet. It receives receipts and verifies
chains, but reception is after the fact and does not gate operation.

### 3.2 Decision plane

On each site, local. Inputs are the current verified bundle and an evidence
snapshot of the links, where every measurement carries a timestamp and a source.
Output is one signed `EligibilityDecision`: per traffic class, the set of permitted
links, the excluded links each with the rule that excluded it and the evidence it
was excluded on, a valid-until time, the bundle hash, and the evidence hash.

This is the expensive, auditable layer. It runs on evidence change or on expiry,
never per packet.

### 3.3 Execution plane

Local and cheap. A scheduler picks freely among the permitted links on pure metric
grounds and an adapter translates that into what the dataplane actually does. The
scheduler's only governed obligation is to stay inside the permitted set, and that
it did so is verifiable after the fact.

### 3.4 Two consequences

**Evidence has an age.** A measurement is not a value; it is a value with a
timestamp and a source. Policy can require that FSO is not permitted for a class
without a weather observation younger than ten minutes. As evidence ages past what
policy requires, the permitted set contracts on its own. That is abstention,
expressed in a form a network operator can read.

**Fail-closed is not fail-off.** If the bundle is missing, expired, or fails
verification, the site falls to degraded mode: a built-in conservative floor policy
that is part of the agent's signed configuration, not a runtime default. Traffic
does not stop; the permitted set becomes the narrow and defensible one. Everything
decided in degraded mode is marked as such in the receipts, so it is visible
afterwards how long a site ran without fresh authority.

## 4. Domain model

Five objects.

**Link.** An access path with a type (`fiber`, `lte`, `satellite`, `fso`) and static
properties policy can reason over: owner, whether it is metered or capped, whether
it is encrypted at the layer below, which jurisdiction traffic crosses. The type is
not a label; it carries the failure model. Fiber fails rarely and totally. LTE
degrades with load and quota. Satellite has a baseline latency floor and weather
sensitivity. FSO fails fast and predictably with visibility.

**Observation.** One measurement: link, quantity, value, timestamp, source. Source
is a first-class field because policy must distinguish "measured by the agent"
from "reported by the operator" from "modelled". An evidence snapshot is a set of
observations with a combined hash.

**TrafficClass.** What policy discriminates on. Named classes with requirements,
not raw DSCP values: acceptable latency, whether the class tolerates a metered
link, constraints on where it may go.

**Rule.** A policy rule that excludes. Rules never admit a link into the set; they
take links out, with a reason. This keeps the decision monotone and explainable:
every link was a candidate, these three were removed, here is why for each.

**EligibilityDecision.** Per traffic class: the permitted set, the exclusions with
rule id and evidence reference, valid-until, bundle hash, evidence hash, and
whether it was taken in degraded mode.

## 5. Protocol

CBOR-encoded messages, each signed in an envelope carrying issuer, timestamp and
nonce. Four messages, all one-directional and self-standing. There is no
request/response pair in the set, because a site may be without connectivity for
hours and must still be correct.

**`POLICY_BUNDLE`** (authority to site). Signed rule set with hash and validity
window. Idempotent, may arrive by any route, verifiable on its own.

**`OBSERVATION_BATCH`** (site to authority). Compressed telemetry. Not required for
operation; it exists for visibility and to feed the rig. It may be dropped freely
when the link is expensive, and the fact that it was dropped is itself an event.

**`DECISION_RECEIPT`** (site to authority). The signed decision, hash-chained to the
previous receipt from the same site. This is the audit trail: append-only, with
contiguous sequence numbers so gaps are visible rather than silent.

**`AUTHORITY_DIRECTIVE`** (authority to site). The one thing that is not policy: an
explicit, time-bounded override for a human who must take a link out now. It is
separate from the bundle precisely because it is an exceptional act that should
stand out in the log.

### 5.1 The envelope is normative

Canonical CBOR rules, field ordering and signature computation are specified in
`spec/` together with test vectors. The Python implementation is tested against the
vectors rather than defining them. This is what allows a Rust agent later without
renegotiation.

Security sits in the message, not the channel. The normative transport binding is
QUIC/HTTP3; a degraded binding works over anything that can move an octet string,
including a satellite backup path or a file carried by hand. A policy bundle that is
only valid while a TLS session stands would be useless in exactly the scenario this
system is built for.

## 6. SDK

One small, stable `pilotfish.sdk`: contract over internal code, typed errors, and
a public API snapshot pinned by a test that CI runs. Four integration points, each a protocol to
implement rather than a class to subclass.

**`ObservationSource`.** Supplies measurements, each with timestamp and source.
Planned sources, none of them written yet: active probing, `/proc` counters, a
modem AT source for LTE signal and quota, a weather source for FSO.

**`DataplaneAdapter`.** Takes a permitted set and makes it real. One method in, and
one method to read back what is actually configured now. The second is not
decoration: without it there is no postcondition, and the postcondition is the part
of the REMORA inheritance that matters most here. A decision that was taken but
never reached the dataplane is among the most common and least visible failures in
this domain. Shipped adapter: no-op, which records what it was told and reports
it back. `ip rule` and mwan3 adapters are planned and not written: both need a
Linux host to test honestly, and an untested adapter in this layer is worse than
no adapter, because a silent failure here is exactly what the postcondition
exists to catch.

**`ReceiptSink`.** Where receipts go. A local append-only file is the default and is
sufficient; uplink delivery is a separate resumable job reading the same file. No
path uses an expensive link synchronously for audit.

**`PolicyAuthorityClient`.** Fetches and verifies the bundle. Verification is not
optional and has no skip flag.

The decision function itself is pure: bundle, evidence snapshot and clock in,
`EligibilityDecision` out. No I/O, no network, no hidden state. This is why the rig
in section 7 can run millions of decisions quickly and why each one is reproducible
from its input.

### 6.1 Errors

Typed and few. The bundle fails verification; the bundle is expired; evidence is
older than policy requires; the adapter failed to enforce. The first three are not
exceptions in the ordinary sense. They are inputs to the decision that yield a
narrower set and a stated reason. Only the fourth is an operational fault: the
decision stands, reality disagrees, and it must be raised loudly.

## 7. Test rig

A discrete-event simulator over the same pure decision function the production path
uses. Not a separate model: because the function is pure, it is literally the same
code.

A scenario is a site configuration, a set of links with failure models, a traffic
mix over classes, and an event trace: fiber cut, fog rolling in over the FSO hop,
LTE quota exhausted on the 20th, satellite obstruction, and above all loss of
contact with the authority, preferably concurrent with something else.

### 7.1 Baselines

Greedy metric selection (always take lowest RTT), static priority list (fiber, then
LTE, then satellite), and hysteresis-based failover as mwan3 actually implements it.
This is an honest comparison: these three are what people run today and they are
good.

### 7.2 What is measured

Not uptime alone, since greedy often wins on uptime. The discriminating measures are
class-requirement violations (traffic that went somewhere policy forbade), cost
under metered usage, flapping, and time spent in degraded mode without harm.

### 7.3 Falsification

The honest hypothesis is narrow: the gain lies in quota-constrained and regulated
scenarios, not in ordinary failover. If governed link selection costs more uptime
than it saves in policy violations, the rig must say so and the result belongs in
`NEGATIVE_RESULTS.md`. That file exists from day one.

## 8. Testing strategy

TDD on the decision core. Three layers:

- Unit tests on the rules.
- Property tests on the decision function: monotonicity, meaning more exclusion
  grounds never yield a larger permitted set; determinism, meaning the same input
  yields a bit-identical decision.
- Contract tests on the protocol against the checked-in test vectors.

One contract test is called out explicitly, by analogy with REMORA's
policy-change-under-review case: the bundle is swapped mid decision cycle, and the
decision must either complete against the bundle it started with or be discarded
cleanly. It must never mix two.

## 9. Repository layout

```
pilotfish/
  core/        pure rules, decision function, models
  protocol/    envelope, CBOR encoding, verification
  sdk/         the four protocols and typed errors
  agent/       the site agent binding it together
  authority/   bundle signing and publication
  adapters/    receipt sinks, no-op dataplane (iprule and mwan3 are planned)
sim/           scenarios, failure models, baselines
spec/          protocol specification and test vectors
docs/
```

Python first. The protocol is specified as a document with test vectors rather than
as whatever the Python happens to do, so a Rust agent can follow later without
anything being torn out. Moving the agent and protocol core to Rust is triggered by
the rig showing the decision model holds, not before.

Licence follows the REMORA pattern: BUSL-1.1, source-available.

## 9a. Revisions after the first external review, 2026-08-28

An external review found that several claims in sections 3 to 6 were true of the
design and not yet of the code. The implementation was corrected rather than the
claims softened, except where noted above as planned work.

- Non-finite measurements are refused at construction. NaN compares false against
  every threshold, so a NaN reading previously satisfied every rule at once.
- Evidence dated further ahead than a fixed skew allowance is discarded before
  any rule reads it, and age never goes negative. A clock running fast could
  otherwise switch abstention off.
- A bundle is bound to its authority and to a monotone sequence, and an envelope
  cannot be replayed. Authenticity is not freshness: a correctly signed older
  policy could previously replace a newer, stricter one.
- The receipt chain recovers its head from the existing log, and refuses a log
  from another site, signed by another key, or with a hole in it.
- Each cycle writes three receipts: what was authorised, what was attempted, and
  what the dataplane was observed to hold, with a hash of that observed state.
- The floor policy is signed by the authority and bound to the site and its link
  inventory, and it keeps every constraint each traffic class declares. Making it
  a real per-class configuration exposed that the earlier floor silently dropped
  jurisdiction and encryption requirements in degraded mode.
- The bundle hash is the hash of the wire encoding. It previously included
  Python's `repr()`, which no second implementation could reproduce.

## 10. Decisions taken during design

- Control plane only, with the simulator in the same repo. Not a dataplane.
- Fleet with central authority; single-site local autonomy as the degraded mode.
- Two layers: policy governs link eligibility, a cheap local scheduler chooses
  within the permitted set.
- Transport-agnostic signed message format, not gRPC or REST over TLS.
- Python first, protocol frozen by test vectors.
