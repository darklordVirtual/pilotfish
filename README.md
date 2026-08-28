# Pilotfish

Governed access-link selection and traffic routing.

Link selection today is a metric optimisation: pick the path with the best
measured latency or loss, with some hysteresis so it stops flapping. That is a
good answer to the wrong question whenever something other than a metric
constrains the choice. A metered LTE plan with a monthly cap. A contractual SLA.
Traffic that may not cross an unencrypted or foreign path. An FSO hop whose
weather evidence has gone stale.

Those constraints are invisible to a metric. In practice they end up as static
failover priority lists that nobody can audit and that quietly stop matching the
contract they were written for.

Pilotfish makes the constraint side of that decision a first-class,
evidence-bound, auditable object, and leaves the metric side alone.

## How it works

Policy governs which links a traffic class is *permitted* to use. A cheap local
scheduler then chooses freely within that permitted set on ordinary metric
grounds. The expensive, signed, auditable decision is the permission; the
frequent decision is the choice.

Three planes:

- **Authority.** Central. Owns the policy, signs it into a bundle with a hash,
  publishes it. Takes no real-time decisions. No site has to reach it to route a
  packet.
- **Decision.** On each site. Takes the verified bundle and a timestamped
  evidence snapshot, returns one signed decision naming the permitted links per
  class and the reason each excluded link was excluded.
- **Execution.** Local and cheap. A scheduler picks within the permitted set; an
  adapter applies it to the dataplane and reads back what actually landed.

Two properties matter more than the rest:

**Evidence has an age.** A measurement is a value with a timestamp and a source.
Policy can require that FSO is not permitted without a weather observation
younger than ten minutes. As evidence ages past what policy requires, the
permitted set contracts on its own. Absence of evidence is never evidence of
health.

**Fail-closed is not fail-off.** If the bundle is missing, expired or fails
verification, the site falls to a conservative floor policy that is part of its
signed configuration. Traffic keeps flowing; the permitted set becomes the narrow
and defensible one, and every decision taken that way is marked as degraded in
the receipts.

## What this is not

Pilotfish does not forward packets, does not replace a dataplane, does not speak
BGP and is not an SD-WAN product.

## Status

Early, and honest about it. The decision core, the protocol, the agent and the
simulator are implemented and tested. The dataplane adapters that would make this
useful on a real router, `ip rule` and mwan3, are not written: they need a Linux
host to test honestly, and an untested adapter in that layer defeats the
postcondition check that is the point of having one.

The design specification is in
`docs/superpowers/specs/2026-08-28-pilotfish-design.md` and the implementation
plan beside it. Whether governed eligibility actually beats greedy selection is
an open question the simulator in `sim/` exists to answer, and
`NEGATIVE_RESULTS.md` exists to record if it does not.

## Licence

BUSL-1.1, source-available. See `LICENSE`.
