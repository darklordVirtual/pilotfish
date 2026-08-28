# Negative results

Results that did not go our way, recorded as measured. Nothing here is rounded in
our favour, and nothing is omitted because it was inconvenient.

## The hypothesis under test

Governed link eligibility is expected to pay for itself in quota-constrained and
regulated scenarios, and to lose to greedy metric selection on plain uptime
during ordinary failover. Section 7.3 of the design specification commits us to
publishing that loss.

## Comparison run, 2026-08-28, after the review hardening

Five scenarios, four selectors, five seeds each, 3600 simulated seconds per run
at a 30 second step. Reproduce with:

```
python -c "from sim.report import compare, render_markdown; from sim.scenarios import ALL_SCENARIOS; print(render_markdown(compare(ALL_SCENARIOS, seeds=range(5))))"
```

Measures are summed over the five seeds. A violation is one traffic class in one
step sent somewhere its stated requirement forbade, judged by an oracle that
reads the simulator's true state and never consults the policy engine. "Link
down" counts class-seconds where the chosen link was actually dead. "Refused" is
separate on purpose: class-seconds where policy permitted nothing, so the site
declined to carry traffic it could physically have carried.

### plain-failover

| selector | violations | link down (s) | refused (s) | flaps | overage cost | degraded (s) |
|---|---:|---:|---:|---:|---:|---:|
| greedy | 0 | 0 | 0 | 0 | 0.00 | 0 |
| static_priority | 400 | 0 | 0 | 30 | 0.00 | 0 |
| hysteresis | 0 | 0 | 0 | 0 | 0.00 | 0 |
| governed | 0 | 0 | 0 | 0 | 0.00 | 0 |

### quota-squeeze

| selector | violations | link down (s) | refused (s) | flaps | overage cost | degraded (s) |
|---|---:|---:|---:|---:|---:|---:|
| greedy | 1315 | 0 | 0 | 30 | 113.16 | 0 |
| static_priority | 1815 | 0 | 0 | 30 | 168.36 | 0 |
| hysteresis | 1315 | 0 | 0 | 30 | 113.16 | 0 |
| governed | 0 | 0 | 21000 | 30 | 0.00 | 0 |

### regulated-health-traffic

| selector | violations | link down (s) | refused (s) | flaps | overage cost | degraded (s) |
|---|---:|---:|---:|---:|---:|---:|
| greedy | 600 | 0 | 0 | 30 | 0.00 | 0 |
| static_priority | 800 | 0 | 0 | 30 | 0.00 | 0 |
| hysteresis | 600 | 0 | 0 | 30 | 0.00 | 0 |
| governed | 0 | 0 | 18000 | 30 | 0.00 | 0 |

### flapping-fso

| selector | violations | link down (s) | refused (s) | flaps | overage cost | degraded (s) |
|---|---:|---:|---:|---:|---:|---:|
| greedy | 0 | 0 | 0 | 420 | 0.00 | 0 |
| static_priority | 0 | 0 | 0 | 0 | 0.00 | 0 |
| hysteresis | 0 | 0 | 0 | 210 | 0.00 | 0 |
| governed | 0 | 0 | 0 | 420 | 0.00 | 0 |

### authority-blackout

| selector | violations | link down (s) | refused (s) | flaps | overage cost | degraded (s) |
|---|---:|---:|---:|---:|---:|---:|
| greedy | 0 | 0 | 0 | 0 | 0.00 | 0 |
| static_priority | 400 | 0 | 0 | 30 | 0.00 | 0 |
| hysteresis | 0 | 0 | 0 | 0 | 0.00 | 0 |
| governed | 0 | 0 | 9300 | 45 | 0.00 | 7650 |

## What this says

**Where it pays.** In the two scenarios with a constraint a metric cannot see,
governed selection removed every violation: 1315 down to 0 under quota pressure,
600 down to 0 for regulated health traffic, against baselines that are otherwise
perfectly reasonable. Overage cost went from 113.16 to nothing, because the
policy refused a spent allowance rather than quietly paying for it.

**What it cost.** The price is stated in the "refused" column and it is not
small: 21000 class-seconds under quota pressure, 18000 for the regulated
scenario. The site declined to carry traffic it was physically able to carry.
Whether that is the right trade is a question about the contract and the
regulation, not about the software, and anyone deploying this should read those
numbers as the actual cost of compliance rather than as a defect.

**Where it loses, or fails to help.**

Plain failover: greedy and governed tie at zero violations and zero unserved
seconds. Governance bought nothing here. This is the expected result and it is
the honest reading of the common case: if no constraint applies beyond keeping
packets moving, a good metric selector is already correct.

Flapping: governed flapped 420 times, identical to greedy, and twice as much as
the hysteresis baseline at 210. Eligibility is not hysteresis and does not
pretend to be. A deployment that cares about flapping still needs a damped
scheduler inside the permitted set; the two-layer design allows that, but this
implementation does not provide it.

Authority blackout: the site spent 7650 class-seconds degraded and refused 9300,
having fallen to the floor policy when its bundle aged out. It violated nothing,
which is what fail-closed is supposed to buy. Greedy sailed through the same
scenario with no unserved seconds at all and also violated nothing, because this
particular scenario contains no constraint for it to breach. That is a fair loss
and it is recorded as one.

## Change from the first run

The first published run reported 13950 refused class-seconds in the authority
blackout scenario. It is 9300 here. The floor policy at the time carried a single
generic traffic class, and the simulator mapped the site's real classes on to it,
which refused more traffic than the floor actually required. The floor is now
signed per site and carries the site's own classes, so the number fell.

Making that change also exposed a defect worth recording: the earlier floor
dropped the jurisdiction and encryption requirements of the classes it governed.
A site running degraded would have kept its metered-path refusal while quietly
losing its regulatory constraints, which is fail-open wearing the name of
fail-closed. The floor now carries every constraint a class declares, and a
conformance test holds it there.

## What is not measured

The simulator does not model per-flow behaviour, TCP dynamics, partial
degradation under load, or the operational cost of running an authority. The
violation counts are class-steps, not bytes or users affected, so they measure
frequency rather than harm.

There is no cost model yet, so "zero violations" and "21000 refused seconds"
cannot be weighed against each other. Until there is one, the table reports both
and takes no view on which deployment should prefer which.
