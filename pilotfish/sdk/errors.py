"""Typed errors.

Three of these are not faults. A bundle that fails to verify, a bundle that has
expired, and evidence that has aged past what policy requires are all inputs to
the decision: they yield a narrower permitted set and a stated reason. They are
raised where a caller asked for something specific and cannot be given it, and
they are caught by the agent cycle, which continues on the floor policy.

Only :class:`EnforcementFailed` is an operational fault. It means the decision
stands and reality disagrees with it, which nothing downstream can compensate
for and which must be raised loudly.
"""

from __future__ import annotations


class PilotfishError(Exception):
    """Base for everything this library raises deliberately."""


class BundleUnverified(PilotfishError):
    """A policy bundle did not verify under the trusted authority key."""


class BundleExpired(PilotfishError):
    """A policy bundle is outside its validity window."""


class EvidenceStale(PilotfishError):
    """Evidence required by policy is older than policy permits."""


class EnforcementFailed(PilotfishError):
    """The dataplane did not accept, or did not keep, what was decided."""
