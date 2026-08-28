"""The Pilotfish SDK: one small surface, deliberately hard to widen.

Everything a consumer needs is here. Nothing else is public. ``PUBLIC_API`` is
checked in a test, so adding a name to this module is a decision somebody has to
make on purpose rather than a side effect of an import.
"""

from pilotfish.core.bundle import PolicyBundle, floor_bundle
from pilotfish.core.decide import ClassEligibility, EligibilityDecision, decide
from pilotfish.core.models import EvidenceSnapshot, Link, LinkType, Observation, TrafficClass
from pilotfish.core.rules import Exclusion, Rule
from pilotfish.sdk.errors import (
    BundleExpired,
    BundleUnverified,
    EnforcementFailed,
    EvidenceStale,
    PilotfishError,
)
from pilotfish.sdk.protocols import (
    DataplaneAdapter,
    ObservationSource,
    PolicyAuthorityClient,
    ReceiptSink,
)

__all__ = [
    "BundleExpired",
    "BundleUnverified",
    "ClassEligibility",
    "DataplaneAdapter",
    "EligibilityDecision",
    "EnforcementFailed",
    "EvidenceSnapshot",
    "EvidenceStale",
    "Exclusion",
    "Link",
    "LinkType",
    "Observation",
    "ObservationSource",
    "PilotfishError",
    "PolicyAuthorityClient",
    "PolicyBundle",
    "ReceiptSink",
    "Rule",
    "TrafficClass",
    "decide",
    "floor_bundle",
]

#: Frozen snapshot of the public surface. Widening it should fail a test first.
PUBLIC_API = frozenset(__all__) | {"PUBLIC_API"}
