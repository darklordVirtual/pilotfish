import inspect
from datetime import UTC, datetime

import pilotfish.sdk as sdk
from pilotfish.sdk import (
    BundleExpired,
    BundleUnverified,
    DataplaneAdapter,
    EnforcementFailed,
    EvidenceStale,
    ObservationSource,
    PilotfishError,
    PolicyAuthorityClient,
    ReceiptSink,
)

T0 = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def test_public_api_snapshot_is_unchanged():
    """Submodules reachable as attributes are not the surface; everything else is."""
    exported = {
        name
        for name in dir(sdk)
        if not name.startswith("_") and not inspect.ismodule(getattr(sdk, name))
    }
    assert exported == sdk.PUBLIC_API


def test_all_matches_the_snapshot():
    assert set(sdk.__all__) == sdk.PUBLIC_API - {"PUBLIC_API"}


def test_every_error_descends_from_the_one_base():
    for cls in (BundleUnverified, BundleExpired, EvidenceStale, EnforcementFailed):
        assert issubclass(cls, PilotfishError)


def test_a_plain_object_satisfies_the_protocols_structurally():
    class Everything:
        def observe(self, now):
            return ()

        def apply(self, decision):
            return None

        def readback(self):
            return {}

        def append(self, receipt_bytes):
            return None

        def fetch(self):
            return None

    thing = Everything()
    assert isinstance(thing, ObservationSource)
    assert isinstance(thing, DataplaneAdapter)
    assert isinstance(thing, ReceiptSink)
    assert isinstance(thing, PolicyAuthorityClient)


def test_something_missing_readback_is_not_a_dataplane_adapter():
    class HalfAdapter:
        def apply(self, decision):
            return None

    assert not isinstance(HalfAdapter(), DataplaneAdapter)
