"""Canonical CBOR encoding.

Deterministic encoding is not a detail here. Two parties must be able to compute
the same bytes from the same values, or every signature and every hash in the
system becomes a coin toss.
"""

from __future__ import annotations

from typing import Any

import cbor2


def dumps(obj: Any) -> bytes:
    """Encode with canonical rules: sorted map keys, shortest-form integers."""

    return cbor2.dumps(obj, canonical=True)


def loads(data: bytes) -> Any:
    return cbor2.loads(data)
