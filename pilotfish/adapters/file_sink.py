"""An append-only receipt sink backed by a local file.

One base64 line per envelope, so a torn tail from a power cut can be identified
and discarded while the rest of the chain still verifies. This is the default
sink and for most sites it is the only one needed: uplink delivery reads the same
file at its own pace.
"""

from __future__ import annotations

import base64
from pathlib import Path


class FileReceiptSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, receipt_bytes: bytes) -> None:
        with self._path.open("ab") as handle:
            handle.write(base64.b64encode(receipt_bytes) + b"\n")
            handle.flush()

    def read_all(self) -> list[bytes]:
        """Return every complete line. A torn final line is dropped, not guessed at."""

        if not self._path.exists():
            return []
        raw = self._path.read_bytes()
        lines = raw.split(b"\n")
        if raw and not raw.endswith(b"\n"):
            lines = lines[:-1]
        return [base64.b64decode(line) for line in lines if line]


class MemoryReceiptSink:
    """For tests and for the simulator, where writing to disk would only slow things down."""

    def __init__(self) -> None:
        self.lines: list[bytes] = []

    def append(self, receipt_bytes: bytes) -> None:
        self.lines.append(receipt_bytes)

    def read_all(self) -> list[bytes]:
        return list(self.lines)
