"""The durable high-water mark for accepted policy.

Rollback protection that lives in process memory protects a site for exactly as
long as nobody restarts it. That is not a security property: an attacker who can
cause a restart, or simply wait for one, gets the rollback back, and a power cut
is enough.

So the highest accepted authority sequence is written down, atomically, before
the bundle carrying it takes effect.

On the nonce question, stated explicitly because it is a design choice rather
than an oversight: with a durable, strictly increasing sequence, replaying an
envelope is refused by the sequence check alone, since a replayed bundle can
never carry a number higher than the one already recorded. The in-process nonce
set is therefore a redundant second line, useful only against two envelopes
sharing one sequence within a single run, and it deliberately does not grow into
a permanent store. The durable guarantee is the sequence.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol, runtime_checkable

#: Value meaning "no policy has ever been accepted here".
NO_EPOCH = -1


class EpochUnreadable(Exception):
    """The recorded high-water mark exists but cannot be read.

    Treated as fatal rather than as zero. Reading a corrupt mark as "nothing
    accepted yet" would reopen the entire rollback window, which is the one
    outcome this file exists to prevent.
    """


@runtime_checkable
class EpochStore(Protocol):
    """Records the highest authority sequence this site has ever accepted."""

    def read(self) -> int: ...

    def commit(self, sequence: int) -> None: ...


class MemoryEpochStore:
    """For tests and the simulator. Explicitly volatile, and named so."""

    def __init__(self, sequence: int = NO_EPOCH) -> None:
        self._sequence = sequence

    def read(self) -> int:
        return self._sequence

    def commit(self, sequence: int) -> None:
        self._sequence = max(self._sequence, sequence)


class FileEpochStore:
    """The high-water mark as a small file, replaced atomically.

    Written to a temporary file in the same directory and moved into place, so a
    crash mid-write leaves either the old mark or the new one, never a truncated
    number that would read as a lower epoch.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def read(self) -> int:
        if not self._path.exists():
            return NO_EPOCH
        raw = self._path.read_text(encoding="utf-8").strip()
        try:
            return int(raw)
        except ValueError as exc:
            raise EpochUnreadable(f"epoch mark at {self._path} is not a number: {raw!r}") from exc

    def commit(self, sequence: int) -> None:
        if sequence <= self.read():
            return
        handle, temp_path = tempfile.mkstemp(dir=self._path.parent, prefix=".epoch-")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as file:
                file.write(f"{sequence}\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp_path, self._path)
        except BaseException:
            Path(temp_path).unlink(missing_ok=True)
            raise
