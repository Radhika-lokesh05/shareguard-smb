"""
lab/workloads/_base.py – Shared base class and helpers for workload scripts.

Every workload inherits :class:`BaseWorkload` and implements :meth:`_loop`.
The base class handles:

* Creating and cleaning up the ``workload_<name>/`` subfolder.
* Running the loop for exactly *duration* seconds.
* Thread-safe shutdown on ``KeyboardInterrupt``.

⚠️  LAB ONLY – never import from production code.
"""

from __future__ import annotations

import abc
import random
import time
from pathlib import Path

from lab.safety import check_safety, retry_on_windows_busy

__all__ = ["BaseWorkload", "human_pause", "random_bytes", "random_text"]

# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------


def human_pause(min_s: float = 0.05, max_s: float = 0.3, rng: random.Random | None = None) -> None:
    """Sleep for a random duration that mimics a human think-time.

    Args:
        min_s: Minimum sleep duration in seconds.
        max_s: Maximum sleep duration in seconds.
        rng: Optional :class:`random.Random` instance for reproducibility.
    """
    r = rng or random
    time.sleep(r.uniform(min_s, max_s))


def random_bytes(size: int, rng: random.Random | None = None) -> bytes:
    """Return *size* random bytes.

    Args:
        size: Number of bytes.
        rng: Optional :class:`random.Random` instance.
    """
    r = rng or random
    return bytes(r.getrandbits(8) for _ in range(size))


def random_text(lines: int = 10, rng: random.Random | None = None) -> str:
    """Return a block of random-looking ASCII text with *lines* lines.

    Args:
        lines: Number of text lines to generate.
        rng: Optional :class:`random.Random` instance.
    """
    r = rng or random
    words = [
        "report", "summary", "update", "review", "draft", "final",
        "budget", "plan", "schedule", "meeting", "project", "alpha",
        "data", "analysis", "output", "result", "notes", "action",
    ]
    result: list[str] = []
    for _ in range(lines):
        n = r.randint(5, 12)
        result.append(" ".join(r.choices(words, k=n)))
    return "\n".join(result) + "\n"


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class BaseWorkload(abc.ABC):
    """Abstract base for a normal-activity workload.

    Sub-classes must implement :meth:`_loop` which is called repeatedly
    until *duration* seconds have elapsed.  The subfolder lifecycle
    (create on entry, delete on exit) is handled by :meth:`run`.

    Args:
        name: Workload name used to build the subfolder (``workload_<name>``).
        target: Root target directory (must exist).
        duration: How many seconds to run.
        seed: Optional random seed for reproducibility.
    """

    def __init__(
        self,
        name: str,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        check_safety(target, confirmed=confirmed, require_marker=True, require_manifest=True, config_path=config_path)
        self.name = name
        self.target = target.resolve()
        self.duration = duration
        self.rng = random.Random(seed)
        self.confirmed = confirmed
        self.subfolder: Path = self.target / f"workload_{name}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Create the subfolder, run the workload loop, then clean up."""
        self.subfolder.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.duration
        try:
            while time.monotonic() < deadline:
                self._loop()
        finally:
            self._cleanup()

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def _loop(self) -> None:
        """Perform one iteration of work.  Called in a tight loop until deadline."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        """Recursively delete *self.subfolder* if it still exists."""
        if self.subfolder.exists():
            for child in sorted(self.subfolder.rglob("*"), reverse=True):
                if child.is_file():
                    try:
                        retry_on_windows_busy(lambda p=child: p.unlink(missing_ok=True))
                    except OSError:
                        pass
                elif child.is_dir():
                    try:
                        retry_on_windows_busy(lambda p=child: p.rmdir() if p.exists() else None)
                    except OSError:
                        pass
            try:
                retry_on_windows_busy(lambda: self.subfolder.rmdir() if self.subfolder.exists() else None)
            except OSError:
                pass

    def _tmp_path(self, name: str) -> Path:
        """Return a path inside *self.subfolder*, creating parents as needed."""
        p = self.subfolder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
