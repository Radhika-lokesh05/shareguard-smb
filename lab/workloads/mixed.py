"""
lab/workloads/mixed.py – Normal-activity workload: concurrent mix.

Runs several workloads simultaneously using :mod:`threading` to produce a
realistic mixture of normal SMB traffic (office edits, bulk copies, and
zip/unzip activity happening at the same time).

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.mixed --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

from lab.workloads._base import BaseWorkload

__all__ = ["MixedWorkload", "run"]

# Which sub-workloads to run concurrently.  Import lazily to keep startup fast.
_SUB_WORKLOAD_NAMES = ["office_edit", "bulk_copy", "zip_unzip"]


class MixedWorkload(BaseWorkload):
    """Runs multiple workloads concurrently in daemon threads."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("mixed", target, duration, seed, confirmed=confirmed, config_path=config_path)

    def _loop(self) -> None:
        # Unused – run() overrides the full execution cycle.
        pass  # pragma: no cover

    def run(self) -> None:
        """Launch sub-workloads in parallel threads and wait for all to finish."""
        import importlib

        self.subfolder.mkdir(parents=True, exist_ok=True)
        threads: list[threading.Thread] = []

        try:
            for i, name in enumerate(_SUB_WORKLOAD_NAMES):
                mod = importlib.import_module(f"lab.workloads.{name}")
                seed_i = (self.rng.getrandbits(32)) ^ i
                t = threading.Thread(
                    target=mod.run,
                    args=(self.target, self.duration),
                    kwargs={"seed": seed_i, "confirmed": self.confirmed},
                    daemon=True,
                    name=f"workload-{name}",
                )
                threads.append(t)
                t.start()

            deadline = time.monotonic() + self.duration
            for t in threads:
                remaining = max(0.0, deadline - time.monotonic())
                t.join(timeout=remaining + 1.0)
        finally:
            self._cleanup()


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the mixed workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    MixedWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Mixed concurrent workload")
    parser.add_argument("--target", required=True)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--i-understand-this-is-a-lab",
        action="store_true",
        dest="confirmed",
        help="Required safety acknowledgement flag",
    )
    args = parser.parse_args()
    run(Path(args.target), args.duration, args.seed, confirmed=args.confirmed)


if __name__ == "__main__":
    main()
