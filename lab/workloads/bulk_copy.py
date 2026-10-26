"""
lab/workloads/bulk_copy.py – Normal-activity workload: bulk file copy.

Copies thousands of small files into ``workload_bulk_copy/`` without
performing any renames.  This mimics a user copying a folder of documents
to the share.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.bulk_copy --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
import time
from pathlib import Path

from lab.workloads._base import BaseWorkload, random_bytes

__all__ = ["BulkCopyWorkload", "run"]

_BATCH_SIZE = 50          # files per iteration
_FILE_SIZE = 1024         # bytes per source file


class BulkCopyWorkload(BaseWorkload):
    """Copies batches of small files from a temp source into the subfolder."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("bulk_copy", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._src_dir: Path | None = None
        self._src_files: list[Path] = []
        self._counter = 0

    def run(self) -> None:
        """Seed source files in a temp dir, run copy loop, clean up."""
        self.subfolder.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix="sg_bulk_src_")
        self._src_dir = Path(tmp)
        try:
            # Create _BATCH_SIZE source files to copy repeatedly.
            for i in range(_BATCH_SIZE):
                p = self._src_dir / f"src_{i:04d}.dat"
                p.write_bytes(random_bytes(_FILE_SIZE, self.rng))
                self._src_files.append(p)

            deadline = time.monotonic() + self.duration
            while time.monotonic() < deadline:
                self._loop()
        finally:
            self._cleanup()
            # Remove temp source directory.
            if self._src_dir and self._src_dir.exists():
                shutil.rmtree(self._src_dir, ignore_errors=True)

    def _loop(self) -> None:
        """Copy one batch of source files into the subfolder."""
        batch_dir = self.subfolder / f"batch_{self._counter:06d}"
        batch_dir.mkdir(parents=True, exist_ok=True)
        for src in self._src_files:
            dst = batch_dir / src.name
            shutil.copy2(src, dst)
        self._counter += 1


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the bulk_copy workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    BulkCopyWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Bulk copy workload")
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
