"""
lab/workloads/many_small_files.py – Normal-activity workload: dev-like temp files.

Rapidly creates and deletes many small temporary files inside
``workload_many_small_files/``, mimicking a development build system or
compiler that produces lots of intermediate artifacts.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.many_small_files --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
from pathlib import Path

from lab.safety import retry_on_windows_busy
from lab.workloads._base import BaseWorkload, random_bytes

__all__ = ["ManySmallFilesWorkload", "run"]

_WAVE_SIZE = 100      # files to create per wave
_FILE_SIZE = 256      # bytes per file


class ManySmallFilesWorkload(BaseWorkload):
    """Rapid create/delete of small temp files — dev build simulation."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("many_small_files", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._wave = 0

    def _loop(self) -> None:
        """Create a wave of temp files, then delete them all."""
        wave_dir = self.subfolder / f"wave_{self._wave:06d}"
        wave_dir.mkdir(parents=True, exist_ok=True)

        # Create files.
        paths: list[Path] = []
        for i in range(_WAVE_SIZE):
            ext = self.rng.choice([".o", ".tmp", ".pyc", ".class", ".obj"])
            p = wave_dir / f"tmp_{i:04d}{ext}"
            data = random_bytes(_FILE_SIZE, self.rng)
            try:
                retry_on_windows_busy(lambda path=p, b=data: path.write_bytes(b))
                paths.append(p)
            except OSError:
                pass

        # Delete them all (simulate make clean / cache invalidation).
        for p in paths:
            try:
                retry_on_windows_busy(lambda path=p: path.unlink(missing_ok=True))
            except OSError:
                pass
        try:
            retry_on_windows_busy(lambda: wave_dir.rmdir() if wave_dir.exists() else None)
        except OSError:
            pass

        self._wave += 1


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the many_small_files workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    ManySmallFilesWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Many small files workload")
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
