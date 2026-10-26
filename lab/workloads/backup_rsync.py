"""
lab/workloads/backup_rsync.py – Normal-activity workload: read-everything backup.

Simulates a backup job: reads every file in the target share once (stat + open),
then writes a single archive copy in ``workload_backup_rsync/``.  Repeats
until *duration* elapses.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.backup_rsync --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
from pathlib import Path

from lab.safety import (
    KEY_FILENAME,
    MANIFEST_FILENAME,
    MARKER_FILENAME,
    MARKER_LEGACY,
    retry_on_windows_busy,
)
from lab.workloads._base import BaseWorkload

__all__ = ["BackupRsyncWorkload", "run"]

_SKIP_NAMES = {
    MARKER_FILENAME,
    MARKER_LEGACY,
    MANIFEST_FILENAME,
    KEY_FILENAME,
    "run_summary.json",
    "README_LAB_NOTE.txt",
    "labels.csv",
}


class BackupRsyncWorkload(BaseWorkload):
    """Simulates a backup: full read of the share, single archive write."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("backup_rsync", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._iteration = 0

    def _loop(self) -> None:
        """Read every file in target once, write a concatenated archive."""
        archive_name = f"backup_{self._iteration:04d}.bak"
        archive_path = self.subfolder / archive_name

        collected: list[bytes] = []
        for p in sorted(self.target.rglob("*")):
            if not p.is_file():
                continue
            if p.name in _SKIP_NAMES or p.name.startswith(("__sg_start_", "__sg_end_")):
                continue
            # Skip our own subfolder files to avoid reading what we just wrote.
            try:
                p.relative_to(self.subfolder)
                continue  # inside our own subfolder
            except ValueError:
                pass
            try:
                data = retry_on_windows_busy(p.read_bytes)
                collected.append(data)
            except OSError:
                pass

        try:
            retry_on_windows_busy(lambda: archive_path.write_bytes(b"\n".join(collected)))
        except OSError:
            pass
        self._iteration += 1


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the backup_rsync workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    BackupRsyncWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Backup/rsync workload")
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
