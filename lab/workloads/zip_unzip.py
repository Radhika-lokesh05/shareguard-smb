"""
lab/workloads/zip_unzip.py – Normal-activity workload: zip and extract a folder.

Creates a small directory tree inside ``workload_zip_unzip/``, zips it with
the stdlib :mod:`zipfile`, then extracts it again — and repeats until
*duration* elapses.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.zip_unzip --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from lab.safety import retry_on_windows_busy
from lab.workloads._base import BaseWorkload, random_bytes, random_text

__all__ = ["ZipUnzipWorkload", "run"]

_NUM_FILES = 10
_FILE_SIZE = 2048


class ZipUnzipWorkload(BaseWorkload):
    """Zip a folder tree, extract it, repeat — simulating backup/archive activity."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("zip_unzip", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._iteration = 0

    def _loop(self) -> None:
        """Create a fresh source tree, zip it, extract it, delete both."""
        src = self.subfolder / f"tree_{self._iteration:04d}"
        src.mkdir(parents=True, exist_ok=True)

        # Populate the source tree.
        for i in range(_NUM_FILES):
            ext = self.rng.choice([".txt", ".dat", ".csv"])
            f = src / f"file_{i:03d}{ext}"
            if ext == ".txt":
                text = random_text(rng=self.rng)
                retry_on_windows_busy(lambda p=f, t=text: p.write_text(t, encoding="utf-8"))
            else:
                b = random_bytes(_FILE_SIZE, self.rng)
                retry_on_windows_busy(lambda p=f, data=b: p.write_bytes(data))

        archive = self.subfolder / f"archive_{self._iteration:04d}.zip"
        extract = self.subfolder / f"extract_{self._iteration:04d}"

        # Zip.
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for child in src.rglob("*"):
                if child.is_file():
                    zf.write(child, child.relative_to(src))

        # Extract.
        extract.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(extract)

        # Clean up this iteration's artifacts (keep subfolder itself alive).
        for child in sorted(src.rglob("*"), reverse=True):
            if child.is_file():
                try:
                    retry_on_windows_busy(lambda p=child: p.unlink(missing_ok=True))
                except OSError:
                    pass
        try:
            retry_on_windows_busy(lambda: src.rmdir() if src.exists() else None)
        except OSError:
            pass
        try:
            retry_on_windows_busy(lambda: archive.unlink(missing_ok=True))
        except OSError:
            pass
        for child in sorted(extract.rglob("*"), reverse=True):
            if child.is_file():
                try:
                    retry_on_windows_busy(lambda p=child: p.unlink(missing_ok=True))
                except OSError:
                    pass
        try:
            retry_on_windows_busy(lambda: extract.rmdir() if extract.exists() else None)
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
    """Run the zip_unzip workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    ZipUnzipWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Zip/Unzip workload")
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
