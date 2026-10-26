"""
lab/workloads/photo_import.py – Normal-activity workload: photo import.

Copies many large JPEG-like files (1–5 MB random bytes) into
``workload_photo_import/`` simulating a user importing photos from a camera
card to the share.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.photo_import --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
from pathlib import Path

from lab.safety import retry_on_windows_busy
from lab.workloads._base import BaseWorkload, random_bytes

__all__ = ["PhotoImportWorkload", "run"]

_MIN_SIZE = 1024 * 1024      # 1 MB
_MAX_SIZE = 5 * 1024 * 1024  # 5 MB
_BATCH = 5                   # photos per iteration


class PhotoImportWorkload(BaseWorkload):
    """Copies batches of large JPEG-like files into the subfolder."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("photo_import", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._counter = 0

    def _loop(self) -> None:
        """Write one batch of large photo-stub files."""
        for _ in range(_BATCH):
            size = self.rng.randint(_MIN_SIZE, _MAX_SIZE)
            # Minimal JFIF header so the file looks like a JPEG.
            jfif_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + b"JFIF\x00"
            data = jfif_header + random_bytes(size - len(jfif_header), self.rng)
            name = f"IMG_{self._counter:06d}.jpg"
            dest = self.subfolder / name
            try:
                retry_on_windows_busy(lambda p=dest, d=data: p.write_bytes(d))
                self._counter += 1
            except OSError:
                pass


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the photo_import workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    PhotoImportWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Photo import workload")
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
