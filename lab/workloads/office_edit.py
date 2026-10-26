"""
lab/workloads/office_edit.py – Normal-activity workload: office file editing.

Simulates a user opening, editing, and saving small text/document stubs with
human-like pauses.  All files are created inside ``workload_office_edit/``
and removed on exit.

⚠️  LAB ONLY – never import from production code.

Usage::

    python -m lab.workloads.office_edit --target /mnt/share --duration 120
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from lab.safety import retry_on_windows_busy
from lab.workloads._base import BaseWorkload, human_pause, random_text

__all__ = ["OfficeEditWorkload", "run"]

_EXTENSIONS = [".txt", ".docx", ".odt", ".pptx", ".xlsx"]
_NUM_FILES = 20


class OfficeEditWorkload(BaseWorkload):
    """Simulates office editing: create → read → edit → save small files."""

    def __init__(
        self,
        target: Path,
        duration: float,
        seed: int | None = None,
        confirmed: bool = False,
        config_path: Path | None = None,
    ) -> None:
        super().__init__("office_edit", target, duration, seed, confirmed=confirmed, config_path=config_path)
        self._files: list[Path] = []
        self._iteration = 0

    def run(self) -> None:
        """Seed files, then run edit loop, then clean up."""
        self.subfolder.mkdir(parents=True, exist_ok=True)
        # Create initial set of files.
        for i in range(_NUM_FILES):
            ext = self.rng.choice(_EXTENSIONS)
            p = self.subfolder / f"doc_{i:03d}{ext}"
            text = random_text(rng=self.rng)
            retry_on_windows_busy(lambda path=p, t=text: path.write_text(t, encoding="utf-8"))
            self._files.append(p)

        deadline = time.monotonic() + self.duration
        try:
            while time.monotonic() < deadline:
                self._loop()
        finally:
            self._cleanup()

    def _loop(self) -> None:
        """Pick a random file, read it, append a line, save."""
        if not self._files:
            return
        p = self.rng.choice(self._files)
        if p.exists():
            try:
                content = retry_on_windows_busy(lambda: p.read_text(encoding="utf-8"))
                content += random_text(lines=1, rng=self.rng)
                retry_on_windows_busy(lambda: p.write_text(content, encoding="utf-8"))
            except OSError:
                pass
        human_pause(0.05, 0.3, self.rng)
        self._iteration += 1


def run(
    target: Path,
    duration: float,
    seed: int | None = None,
    confirmed: bool = False,
    config_path: Path | None = None,
) -> None:
    """Run the office_edit workload for *duration* seconds against *target*.

    Args:
        target: Root directory of the share.
        duration: How many seconds to run.
        seed: Optional random seed.
        confirmed: Safety confirmation flag.
        config_path: Optional custom config path.
    """
    OfficeEditWorkload(target, duration, seed, confirmed=confirmed, config_path=config_path).run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="[LAB] Office edit workload")
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
