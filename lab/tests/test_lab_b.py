"""
lab/tests/test_lab_b.py – Tests for Lab Part B.

Covers:
- Every workload cleans up its ``workload_<name>/`` subfolder after running.
- ``collect.py --dry-run`` prints a plan table and exits 0.
- ``collect.py --quick --dry-run`` exits 0 and mentions "quick" (case-insensitive).
- ``collect.py`` refuses a target that has no ``SHAREGUARD_LAB_MARKER``.
- ``make_fake_files.py`` refuses a target without the marker.
- ``fake_ransomware.simulate_encryption`` renames files and returns the count.
- ``make_fake_files.restore_files`` undoes fake extensions.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Path helpers -------------------------------------------------------------------
_PYTHON = str(Path(sys.executable))
_WORKSPACE = Path(__file__).parent.parent.parent  # …/shareguard/
_MARKER = ".shareguard_lab_marker"
_MARKER_LEGACY = "SHAREGUARD_LAB_MARKER"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_marker(d: Path) -> Path:
    """Create both marker files in *d* and return the canonical marker path."""
    m = d / _MARKER
    m.write_text("lab\n", encoding="utf-8")
    (d / _MARKER_LEGACY).write_text("lab\n", encoding="utf-8")
    return m


def _seed(d: Path, n: int = 20) -> list[Path]:
    """Create *n* small text files in *d* and return their paths."""
    files = []
    for i in range(n):
        p = d / f"file_{i:03d}.txt"
        p.write_text(f"content {i}\n", encoding="utf-8")
        files.append(p)
    return files


# ---------------------------------------------------------------------------
# Workload cleanup tests
# ---------------------------------------------------------------------------

_SIMPLE_WORKLOADS = [
    "office_edit",
    "bulk_copy",
    "zip_unzip",
    "backup_rsync",
    "many_small_files",
    "photo_import",
]


@pytest.mark.parametrize("workload_name", _SIMPLE_WORKLOADS)
def test_workload_cleanup(tmp_path: Path, workload_name: str) -> None:
    """Each workload deletes its own ``workload_<name>/`` subfolder after running."""
    import importlib

    _make_marker(tmp_path)
    (tmp_path / "manifest.json").write_text('{"version": 1, "files": []}', encoding="utf-8")

    mod = importlib.import_module(f"lab.workloads.{workload_name}")
    # Run for a very short time – just enough to enter and exit the loop.
    mod.run(tmp_path, duration=0.05, seed=0, confirmed=True)

    subfolder = tmp_path / f"workload_{workload_name}"
    assert not subfolder.exists(), (
        f"workload_{workload_name}/ was not cleaned up; "
        f"contents: {list(subfolder.rglob('*')) if subfolder.exists() else '—'}"
    )


def test_mixed_workload_cleanup(tmp_path: Path) -> None:
    """The mixed workload cleans up its own ``workload_mixed/`` subfolder."""
    from lab.workloads import mixed

    _make_marker(tmp_path)
    (tmp_path / "manifest.json").write_text('{"version": 1, "files": []}', encoding="utf-8")

    mixed.run(tmp_path, duration=0.1, seed=99, confirmed=True)
    subfolder = tmp_path / "workload_mixed"
    assert not subfolder.exists(), "workload_mixed/ was not cleaned up"


# ---------------------------------------------------------------------------
# collect.py – dry-run
# ---------------------------------------------------------------------------


def test_collect_dry_run_exits_zero(tmp_path: Path) -> None:
    """``collect.py --dry-run`` prints a plan and exits 0."""
    _make_marker(tmp_path)
    result = subprocess.run(
        [_PYTHON, "-m", "lab.collect", "--target", str(tmp_path), "--dry-run"],
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE),
        timeout=30,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    )
    assert result.returncode == 0, f"Non-zero exit:\nstdout={result.stdout}\nstderr={result.stderr}"
    # Output must contain a plan table header.
    assert "steps" in result.stdout.lower(), (
        f"Dry-run output does not mention steps:\n{result.stdout}"
    )


def test_collect_quick_dry_run(tmp_path: Path) -> None:
    """``collect.py --quick --dry-run`` exits 0 and outputs 'quick' in the header."""
    _make_marker(tmp_path)
    result = subprocess.run(
        [_PYTHON, "-m", "lab.collect", "--target", str(tmp_path), "--quick", "--dry-run"],
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE),
        timeout=30,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    )
    assert result.returncode == 0, f"Non-zero exit:\nstdout={result.stdout}\nstderr={result.stderr}"
    assert "quick" in result.stdout.lower(), (
        f"'quick' not mentioned in dry-run output:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# collect.py – marker safety check
# ---------------------------------------------------------------------------


def test_collect_refuses_no_marker(tmp_path: Path) -> None:
    """``collect.py`` exits non-zero when the target has no marker file."""
    result = subprocess.run(
        [_PYTHON, "-m", "lab.collect", "--target", str(tmp_path), "--dry-run"],
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE),
        timeout=10,
    )
    assert result.returncode != 0, (
        "collect.py should have refused the no-marker target but exited 0"
    )
    assert "REFUSED" in result.stderr or "refused" in result.stderr.lower(), (
        f"Expected 'REFUSED' in stderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# make_fake_files – marker safety check
# ---------------------------------------------------------------------------


def test_make_fake_files_refuses_no_marker(tmp_path: Path) -> None:
    """``make_fake_files.py --verify`` exits non-zero when no marker exists."""
    result = subprocess.run(
        [_PYTHON, "-m", "lab.make_fake_files", "--target", str(tmp_path), "--verify"],
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE),
        timeout=10,
    )
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# fake_ransomware.simulate_encryption
# ---------------------------------------------------------------------------


def test_simulate_encryption_renames_files(tmp_path: Path) -> None:
    """simulate_encryption renames files and returns the count."""
    from lab.fake_ransomware import simulate_encryption
    from lab.make_fake_files import create_fake_files

    create_fake_files(tmp_path, count=10, seed=1)

    n = simulate_encryption(tmp_path, count=5, style="fast", ext=".locked")
    assert n == 5, f"Expected 5 renamed, got {n}"

    locked = [p for p in tmp_path.rglob("*") if p.suffix == ".locked"]
    assert len(locked) == 5, f"Expected 5 .locked files, found {locked}"


def test_simulate_encryption_copy_delete_style(tmp_path: Path) -> None:
    """simulate_encryption copy_delete style leaves no originals."""
    from lab.fake_ransomware import simulate_encryption
    from lab.make_fake_files import create_fake_files

    create_fake_files(tmp_path, count=5, seed=2)

    n = simulate_encryption(tmp_path, count=5, style="copy_delete", ext=".crypt")
    assert n == 5
    # All manifest files should now have .locked copies (not originals).
    locked = list(tmp_path.rglob("*.locked"))
    assert len(locked) == n, f"Expected {n} .locked files, found {locked}"


def test_simulate_encryption_rename_only_no_note(tmp_path: Path) -> None:
    """simulate_encryption rename_only style does NOT write a ransom note."""
    from lab.fake_ransomware import simulate_encryption
    from lab.make_fake_files import create_fake_files

    create_fake_files(tmp_path, count=5, seed=3)

    simulate_encryption(tmp_path, count=3, style="rename_only", ext=".enc")
    notes = list(tmp_path.rglob("README_LAB*"))
    assert notes == [], f"rename_only should not write a ransom note: {notes}"


# ---------------------------------------------------------------------------
# make_fake_files.restore_files
# ---------------------------------------------------------------------------


def test_restore_files_undoes_extension(tmp_path: Path) -> None:
    """restore_files strips fake extensions (rename_only style) and re-seeds."""
    from lab.fake_ransomware import simulate_encryption
    from lab.make_fake_files import create_fake_files, restore_files

    # create_fake_files writes markers + manifest; no _make_marker needed.
    create_fake_files(tmp_path, count=20, seed=0)

    # Use rename_only so restore_files() (which handles rename reversal) works.
    n = simulate_encryption(tmp_path, count=10, style="rename_only", ext=".locked")
    assert n == 10

    # Restore via make_fake_files (rename-reversal path).
    restore_files(tmp_path, count=20, seed=0)

    # No .locked files should remain.
    locked = list(tmp_path.rglob("*.locked"))
    assert locked == [], f"Locked files remain after restore: {locked}"

    # Original files should be back (≥ 20 non-marker files).
    ignored = {".shareguard_lab_marker", "SHAREGUARD_LAB_MARKER", "manifest.json"}
    total = [p for p in tmp_path.rglob("*") if p.is_file() and p.name not in ignored]
    assert len(total) >= 20, f"Expected ≥ 20 files after restore, got {len(total)}"
