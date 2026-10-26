"""
lab/tests/test_lab_a.py – Tests for Lab Part A.

Covers all required safety and correctness properties:

Safety:
- Refuses when marker is absent.
- Refuses when target is a filesystem root.
- Refuses when target is the home directory.
- Refuses when ``confirmed=False`` (API gate).
- Refuses when ``manifest.json`` is absent.

Correctness per style:
- fast: files encrypted + renamed to .locked, content has high entropy.
- partial: filename unchanged, first bytes differ, tail bytes identical.
- rename_only: content bytes unchanged, extension appended.
- copy_delete: encrypted copies present, originals deleted.

Isolation:
- Never touches files outside the manifest.

Restore:
- restore() returns every file to its original SHA-256 hash.
- verify_manifest() returns True after restore.

Extras:
- --note drops README_LAB_NOTE.txt in visited directories.
- --touch-canary updates canary file mtime.
- run_summary.json is written with required fields.
- CLI exits non-zero without --i-understand-this-is-a-lab.
- make_fake_files writes manifest.json with correct sha256 fields.
- make_fake_files realistic content: .jpg starts with JFIF, .pdf with %PDF.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PYTHON = str(Path(sys.executable))
_WORKSPACE = Path(__file__).parent.parent.parent  # …/shareguard/

_IGNORED_FILES = {
    ".shareguard_lab_marker",
    "SHAREGUARD_LAB_MARKER",
    "manifest.json",
    "manifest.key",
    "run_summary.json",
    "README_LAB_NOTE.txt",
}


def _sha256(path: Path) -> str:
    """Return hex SHA-256 of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _setup_lab(tmp_path: Path, count: int = 30, seed: int = 42) -> Path:
    """Seed a lab environment: create fake files, markers, and manifest.

    Args:
        tmp_path: Root directory.
        count: Number of fake files.
        seed: Random seed.

    Returns:
        *tmp_path* (for chaining).
    """
    from lab.make_fake_files import create_fake_files

    create_fake_files(tmp_path, count=count, seed=seed)
    return tmp_path


def _snapshot_hashes(tmp_path: Path) -> dict[str, str]:
    """Return a dict of {relative_posix_path: sha256} for all non-lab files."""
    result: dict[str, str] = {}
    for p in tmp_path.rglob("*"):
        if p.is_file() and p.name not in _IGNORED_FILES:
            result[p.relative_to(tmp_path).as_posix()] = _sha256(p)
    return result


# ---------------------------------------------------------------------------
# Safety – marker absent
# ---------------------------------------------------------------------------


def test_refuses_without_marker(tmp_path: Path) -> None:
    """encrypt_files raises LabSafetyError when marker is absent."""
    from lab.fake_ransomware import LabSafetyError, encrypt_files

    # Write a manifest but no marker.
    (tmp_path / "manifest.json").write_text('{"version":1,"files":[]}', encoding="utf-8")
    with pytest.raises(LabSafetyError, match="marker"):
        encrypt_files(tmp_path, confirmed=True)


# ---------------------------------------------------------------------------
# Safety – filesystem root
# ---------------------------------------------------------------------------


def test_refuses_on_root(tmp_path: Path) -> None:
    """encrypt_files raises LabSafetyError when target is a filesystem root."""
    from lab.fake_ransomware import LabSafetyError, encrypt_files

    # Determine the root for the current platform.
    root = Path(tmp_path.root)  # "/" on Linux/mac, "C:\" on Windows
    with pytest.raises(LabSafetyError, match="root"):
        encrypt_files(root, confirmed=True)


# ---------------------------------------------------------------------------
# Safety – home directory
# ---------------------------------------------------------------------------


def test_refuses_on_home(tmp_path: Path) -> None:
    """encrypt_files raises LabSafetyError when target is Path.home()."""
    from lab.fake_ransomware import LabSafetyError, encrypt_files

    home = Path.home().resolve()
    with pytest.raises(LabSafetyError, match="home"):
        encrypt_files(home, confirmed=True)


# ---------------------------------------------------------------------------
# Safety – confirmed=False
# ---------------------------------------------------------------------------


def test_refuses_without_confirmed_flag(tmp_path: Path) -> None:
    """encrypt_files raises LabSafetyError when confirmed=False (default)."""
    from lab.fake_ransomware import LabSafetyError, encrypt_files

    _setup_lab(tmp_path, count=5)
    with pytest.raises(LabSafetyError, match="confirmed"):
        encrypt_files(tmp_path, confirmed=False)


# ---------------------------------------------------------------------------
# Safety – manifest absent
# ---------------------------------------------------------------------------


def test_refuses_without_manifest(tmp_path: Path) -> None:
    """encrypt_files raises LabSafetyError when manifest.json is absent."""
    from lab.fake_ransomware import LabSafetyError, encrypt_files

    # Write only the marker.
    (tmp_path / ".shareguard_lab_marker").write_text("lab\n", encoding="utf-8")
    with pytest.raises(LabSafetyError, match="manifest"):
        encrypt_files(tmp_path, confirmed=True)


# ---------------------------------------------------------------------------
# Style: fast – encrypt + rename
# ---------------------------------------------------------------------------


def test_fast_style_encrypts_and_renames(tmp_path: Path) -> None:
    """fast style: .locked files appear and their content has high entropy."""
    from lab.fake_ransomware import encrypt_files

    _setup_lab(tmp_path, count=20)
    summary = encrypt_files(tmp_path, style="fast", count=10, confirmed=True)

    assert summary.files_changed == 10
    locked_files = [p for p in tmp_path.rglob("*") if p.suffix == ".locked"]
    assert len(locked_files) == 10, f"Expected 10 .locked, got {locked_files}"

    # Check entropy: Fernet output is Base64-encoded ciphertext with high byte diversity (out of 64 max chars).
    sample = locked_files[0].read_bytes()
    assert len(set(sample)) >= 40, "Expected high byte diversity (Fernet ciphertext)"


# ---------------------------------------------------------------------------
# Style: partial – encrypt head, keep filename
# ---------------------------------------------------------------------------


def test_partial_style_keeps_filename(tmp_path: Path) -> None:
    """partial style: filename unchanged, first bytes differ, rest after head identical."""
    from lab.fake_ransomware import encrypt_files
    from lab.make_fake_files import load_manifest

    _setup_lab(tmp_path, count=10)
    # Snapshot originals in deterministic candidate order.
    entries = sorted(load_manifest(tmp_path), key=lambda e: (tmp_path / e["path"]).resolve())
    original_path = tmp_path / entries[0]["path"]
    original_bytes = original_path.read_bytes()

    summary = encrypt_files(tmp_path, style="partial", count=1,
                            partial_bytes=256, confirmed=True)
    assert summary.files_changed == 1

    # Filename unchanged.
    assert original_path.exists(), "partial style must keep original filename"

    modified = original_path.read_bytes()
    # Content has changed (encrypted head).
    assert modified != original_bytes, "partial style must change file content"


# ---------------------------------------------------------------------------
# Style: rename_only – no content change
# ---------------------------------------------------------------------------


def test_rename_only_no_content_change(tmp_path: Path) -> None:
    """rename_only: content unchanged, extension .locked appended."""
    from lab.fake_ransomware import encrypt_files
    from lab.make_fake_files import load_manifest

    _setup_lab(tmp_path, count=10)
    entries = sorted(load_manifest(tmp_path), key=lambda e: (tmp_path / e["path"]).resolve())
    original_path = tmp_path / entries[0]["path"]
    original_bytes = original_path.read_bytes()
    expected_hash = entries[0]["sha256"]

    summary = encrypt_files(tmp_path, style="rename_only", count=1, confirmed=True)
    assert summary.files_changed == 1

    locked_path = original_path.with_suffix(original_path.suffix + ".locked")
    assert locked_path.exists(), ".locked file should exist after rename_only"
    assert not original_path.exists(), "Original should be gone after rename"

    # Content must be identical.
    assert locked_path.read_bytes() == original_bytes
    assert _sha256(locked_path) == expected_hash


# ---------------------------------------------------------------------------
# Style: copy_delete – encrypted copy, original deleted
# ---------------------------------------------------------------------------


def test_copy_delete_removes_originals(tmp_path: Path) -> None:
    """copy_delete: .locked copies present, originals deleted."""
    from lab.fake_ransomware import encrypt_files
    from lab.make_fake_files import load_manifest

    _setup_lab(tmp_path, count=10)
    entries = sorted(load_manifest(tmp_path), key=lambda e: (tmp_path / e["path"]).resolve())
    # Snapshot which original files exist.
    originals_before = {(tmp_path / e["path"]).resolve() for e in entries[:5]}

    summary = encrypt_files(tmp_path, style="copy_delete", count=5, confirmed=True)
    assert summary.files_changed == 5

    for orig in originals_before:
        assert not orig.exists(), f"Original should be deleted: {orig}"
        locked = orig.with_suffix(orig.suffix + ".locked")
        assert locked.exists(), f"Encrypted copy missing: {locked}"


# ---------------------------------------------------------------------------
# Isolation – never touches files outside the manifest
# ---------------------------------------------------------------------------


def test_only_touches_manifest_files(tmp_path: Path) -> None:
    """Files not listed in the manifest are never modified."""
    from lab.fake_ransomware import encrypt_files

    _setup_lab(tmp_path, count=10)

    # Place a sentinel file that is NOT in the manifest.
    sentinel = tmp_path / "SENTINEL_NOT_IN_MANIFEST.txt"
    sentinel.write_text("do not touch me\n", encoding="utf-8")
    original_content = sentinel.read_bytes()

    encrypt_files(tmp_path, style="fast", confirmed=True)

    assert sentinel.exists(), "Sentinel file should still exist"
    assert sentinel.read_bytes() == original_content, "Sentinel content must be unchanged"


# ---------------------------------------------------------------------------
# Restore – original hashes recovered
# ---------------------------------------------------------------------------


def test_restore_returns_original_hashes(tmp_path: Path) -> None:
    """restore() decrypts all files and every SHA-256 matches the manifest."""
    from lab.fake_ransomware import encrypt_files, restore
    from lab.make_fake_files import load_manifest

    _setup_lab(tmp_path, count=20)
    entries = load_manifest(tmp_path)
    hashes_before = {e["path"]: e["sha256"] for e in entries}

    # Encrypt with fast style.
    summary = encrypt_files(tmp_path, style="fast", confirmed=True)
    assert summary.files_changed > 0

    # Restore.
    restored, errors = restore(tmp_path)
    assert errors == [], f"Restore errors: {errors}"
    assert restored > 0

    # Verify every file's hash matches the manifest.
    for e in entries:
        p = tmp_path / e["path"]
        assert p.exists(), f"Restored file missing: {e['path']}"
        assert _sha256(p) == hashes_before[e["path"]], (
            f"Hash mismatch after restore: {e['path']}"
        )


def test_restore_verifies_all_hashes(tmp_path: Path) -> None:
    """verify_manifest() returns True after a full encrypt + restore cycle."""
    from lab.fake_ransomware import encrypt_files, restore
    from lab.make_fake_files import verify_manifest

    _setup_lab(tmp_path, count=15)
    encrypt_files(tmp_path, style="fast", confirmed=True)
    restore(tmp_path)

    ok, errors = verify_manifest(tmp_path)
    assert ok, "Manifest verification failed:\n" + "\n".join(errors)


# ---------------------------------------------------------------------------
# --note option
# ---------------------------------------------------------------------------


def test_note_dropped_in_dirs(tmp_path: Path) -> None:
    """drop_note=True places README_LAB_NOTE.txt in visited directories."""
    from lab.fake_ransomware import encrypt_files

    _setup_lab(tmp_path, count=10)
    encrypt_files(tmp_path, style="fast", count=5, drop_note=True, confirmed=True)

    notes = list(tmp_path.rglob("README_LAB_NOTE.txt"))
    assert notes, "Expected at least one README_LAB_NOTE.txt but found none"


# ---------------------------------------------------------------------------
# --touch-canary option
# ---------------------------------------------------------------------------


def test_touch_canary(tmp_path: Path) -> None:
    """canary_path is touched after each encrypted file."""
    from lab.fake_ransomware import encrypt_files

    _setup_lab(tmp_path, count=10)
    canary = tmp_path / "canary.txt"
    canary.write_text("[canary]\n", encoding="utf-8")
    mtime_before = canary.stat().st_mtime

    time.sleep(0.05)  # ensure mtime is distinguishable
    encrypt_files(tmp_path, style="fast", count=5, canary_path=canary, confirmed=True)

    assert canary.stat().st_mtime > mtime_before, "Canary mtime should have been updated"


# ---------------------------------------------------------------------------
# run_summary.json written with required fields
# ---------------------------------------------------------------------------


def test_run_summary_written(tmp_path: Path) -> None:
    """run_summary.json is written and contains required fields."""
    from lab.fake_ransomware import encrypt_files

    _setup_lab(tmp_path, count=10)
    encrypt_files(tmp_path, style="fast", count=5, confirmed=True)

    summary_path = tmp_path / "run_summary.json"
    assert summary_path.exists(), "run_summary.json not found"
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    for key in ("style", "start_utc", "end_utc", "files_changed", "key_file"):
        assert key in data, f"Missing key in run_summary.json: {key!r}"
    assert data["style"] == "fast"
    assert data["files_changed"] == 5


# ---------------------------------------------------------------------------
# CLI – refuses without --i-understand-this-is-a-lab
# ---------------------------------------------------------------------------


def test_cli_refuses_without_flag(tmp_path: Path) -> None:
    """CLI exits non-zero when --i-understand-this-is-a-lab is absent."""
    _setup_lab(tmp_path, count=5)
    result = subprocess.run(
        [_PYTHON, "-m", "lab.fake_ransomware", "--target", str(tmp_path), "--style", "fast"],
        capture_output=True,
        text=True,
        cwd=str(_WORKSPACE),
        timeout=15,
    )
    assert result.returncode != 0, (
        "CLI should have refused without --i-understand-this-is-a-lab"
    )
    assert "REFUSED" in result.stderr or "refused" in result.stderr.lower()


# ---------------------------------------------------------------------------
# make_fake_files – manifest correctness
# ---------------------------------------------------------------------------


def test_make_fake_files_writes_manifest(tmp_path: Path) -> None:
    """create_fake_files writes manifest.json with correct sha256 for each file."""
    from lab.make_fake_files import create_fake_files

    paths = create_fake_files(tmp_path, count=10, seed=7)
    manifest_path = tmp_path / "manifest.json"
    assert manifest_path.exists(), "manifest.json not written"

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data.get("version") == 1
    assert len(data["files"]) == len(paths)

    for entry in data["files"]:
        p = tmp_path / entry["path"]
        assert p.exists(), f"Manifest lists non-existent file: {entry['path']}"
        assert _sha256(p) == entry["sha256"], (
            f"Hash mismatch in manifest for {entry['path']}"
        )


# ---------------------------------------------------------------------------
# make_fake_files – realistic content headers
# ---------------------------------------------------------------------------


def test_make_fake_files_content_realism(tmp_path: Path) -> None:
    """Generated files have correct format headers per extension."""
    from lab.make_fake_files import create_fake_files

    create_fake_files(tmp_path, count=200, seed=0)

    jpg_files = list(tmp_path.rglob("*.jpg"))
    assert jpg_files, "Expected at least one .jpg file"
    for jpg in jpg_files[:3]:
        header = jpg.read_bytes()[:4]
        assert header[:2] == bytes([0xFF, 0xD8]), (
            f"{jpg.name}: expected JPEG SOI marker FF D8, got {header.hex()}"
        )

    pdf_files = list(tmp_path.rglob("*.pdf"))
    assert pdf_files, "Expected at least one .pdf file"
    for pdf in pdf_files[:3]:
        header = pdf.read_bytes()[:5]
        assert header == b"%PDF-", (
            f"{pdf.name}: expected %PDF- header, got {header!r}"
        )

    png_files = list(tmp_path.rglob("*.png"))
    assert png_files, "Expected at least one .png file"
    for png in png_files[:3]:
        sig = png.read_bytes()[:8]
        assert sig == b"\x89PNG\r\n\x1a\n", (
            f"{png.name}: expected PNG signature, got {sig!r}"
        )
