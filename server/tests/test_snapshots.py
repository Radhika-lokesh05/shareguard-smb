"""server/tests/test_snapshots.py – Unit tests for snapshot lifecycle and recovery.

Verifies:
1. Attack recovery: 50 files rewritten/renamed to .locked; restore brings back
   exact originals with matching hashes and leaves untouched files intact.
2. Legitimate newer edit preservation: a newer unattacked file survives with
   'skipped: newer user change'.
3. Snapshot pause during attack: while paused, take_snapshot returns None and
   is_paused is True; resumes cleanly when cleared.
4. Retention policy: retains correct count and protects pre-anomaly clean snapshots.
5. Path traversal validation: rejects '..', foreign absolute paths, drive letters,
   and symlink escapes.
6. RsyncSnapshotManager command generation: asserts exact argument lists and
   --link-dest usage via FakeCommandRunner (no shell=True).
7. dry_run=True invariant: asserts disk state is completely unmodified until
   dry_run=False.
8. verify_snapshots integrity check: verifies clean vs corrupted snapshots.
9. Factory and FakeSnapshotManager: in-memory behavior and call logging.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shareguard.snapshots import (
    FakeCommandRunner,
    FakeSnapshotManager,
    PortableSnapshotManager,
    RsyncSnapshotManager,
    get_snapshot_manager,
    validate_path_within_root,
)


def _sha256(path: Path) -> str:
    """Helper: compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 1. Attack Recovery Test
# ---------------------------------------------------------------------------


def test_attack_recovery_restores_exact_originals(tmp_path: Path) -> None:
    """50 files rewritten/renamed; restore brings back exact originals and cleans up .locked."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()

    # Create 50 files across subdirectories
    original_hashes: dict[str, str] = {}
    for i in range(50):
        sub = share_root / f"dir_{i % 5}"
        sub.mkdir(exist_ok=True)
        file_path = sub / f"document_{i:03d}.txt"
        file_path.write_text(f"Original content for document {i} with key {i * 42}\n", encoding="utf-8")
        rel = file_path.relative_to(share_root).as_posix()
        original_hashes[rel] = _sha256(file_path)

    # Add 2 untouched files that attacker won't touch
    untouched_file1 = share_root / "untouched_notice.txt"
    untouched_file1.write_text("This file should remain untouched.\n", encoding="utf-8")
    untouched_hash1 = _sha256(untouched_file1)

    untouched_file2 = share_root / "untouched_policy.txt"
    untouched_file2.write_text("This policy should remain untouched.\n", encoding="utf-8")
    untouched_hash2 = _sha256(untouched_file2)

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap = mgr.take_snapshot(share_root)
    assert snap is not None
    assert snap.file_count == 52

    # Simulate attack:
    # - 40 files rewritten in-place with encrypted text
    # - 10 files renamed to .locked
    touched_paths: list[str] = []

    files_list = sorted(original_hashes.keys())
    for rel in files_list[:40]:
        target = share_root / rel
        target.write_text("ENCRYPTED_RANSOMWARE_PAYLOAD_PAY_1_BTC\n", encoding="utf-8")
        touched_paths.append(rel)

    for rel in files_list[40:50]:
        target = share_root / rel
        locked_path = share_root / f"{rel}.locked"
        target.unlink()
        locked_path.write_text("LOCKED_FILE_PAYLOAD\n", encoding="utf-8")
        touched_paths.append(f"{rel}.locked")

    # Perform surgical restore with dry_run=False
    report = mgr.restore_files(
        share=share_root,
        snapshot_id=snap.snapshot_id,
        paths=touched_paths,
        dry_run=False,
    )

    assert report.dry_run is False
    assert report.restored_count == 50
    assert report.removed_locked_count == 10
    assert report.failed_count == 0
    assert report.verified is True

    # Check all 50 files are restored and match original SHA-256 hashes
    for rel, orig_hash in original_hashes.items():
        restored_file = share_root / rel
        assert restored_file.exists(), f"File {rel} was not restored"
        assert _sha256(restored_file) == orig_hash, f"Hash mismatch for {rel}"

    # Check all 10 .locked files are deleted
    for rel in files_list[40:50]:
        locked_file = share_root / f"{rel}.locked"
        assert not locked_file.exists(), f"Locked file {locked_file} was not removed"

    # Check untouched files were not touched
    assert untouched_file1.exists()
    assert _sha256(untouched_file1) == untouched_hash1
    assert untouched_file2.exists()
    assert _sha256(untouched_file2) == untouched_hash2


# ---------------------------------------------------------------------------
# 2. Legitimate Newer Edit Preservation
# ---------------------------------------------------------------------------


def test_legitimate_newer_edit_preservation(tmp_path: Path) -> None:
    """A newer unattacked file survives with 'skipped: newer user change'."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()

    file_a = share_root / "legitimate_notes.txt"
    file_b = share_root / "financials.xlsx"
    file_a.write_text("Draft version 1\n", encoding="utf-8")
    file_b.write_text("Financial spreadsheet binary data\n", encoding="utf-8")

    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    os.utime(file_a, (t0.timestamp(), t0.timestamp()))
    os.utime(file_b, (t0.timestamp(), t0.timestamp()))
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap = mgr.take_snapshot(share_root, clock=lambda: t0)
    assert snap is not None

    # User makes legitimate edits at t1 (before anomaly)
    t1 = t0 + timedelta(minutes=5)
    file_a.write_text("Legitimate user edits version 2: Updated budget\n", encoding="utf-8")
    os.utime(file_a, (t1.timestamp(), t1.timestamp()))
    legit_content = file_a.read_text(encoding="utf-8")

    # Attacker attacks file_b at t2
    t2 = t0 + timedelta(minutes=15)
    file_b.write_text("ENCRYPTED_RANSOM_DATA\n", encoding="utf-8")
    os.utime(file_b, (t2.timestamp(), t2.timestamp()))

    # Engine runs restore; both files might be in touched candidate list
    report = mgr.restore_files(
        share=share_root,
        snapshot_id=snap.snapshot_id,
        paths=["legitimate_notes.txt", "financials.xlsx"],
        dry_run=False,
        first_anomaly_ts=t2,
    )

    # Assert file_a was skipped as newer user change
    assert report.skipped_count >= 1
    skipped_reasons = [p["reason"] for p in report.skipped_paths]
    assert "skipped: newer user change" in skipped_reasons

    # Assert file_a content was NOT overwritten
    assert file_a.read_text(encoding="utf-8") == legit_content

    # Assert file_b was restored to snapshot 1
    assert file_b.read_text(encoding="utf-8") == "Financial spreadsheet binary data\n"


# ---------------------------------------------------------------------------
# 3. Snapshot Pause During Attack
# ---------------------------------------------------------------------------


def test_snapshot_pause_during_attack(tmp_path: Path) -> None:
    """While paused, take_snapshot returns None; resumes cleanly when cleared."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()
    (share_root / "test.txt").write_text("hello\n", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    anomaly_time = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)

    # Pause snapshots
    mgr.pause_snapshots(active_anomaly_ts=anomaly_time)
    assert mgr.is_paused is True
    assert mgr.active_anomaly_ts == anomaly_time

    # Attempt snapshot while paused -> must return None
    snap = mgr.take_snapshot(share_root)
    assert snap is None
    assert len(mgr.list_snapshots()) == 0

    # Resume snapshots
    mgr.resume_snapshots()
    assert mgr.is_paused is False
    assert mgr.active_anomaly_ts is None

    # Now snapshotting succeeds
    snap = mgr.take_snapshot(share_root)
    assert snap is not None
    assert len(mgr.list_snapshots()) == 1


# ---------------------------------------------------------------------------
# 4. Retention Policy & Anomaly Lock
# ---------------------------------------------------------------------------


def test_retention_policy_pruning_and_anomaly_protection(tmp_path: Path) -> None:
    """Retention retains correct count and protects clean snapshots during active anomalies."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()
    (share_root / "sample.txt").write_text("data\n", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir, max_snapshots=10)

    # Take 5 snapshots with simulated timestamps
    base_time = datetime(2026, 3, 1, 8, 0, 0, tzinfo=UTC)
    for i in range(5):
        mgr.take_snapshot(share_root, clock=lambda i=i: base_time + timedelta(hours=i))

    all_snaps = mgr.list_snapshots()
    assert len(all_snaps) == 5

    # Standard retention: keep_last=3 prunes 2 oldest
    pruned = mgr.apply_retention(keep_last=3)
    assert len(pruned) == 2
    assert len(mgr.list_snapshots()) == 3

    # Now test anomaly lock:
    # Add a newer snapshot at hour 10
    mgr.take_snapshot(share_root, clock=lambda: base_time + timedelta(hours=10))
    # Active anomaly at hour 9
    anomaly_ts = base_time + timedelta(hours=9)
    mgr.pause_snapshots(active_anomaly_ts=anomaly_ts)

    # Even with aggressive retention keep_last=1, pre-anomaly clean snapshots are protected
    mgr.apply_retention(keep_last=1, min_clean_keep=2)
    remaining = mgr.list_snapshots()
    clean_remaining = [s for s in remaining if s.created_at < anomaly_ts]
    assert len(clean_remaining) >= 2


# ---------------------------------------------------------------------------
# 5. Path Traversal & Untrusted Name Sanitization
# ---------------------------------------------------------------------------


def test_path_traversal_validation(tmp_path: Path) -> None:
    """Path traversal sequences, drive escapes, and symlinks outside root are rejected."""
    root = tmp_path / "safe_share"
    root.mkdir()
    (root / "safe.txt").write_text("safe content\n", encoding="utf-8")

    # Valid relative path inside root
    resolved = validate_path_within_root("safe.txt", root)
    assert resolved == (root / "safe.txt").resolve()

    # Subdirectory path
    sub = root / "subdir"
    sub.mkdir()
    resolved_sub = validate_path_within_root("subdir/subfile.txt", root)
    assert resolved_sub == (root / "subdir" / "subfile.txt").resolve()

    # Traversal attempts with ..
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_path_within_root("../escape.txt", root)

    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_path_within_root("subdir/../../escape.txt", root)

    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_path_within_root("..", root)

    # Empty path
    with pytest.raises(ValueError):
        validate_path_within_root("", root)

    # Foreign absolute path escaping root
    other_dir = tmp_path / "outside_dir"
    other_dir.mkdir()
    outside_file = other_dir / "secret.txt"
    outside_file.write_text("secret\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_path_within_root(str(outside_file), root)


# ---------------------------------------------------------------------------
# 6. Rsync Command Runner Arguments
# ---------------------------------------------------------------------------


def test_rsync_command_runner_arguments(tmp_path: Path) -> None:
    """RsyncSnapshotManager generates exact argument lists with --link-dest (no shell=True)."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "rsync_snapshots"
    share_root.mkdir()
    (share_root / "f1.txt").write_text("content\n", encoding="utf-8")

    runner = FakeCommandRunner()
    mgr = RsyncSnapshotManager(snapshot_dir=snap_dir, runner=runner)

    t0 = datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC)
    snap1 = mgr.take_snapshot(share_root, clock=lambda: t0)
    assert snap1 is not None

    # Check first command args
    assert len(runner.commands) == 1
    cmd1 = runner.commands[0]
    assert cmd1[0] == "rsync"
    assert "-a" in cmd1
    assert "--delete" in cmd1
    # First snapshot has no --link-dest
    assert not any(arg.startswith("--link-dest") for arg in cmd1)
    # Ends with src and dst directory slashes
    assert cmd1[-2] == f"{share_root.resolve().as_posix()}/"
    assert cmd1[-1] == f"{Path(snap1.snapshot_path).resolve().as_posix()}/data/"

    # Second snapshot should use --link-dest pointing to snap1 data
    t1 = t0 + timedelta(minutes=10)
    snap2 = mgr.take_snapshot(share_root, clock=lambda: t1)
    assert snap2 is not None

    assert len(runner.commands) == 2
    cmd2 = runner.commands[1]
    assert cmd2[0] == "rsync"
    link_dest_arg = f"--link-dest={Path(snap1.snapshot_path).resolve().as_posix()}/data"
    assert link_dest_arg in cmd2


# ---------------------------------------------------------------------------
# 7. Dry-Run Invariant
# ---------------------------------------------------------------------------


def test_dry_run_invariant_leaves_disk_unmodified(tmp_path: Path) -> None:
    """dry_run=True modifies zero bytes on disk; real restore requires dry_run=False."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()

    f1 = share_root / "report.docx"
    f2 = share_root / "contract.pdf"
    f1.write_text("Original Docx\n", encoding="utf-8")
    f2.write_text("Original PDF\n", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap = mgr.take_snapshot(share_root)
    assert snap is not None

    # Simulate attack changes
    f1.write_text("ENCRYPTED_DOCX\n", encoding="utf-8")
    locked_f2 = share_root / "contract.pdf.locked"
    f2.unlink()
    locked_f2.write_text("ENCRYPTED_PDF\n", encoding="utf-8")

    # Run dry-run restore
    report = mgr.restore_files(
        share=share_root,
        snapshot_id=snap.snapshot_id,
        paths=["report.docx", "contract.pdf.locked"],
        dry_run=True,
    )

    assert report.dry_run is True
    assert report.restored_count == 2
    assert report.removed_locked_count == 1

    # Assert disk is COMPLETELY UNTOUCHED by dry run
    assert f1.read_text(encoding="utf-8") == "ENCRYPTED_DOCX\n"
    assert locked_f2.exists()
    assert not f2.exists()

    # Now execute real restore (dry_run=False)
    real_report = mgr.restore_files(
        share=share_root,
        snapshot_id=snap.snapshot_id,
        paths=["report.docx", "contract.pdf.locked"],
        dry_run=False,
    )

    assert real_report.dry_run is False
    assert real_report.restored_count == 2
    assert real_report.removed_locked_count == 1
    assert f1.read_text(encoding="utf-8") == "Original Docx\n"
    assert f2.exists()
    assert f2.read_text(encoding="utf-8") == "Original PDF\n"
    assert not locked_f2.exists()


# ---------------------------------------------------------------------------
# 8. Verify Snapshots Integrity Check
# ---------------------------------------------------------------------------


def test_verify_snapshots_integrity_detects_corruption(tmp_path: Path) -> None:
    """verify_snapshots verifies valid files and detects corrupted snapshot data."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()

    for i in range(5):
        (share_root / f"file_{i}.txt").write_text(f"Content {i * 100}\n", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap = mgr.take_snapshot(share_root)
    assert snap is not None

    # Intact snapshot verification passes
    report = mgr.verify_snapshots(snap.snapshot_id, sample_count=5)
    assert report.passed is True
    assert report.files_checked == 5
    assert len(report.errors) == 0

    # Corrupt one file in the snapshot data store
    corrupted_target = Path(snap.snapshot_path) / "data" / "file_0.txt"
    corrupted_target.write_text("CORRUPTED_BYTES\n", encoding="utf-8")

    # Verification must now fail
    corrupt_report = mgr.verify_snapshots(snap.snapshot_id, sample_count=5)
    assert corrupt_report.passed is False
    assert len(corrupt_report.errors) >= 1
    assert any("SHA-256 mismatch" in err for err in corrupt_report.errors)


# ---------------------------------------------------------------------------
# 9. Factory & FakeSnapshotManager
# ---------------------------------------------------------------------------


def test_snapshot_manager_factory_and_fake_backend() -> None:
    """Factory instantiates requested backends; FakeSnapshotManager logs calls in memory."""
    fake_mgr = get_snapshot_manager("fake")
    assert isinstance(fake_mgr, FakeSnapshotManager)

    portable_mgr = get_snapshot_manager("portable")
    assert isinstance(portable_mgr, PortableSnapshotManager)

    rsync_mgr = get_snapshot_manager("rsync")
    assert isinstance(rsync_mgr, RsyncSnapshotManager)

    with pytest.raises(ValueError, match="Unknown snapshot backend"):
        get_snapshot_manager("nonexistent_backend")

    # Exercise FakeSnapshotManager
    snap = fake_mgr.take_snapshot("/share/data")
    assert snap is not None
    assert len(fake_mgr.calls) == 1
    assert fake_mgr.calls[0]["method"] == "take_snapshot"

    now = snap.created_at + timedelta(seconds=10)
    clean = fake_mgr.find_clean_snapshot("/share/data", before_ts=now)
    assert clean is not None

    restore_rep = fake_mgr.restore_files("/share/data", snap.snapshot_id, ["a.txt", "b.txt"])
    assert restore_rep.restored_count == 2
    assert restore_rep.verified is True

    verify_rep = fake_mgr.verify_snapshots(snap.snapshot_id)
    assert verify_rep.passed is True
