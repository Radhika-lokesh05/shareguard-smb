"""
server/tests/test_features.py – Unit tests for compute_features lifecycle tracking.

Tests:
- Zip-like workload: many writes to a single newly created archive -> distinct_high_entropy_files is 1.
- Dev-like workload: developer creates and unlinks own files -> delete_after_copy_count is 0.
- Ransomware copy-delete workload: reads pre-existing files, creates .locked copies, deletes originals -> delete_after_copy_count > 0.
- Ransomware mass-overwrite: modifies many pre-existing documents -> distinct_high_entropy_files is high.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shareguard.features import compute_features
from shareguard.parser import AuditEvent


def _make_event(
    op: str,
    path: str,
    new_path: str = "",
    args: str = "0x20",
    ts: datetime | None = None,
    ip: str = "192.168.1.10",
    user: str = "alice",
) -> AuditEvent:
    if ts is None:
        ts = datetime.now(tz=UTC)
    return AuditEvent(
        ts=ts,
        host="fileserver",
        user=user,
        ip=ip,
        machine="PC",
        share="data",
        op=op,
        result="ok",
        args=args,
        path=path,
        new_path=new_path,
        raw="",
    )


def test_compute_features_zip_single_archive() -> None:
    """Reading many files and writing 50 blocks to a single zip archive yields distinct_high_entropy_files = 1."""
    base_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    events: list[AuditEvent] = []

    # Read 30 files
    for i in range(30):
        t = base_ts + timedelta(seconds=i * 0.1)
        events.append(_make_event("openat", f"docs/file_{i}.docx", args="0x20", ts=t))

    # Write 50 blocks to shared/archive.zip
    for i in range(50):
        t = base_ts + timedelta(seconds=5 + i * 0.1)
        events.append(_make_event("openat", "shared/archive.zip", args="0x42", ts=t))

    features = compute_features(events, client_ip="192.168.1.10", username="alice")
    assert features.write_count == 50
    assert features.read_count == 30
    assert features.extra["distinct_high_entropy_files"] == 1.0
    assert features.extra["delete_after_copy_count"] == 0.0


def test_compute_features_dev_temp_files() -> None:
    """Developer creating and unlinking their own files has delete_after_copy_count = 0."""
    base_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    events: list[AuditEvent] = []

    for i in range(20):
        t = base_ts + timedelta(seconds=i * 0.2)
        p = f"src/temp_{i}.py"
        events.append(_make_event("openat", p, args="0x42", ts=t))
        events.append(_make_event("close", p, ts=t + timedelta(milliseconds=10)))
        events.append(_make_event("unlinkat", p, ts=t + timedelta(milliseconds=20)))

    features = compute_features(events, client_ip="192.168.1.10", username="alice")
    assert features.delete_count == 20
    assert features.extra["delete_after_copy_count"] == 0.0


def test_compute_features_ransomware_copy_delete() -> None:
    """Copy-delete ransomware deleting pre-existing files records delete_after_copy_count > 0."""
    base_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    events: list[AuditEvent] = []

    for i in range(15):
        t = base_ts + timedelta(seconds=i * 0.5)
        src = f"finance/sheet_{i}.xlsx"
        enc = f"finance/sheet_{i}.locked"

        # 1. Read pre-existing file
        events.append(_make_event("openat", src, args="0x20", ts=t))
        # 2. Write encrypted copy
        events.append(_make_event("openat", enc, args="0x42", ts=t + timedelta(milliseconds=50)))
        events.append(_make_event("close", enc, ts=t + timedelta(milliseconds=60)))
        # 3. Unlink original pre-existing file
        events.append(_make_event("unlinkat", src, ts=t + timedelta(milliseconds=100)))

    features = compute_features(events, client_ip="10.0.0.55", username="attacker")
    assert features.delete_count == 15
    assert features.extra["delete_after_copy_count"] == 15.0
    assert features.extra["preexisting_files_deleted"] == 15.0


def test_compute_features_empty_events() -> None:
    """Empty events list returns default zero ClientFeatures."""
    features = compute_features([], client_ip="192.168.1.10", username="alice")
    assert features.client_ip == "192.168.1.10"
    assert features.username == "alice"
    assert features.window_start == 0.0
    assert features.window_end == 0.0
    assert features.rename_count == 0
    assert features.delete_count == 0
    assert features.write_count == 0
    assert features.read_count == 0
    assert features.total_events == 0


def test_compute_features_canary_and_ransom_notes() -> None:
    """Canary decoys and ransom notes are detected across multiple directories."""
    base_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    events: list[AuditEvent] = [
        # Canary touch in primary path
        _make_event("openat", ".shareguard_canary/canary_1.docx", ts=base_ts),
        # Canary touch in rename destination
        _make_event(
            "renameat",
            "docs/file.txt",
            new_path=".shareguard_canary/canary_2.docx",
            ts=base_ts + timedelta(seconds=1),
        ),
        # Ransom notes in 2 distinct directories
        _make_event("openat", "finance/README_NOTE.txt", args="0x42", ts=base_ts + timedelta(seconds=2)),
        _make_event("openat", "legal/HOW_TO_DECRYPT.txt", args="0x42", ts=base_ts + timedelta(seconds=3)),
    ]

    features = compute_features(events, client_ip="10.0.0.99", username="mallory")
    assert features.extra["canary_touch_count"] == 2.0
    assert features.extra["ransom_note_count"] == 2.0
    assert features.extra["ransom_note_dirs"] == 2.0


def test_compute_features_renames_and_extension_changes() -> None:
    """Renames to suspicious extensions increase ext_change_count and unique_extensions."""
    base_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    events: list[AuditEvent] = [
        _make_event(
            "renameat",
            "docs/report.pdf",
            new_path="docs/report.pdf.locked",
            ts=base_ts + timedelta(seconds=1),
        ),
        _make_event(
            "renameat",
            "docs/sheet.xlsx",
            new_path="docs/sheet.xlsx.crypto",
            ts=base_ts + timedelta(seconds=2),
        ),
        _make_event(
            "renameat",
            "docs/notes.txt",
            new_path="docs/notes_renamed.txt",
            ts=base_ts + timedelta(seconds=3),
        ),
    ]

    features = compute_features(events, client_ip="10.0.0.99", username="mallory")
    assert features.rename_count == 3
    assert features.extra["ext_change_count"] == 2.0
    assert features.unique_extensions >= 2
    assert features.total_events == 3
    assert features.extra["ops_per_sec"] > 0.0
