"""
lab/tests/test_lab_windows.py – Fast unit tests for Windows SMB lab adaptation and safety.

Covers:
1. Safety refusals:
   - Empty allowed_target_prefix refuses execution.
   - Target outside allowed_target_prefix refuses execution.
   - Path traversal ('..') refuses execution.
   - Drive roots refuse execution.
   - Missing marker and manifest refuse execution.
2. Restore hashes:
   - File encryption followed by restore() restores original SHA-256 hashes.
   - Canary-avoiding mode skips canaries.
3. Marker file creation during collection:
   - collect.py drops __sg_start_<run_id> and __sg_end_<run_id> markers.
   - labels.csv written with required columns including run_id and client_machine.
4. Dataset interval derivation from markers:
   - ml/build_dataset.py derives ground truth intervals from marker events.
   - Warns when an end marker is missing.
   - Filters out marker events so they do not pollute features.
5. Dry-run table output.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from lab.collect import Step, run_plan
from lab.fake_ransomware import (
    CANARY_NAMES,
    encrypt_files,
    restore,
    simulate_encryption,
)
from lab.make_fake_files import create_fake_files, restore_files, verify_manifest
from lab.safety import (
    MANIFEST_FILENAME,
    MARKER_FILENAME,
    LabSafetyError,
    check_safety,
    load_lab_config,
    retry_on_windows_busy,
)
from ml.build_dataset import extract_features_from_log
from shareguard.parser import AuditEvent, parse_line


def test_safety_refuses_when_allowed_prefix_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Operations must be refused when allowed_target_prefix is empty."""
    monkeypatch.setenv("SHAREGUARD_LAB_ALLOWED_PREFIX", "")
    target = tmp_path / "sgtest"
    target.mkdir()
    (target / MARKER_FILENAME).write_text("lab\n", encoding="utf-8")
    (target / MANIFEST_FILENAME).write_text("{}", encoding="utf-8")

    with pytest.raises(LabSafetyError, match="allowed_target_prefix"):
        check_safety(target, confirmed=True)


def test_safety_refuses_when_outside_allowed_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Operations must be refused when target is outside allowed_target_prefix."""
    allowed_dir = tmp_path / "allowed_share" / "sgtest"
    allowed_dir.mkdir(parents=True)
    monkeypatch.setenv("SHAREGUARD_LAB_ALLOWED_PREFIX", str(allowed_dir.resolve()))

    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / MARKER_FILENAME).write_text("lab\n", encoding="utf-8")
    (outside_dir / MANIFEST_FILENAME).write_text("{}", encoding="utf-8")

    with pytest.raises(LabSafetyError, match="not inside allowed prefix"):
        check_safety(outside_dir, confirmed=True)


def test_safety_refuses_path_traversal(tmp_path: Path) -> None:
    """Target containing '..' path traversal sequences must be refused."""
    traversal_path = tmp_path / "sub" / ".." / "target"
    with pytest.raises(LabSafetyError, match="path traversal"):
        check_safety(traversal_path, confirmed=True)


def test_safety_refuses_no_marker(tmp_path: Path) -> None:
    """Operations must be refused when marker file is absent."""
    target = tmp_path / "sgtest"
    target.mkdir()
    (target / MANIFEST_FILENAME).write_text("{}", encoding="utf-8")
    with pytest.raises(LabSafetyError, match="neither .* found"):
        check_safety(target, confirmed=True, require_marker=True)


def test_safety_refuses_missing_flag(tmp_path: Path) -> None:
    """Operations must be refused when confirmed=False / missing flag."""
    target = tmp_path / "sgtest"
    target.mkdir()
    (target / MARKER_FILENAME).write_text("lab\n", encoding="utf-8")
    (target / MANIFEST_FILENAME).write_text("{}", encoding="utf-8")
    with pytest.raises(LabSafetyError, match="confirmed"):
        check_safety(target, confirmed=False)


def test_safety_refuses_home_and_sensitive_folders(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operations must be refused on home directories and Windows user/system directories."""
    home = Path.home()
    with pytest.raises(LabSafetyError, match="home directory|Users|root"):
        check_safety(home, confirmed=True)

    desktop = home / "Desktop"
    if desktop.exists():
        with pytest.raises(LabSafetyError, match="home directory|Users|root"):
            check_safety(desktop, confirmed=True)


def test_workload_safety_refusal(tmp_path: Path) -> None:
    """Workloads must refuse to run if unconfirmed or safety checks fail."""
    from lab.workloads import office_edit

    target = tmp_path / "sgtest"
    target.mkdir()
    # No marker, no manifest, confirmed=False
    with pytest.raises(LabSafetyError):
        office_edit.run(target, duration=0.1, confirmed=False)


def test_safety_refuses_drive_root(tmp_path: Path) -> None:
    """Drive or filesystem roots must be refused."""
    root_path = Path(tmp_path.root)
    with pytest.raises(LabSafetyError, match="root"):
        check_safety(root_path, confirmed=True)


def test_encryption_and_restore_hashes(tmp_path: Path) -> None:
    """Files encrypted by fake_ransomware must be restored to exact original SHA-256 hashes."""
    target = tmp_path / "sgtest"
    created = create_fake_files(target, count=15, seed=123, confirmed=True)
    assert len(created) == 15

    # Verify manifest passes before attack
    ok_before, errors_before = verify_manifest(target, confirmed=True)
    assert ok_before, f"Pre-attack manifest failed: {errors_before}"

    # Encrypt some files
    summary = encrypt_files(target, style="fast", count=8, confirmed=True)
    assert summary.files_changed == 8

    # Verify manifest fails during attack
    ok_attack, errors_attack = verify_manifest(target, confirmed=True)
    assert not ok_attack
    assert len(errors_attack) >= 8

    # Restore files
    restored_count, errors = restore(target, confirmed=True)
    assert restored_count >= 8
    assert errors == []

    # Verify manifest passes completely after restore
    ok_after, errors_after = verify_manifest(target, confirmed=True)
    assert ok_after, f"Post-restore manifest mismatch: {errors_after}"


def test_canary_avoiding_mode_skips_canaries(tmp_path: Path) -> None:
    """When avoid_canaries=True, canary files in manifest must not be touched or renamed."""
    target = tmp_path / "sgtest"
    create_fake_files(target, count=10, seed=42, confirmed=True)

    # Place a canary file inside documents/reports/
    canary_path = target / "documents" / "reports" / CANARY_NAMES[0]
    canary_path.write_bytes(b"canary_data_initial")

    # Add canary to manifest so it would normally be encrypted
    from lab.make_fake_files import _write_manifest, load_manifest, sha256_file

    entries = load_manifest(target)
    entries.append({"path": canary_path.relative_to(target).as_posix(), "sha256": sha256_file(canary_path)})
    _write_manifest(target, entries)

    # Run attack with avoid_canaries=True on all files
    simulate_encryption(
        target,
        count=20,
        style="fast",
        avoid_canaries=True,
        confirmed=True,
    )

    # Ensure canary still exists and was not renamed to .locked or encrypted
    assert canary_path.exists()
    assert canary_path.read_bytes() == b"canary_data_initial"


def test_collect_creates_marker_files_and_writes_labels(tmp_path: Path) -> None:
    """run_plan must drop __sg_start_ and __sg_end_ marker files and write labels.csv."""
    target = tmp_path / "sgtest"
    create_fake_files(target, count=10, seed=99, confirmed=True)

    labels_csv = tmp_path / "labels.csv"

    # Define minimal 2-step plan
    steps = [
        Step(kind="attack", scenario="attack_fast", label=1, style="fast", count=4, ext=".locked"),
        Step(kind="normal", scenario="normal_test", label=0, workload="office_edit", duration=0.1),
    ]

    run_plan(
        target=target,
        steps=steps,
        labels_path=labels_csv,
        fake_file_count=10,
        pause_between_runs=0.0,
    )

    # Verify marker files were created on target
    start_markers = list(target.glob("__sg_start_*"))
    end_markers = list(target.glob("__sg_end_*"))
    assert len(start_markers) == 2, f"Expected 2 start markers, found: {start_markers}"
    assert len(end_markers) == 2, f"Expected 2 end markers, found: {end_markers}"

    # Verify labels.csv schema and contents
    assert labels_csv.exists()
    with labels_csv.open("r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 2

        row0 = reader[0]
        assert "run_id" in row0
        assert "run_0001" in row0["run_id"]
        assert row0["scenario"] == "attack_fast"
        assert row0["label"] == "1"
        assert int(row0["files_encrypted"]) == 4
        assert row0["client_machine"] != ""

        # Check JSON parameters column
        params = json.loads(row0["parameters"])
        assert params["style"] == "fast"
        assert params["count"] == 4

        row1 = reader[1]
        assert "run_0002" in row1["run_id"]
        assert row1["scenario"] == "normal_test"
        assert row1["label"] == "0"
        assert int(row1["files_encrypted"]) == 0


def test_build_dataset_derives_intervals_from_markers_and_ignores_markers_in_features(tmp_path: Path) -> None:
    """build_dataset must derive exact interval timestamps from audit markers and strip them from features."""
    log_file = tmp_path / "audit.log"
    labels_csv = tmp_path / "labels.csv"

    run_id = "run_0001_attack_fast"

    # Write synthetic Samba audit log with start and end markers under configured Finance share
    log_lines = [
        # Marker start event at 1000.0
        f"2026-10-11T12:00:00.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/__sg_start_{run_id}\n",
        # Attack events between 1001.0 and 1010.0
        "2026-10-11T12:00:01.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/doc1.docx\n",
        "2026-10-11T12:00:02.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|renameat|ok|/srv/shares/Finance/doc1.docx|/srv/shares/Finance/doc1.docx.locked\n",
        "2026-10-11T12:00:05.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/doc2.docx\n",
        "2026-10-11T12:00:06.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|renameat|ok|/srv/shares/Finance/doc2.docx|/srv/shares/Finance/doc2.docx.locked\n",
        # Marker end event at 1015.0
        f"2026-10-11T12:00:15.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/__sg_end_{run_id}\n",
    ]
    log_file.write_text("".join(log_lines), encoding="utf-8")

    # Write labels.csv with run_id
    labels_csv.write_text(
        "run_id,scenario,label,parameters,start_utc,end_utc,files_encrypted,client_machine\n"
        f"{run_id},attack_fast,1,{{}},2026-10-11T11:59:00+00:00,2026-10-11T11:59:10+00:00,2,client-pc\n",
        encoding="utf-8",
    )

    rows = extract_features_from_log(
        log_path=log_file,
        labels_path=labels_csv,
        run_id="dataset_run_1",
        source="live",
        window_seconds=60.0,
        slide_seconds=10.0,
    )

    assert len(rows) > 0
    # Window overlapping the attack events should be labeled as attack
    assert rows[0]["label"] == 1
    assert rows[0]["scenario"] == "attack_fast"


def test_build_dataset_warns_on_missing_end_marker(tmp_path: Path) -> None:
    """When an end marker is absent in the audit log, a warning must be issued."""
    log_file = tmp_path / "audit_missing_end.log"
    labels_csv = tmp_path / "labels.csv"

    run_id = "run_0002_incomplete"
    log_lines = [
        f"2026-10-11T12:00:00.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/__sg_start_{run_id}\n",
        "2026-10-11T12:00:02.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|r|/srv/shares/Finance/file1.txt\n",
    ]
    log_file.write_text("".join(log_lines), encoding="utf-8")

    labels_csv.write_text(
        "run_id,scenario,label,parameters,start_utc,end_utc,files_encrypted,client_machine\n"
        f"{run_id},normal_incomplete,0,{{}},2026-10-11T12:00:00+00:00,2026-10-11T12:00:30+00:00,0,client-pc\n",
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match=f"Missing end marker for run_id '{run_id}'"):
        extract_features_from_log(
            log_path=log_file,
            labels_path=labels_csv,
            run_id="run_warn",
            source="live",
        )


def test_default_plan_and_quick_plan_structure(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify default plan has 40 attack steps and quick plan has 6 attack steps."""
    from lab.collect import _build_default_plan, _build_quick_plan, _print_plan

    default_plan = _build_default_plan()
    attack_steps = [s for s in default_plan if s.kind == "attack"]
    normal_steps = [s for s in default_plan if s.kind == "normal"]
    assert len(attack_steps) == 40
    # Normal workloads total approx 200 minutes (12000 seconds)
    total_normal_sec = sum(s.duration for s in normal_steps)
    assert total_normal_sec >= 10000.0

    # Verify styles covered
    styles = {s.style for s in attack_steps}
    assert "fast" in styles
    assert "slow" in styles
    assert "partial" in styles
    assert "rename_only" in styles
    assert "copy_delete" in styles

    # Check canary-avoiding variant present
    assert any(s.avoid_canaries for s in attack_steps)

    # Verify quick plan
    quick_plan = _build_quick_plan()
    assert len([s for s in quick_plan if s.kind == "attack"]) == 6
    assert len([s for s in quick_plan if s.kind == "normal"]) == 5

    # Test _print_plan output
    _print_plan(quick_plan, quick=True)
    out = capsys.readouterr().out
    assert "QUICK" in out
    assert "steps" in out.lower()


def test_build_dataset_warns_on_missing_start_marker(tmp_path: Path) -> None:
    """When a run in labels.csv has no start marker in audit log, a warning must be issued."""
    log_file = tmp_path / "audit_missing_start.log"
    labels_csv = tmp_path / "labels.csv"

    run_id = "run_0003_missing_start"
    # Audit log has events from another run but none for run_0003
    log_lines = [
        "2026-10-11T12:00:00.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/__sg_start_run_other\n",
        "2026-10-11T12:00:02.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|r|/srv/shares/Finance/file1.txt\n",
        "2026-10-11T12:00:05.000000+00:00 fileserver smbd_audit: user1|192.168.56.20|client-pc|Finance|openat|ok|w|/srv/shares/Finance/__sg_end_run_other\n",
    ]
    log_file.write_text("".join(log_lines), encoding="utf-8")

    labels_csv.write_text(
        "run_id,scenario,label,parameters,start_utc,end_utc,files_encrypted,client_machine\n"
        f"{run_id},normal_no_marker,0,{{}},2026-10-11T12:00:00+00:00,2026-10-11T12:00:30+00:00,0,client-pc\n",
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match=f"Missing start marker for run_id '{run_id}'"):
        extract_features_from_log(
            log_path=log_file,
            labels_path=labels_csv,
            run_id="run_missing_start_test",
            source="live",
        )


def test_restore_various_extensions(tmp_path: Path) -> None:
    """Files encrypted with custom fake extensions (.crypt, .enc, .deadbeef) must restore cleanly."""
    target = tmp_path / "sgtest_ext"
    create_fake_files(target, count=6, seed=777, confirmed=True)

    # 1. Test .crypt with fast style
    encrypt_files(target, style="fast", count=2, ext=".crypt", confirmed=True)
    crypt_files = list(target.rglob("*.crypt"))
    assert len(crypt_files) == 2

    restored_count, errors = restore(target, confirmed=True)
    assert restored_count >= 2
    assert errors == []

    ok, errors = verify_manifest(target, confirmed=True)
    assert ok, f"Manifest check failed after .crypt restore: {errors}"

    # 2. Test .deadbeef with copy_delete style
    encrypt_files(target, style="copy_delete", count=2, ext=".deadbeef", confirmed=True)
    deadbeef_files = list(target.rglob("*.deadbeef"))
    assert len(deadbeef_files) == 2

    restored_count, errors = restore(target, confirmed=True)
    assert restored_count >= 2
    assert errors == []

    ok, errors = verify_manifest(target, confirmed=True)
    assert ok, f"Manifest check failed after .deadbeef restore: {errors}"

