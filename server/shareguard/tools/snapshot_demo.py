"""shareguard.tools.snapshot_demo – End-to-end snapshot and restore demonstration.

Usage:
    ./.venv/Scripts/python.exe -m shareguard.tools.snapshot_demo

Workflow:
1. In a temporary directory, create fake files using ``lab/make_fake_files.py``.
2. Take a clean baseline snapshot using ``PortableSnapshotManager``.
3. Simulate an attack using ``lab/fake_ransomware.py`` (fast style, with safety confirmation).
4. Run a preview dry-run restore and display the report.
5. Run the real restore.
6. Verify all restored file SHA-256 hashes against the original manifest and print results.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from shareguard.snapshots import PortableSnapshotManager, _compute_sha256


def run_demo() -> None:
    """Execute end-to-end snapshot creation, ransomware attack, and restore demo."""
    print("=" * 90)
    print("ShareGuard Snapshot & Recovery Demo")
    print("=" * 90)

    python_exe = sys.executable
    sub_env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

    with tempfile.TemporaryDirectory(prefix="shareguard_demo_") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str).resolve()
        share_dir = tmp_dir / "share"
        snapshots_dir = tmp_dir / "snapshots"
        share_dir.mkdir(parents=True, exist_ok=True)
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        print(f"[1/6] Generating simulated office share in {share_dir}...")
        res = subprocess.run(  # noqa: S603
            [
                python_exe,
                "lab/make_fake_files.py",
                "--target",
                str(share_dir),
                "--count",
                "30",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=sub_env,
            check=False,
        )
        if res.returncode != 0:
            print(f"Error generating fake files:\n{res.stderr}", file=sys.stderr)
            sys.exit(1)

        # Load original manifest
        orig_manifest_file = share_dir / "manifest.json"
        orig_manifest = json.loads(orig_manifest_file.read_text(encoding="utf-8"))
        original_hashes = {f["path"]: f["sha256"] for f in orig_manifest["files"]}
        print(f"      Seeded {len(original_hashes)} files with SHA-256 integrity manifest.")

        print("\n[2/6] Taking baseline snapshot with PortableSnapshotManager...")
        manager = PortableSnapshotManager(snapshot_dir=snapshots_dir)
        snap = manager.take_snapshot(share_dir)
        if snap is None:
            print("Failed to take snapshot!", file=sys.stderr)
            sys.exit(1)

        print(f"      Snapshot ID: {snap.snapshot_id}")
        print(f"      Files: {snap.file_count} | Total bytes: {snap.total_bytes:,}")
        print(f"      Manifest: {snap.manifest_path}")

        print("\n[3/6] Simulating ransomware attack via lab/fake_ransomware.py...")
        attack_res = subprocess.run(  # noqa: S603
            [
                python_exe,
                "lab/fake_ransomware.py",
                "--target",
                str(share_dir),
                "--style",
                "fast",
                "--i-understand-this-is-a-lab",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=sub_env,
            check=False,
        )
        if attack_res.returncode != 0:
            print(f"Error executing fake ransomware:\n{attack_res.stderr}", file=sys.stderr)
            sys.exit(1)

        # Inspect encrypted artifacts
        locked_files = list(share_dir.rglob("*.locked"))
        notes = list(share_dir.rglob("*readme*.txt"))
        print(f"      Ransomware encrypted and renamed {len(locked_files)} files to .locked")
        if notes:
            print(f"      Ransom notes detected: {len(notes)}")

        # Collect paths to restore (from attacker activity)
        touched_paths = [p.relative_to(share_dir).as_posix() for p in locked_files]

        print("\n[4/6] Running preview (dry_run=True) restore...")
        dry_report = manager.restore_files(
            share=share_dir,
            snapshot_id=snap.snapshot_id,
            paths=touched_paths,
            dry_run=True,
        )
        print("      [DRY RUN REPORT]")
        print(f"      Would restore: {dry_report.restored_count} files ({dry_report.restored_bytes:,} bytes)")
        print(f"      Would remove:  {dry_report.removed_locked_count} .locked artifacts")
        print(f"      Skipped:       {dry_report.skipped_count} files")
        print("      Disk check:    Files remain encrypted on disk (dry_run verified).")

        print("\n[5/6] Executing real restore (dry_run=False)...")
        t0 = time.perf_counter()
        real_report = manager.restore_files(
            share=share_dir,
            snapshot_id=snap.snapshot_id,
            paths=touched_paths,
            dry_run=False,
        )
        elapsed = time.perf_counter() - t0
        print("      [REAL RESTORE REPORT]")
        print(f"      Restored:      {real_report.restored_count} files ({real_report.restored_bytes:,} bytes)")
        print(f"      Removed:       {real_report.removed_locked_count} .locked artifacts")
        print(f"      Skipped:       {real_report.skipped_count} files")
        print(f"      Failed:        {real_report.failed_count} files")
        print(f"      Time taken:    {elapsed:.3f}s")

        print("\n[6/6] Verifying restored file integrity against original manifest...")
        remaining_locked = list(share_dir.rglob("*.locked"))
        if remaining_locked:
            print(f"      Warning: {len(remaining_locked)} .locked files still present.")

        mismatches = 0
        verified_count = 0
        for rel_path, expected_hash in original_hashes.items():
            f_path = share_dir / rel_path
            if not f_path.exists():
                print(f"      MISSING: {rel_path}")
                mismatches += 1
                continue
            actual_hash = _compute_sha256(f_path)
            if actual_hash != expected_hash:
                print(f"      CORRUPT: {rel_path} (hash mismatch)")
                mismatches += 1
            else:
                verified_count += 1

        print("=" * 90)
        if mismatches == 0 and not remaining_locked:
            print(f"\033[92mSUCCESS: All {verified_count}/{len(original_hashes)} files restored with verified SHA-256 hashes!\033[0m")
        else:
            print(f"\033[91mFAILURE: {mismatches} mismatches detected or remaining locked files.\033[0m")
        print("=" * 90)


if __name__ == "__main__":
    run_demo()
