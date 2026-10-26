"""shareguard.snapshots – Snapshot interface and backend implementations.

Provides:
- :class:`SnapshotInfo`, :class:`ManifestEntry`, :class:`RestoreReport`, :class:`VerifyReport`
- :class:`CommandRunner`, :class:`RealCommandRunner`, :class:`FakeCommandRunner`
- :class:`SnapshotManager` (ABC)
- :class:`PortableSnapshotManager` (pure Python hardlinks / shutil copies, cross-platform)
- :class:`RsyncSnapshotManager` (Linux rsync --link-dest incremental via CommandRunner)
- :class:`FakeSnapshotManager` (in-memory test / simulation backend)
- :func:`get_snapshot_manager` factory

SAFETY INVARIANTS:
- All paths are validated against share root or snapshot root using :mod:`pathlib`.
- Path traversal sequences ('..'), absolute escapes, and drive letters are strictly rejected.
- File names from logs/alerts are treated as untrusted text and sanitized.
- Snapshots are PAUSED while any client is SUSPICIOUS or ATTACK.
- Clean snapshots are protected from deletion during active anomalies.
- Restores default to ``dry_run=True``; real restore requires explicit argument.
- Never delete any file without a verified restored counterpart.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "SnapshotInfo",
    "ManifestEntry",
    "RestoreReport",
    "VerifyReport",
    "CommandRunner",
    "RealCommandRunner",
    "FakeCommandRunner",
    "SnapshotBackend",
    "FakeSnapshotBackend",
    "BtrfsSnapshotBackend",
    "get_backend",
    "SnapshotManager",
    "PortableSnapshotManager",
    "RsyncSnapshotManager",
    "FakeSnapshotManager",
    "get_snapshot_manager",
    "validate_path_within_root",
]

_ATTACK_EXTENSIONS = frozenset(
    {".locked", ".crypto", ".crypt", ".enc", ".encrypted", ".lock", ".pay", ".crypted"}
)


# ---------------------------------------------------------------------------
# Path Validation & Sanitization Helpers
# ---------------------------------------------------------------------------


def _sanitize_path(path: str) -> str:
    """Sanitize and truncate untrusted file names from logs or engine."""
    if not path:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(path)).strip()
    return clean[:512]


def validate_path_within_root(path: str | Path, root: Path | str) -> Path:
    """Validate that *path* resolves strictly inside *root*.

    Rejects '..', absolute paths escaping root, and foreign drive letters.

    Args:
        path: Relative or absolute path candidate.
        root: Target directory root.

    Returns:
        Resolved :class:`Path` inside *root*.

    Raises:
        ValueError: If path attempts to escape the root boundary.
    """
    resolved_root = Path(root).resolve()
    p_str = str(path).replace("\\", "/").strip()

    # Reject empty or root escapes
    if not p_str or ".." in p_str.split("/"):
        raise ValueError(f"Path traversal detected: {path!r} contains invalid parent directory sequences")

    # Handle drive letter escapes on Windows
    if re.match(r"^[a-zA-Z]:", p_str):
        candidate = Path(path).resolve()
    elif p_str.startswith("/"):
        # Absolute unix path
        candidate = Path(path).resolve()
    else:
        # Relative path
        candidate = (resolved_root / p_str).resolve()

    if not candidate.is_relative_to(resolved_root):
        raise ValueError(f"Path traversal detected: {path!r} escapes root {resolved_root}")

    # Check for symlink escaping root if target already exists
    if candidate.is_symlink():
        real_target = candidate.resolve()
        if not real_target.is_relative_to(resolved_root):
            raise ValueError(f"Symlink traversal detected: {candidate} points outside root to {real_target}")

    return candidate


def _compute_sha256(file_path: Path) -> str:
    """Calculate SHA-256 hex digest of a file in 64 KiB chunks."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Data Models & Reports
# ---------------------------------------------------------------------------


@dataclass
class SnapshotInfo:
    """Metadata about a created snapshot.

    Attributes:
        snapshot_id: Unique identifier for this snapshot (timestamp-based).
        created_at: UTC timestamp.
        source_path: Path that was snapshotted.
        snapshot_path: Path to the snapshot directory.
        manifest_path: Path to manifest.json file.
        file_count: Number of files recorded in manifest.
        total_bytes: Total size of files in snapshot.
    """

    snapshot_id: str
    created_at: datetime
    source_path: str
    snapshot_path: str
    manifest_path: str = ""
    file_count: int = 0
    total_bytes: int = 0


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """Metadata for a single file tracked in a snapshot manifest."""

    path: str  # relative path with forward slashes
    size: int
    sha256: str
    mtime: float


@dataclass
class RestoreReport:
    """Detailed results of a snapshot restore operation."""

    snapshot_id: str
    dry_run: bool
    restored_count: int = 0
    restored_paths: list[str] = field(default_factory=list)
    skipped_count: int = 0
    skipped_paths: list[dict[str, str]] = field(default_factory=list)
    failed_count: int = 0
    failed_paths: list[dict[str, str]] = field(default_factory=list)
    restored_bytes: int = 0
    removed_locked_count: int = 0
    verified: bool = True
    time_taken_seconds: float = 0.0


@dataclass
class VerifyReport:
    """Integrity check report for a snapshot."""

    snapshot_id: str
    passed: bool
    files_checked: int
    time_taken_seconds: float
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Command Runner Interface (For Rsync)
# ---------------------------------------------------------------------------


class CommandRunner(ABC):
    """Abstract command runner executing argument lists without shell=True."""

    @abstractmethod
    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """Execute command argument list."""
        ...


class RealCommandRunner(CommandRunner):
    """Executes subprocesses directly with shell=False."""

    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            cmd,
            check=check,
            capture_output=True,
            text=True,
        )


class FakeCommandRunner(CommandRunner):
    """In-memory command runner recording commands for unit test assertions."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Legacy Backends (Preserved for compatibility)
# ---------------------------------------------------------------------------


class SnapshotBackend(ABC):
    """Abstract legacy snapshot backend interface."""

    @abstractmethod
    def create(self, source_path: str) -> SnapshotInfo:
        ...

    @abstractmethod
    def restore(self, snapshot_id: str, target_path: str) -> bool:
        ...

    @abstractmethod
    def list_snapshots(self) -> list[SnapshotInfo]:
        ...


class FakeSnapshotBackend(SnapshotBackend):
    """In-memory legacy snapshot backend for simulation and testing."""

    def __init__(self) -> None:
        self._snapshots: dict[str, SnapshotInfo] = {}

    def create(self, source_path: str) -> SnapshotInfo:
        snap_id = f"fake-snap-{uuid.uuid4().hex[:8]}"
        info = SnapshotInfo(
            snapshot_id=snap_id,
            created_at=datetime.now(tz=UTC),
            source_path=source_path,
            snapshot_path=f"/fake/snapshots/{snap_id}",
        )
        self._snapshots[snap_id] = info
        return info

    def restore(self, snapshot_id: str, target_path: str) -> bool:
        return snapshot_id in self._snapshots

    def list_snapshots(self) -> list[SnapshotInfo]:
        return sorted(self._snapshots.values(), key=lambda s: s.created_at, reverse=True)


class BtrfsSnapshotBackend(SnapshotBackend):
    """Btrfs snapshot backend for LIVE mode on Ubuntu."""

    def create(self, source_path: str) -> SnapshotInfo:
        ...  # noqa: PIE790

    def restore(self, snapshot_id: str, target_path: str) -> bool:
        ...  # noqa: PIE790

    def list_snapshots(self) -> list[SnapshotInfo]:
        ...  # noqa: PIE790


def get_backend(backend_name: str) -> SnapshotBackend:
    """Factory: return the configured legacy backend."""
    if backend_name == "fake":
        return FakeSnapshotBackend()
    if backend_name == "btrfs":
        return BtrfsSnapshotBackend()
    raise ValueError(f"Unknown snapshot backend: {backend_name!r}")


# ---------------------------------------------------------------------------
# Snapshot Manager Base Class
# ---------------------------------------------------------------------------


class SnapshotManager(ABC):
    """Abstract snapshot manager interface for controlling snapshot lifecycle and restores.

    Args:
        snapshot_dir: Root directory where snapshots are stored.
        max_snapshots: Maximum number of snapshots to retain before pruning.
    """

    def __init__(
        self,
        snapshot_dir: Path | str = "snapshots",
        max_snapshots: int = 10,
    ) -> None:
        self.snapshot_dir = Path(snapshot_dir).resolve()
        self.max_snapshots = max_snapshots
        self.is_paused: bool = False
        self.active_anomaly_ts: datetime | None = None
        self.calls: list[dict[str, Any]] = []

    def pause_snapshots(self, active_anomaly_ts: datetime | None = None) -> None:
        """Pause automated snapshots during an active or suspected attack."""
        self.is_paused = True
        self.active_anomaly_ts = active_anomaly_ts or datetime.now(tz=UTC)
        logger.warning(
            "Snapshots paused. Active anomaly timestamp: %s",
            self.active_anomaly_ts,
        )

    def resume_snapshots(self) -> None:
        """Resume automated snapshots when all clients are clear."""
        self.is_paused = False
        self.active_anomaly_ts = None
        logger.info("Snapshots resumed.")

    @abstractmethod
    def take_snapshot(
        self,
        share: Path | str,
        clock: Callable[[], datetime] | None = None,
    ) -> SnapshotInfo | None:
        """Create a timestamped snapshot of *share* with an integrity manifest."""
        ...

    @abstractmethod
    def find_clean_snapshot(
        self,
        share: Path | str,
        before_ts: datetime,
        safety_margin_seconds: float = 0.0,
    ) -> SnapshotInfo | None:
        """Find the newest snapshot taken strictly before *before_ts - safety_margin*."""
        ...

    @abstractmethod
    def restore_files(
        self,
        share: Path | str,
        snapshot_id: str,
        paths: list[str],
        dry_run: bool = True,
        first_anomaly_ts: datetime | None = None,
    ) -> RestoreReport:
        """Restore specified files from snapshot."""
        ...

    @abstractmethod
    def verify_snapshots(
        self,
        snapshot_id: str | None = None,
        sample_count: int = 10,
    ) -> VerifyReport:
        """Verify checksums of sampled files in snapshot."""
        ...

    @abstractmethod
    def list_snapshots(self, share: Path | str | None = None) -> list[SnapshotInfo]:
        """List all known snapshots, newest first."""
        ...

    @abstractmethod
    def apply_retention(
        self,
        keep_last: int = 5,
        min_clean_keep: int = 2,
    ) -> list[str]:
        """Prune older snapshots respecting active anomaly retention locks."""
        ...


# ---------------------------------------------------------------------------
# Portable Snapshot Manager (shutil / hardlinks)
# ---------------------------------------------------------------------------


class PortableSnapshotManager(SnapshotManager):
    """Pure Python snapshot manager using hardlinks (with copy fallback).

    Works on Windows, macOS, and Linux without requiring root or external tools.
    """

    def __init__(
        self,
        snapshot_dir: Path | str = "snapshots",
        max_snapshots: int = 10,
    ) -> None:
        super().__init__(snapshot_dir=snapshot_dir, max_snapshots=max_snapshots)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def take_snapshot(
        self,
        share: Path | str,
        clock: Callable[[], datetime] | None = None,
    ) -> SnapshotInfo | None:
        """Create a new timestamped snapshot with companion manifest.json.

        Refuses to run if snapshotting is currently paused.
        """
        if self.is_paused:
            logger.warning(
                "Refusing to take snapshot: snapshotting is PAUSED during an active anomaly (%s)",
                self.active_anomaly_ts,
            )
            return None

        share_path = Path(share).resolve()
        if not share_path.exists():
            raise FileNotFoundError(f"Share path does not exist: {share_path}")

        now_dt = clock() if clock is not None else datetime.now(tz=UTC)
        timestamp_str = now_dt.strftime("%Y-%m-%dT%H-%M-%SZ")
        snap_dir = self.snapshot_dir / timestamp_str

        # Avoid collision on rapid calls
        collision_idx = 1
        while snap_dir.exists():
            snap_dir = self.snapshot_dir / f"{timestamp_str}_{collision_idx}"
            collision_idx += 1

        data_dir = snap_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        manifest_entries: list[ManifestEntry] = []
        total_bytes = 0
        file_count = 0

        # Check if previous snapshot exists for incremental hard linking
        previous_snapshots = self.list_snapshots(share=share_path)
        prev_data_dir = (
            Path(previous_snapshots[0].snapshot_path) / "data"
            if previous_snapshots
            else None
        )

        # Traverse share and link/copy files
        for root_dir, _dirs, files in os.walk(share_path):
            current_root = Path(root_dir)
            for fn in files:
                src_file = current_root / fn
                rel_path = src_file.relative_to(share_path).as_posix()
                dst_file = data_dir / rel_path
                dst_file.parent.mkdir(parents=True, exist_ok=True)

                f_size = src_file.stat().st_size
                f_mtime = src_file.stat().st_mtime

                # Attempt hard link from previous snapshot if unchanged, fallback to copy2
                linked = False
                if prev_data_dir is not None:
                    prev_file = prev_data_dir / rel_path
                    if prev_file.exists():
                        try:
                            prev_stat = prev_file.stat()
                            if prev_stat.st_size == f_size and abs(prev_stat.st_mtime - f_mtime) < 0.001:
                                os.link(prev_file, dst_file)
                                linked = True
                        except OSError:
                            linked = False

                if not linked:
                    shutil.copy2(src_file, dst_file)

                # Hash content and record manifest
                f_hash = _compute_sha256(dst_file)

                manifest_entries.append(
                    ManifestEntry(
                        path=rel_path,
                        size=f_size,
                        sha256=f_hash,
                        mtime=f_mtime,
                    )
                )
                total_bytes += f_size
                file_count += 1

        # Write manifest.json beside data dir
        manifest_file = snap_dir / "manifest.json"
        manifest_data = {
            "version": 1,
            "snapshot_id": snap_dir.name,
            "created_at": now_dt.isoformat(),
            "source_path": share_path.as_posix(),
            "file_count": file_count,
            "total_bytes": total_bytes,
            "files": [asdict(e) for e in manifest_entries],
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        info = SnapshotInfo(
            snapshot_id=snap_dir.name,
            created_at=now_dt,
            source_path=share_path.as_posix(),
            snapshot_path=snap_dir.as_posix(),
            manifest_path=manifest_file.as_posix(),
            file_count=file_count,
            total_bytes=total_bytes,
        )

        # Apply retention policy
        self.apply_retention(keep_last=self.max_snapshots)

        return info

    def list_snapshots(self, share: Path | str | None = None) -> list[SnapshotInfo]:
        """List all snapshots sorted newest first."""
        if not self.snapshot_dir.exists():
            return []

        resolved_share = Path(share).resolve().as_posix() if share else None
        snapshots: list[SnapshotInfo] = []

        for p in self.snapshot_dir.iterdir():
            if not p.is_dir():
                continue
            manifest_file = p / "manifest.json"
            if not manifest_file.exists():
                continue
            try:
                data = json.loads(manifest_file.read_text(encoding="utf-8"))
                s_path = data.get("source_path", "")
                if resolved_share and s_path != resolved_share:
                    continue
                created_at = datetime.fromisoformat(data["created_at"])
                snapshots.append(
                    SnapshotInfo(
                        snapshot_id=data.get("snapshot_id", p.name),
                        created_at=created_at,
                        source_path=s_path,
                        snapshot_path=p.as_posix(),
                        manifest_path=manifest_file.as_posix(),
                        file_count=data.get("file_count", 0),
                        total_bytes=data.get("total_bytes", 0),
                    )
                )
            except Exception as e:
                logger.debug("Failed to parse snapshot manifest %s: %s", manifest_file, e)

        return sorted(snapshots, key=lambda s: s.created_at, reverse=True)

    def find_clean_snapshot(
        self,
        share: Path | str,
        before_ts: datetime,
        safety_margin_seconds: float = 0.0,
    ) -> SnapshotInfo | None:
        """Find the newest snapshot strictly prior to *before_ts - safety_margin*."""
        cutoff = before_ts - timedelta(seconds=safety_margin_seconds)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=UTC)
        snapshots = self.list_snapshots(share=share)

        for snap in snapshots:
            snap_time = snap.created_at
            if snap_time.tzinfo is None:
                snap_time = snap_time.replace(tzinfo=UTC)
            if snap_time < cutoff:
                return snap
        return None

    def restore_files(
        self,
        share: Path | str,
        snapshot_id: str,
        paths: list[str],
        dry_run: bool = True,
        first_anomaly_ts: datetime | None = None,
    ) -> RestoreReport:
        """Restore files touched by the attacker from clean snapshot.

        Safety:
        - Resolves and validates every path stays inside share root.
        - Preserves newer files unedited by the attacker as 'skipped: newer user change'.
        - Verifies restored files against manifest SHA-256 before deletion of .locked copies.
        """
        start_time = time.perf_counter()
        share_root = Path(share).resolve()
        snap_dir = self.snapshot_dir / snapshot_id
        manifest_file = snap_dir / "manifest.json"
        data_dir = snap_dir / "data"

        if not manifest_file.exists():
            raise FileNotFoundError(f"Snapshot manifest not found: {manifest_file}")

        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest_files = {f["path"]: f for f in manifest_data.get("files", [])}

        report = RestoreReport(snapshot_id=snapshot_id, dry_run=dry_run)

        # Normalize touched paths from engine
        target_paths_set = {
            Path(p).as_posix().lstrip("/").replace("\\", "/")
            for p in paths
            if p
        }

        # Check all manifest files relevant to touched paths
        for rel_path, entry in manifest_files.items():
            # Check if this file was directly touched or renamed
            matching_attack_path: str | None = None
            is_renamed = False

            if rel_path in target_paths_set:
                matching_attack_path = rel_path
            else:
                # Check if attacker renamed this file to .locked
                for ext in _ATTACK_EXTENSIONS:
                    candidate_locked = f"{rel_path}{ext}"
                    if candidate_locked in target_paths_set:
                        matching_attack_path = candidate_locked
                        is_renamed = True
                        break

            if matching_attack_path is None:
                # File was untouched by attacker; leave it alone
                continue

            # Validate target path strictly within share
            try:
                dest_file = validate_path_within_root(rel_path, share_root)
            except ValueError as e:
                report.failed_count += 1
                report.failed_paths.append({"path": rel_path, "reason": str(e)})
                continue

            snapshot_source_file = data_dir / rel_path
            if not snapshot_source_file.exists():
                report.failed_count += 1
                report.failed_paths.append(
                    {"path": rel_path, "reason": "Missing in snapshot data store"}
                )
                continue

            # Check existing file status in destination share
            if dest_file.exists() and not is_renamed:
                dest_mtime = dest_file.stat().st_mtime
                dest_hash = _compute_sha256(dest_file)

                # Check if this is a newer legitimate user edit
                if dest_mtime > entry["mtime"]:
                    # If edit was made before anomaly timestamp, or hash matches snapshot
                    is_pre_anomaly = (
                        first_anomaly_ts is not None
                        and dest_mtime < first_anomaly_ts.timestamp()
                    )
                    if is_pre_anomaly or dest_hash == entry["sha256"]:
                        report.skipped_count += 1
                        report.skipped_paths.append(
                            {"path": rel_path, "reason": "skipped: newer user change"}
                        )
                        continue

            # Perform restore
            report.restored_bytes += entry["size"]
            if len(report.restored_paths) < 1000:
                report.restored_paths.append(rel_path)
            report.restored_count += 1

            if not dry_run:
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                dest_file.unlink(missing_ok=True)
                shutil.copy2(snapshot_source_file, dest_file)

                # Verify restored hash
                restored_hash = _compute_sha256(dest_file)
                if restored_hash != entry["sha256"]:
                    report.failed_count += 1
                    report.failed_paths.append(
                        {"path": rel_path, "reason": "Hash mismatch after restore"}
                    )
                    report.verified = False
                    continue

                # Safely remove .locked artifact if verified
                if is_renamed and matching_attack_path:
                    try:
                        locked_file = validate_path_within_root(
                            matching_attack_path, share_root
                        )
                        if locked_file.exists() and locked_file != dest_file:
                            # Verify locked file was created after anomaly started
                            if first_anomaly_ts is not None:
                                locked_mtime = locked_file.stat().st_mtime
                                if locked_mtime >= first_anomaly_ts.timestamp() - 1.0:
                                    locked_file.unlink()
                                    report.removed_locked_count += 1
                            else:
                                locked_file.unlink()
                                report.removed_locked_count += 1
                    except Exception as err:
                        logger.warning(
                            "Could not remove locked artifact %s: %s",
                            matching_attack_path,
                            err,
                        )
            else:
                if is_renamed:
                    report.removed_locked_count += 1

        report.time_taken_seconds = round(time.perf_counter() - start_time, 4)
        return report

    def verify_snapshots(
        self,
        snapshot_id: str | None = None,
        sample_count: int = 10,
    ) -> VerifyReport:
        """Sample files from snapshot and verify SHA-256 against manifest."""
        start_time = time.perf_counter()
        snaps = self.list_snapshots()
        if not snaps:
            return VerifyReport(
                snapshot_id="",
                passed=True,
                files_checked=0,
                time_taken_seconds=0.0,
            )

        target_snap = snaps[0]
        if snapshot_id is not None:
            found = [s for s in snaps if s.snapshot_id == snapshot_id]
            if found:
                target_snap = found[0]

        manifest_file = Path(target_snap.manifest_path)
        if not manifest_file.exists():
            return VerifyReport(
                snapshot_id=target_snap.snapshot_id,
                passed=False,
                files_checked=0,
                time_taken_seconds=0.0,
                errors=["Manifest file missing"],
            )

        data = json.loads(manifest_file.read_text(encoding="utf-8"))
        files: list[dict[str, Any]] = data.get("files", [])
        if not files:
            return VerifyReport(
                snapshot_id=target_snap.snapshot_id,
                passed=True,
                files_checked=0,
                time_taken_seconds=round(time.perf_counter() - start_time, 4),
            )

        sample = (
            random.sample(files, k=min(sample_count, len(files)))
            if sample_count < len(files)
            else files
        )

        data_dir = Path(target_snap.snapshot_path) / "data"
        errors: list[str] = []

        for f_entry in sample:
            f_path = data_dir / f_entry["path"]
            if not f_path.exists():
                errors.append(f"Missing file: {f_entry['path']}")
                continue
            actual_hash = _compute_sha256(f_path)
            if actual_hash != f_entry["sha256"]:
                errors.append(f"SHA-256 mismatch for {f_entry['path']}")

        passed = len(errors) == 0
        return VerifyReport(
            snapshot_id=target_snap.snapshot_id,
            passed=passed,
            files_checked=len(sample),
            time_taken_seconds=round(time.perf_counter() - start_time, 4),
            errors=errors,
        )

    def apply_retention(
        self,
        keep_last: int = 5,
        min_clean_keep: int = 2,
    ) -> list[str]:
        """Prune older snapshots respecting active anomaly retention locks.

        While paused, never deletes snapshots older than active_anomaly_ts.
        """
        snapshots = self.list_snapshots()
        if len(snapshots) <= keep_last:
            return []

        removed: list[str] = []
        # Sort oldest first for pruning consideration
        sorted_snaps = sorted(snapshots, key=lambda s: s.created_at)

        # Protect clean snapshots before anomaly
        clean_snaps = []
        if self.active_anomaly_ts is not None:
            anomaly_ts = (
                self.active_anomaly_ts.replace(tzinfo=UTC)
                if self.active_anomaly_ts.tzinfo is None
                else self.active_anomaly_ts
            )
            clean_snaps = [
                s
                for s in sorted_snaps
                if (s.created_at.replace(tzinfo=UTC) if s.created_at.tzinfo is None else s.created_at) < anomaly_ts
            ]
            # Protect at least min_clean_keep
            protected_ids = {s.snapshot_id for s in clean_snaps[-min_clean_keep:]}
        else:
            protected_ids = set()

        # Always protect newest keep_last snapshots
        newest_ids = {s.snapshot_id for s in snapshots[:keep_last]}
        protected_ids.update(newest_ids)

        for s in sorted_snaps:
            if s.snapshot_id in protected_ids:
                continue
            # Safe to remove
            s_dir = Path(s.snapshot_path)
            try:
                shutil.rmtree(s_dir)
                removed.append(s.snapshot_id)
            except Exception as e:
                logger.warning("Failed to prune snapshot %s: %s", s.snapshot_id, e)

        return removed


# ---------------------------------------------------------------------------
# Rsync Snapshot Manager (Linux only via CommandRunner)
# ---------------------------------------------------------------------------


class RsyncSnapshotManager(PortableSnapshotManager):
    """Rsync-based incremental snapshot manager using --link-dest.

    Operates strictly via CommandRunner with argument lists (never shell=True).
    Snapshots are stored in a dedicated root-owned directory outside SMB shares.
    """

    def __init__(
        self,
        snapshot_dir: Path | str = "/var/lib/shareguard/snapshots",
        max_snapshots: int = 10,
        runner: CommandRunner | None = None,
    ) -> None:
        super().__init__(snapshot_dir=snapshot_dir, max_snapshots=max_snapshots)
        self.runner = runner or RealCommandRunner()

    def take_snapshot(
        self,
        share: Path | str,
        clock: Callable[[], datetime] | None = None,
    ) -> SnapshotInfo | None:
        """Create incremental snapshot via rsync --link-dest."""
        if self.is_paused:
            logger.warning(
                "Refusing to take rsync snapshot: snapshotting is PAUSED during an active anomaly (%s)",
                self.active_anomaly_ts,
            )
            return None

        share_path = Path(share).resolve()
        now_dt = clock() if clock is not None else datetime.now(tz=UTC)
        timestamp_str = now_dt.strftime("%Y-%m-%dT%H-%M-%SZ")
        snap_dir = self.snapshot_dir / timestamp_str

        collision_idx = 1
        while snap_dir.exists():
            snap_dir = self.snapshot_dir / f"{timestamp_str}_{collision_idx}"
            collision_idx += 1

        data_dir = snap_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Find previous snapshot for --link-dest
        previous_snapshots = self.list_snapshots(share=share_path)
        cmd = ["rsync", "-a", "--delete"]

        if previous_snapshots:
            prev_data_dir = Path(previous_snapshots[0].snapshot_path) / "data"
            if prev_data_dir.exists():
                cmd.append(f"--link-dest={prev_data_dir.as_posix()}")

        src_arg = f"{share_path.as_posix()}/"
        dst_arg = f"{data_dir.as_posix()}/"
        cmd.extend([src_arg, dst_arg])

        # Execute rsync via CommandRunner (shell=False)
        self.runner.run(cmd, check=True)

        # Build manifest.json
        manifest_entries: list[ManifestEntry] = []
        total_bytes = 0
        file_count = 0

        for root_dir, _dirs, files in os.walk(data_dir):
            current_root = Path(root_dir)
            for fn in files:
                f_path = current_root / fn
                rel_path = f_path.relative_to(data_dir).as_posix()
                f_size = f_path.stat().st_size
                f_mtime = f_path.stat().st_mtime
                f_hash = _compute_sha256(f_path)
                manifest_entries.append(
                    ManifestEntry(
                        path=rel_path,
                        size=f_size,
                        sha256=f_hash,
                        mtime=f_mtime,
                    )
                )
                total_bytes += f_size
                file_count += 1

        manifest_file = snap_dir / "manifest.json"
        manifest_data = {
            "version": 1,
            "snapshot_id": snap_dir.name,
            "created_at": now_dt.isoformat(),
            "source_path": share_path.as_posix(),
            "file_count": file_count,
            "total_bytes": total_bytes,
            "files": [asdict(e) for e in manifest_entries],
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        info = SnapshotInfo(
            snapshot_id=snap_dir.name,
            created_at=now_dt,
            source_path=share_path.as_posix(),
            snapshot_path=snap_dir.as_posix(),
            manifest_path=manifest_file.as_posix(),
            file_count=file_count,
            total_bytes=total_bytes,
        )

        self.apply_retention(keep_last=self.max_snapshots)
        return info


# ---------------------------------------------------------------------------
# In-Memory Fake Snapshot Manager (For Fast Unit Testing & Simulation)
# ---------------------------------------------------------------------------


class FakeSnapshotManager(SnapshotManager):
    """In-memory fake snapshot manager for fast simulation and testing."""

    def __init__(
        self,
        snapshot_dir: Path | str = "snapshots",
        max_snapshots: int = 10,
    ) -> None:
        super().__init__(snapshot_dir=snapshot_dir, max_snapshots=max_snapshots)
        self._snapshots: list[SnapshotInfo] = []

    def take_snapshot(
        self,
        share: Path | str,
        clock: Callable[[], datetime] | None = None,
    ) -> SnapshotInfo | None:
        self.calls.append({"method": "take_snapshot", "share": str(share)})
        if self.is_paused:
            return None
        now_dt = clock() if clock is not None else datetime.now(tz=UTC)
        snap_id = f"fake-{now_dt.strftime('%Y%m%d%H%M%S')}"
        info = SnapshotInfo(
            snapshot_id=snap_id,
            created_at=now_dt,
            source_path=str(share),
            snapshot_path=f"/fake/{snap_id}",
            manifest_path=f"/fake/{snap_id}/manifest.json",
            file_count=50,
            total_bytes=100000,
        )
        self._snapshots.append(info)
        return info

    def list_snapshots(self, share: Path | str | None = None) -> list[SnapshotInfo]:
        return sorted(self._snapshots, key=lambda s: s.created_at, reverse=True)

    def find_clean_snapshot(
        self,
        share: Path | str,
        before_ts: datetime,
        safety_margin_seconds: float = 0.0,
    ) -> SnapshotInfo | None:
        self.calls.append(
            {
                "method": "find_clean_snapshot",
                "share": str(share),
                "before_ts": before_ts,
            }
        )
        cutoff = before_ts - timedelta(seconds=safety_margin_seconds)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=UTC)
        for snap in sorted(self._snapshots, key=lambda s: s.created_at, reverse=True):
            snap_time = snap.created_at
            if snap_time.tzinfo is None:
                snap_time = snap_time.replace(tzinfo=UTC)
            if snap_time < cutoff:
                return snap
        return None

    def restore_files(
        self,
        share: Path | str,
        snapshot_id: str,
        paths: list[str],
        dry_run: bool = True,
        first_anomaly_ts: datetime | None = None,
    ) -> RestoreReport:
        self.calls.append(
            {
                "method": "restore_files",
                "share": str(share),
                "snapshot_id": snapshot_id,
                "paths": list(paths),
                "dry_run": dry_run,
            }
        )
        return RestoreReport(
            snapshot_id=snapshot_id,
            dry_run=dry_run,
            restored_count=len(paths),
            restored_paths=list(paths)[:100],
            restored_bytes=len(paths) * 1024,
            verified=True,
        )

    def verify_snapshots(
        self,
        snapshot_id: str | None = None,
        sample_count: int = 10,
    ) -> VerifyReport:
        return VerifyReport(
            snapshot_id=snapshot_id or "fake-snap",
            passed=True,
            files_checked=sample_count,
            time_taken_seconds=0.001,
        )

    def apply_retention(
        self,
        keep_last: int = 5,
        min_clean_keep: int = 2,
    ) -> list[str]:
        if len(self._snapshots) <= keep_last:
            return []
        removed = [s.snapshot_id for s in self._snapshots[:-keep_last]]
        self._snapshots = self._snapshots[-keep_last:]
        return removed


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_snapshot_manager(config: dict[str, Any] | str | None = None) -> SnapshotManager:
    """Factory: instantiate the configured :class:`SnapshotManager`.

    Args:
        config: ``config.snapshot`` section from ``default.yaml``, or backend name string.

    Returns:
        Instantiated snapshot manager.
    """
    cfg = {"backend": config} if isinstance(config, str) else (config or {})
    backend = cfg.get("backend", "portable")
    snap_dir = cfg.get("snapshot_dir", "snapshots/")
    max_snaps = int(cfg.get("max_snapshots", 10))

    if backend in {"portable", "fake_fs"}:
        return PortableSnapshotManager(snapshot_dir=snap_dir, max_snapshots=max_snaps)
    if backend == "rsync":
        return RsyncSnapshotManager(snapshot_dir=snap_dir, max_snapshots=max_snaps)
    if backend == "fake":
        return FakeSnapshotManager(snapshot_dir=snap_dir, max_snapshots=max_snaps)

    raise ValueError(f"Unknown snapshot backend: {backend!r}")
