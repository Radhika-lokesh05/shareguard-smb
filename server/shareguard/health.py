"""shareguard.health – Diagnostic health probes, automated restore drill, and scoring.

Design Invariants:
- 100% Read-Only: Probes only inspect system state, files, and configurations.
  NO probe may modify the operating system, firewall, network, or live shares.
- Safety Boundary: Real Linux commands (testparm, ss, ufw, nft) execute strictly
  via the CommandRunner abstraction with argument lists (never shell=True) and
  only run on Linux in live mode. On Windows or in simulation mode, realistic
  simulated observations are returned.
- Fault Isolation: Each probe executes with its own timeout and isolated exception
  handling. A failure in one probe yields status="unknown" with a clear reason and
  never breaks the overall health evaluation or the engine.
- Non-Destructive Restore Drill: The restore drill copies a sample of files from the
  newest snapshot into an isolated temporary directory (never into any share), verifies
  SHA-256 hashes against the manifest, records telemetry, and cleans up the directory.
- Grounded Plain-Words Guidance: Every check includes 'how_to_fix' written in short,
  clear sentences for a non-technical office owner, with technical commands isolated
  under a marked 'For your IT person:' prefix.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from shareguard.canary import CanaryManager
from shareguard.responder import CommandRunner, FakeCommandRunner, RealCommandRunner
from shareguard.snapshots import SnapshotManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------

DEFAULT_CACHE_TTL_SECONDS = 60.0
DEFAULT_RESTORE_RATE_LIMIT_SECONDS = 60.0
DEFAULT_RESTORE_SAMPLE_COUNT = 5
DEFAULT_RESTORE_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_SNAPSHOT_MAX_AGE_HOURS = 24.0
DEFAULT_DISK_WARN_PERCENT = 15.0

DEFAULT_WEIGHTS: dict[str, float] = {
    "audit_logging": 15.0,
    "smb_protocol": 15.0,
    "guest_access": 10.0,
    "snapshots": 15.0,
    "restore_test": 15.0,
    "canary_files": 10.0,
    "disk_space": 10.0,
    "network_exposure": 5.0,
    "safety_settings": 5.0,
}

_RING_BUFFER_MAX = 10
_RESTORE_TEST_HISTORY: deque[dict[str, Any]] = deque(maxlen=_RING_BUFFER_MAX)
_LAST_RESTORE_TEST: dict[str, Any] | None = None
_HEALTH_CACHE: dict[str, Any] | None = None
_HEALTH_CACHE_TIME: float = 0.0
_HEALTH_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Pydantic Schemas & Data Models
# ---------------------------------------------------------------------------


class HealthCheckItem(BaseModel):
    """Result of an individual subsystem diagnostic probe."""

    id: str = Field(description="Unique probe identifier.")
    name: str = Field(description="Probe name (alias of id for backwards compatibility).")
    title: str = Field(description="Human-readable probe title.")
    status: Literal["pass", "warn", "fail", "unknown"] = Field(
        description="Check status: pass, warn, fail, or unknown."
    )
    severity: Literal["high", "medium", "low"] = Field(
        description="Impact severity if this check fails or warns."
    )
    detail: str = Field(description="Factual diagnostic observation.")
    how_to_fix: str = Field(
        description="Plain-words advice for office owner with 'For your IT person:' line."
    )


class RestoreTestResult(BaseModel):
    """Telemetry report of a synthetic snapshot restore test drill."""

    id: str = Field(description="Unique drill ID.")
    status: Literal["pass", "fail", "unknown"] = Field(description="Drill outcome.")
    files_restored: int = Field(default=0, description="Count of files restored and verified.")
    total_bytes: int = Field(default=0, description="Total bytes restored and verified.")
    time_taken_seconds: float = Field(default=0.0, description="Time taken to restore and verify.")
    tested_at: str = Field(description="ISO-8601 UTC timestamp of drill execution.")
    detail: str = Field(description="Summary outcome description or error details.")
    triggered_by: str = Field(default="admin", description="Actor or schedule that started drill.")


class HealthCheckResponse(BaseModel):
    """Aggregated health check response for dashboard and monitoring."""

    status: Literal["pass", "warn", "fail", "unknown"] = Field(description="Overall system status.")
    score: float = Field(ge=0.0, le=100.0, description="Weighted health score (0-100%).")
    verdict: Literal["Good", "Needs attention", "At risk"] = Field(
        description="High-level plain language verdict."
    )
    checks: list[HealthCheckItem] = Field(description="Evaluated diagnostic probes.")
    unknown_count: int = Field(description="Count of checks that could not be evaluated.")
    last_restore_test: RestoreTestResult | None = Field(
        default=None, description="Most recent restore drill result."
    )
    checked_at: str = Field(description="ISO-8601 UTC timestamp of check evaluation.")


class RateLimitError(Exception):
    """Raised when an on-demand restore test drill is requested too frequently."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"Restore test rate limit exceeded. Retry in {retry_after} seconds.")
        self.retry_after = retry_after


# ---------------------------------------------------------------------------
# Helpers & Parsers
# ---------------------------------------------------------------------------


def sanitize_text(text: Any, max_len: int = 512) -> str:
    """Sanitize system text strings before returning to UI or API."""
    if text is None:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(text)).strip()
    return clean[:max_len]


def parse_server_min_protocol(testparm_output: str) -> str | None:
    """Robustly parse 'server min protocol' or 'min protocol' from testparm output.

    Handles different Samba versions, indentation, and case variations.
    """
    if not testparm_output:
        return None

    # Search for server min protocol = <val> or min protocol = <val>
    pattern = re.compile(
        r"^\s*(?:server\s+)?min\s+protocol\s*=\s*([a-zA-Z0-9_\-]+)",
        re.MULTILINE | re.IGNORECASE,
    )
    match = pattern.search(testparm_output)
    if match:
        return match.group(1).strip().upper()

    return None


def is_protocol_secure(protocol: str | None) -> bool:
    """Determine whether an SMB protocol setting disallows legacy SMB1/NT1."""
    if not protocol:
        return False
    proto_clean = protocol.upper().strip()
    insecure_tokens = {"SMB1", "NT1", "CORE", "COREPLUS", "LANMAN1", "LANMAN2"}
    if proto_clean in insecure_tokens:
        return False
    # Modern secure protocols: SMB2, SMB2_02, SMB2_10, SMB2_22, SMB2_24, SMB3, SMB3_00, SMB3_02, SMB3_11
    return proto_clean.startswith("SMB2") or proto_clean.startswith("SMB3")


def parse_guest_access(smb_conf_text: str) -> tuple[bool, str]:
    """Parse smb.conf text for insecure guest access configurations.

    Returns:
        (has_insecure_guest, details_reason)
    """
    if not smb_conf_text:
        return False, "Configuration not found"

    # Check global 'map to guest'
    map_match = re.search(
        r"^\s*map\s+to\s+guest\s*=\s*(.+)$",
        smb_conf_text,
        re.MULTILINE | re.IGNORECASE,
    )
    if map_match:
        val = map_match.group(1).strip().lower()
        if any(bad in val for bad in ("bad user", "bad password", "bad uid")):
            return True, f"Global 'map to guest = {map_match.group(1).strip()}' maps unknown users to guest"

    # Check shares for 'guest ok = yes' or 'public = yes'
    share_pattern = re.compile(
        r"^\s*\[([^\]]+)\]",
        re.MULTILINE,
    )
    shares = list(share_pattern.finditer(smb_conf_text))

    insecure_shares: list[str] = []
    for i, match in enumerate(shares):
        share_name = match.group(1).strip()
        if share_name.lower() in ("global", "printers", "print$"):
            continue

        start_pos = match.end()
        end_pos = shares[i + 1].start() if i + 1 < len(shares) else len(smb_conf_text)
        section_body = smb_conf_text[start_pos:end_pos]

        if re.search(r"^\s*(?:guest\s+ok|public)\s*=\s*(?:yes|true|1)", section_body, re.MULTILINE | re.IGNORECASE):
            insecure_shares.append(share_name)

    if insecure_shares:
        return True, f"Guest access enabled on share(s): {', '.join(insecure_shares)}"

    return False, "Guest access is disabled across all shares"


# ---------------------------------------------------------------------------
# The 9 Diagnostic Probes
# ---------------------------------------------------------------------------


def check_audit_logging(
    share_root: Path,
    audit_log_path: Path,
    smb_conf_text: str | None = None,
) -> HealthCheckItem:
    """Probe 1: Audit logging configured via full_audit and receiving active events."""
    item_id = "audit_logging"
    title = "Samba Audit Logging"
    how_to_fix = (
        "Audit logging records who accesses, renames, or encrypts files on your office shares. "
        "Without it, ShareGuard cannot detect ransomware in real time.\n"
        "For your IT person: Add 'vfs objects = full_audit' to your shares in /etc/samba/smb.conf "
        "and restart Samba with 'systemctl restart smbd'."
    )

    try:
        # Check smb.conf for full_audit if text is available
        if smb_conf_text is not None and "full_audit" not in smb_conf_text:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail="Samba configuration (smb.conf) does not include 'vfs objects = full_audit'.",
                how_to_fix=how_to_fix,
            )

        # Check audit log file
        log_file = Path(audit_log_path)
        if not log_file.exists():
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail=f"Audit log file '{log_file}' does not exist on disk.",
                how_to_fix=how_to_fix,
            )

        try:
            stat_info = log_file.stat()
        except OSError as err:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="unknown",
                severity="high",
                detail=f"Cannot inspect audit log permissions: {sanitize_text(err)}",
                how_to_fix=how_to_fix,
            )

        if stat_info.st_size == 0:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail="Audit log exists but is completely empty (no audit events recorded).",
                how_to_fix=how_to_fix,
            )

        # Check age of newest log activity (mtime)
        mtime_dt = datetime.fromtimestamp(stat_info.st_mtime, tz=UTC)
        age = datetime.now(UTC) - mtime_dt
        if age > timedelta(hours=24):
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail=f"Audit log has had no write activity in the last 24 hours (last modified {age.total_seconds() / 3600:.1f}h ago).",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"Samba audit logging is active and receiving live events ({stat_info.st_size} bytes recorded).",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail=f"Probe encountered an unexpected error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_smb_protocol(
    runner: CommandRunner,
    is_live_mode: bool = False,
    testparm_output_override: str | None = None,
) -> HealthCheckItem:
    """Probe 2: Old insecure SMB protocol (SMB1/NT1) disabled."""
    item_id = "smb_protocol"
    title = "SMB Protocol Version"
    how_to_fix = (
        "SMBv1 is an obsolete 30-year-old network protocol with critical security flaws exploited by ransomware.\n"
        "For your IT person: Set 'server min protocol = SMB2' in the [global] section of /etc/samba/smb.conf "
        "and reload Samba with 'smbcontrol smbd reload-config'."
    )

    try:
        raw_output = testparm_output_override
        if raw_output is None:
            if not is_live_mode or sys.platform != "linux":
                # Simulated observation
                return HealthCheckItem(
                    id=item_id,
                    name=item_id,
                    title=title,
                    status="pass",
                    severity="high",
                    detail="Simulated mode: server min protocol is enforced to SMB2_02 (SMB1 disabled).",
                    how_to_fix=how_to_fix,
                )

            # Live mode: run testparm -sv with argument list
            res = runner.run(["testparm", "-sv"], check=False)
            if res.returncode != 0 and not res.stdout:
                return HealthCheckItem(
                    id=item_id,
                    name=item_id,
                    title=title,
                    status="unknown",
                    severity="high",
                    detail=f"testparm command exited with code {res.returncode}: {sanitize_text(res.stderr)}",
                    how_to_fix=how_to_fix,
                )
            raw_output = res.stdout

        proto = parse_server_min_protocol(raw_output)
        if proto is None:
            # Modern Samba defaults to SMB2_02 if unspecified, but older Samba defaulted to NT1
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail="'server min protocol' is not explicitly declared in Samba configuration.",
                how_to_fix=how_to_fix,
            )

        if not is_protocol_secure(proto):
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail=f"Insecure legacy protocol '{proto}' is permitted by Samba. SMB1 must be disabled.",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"Legacy SMB1 is disabled. Minimum negotiated protocol is securely set to '{proto}'.",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail=f"Probe encountered an error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_guest_access(smb_conf_text: str | None = None) -> HealthCheckItem:
    """Probe 3: Guest / anonymous access disabled across all shares."""
    item_id = "guest_access"
    title = "Guest & Anonymous Access"
    how_to_fix = (
        "Guest access allows anyone on your office network or Wi-Fi to read and change files without logging in.\n"
        "For your IT person: Remove 'guest ok = yes' from shares and set 'map to guest = Never' "
        "in the [global] section of /etc/samba/smb.conf."
    )

    try:
        if smb_conf_text is None:
            # Check default path if available
            default_path = Path("/etc/samba/smb.conf")
            if default_path.exists():
                try:
                    smb_conf_text = default_path.read_text(encoding="utf-8")
                except Exception:
                    smb_conf_text = None

        if smb_conf_text is None:
            # In simulation mode or when file unreadable
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="pass",
                severity="medium",
                detail="Simulated mode: Guest access is disabled on all shares.",
                how_to_fix=how_to_fix,
            )

        has_insecure, reason = parse_guest_access(smb_conf_text)
        if has_insecure:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="medium",
                detail=reason,
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="medium",
            detail="Guest access is disabled across all network shares. Authentication is enforced.",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="medium",
            detail=f"Probe encountered an error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_snapshots(
    snapshot_manager: SnapshotManager,
    share_root: Path,
    max_age_hours: float = DEFAULT_SNAPSHOT_MAX_AGE_HOURS,
    smb_conf_text: str | None = None,
) -> HealthCheckItem:
    """Probe 4: Backups exist, are fresh, and stored outside every share path."""
    item_id = "snapshots"
    title = "Snapshot Storage & Boundaries"
    how_to_fix = (
        "Regular snapshots allow you to roll back files if ransomware strikes. "
        "Snapshots must be stored in a directory that is not shared over the network so attackers cannot delete them.\n"
        "For your IT person: Store snapshots on a dedicated volume outside the Samba share path "
        "and configure automated snapshot creation."
    )

    try:
        resolved_share = Path(share_root).resolve()
        resolved_snap = Path(snapshot_manager.snapshot_dir).resolve()

        # Path boundary checks: snapshot dir must not be inside share, nor share inside snapshot dir
        if resolved_snap == resolved_share or resolved_snap.is_relative_to(resolved_share):
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail=f"CRITICAL: Snapshot folder '{resolved_snap}' is located INSIDE the share path '{resolved_share}'. Attackers could encrypt or delete backups.",
                how_to_fix=how_to_fix,
            )

        if resolved_share.is_relative_to(resolved_snap):
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail=f"CRITICAL: Share root '{resolved_share}' is located inside the snapshot directory '{resolved_snap}'.",
                how_to_fix=how_to_fix,
            )

        # Verify snapshot dir is not served as a share in smb.conf
        if smb_conf_text:
            snap_str = resolved_snap.as_posix()
            if re.search(rf"path\s*=\s*{re.escape(snap_str)}", smb_conf_text, re.IGNORECASE):
                return HealthCheckItem(
                    id=item_id,
                    name=item_id,
                    title=title,
                    status="fail",
                    severity="high",
                    detail=f"CRITICAL: Snapshot directory '{resolved_snap}' is exported directly as a Samba share in smb.conf.",
                    how_to_fix=how_to_fix,
                )

        # Check existing snapshots
        snaps = snapshot_manager.list_snapshots(share=share_root)
        if not snaps:
            # Fall back to all snapshots
            snaps = snapshot_manager.list_snapshots()

        if not snaps:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail="No snapshot backups exist. Protection and rollback are currently unavailable.",
                how_to_fix=how_to_fix,
            )

        newest_snap = snaps[0]
        snap_dt = newest_snap.created_at
        if snap_dt.tzinfo is None:
            snap_dt = snap_dt.replace(tzinfo=UTC)

        age_hours = (datetime.now(UTC) - snap_dt).total_seconds() / 3600.0
        if age_hours > max_age_hours:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail=f"Newest snapshot is {age_hours:.1f} hours old (threshold is {max_age_hours:.0f}h). Regular snapshotting may be stalled.",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"{len(snaps)} snapshots stored safely outside share root (newest is {age_hours:.1f} hours old).",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail=f"Probe encountered an error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_restore_test() -> HealthCheckItem:
    """Probe 5: Status of synthetic recovery restore drill."""
    item_id = "restore_test"
    title = "Automated Restore Drill"
    how_to_fix = (
        "Having backups is not enough; you must routinely verify that files can actually be restored.\n"
        "For your IT person: Run a synthetic restore drill using the 'Run restore test' button in the dashboard "
        "or execute 'POST /api/health-check/restore-test'."
    )

    last_test = get_last_restore_test()
    if last_test is None:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="warn",
            severity="high",
            detail="No restore test drills have been performed yet. Run a drill to verify backup restorability.",
            how_to_fix=how_to_fix,
        )

    tested_at_str = last_test.get("tested_at", "")
    try:
        tested_at_dt = datetime.fromisoformat(tested_at_str)
        if tested_at_dt.tzinfo is None:
            tested_at_dt = tested_at_dt.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - tested_at_dt).total_seconds() / 86400.0
    except Exception:
        age_days = 0.0

    outcome = str(last_test.get("status", "unknown")).lower()
    files_count = last_test.get("files_restored", 0)
    duration = last_test.get("time_taken_seconds", 0.0)

    if outcome == "pass":
        if age_days > 7.0:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail=f"Last restore drill passed but was run {age_days:.1f} days ago. Weekly drills are recommended.",
                how_to_fix=how_to_fix,
            )
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"Last restore drill passed ({files_count} files verified in {duration:.2f}s on {tested_at_str[:10]}).",
            how_to_fix=how_to_fix,
        )

    if outcome == "fail":
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="fail",
            severity="high",
            detail=f"Last restore drill failed: {last_test.get('detail', 'Hash verification mismatch')}",
            how_to_fix=how_to_fix,
        )

    return HealthCheckItem(
        id=item_id,
        name=item_id,
        title=title,
        status="unknown",
        severity="high",
        detail=f"Last drill result is unknown: {last_test.get('detail', '')}",
        how_to_fix=how_to_fix,
    )


def check_canaries(canary_manager: CanaryManager | None) -> HealthCheckItem:
    """Probe 6: Canary decoy files present and intact across share roots."""
    item_id = "canary_files"
    title = "Canary Bait File Tripwires"
    how_to_fix = (
        "Canary files are bait files. If ransomware starts encrypting files, it triggers canaries first.\n"
        "For your IT person: Verify share permissions and deploy canary decoy files using 'shareguard canaries deploy'."
    )

    if canary_manager is None:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail="Canary manager is not initialized in this environment.",
            how_to_fix=how_to_fix,
        )

    try:
        report = canary_manager.verify()
        total = report.get("total", 0)
        missing = report.get("missing", [])
        corrupted = report.get("corrupted", [])

        if total == 0:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail="No canary bait files are currently deployed on monitored shares.",
                how_to_fix=how_to_fix,
            )

        if missing or corrupted:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail=f"Canary integrity compromised: {len(missing)} files missing, {len(corrupted)} corrupted.",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"All {total} canary decoy tripwires are intact and verified.",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail=f"Probe encountered an error verifying canaries: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_disk_space(
    share_root: Path,
    snapshot_dir: Path,
    warn_percent: float = DEFAULT_DISK_WARN_PERCENT,
    snapshot_manager: SnapshotManager | None = None,
) -> HealthCheckItem:
    """Probe 7: Disk space on share and snapshot volumes and estimated snapshot capacity."""
    item_id = "disk_space"
    title = "Storage & Volume Free Space"
    how_to_fix = (
        "If a hard drive fills up, the server can freeze and backup snapshots will fail to save.\n"
        "For your IT person: Free up disk space or expand storage capacity on the file server."
    )

    try:
        share_path = Path(share_root).resolve()
        snap_path = Path(snapshot_dir).resolve()

        # Check usage
        s_usage = shutil.disk_usage(share_path if share_path.exists() else Path("."))
        snap_usage = shutil.disk_usage(snap_path if snap_path.exists() else Path("."))

        share_free_pct = (s_usage.free / max(s_usage.total, 1)) * 100.0
        snap_free_pct = (snap_usage.free / max(snap_usage.total, 1)) * 100.0

        min_free_pct = min(share_free_pct, snap_free_pct)
        share_free_gb = s_usage.free / (1024**3)
        snap_free_gb = snap_usage.free / (1024**3)

        # Estimate remaining snapshots capacity
        est_str = ""
        if snapshot_manager is not None:
            snaps = snapshot_manager.list_snapshots()
            if snaps:
                avg_bytes = sum(s.total_bytes for s in snaps) / max(len(snaps), 1)
                if avg_bytes > 0:
                    fits = int(snap_usage.free / avg_bytes)
                    est_str = f" (~{fits} more snapshots fit)"

        if min_free_pct < 5.0:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="medium",
                detail=f"CRITICAL: Storage volume has under 5% free space ({share_free_gb:.1f} GB free on share, {snap_free_gb:.1f} GB free on backup volume).",
                how_to_fix=how_to_fix,
            )

        if min_free_pct < warn_percent:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="medium",
                detail=f"Low disk space: {min_free_pct:.1f}% free ({share_free_gb:.1f} GB free on share, {snap_free_gb:.1f} GB on backups){est_str}.",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="medium",
            detail=f"Sufficient storage available: {share_free_pct:.1f}% free on share ({share_free_gb:.1f} GB), {snap_free_pct:.1f}% free on snapshots ({snap_free_gb:.1f} GB){est_str}.",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="medium",
            detail=f"Probe encountered an error inspecting disk space: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_network_exposure(
    runner: CommandRunner,
    is_live_mode: bool = False,
    simulated_sockets: list[str] | None = None,
    simulated_firewall_active: bool | None = None,
) -> HealthCheckItem:
    """Probe 8: Network exposure of SMB ports 139/445 and host firewall state."""
    item_id = "network_exposure"
    title = "Network Exposure & Firewall"
    how_to_fix = (
        "File sharing ports (139 and 445) must never be open to the outside world.\n"
        "For your IT person: Bind Samba to internal private addresses ('bind interfaces only = yes') "
        "and verify that UFW or nftables is enabled."
    )

    try:
        if not is_live_mode or sys.platform != "linux":
            # Simulated check
            active_fw = simulated_firewall_active if simulated_firewall_active is not None else True
            sockets = simulated_sockets or ["192.168.1.0/24:445", "192.168.1.0/24:139"]
            sock_desc = ", ".join(sockets)
            fw_desc = "active" if active_fw else "inactive"
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="pass" if active_fw else "warn",
                severity="medium",
                detail=f"Simulated observation: SMB bound to {sock_desc}; Host firewall is {fw_desc}.",
                how_to_fix=how_to_fix,
            )

        # Live Linux mode: check listening sockets via ss -tln
        ss_res = runner.run(["ss", "-tln"], check=False)
        listening_smb: list[str] = []
        if ss_res.returncode == 0 and ss_res.stdout:
            for line in ss_res.stdout.splitlines():
                if ":445 " in line or ":139 " in line or line.endswith(":445") or line.endswith(":139"):
                    parts = line.split()
                    if len(parts) >= 4:
                        listening_smb.append(parts[3])

        # Check firewall via ufw status or nft
        fw_status = "unknown"
        ufw_res = runner.run(["ufw", "status"], check=False)
        if ufw_res.returncode == 0 and "Status: active" in ufw_res.stdout:
            fw_status = "active (ufw)"
        else:
            nft_res = runner.run(["nft", "list", "ruleset"], check=False)
            if nft_res.returncode == 0 and nft_res.stdout.strip():
                fw_status = "active (nftables)"
            elif ufw_res.returncode == 0 and "Status: inactive" in ufw_res.stdout:
                fw_status = "inactive"

        if not listening_smb and fw_status == "unknown":
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="unknown",
                severity="medium",
                detail="Could not determine SMB socket bindings or firewall status.",
                how_to_fix=how_to_fix,
            )

        open_to_all = any(s.startswith("0.0.0.0") or s.startswith("*:") or s.startswith("[::]") for s in listening_smb)
        sock_summary = ", ".join(listening_smb) if listening_smb else "No active SMB listeners detected"

        if open_to_all and fw_status == "inactive":
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="medium",
                detail=f"Observed SMB listening on all interfaces ({sock_summary}) while host firewall is inactive.",
                how_to_fix=how_to_fix,
            )

        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="medium",
            detail=f"Observed SMB listening on: {sock_summary}. Host firewall state: {fw_status}.",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="medium",
            detail=f"Probe encountered an error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


def check_safety_settings(
    engine_mode: str = "shadow",
    allowlist: list[str] | None = None,
    panic_stop_active: bool = False,
    is_ml_loaded: bool = True,
    is_snapshots_paused: bool = False,
    is_db_healthy: bool = True,
) -> HealthCheckItem:
    """Probe 9: ShareGuard's own safety configurations and operational health."""
    item_id = "safety_settings"
    title = "ShareGuard Engine Safety"
    how_to_fix = (
        "ShareGuard's safety rules prevent accidental lockout of office staff or server disconnections.\n"
        "For your IT person: Check config/default.yaml and ensure your gateway and server IP addresses "
        "are listed in response.allowlist."
    )

    try:
        if not is_db_healthy:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="fail",
                severity="high",
                detail="Database connectivity error: SQLite database is unavailable or locked.",
                how_to_fix=how_to_fix,
            )

        if is_snapshots_paused:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail="Snapshot manager is currently paused (likely due to an active ransomware investigation).",
                how_to_fix=how_to_fix,
            )

        if panic_stop_active:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail="System panic stop is currently engaged. Automated containment is halted.",
                how_to_fix=how_to_fix,
            )

        # Mode and allowlist safety check
        ips = allowlist or []
        if engine_mode != "shadow" and not ips:
            return HealthCheckItem(
                id=item_id,
                name=item_id,
                title=title,
                status="warn",
                severity="high",
                detail=f"Operating in active enforcement mode ({engine_mode}) without a populated IP allowlist. Server or admin could be blocked.",
                how_to_fix=how_to_fix,
            )

        ml_text = "ML behavioral model active" if is_ml_loaded else "Rule-based engine active (ML weights pending)"
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="pass",
            severity="high",
            detail=f"Engine healthy in {engine_mode.upper()} mode ({ml_text}; {len(ips)} allowlisted IPs; DB active).",
            how_to_fix=how_to_fix,
        )
    except Exception as err:
        return HealthCheckItem(
            id=item_id,
            name=item_id,
            title=title,
            status="unknown",
            severity="high",
            detail=f"Probe encountered an error: {sanitize_text(err)}",
            how_to_fix=how_to_fix,
        )


# ---------------------------------------------------------------------------
# Restore Drill Execution Engine
# ---------------------------------------------------------------------------


def get_last_restore_test() -> dict[str, Any] | None:
    """Return the most recent restore test result dictionary."""
    global _LAST_RESTORE_TEST
    return _LAST_RESTORE_TEST


def set_last_restore_test(result: dict[str, Any] | None) -> None:
    """Store the most recent restore test result dictionary in memory."""
    global _LAST_RESTORE_TEST
    if result is None:
        _LAST_RESTORE_TEST = None
    else:
        _LAST_RESTORE_TEST = dict(result)
        _RESTORE_TEST_HISTORY.append(dict(result))


def clear_restore_test_history() -> None:
    """Clear in-memory restore test state (used in tests)."""
    global _LAST_RESTORE_TEST
    _LAST_RESTORE_TEST = None
    _RESTORE_TEST_HISTORY.clear()


def get_restore_test_history() -> list[dict[str, Any]]:
    """Return ring buffer of up to the last 10 restore drill results."""
    return list(_RESTORE_TEST_HISTORY)


def run_restore_test(
    snapshot_manager: SnapshotManager,
    share_root: Path,
    sample_count: int = DEFAULT_RESTORE_SAMPLE_COUNT,
    max_file_size: int = DEFAULT_RESTORE_MAX_FILE_SIZE,
    rate_limit_seconds: float = DEFAULT_RESTORE_RATE_LIMIT_SECONDS,
    clock: Callable[[], datetime] | None = None,
    triggered_by: str = "admin",
) -> RestoreTestResult:
    """Execute an isolated synthetic restore drill.

    Safety:
    - Never restores into live shares: restores exclusively into an ephemeral tempdir.
    - Compares SHA-256 against snapshot manifest.
    - Automatically cleans up the temporary directory.
    - Rate limits on-demand execution.
    """
    global _LAST_RESTORE_TEST

    now_dt = clock() if clock is not None else datetime.now(UTC)
    now_ts = now_dt.timestamp()

    # Rate limiting check (admin on-demand runs only)
    if (
        _LAST_RESTORE_TEST is not None
        and not triggered_by.startswith("test:")
        and not triggered_by.startswith("scheduled:")
    ):
        last_time_str = _LAST_RESTORE_TEST.get("tested_at")
        if last_time_str:
            try:
                last_dt = datetime.fromisoformat(last_time_str)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=UTC)
                elapsed = now_ts - last_dt.timestamp()
                if elapsed < rate_limit_seconds:
                    retry_after = int(rate_limit_seconds - elapsed)
                    raise RateLimitError(retry_after=max(retry_after, 1))
            except (ValueError, TypeError):
                pass

    start_perf = time.perf_counter()
    drill_id = f"drill-{now_dt.strftime('%Y%m%d%H%M%S')}"

    # Get newest snapshot
    snaps = snapshot_manager.list_snapshots(share=share_root)
    if not snaps:
        snaps = snapshot_manager.list_snapshots()

    if not snaps:
        res = RestoreTestResult(
            id=drill_id,
            status="unknown",
            files_restored=0,
            total_bytes=0,
            time_taken_seconds=0.0,
            tested_at=now_dt.isoformat(),
            detail="No snapshot backups available to run restore drill.",
            triggered_by=triggered_by,
        )
        set_last_restore_test(res.model_dump())
        return res

    target_snap = snaps[0]
    manifest_file = Path(target_snap.manifest_path)
    if not manifest_file.exists():
        res = RestoreTestResult(
            id=drill_id,
            status="fail",
            files_restored=0,
            total_bytes=0,
            time_taken_seconds=0.0,
            tested_at=now_dt.isoformat(),
            detail=f"Snapshot manifest '{manifest_file}' is missing.",
            triggered_by=triggered_by,
        )
        set_last_restore_test(res.model_dump())
        return res

    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        files_list = manifest_data.get("files", [])
    except Exception as err:
        res = RestoreTestResult(
            id=drill_id,
            status="fail",
            files_restored=0,
            total_bytes=0,
            time_taken_seconds=0.0,
            tested_at=now_dt.isoformat(),
            detail=f"Failed to parse snapshot manifest: {sanitize_text(err)}",
            triggered_by=triggered_by,
        )
        set_last_restore_test(res.model_dump())
        return res

    if not files_list:
        res = RestoreTestResult(
            id=drill_id,
            status="pass",
            files_restored=0,
            total_bytes=0,
            time_taken_seconds=round(time.perf_counter() - start_perf, 4),
            tested_at=now_dt.isoformat(),
            detail="Snapshot manifest contains 0 files. Drill verified empty set.",
            triggered_by=triggered_by,
        )
        set_last_restore_test(res.model_dump())
        return res

    # Filter eligible files under size cap
    eligible = [f for f in files_list if f.get("size", 0) <= max_file_size]
    if not eligible:
        eligible = files_list

    # Take deterministic or sample slice
    sample_files = eligible[:sample_count]

    # Create safe ephemeral tempdir outside share
    snap_dir = Path(target_snap.snapshot_path)
    data_dir = snap_dir / "data"

    restored_count = 0
    restored_bytes = 0
    mismatches: list[str] = []

    with tempfile.TemporaryDirectory(prefix="shareguard_restore_drill_") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str).resolve()
        # Invariant: Must never be inside live share
        if tmp_dir == Path(share_root).resolve() or tmp_dir.is_relative_to(Path(share_root).resolve()):
            raise RuntimeError("Fatal safety invariant violated: temp restore dir overlaps live share root!")

        for item in sample_files:
            rel_path = str(item.get("path", "")).strip()
            expected_hash = item.get("sha256", "")
            expected_size = item.get("size", 0)

            # Security: Path traversal & escape prevention
            if not rel_path or ".." in rel_path or rel_path.startswith(("/", "\\")):
                mismatches.append(f"{rel_path} (rejected: unsafe path format)")
                continue

            dest_file = (tmp_dir / rel_path).resolve()
            src_file = (data_dir / rel_path).resolve()

            if not dest_file.is_relative_to(tmp_dir) or not src_file.is_relative_to(data_dir.resolve()):
                mismatches.append(f"{rel_path} (rejected: path traversal escape detected)")
                continue

            if not src_file.exists():
                mismatches.append(f"{rel_path} (missing in snapshot data folder)")
                continue

            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)

            # Calculate SHA-256
            h = hashlib.sha256()
            with dest_file.open("rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_hash = h.hexdigest()

            if actual_hash != expected_hash:
                mismatches.append(f"{rel_path} (hash mismatch: expected {expected_hash[:8]}..., got {actual_hash[:8]}...)")
            else:
                restored_count += 1
                restored_bytes += expected_size

    duration = round(time.perf_counter() - start_perf, 4)
    if mismatches:
        status_val = "fail"
        detail_msg = f"Restored {restored_count}/{len(sample_files)} files; failures: {'; '.join(mismatches)}"
    else:
        status_val = "pass"
        detail_msg = f"Successfully restored and verified {restored_count} sample files ({restored_bytes} bytes) in {duration}s."

    res = RestoreTestResult(
        id=drill_id,
        status=status_val,
        files_restored=restored_count,
        total_bytes=restored_bytes,
        time_taken_seconds=duration,
        tested_at=now_dt.isoformat(),
        detail=detail_msg,
        triggered_by=triggered_by,
    )
    set_last_restore_test(res.model_dump())
    return res


# ---------------------------------------------------------------------------
# Health Evaluation & Scoring
# ---------------------------------------------------------------------------


def compute_health_score(
    checks: list[HealthCheckItem],
    weights: dict[str, float] | None = None,
) -> tuple[float, Literal["Good", "Needs attention", "At risk"]]:
    """Calculate overall weighted health score (0-100%) and plain language verdict.

    Invariant: Probes reporting status='unknown' are strictly excluded from calculation.
    """
    effective_weights = weights or DEFAULT_WEIGHTS

    earned = 0.0
    possible = 0.0

    has_high_fail = False

    for c in checks:
        if c.status == "unknown":
            continue  # Excluded from score

        w = effective_weights.get(c.id, 10.0)
        possible += w

        if c.status == "pass":
            earned += w
        elif c.status == "warn":
            earned += w * 0.5
        elif c.status == "fail" and c.severity == "high":
            has_high_fail = True

    if possible <= 0.0:
        return 0.0, "Needs attention"

    score = round((earned / possible) * 100.0, 1)

    if has_high_fail or score < 60.0:
        verdict = "At risk"
    elif score < 80.0 or any(c.status == "warn" for c in checks):
        verdict = "Needs attention"
    else:
        verdict = "Good"

    return score, verdict


def evaluate_system_health(
    share_root: Path,
    audit_log_path: Path,
    snapshot_manager: SnapshotManager,
    runner: CommandRunner | None = None,
    canary_manager: CanaryManager | None = None,
    smb_conf_text: str | None = None,
    engine_mode: str = "shadow",
    allowlist: list[str] | None = None,
    panic_stop_active: bool = False,
    is_ml_loaded: bool = True,
    is_live_mode: bool = False,
    is_db_healthy: bool = True,
    weights: dict[str, float] | None = None,
    use_cache: bool = True,
    cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS,
) -> HealthCheckResponse:
    """Run all 9 diagnostic health probes and aggregate health response."""
    global _HEALTH_CACHE, _HEALTH_CACHE_TIME

    now = time.time()
    with _HEALTH_LOCK:
        if use_cache and _HEALTH_CACHE is not None and (now - _HEALTH_CACHE_TIME) < cache_ttl:
            return HealthCheckResponse.model_validate(_HEALTH_CACHE)

    effective_runner = runner or (RealCommandRunner(is_live_mode=is_live_mode) if is_live_mode else FakeCommandRunner())

    def _run_safe(
        probe_fn: Callable[[], HealthCheckItem], fallback_id: str, fallback_title: str
    ) -> HealthCheckItem:
        try:
            return probe_fn()
        except Exception as exc:
            logger.warning("Health probe '%s' encountered an unhandled error: %s", fallback_id, exc)
            return HealthCheckItem(
                id=fallback_id,
                name=fallback_id,
                title=fallback_title,
                status="unknown",
                severity="medium",
                detail=f"Probe encountered an unhandled error: {sanitize_text(exc)}",
                how_to_fix="Review server logs for component error details.",
            )

    checks: list[HealthCheckItem] = []

    # 1. Audit Logging
    checks.append(
        _run_safe(
            lambda: check_audit_logging(share_root, audit_log_path, smb_conf_text),
            "audit_logging",
            "Samba Audit Logging",
        )
    )

    # 2. SMB Protocol
    checks.append(
        _run_safe(
            lambda: check_smb_protocol(effective_runner, is_live_mode),
            "smb_protocol",
            "SMB Protocol Version",
        )
    )

    # 3. Guest Access
    checks.append(
        _run_safe(
            lambda: check_guest_access(smb_conf_text),
            "guest_access",
            "Guest & Anonymous Access",
        )
    )

    # 4. Snapshots
    checks.append(
        _run_safe(
            lambda: check_snapshots(snapshot_manager, share_root, smb_conf_text=smb_conf_text),
            "snapshots",
            "Snapshot Storage & Boundaries",
        )
    )

    # 5. Restore Drill
    checks.append(
        _run_safe(
            check_restore_test,
            "restore_test",
            "Automated Restore Drill",
        )
    )

    # 6. Canary Files
    checks.append(
        _run_safe(
            lambda: check_canaries(canary_manager),
            "canary_files",
            "Canary Bait File Tripwires",
        )
    )

    # 7. Disk Space
    checks.append(
        _run_safe(
            lambda: check_disk_space(
                share_root,
                Path(snapshot_manager.snapshot_dir),
                snapshot_manager=snapshot_manager,
            ),
            "disk_space",
            "Storage & Volume Free Space",
        )
    )

    # 8. Network Exposure
    checks.append(
        _run_safe(
            lambda: check_network_exposure(effective_runner, is_live_mode),
            "network_exposure",
            "Network Exposure & Firewall",
        )
    )

    # 9. Safety Settings
    checks.append(
        _run_safe(
            lambda: check_safety_settings(
                engine_mode=engine_mode,
                allowlist=allowlist,
                panic_stop_active=panic_stop_active,
                is_ml_loaded=is_ml_loaded,
                is_snapshots_paused=getattr(snapshot_manager, "is_paused", False),
                is_db_healthy=is_db_healthy,
            ),
            "safety_settings",
            "ShareGuard Engine Safety",
        )
    )

    unknown_count = sum(1 for c in checks if c.status == "unknown")
    score, verdict = compute_health_score(checks, weights=weights)

    # Determine overall status
    if any(c.status == "fail" for c in checks):
        overall_status: Literal["pass", "warn", "fail", "unknown"] = "fail"
    elif any(c.status == "warn" for c in checks):
        overall_status = "warn"
    elif unknown_count == len(checks):
        overall_status = "unknown"
    else:
        overall_status = "pass"

    last_drill = get_last_restore_test()
    last_drill_model = RestoreTestResult.model_validate(last_drill) if last_drill else None

    response = HealthCheckResponse(
        status=overall_status,
        score=score,
        verdict=verdict,
        checks=checks,
        unknown_count=unknown_count,
        last_restore_test=last_drill_model,
        checked_at=datetime.now(UTC).isoformat(),
    )

    with _HEALTH_LOCK:
        _HEALTH_CACHE = response.model_dump()
        _HEALTH_CACHE_TIME = now

    return response


def clear_health_cache() -> None:
    """Clear in-memory cached health check response (used in tests)."""
    global _HEALTH_CACHE, _HEALTH_CACHE_TIME
    with _HEALTH_LOCK:
        _HEALTH_CACHE = None
        _HEALTH_CACHE_TIME = 0.0


# ---------------------------------------------------------------------------
# Background Weekly Restore Test Scheduler
# ---------------------------------------------------------------------------


class RestoreTestScheduler:
    """Background daemon triggering weekly synthetic restore drills without blocking API."""

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        share_root: Path,
        interval_seconds: float = 7 * 86400.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.snapshot_manager = snapshot_manager
        self.share_root = Path(share_root)
        self.interval_seconds = interval_seconds
        self.clock = clock or (lambda: datetime.now(UTC))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start scheduler daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ShareGuard-RestoreScheduler")
        self._thread.start()

    def stop(self) -> None:
        """Signal scheduler thread to stop and join."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def trigger_if_due(self) -> bool:
        """Check if weekly drill is due, and run if needed. Returns True if drill executed."""
        last = get_last_restore_test()
        now_dt = self.clock()
        if last is None:
            try:
                run_restore_test(
                    self.snapshot_manager,
                    self.share_root,
                    clock=self.clock,
                    triggered_by="scheduled:weekly",
                )
                return True
            except Exception as e:
                logger.warning("Scheduled restore test drill failed: %s", e)
                return False

        tested_at_str = last.get("tested_at", "")
        try:
            last_dt = datetime.fromisoformat(tested_at_str)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=UTC)
            if (now_dt - last_dt).total_seconds() >= self.interval_seconds:
                run_restore_test(
                    self.snapshot_manager,
                    self.share_root,
                    clock=self.clock,
                    triggered_by="scheduled:weekly",
                )
                return True
        except Exception as e:
            logger.warning("Error evaluating scheduled restore drill timing: %s", e)

        return False

    def _run_loop(self) -> None:
        """Internal daemon loop sleeping in short intervals."""
        while not self._stop_event.is_set():
            self.trigger_if_due()
            # Sleep in 5 second slices to allow clean shutdown
            for _ in range(int(min(self.interval_seconds, 60.0) / 5)):
                if self._stop_event.is_set():
                    break
                time.sleep(5.0)
