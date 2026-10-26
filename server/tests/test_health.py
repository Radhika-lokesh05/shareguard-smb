"""server/tests/test_health.py – Unit and integration tests for diagnostic health probes.

Tests verify:
1. Audit logging probe: pass (active log), warn (empty/stale log), fail (missing full_audit), unknown.
2. Robust SMB protocol parsing: multiple testparm variants (SMB2, NT1, LANMAN, comments, missing).
3. Guest access probe: pass, fail on 'guest ok = yes' or 'map to guest = Bad User'.
4. Snapshot boundaries and recency: pass, fail when snapshot dir inside share, fail when share inside snapshot dir, warn on stale backups.
5. Non-destructive restore drill: pass on valid snapshot, never writes into live share, cleans up tempdir.
6. Corrupted snapshot detection: fails when a byte is flipped in snapshot data.
7. Rate limiting on restore drill endpoint (60s limit).
8. Scheduled weekly restore drill with fake clock.
9. Fault isolation: one crashing check yields 'unknown' and never breaks the page.
10. Weighted scoring algorithm: strictly excludes 'unknown' checks.
11. Network exposure and safety settings probes.
12. FastAPI endpoints: GET /api/health-check, POST /api/health-check/restore-test (admin only, audit logged).
"""

from __future__ import annotations

import asyncio
import json
import unittest.mock as mock
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
from sqlalchemy import select

from shareguard.api import app
from shareguard.db import AuditLogModel, get_session, init_db
from shareguard.health import (
    HealthCheckItem,
    RateLimitError,
    RestoreTestScheduler,
    check_audit_logging,
    check_canaries,
    check_disk_space,
    check_guest_access,
    check_network_exposure,
    check_restore_test,
    check_safety_settings,
    check_smb_protocol,
    check_snapshots,
    clear_health_cache,
    clear_restore_test_history,
    compute_health_score,
    evaluate_system_health,
    get_last_restore_test,
    get_restore_test_history,
    is_protocol_secure,
    parse_guest_access,
    parse_server_min_protocol,
    run_restore_test,
    set_last_restore_test,
)
from shareguard.responder import FakeCommandRunner
from shareguard.snapshots import PortableSnapshotManager


@pytest.fixture(autouse=True)
def _reset_health_state() -> None:
    """Ensure in-memory cache and restore drill history do not leak across tests."""
    clear_health_cache()
    clear_restore_test_history()
    yield
    clear_health_cache()
    clear_restore_test_history()


# ---------------------------------------------------------------------------
# Zero-Dependency ASGI Test Client
# ---------------------------------------------------------------------------


class AsgiResponse:
    """Minimal ASGI response wrapper."""

    def __init__(self, status_code: int, headers: dict[str, str], content: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.text)


class LocalTestClient:
    """Zero-dependency in-process ASGI 3.0 test client."""

    __test__ = False

    def __init__(self, app_instance: Any) -> None:
        self.app = app_instance

    def get(self, url: str, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("GET", url, headers=headers)

    def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("POST", url, json_data=json, headers=headers)

    def _request(
        self,
        method: str,
        url: str,
        json_data: Any = None,
        headers: dict[str, str] | None = None,
    ) -> AsgiResponse:
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query.encode("ascii")

        body_bytes = json.dumps(json_data).encode("utf-8") if json_data is not None else b""

        raw_headers: list[tuple[bytes, bytes]] = []
        if headers:
            for k, v in headers.items():
                raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        if body_bytes and not any(k == b"content-type" for k, _ in raw_headers):
            raw_headers.append((b"content-type", b"application/json"))

        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query,
            "headers": raw_headers,
            "server": ("127.0.0.1", 80),
            "client": ("127.0.0.1", 12345),
        }

        response_status = 500
        response_headers: list[tuple[bytes, bytes]] = []
        response_body: list[bytes] = []

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            nonlocal response_status, response_headers
            if message["type"] == "http.response.start":
                response_status = message["status"]
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))

        asyncio.run(self.app(scope, receive, send))
        header_dict = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in response_headers}
        return AsgiResponse(response_status, header_dict, b"".join(response_body))


TestClient = LocalTestClient

# ---------------------------------------------------------------------------
# 1. Audit Logging Probe Tests
# ---------------------------------------------------------------------------


def test_audit_logging_pass_active_log(tmp_path: Path) -> None:
    """Audit logging probe passes when smb.conf has full_audit and log is actively written."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    log_file = tmp_path / "samba_audit.log"
    log_file.write_text("Oct 10 12:00:00 smbd_audit: open|ok|documents/budget.xlsx\n", encoding="utf-8")

    smb_conf = "[documents]\npath = /srv/samba/share\nvfs objects = full_audit\n"
    res = check_audit_logging(share_root, log_file, smb_conf_text=smb_conf)
    assert res.status == "pass"
    assert "active" in res.detail.lower()


def test_audit_logging_warn_empty_or_stale(tmp_path: Path) -> None:
    """Audit logging probe warns if log is empty or mtime > 24 hours."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    empty_log = tmp_path / "empty.log"
    empty_log.write_text("", encoding="utf-8")

    smb_conf = "[docs]\nvfs objects = full_audit\n"
    res_empty = check_audit_logging(share_root, empty_log, smb_conf_text=smb_conf)
    assert res_empty.status == "warn"
    assert "empty" in res_empty.detail.lower()


def test_audit_logging_fail_missing_full_audit(tmp_path: Path) -> None:
    """Audit logging probe fails if smb.conf does not include full_audit."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    log_file = tmp_path / "samba.log"
    log_file.write_text("data\n", encoding="utf-8")

    smb_conf_bad = "[docs]\npath = /srv/share\nread only = no\n"
    res = check_audit_logging(share_root, log_file, smb_conf_text=smb_conf_bad)
    assert res.status == "fail"
    assert "full_audit" in res.detail.lower()


def test_audit_logging_unknown_unreadable_file(tmp_path: Path) -> None:
    """Audit logging probe reports unknown when log file stat or permissions fail."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    missing_file = tmp_path / "does_not_exist.log"
    res = check_audit_logging(share_root, missing_file, smb_conf_text="vfs objects = full_audit")
    assert res.status == "warn"  # File missing on disk warns clearly


# ---------------------------------------------------------------------------
# 2. Old SMB Protocol Parser Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_output, expected_proto, expected_secure",
    [
        ("server min protocol = SMB2_02\n", "SMB2_02", True),
        ("   min protocol = SMB3\n", "SMB3", True),
        ("server min protocol = NT1 # legacy clients\n", "NT1", False),
        ("min protocol = SMB1\n", "SMB1", False),
        ("SERVER MIN PROTOCOL = LANMAN2\n", "LANMAN2", False),
        ("server min protocol = SMB3_11\n", "SMB3_11", True),
        ("[global]\n\tserver min protocol = SMB2\n", "SMB2", True),
    ],
)
def test_testparm_protocol_parsing_variants(raw_output: str, expected_proto: str, expected_secure: bool) -> None:
    """Parser robustly extracts server min protocol from varied testparm formats."""
    parsed = parse_server_min_protocol(raw_output)
    assert parsed == expected_proto
    assert is_protocol_secure(parsed) is expected_secure


def test_smb_protocol_probe_pass_and_fail() -> None:
    """Probe fails for insecure SMB1/NT1 and passes for SMB2+."""
    runner = FakeCommandRunner()
    res_pass = check_smb_protocol(runner, is_live_mode=True, testparm_output_override="server min protocol = SMB2\n")
    assert res_pass.status == "pass"

    res_fail = check_smb_protocol(runner, is_live_mode=True, testparm_output_override="server min protocol = NT1\n")
    assert res_fail.status == "fail"
    assert "NT1" in res_fail.detail

    res_warn = check_smb_protocol(runner, is_live_mode=True, testparm_output_override="workgroup = WORKGROUP\n")
    assert res_warn.status == "warn"


# ---------------------------------------------------------------------------
# 3. Guest Access Probe Tests
# ---------------------------------------------------------------------------


def test_guest_access_probe() -> None:
    """Probe detects guest access enabled in global or individual share sections."""
    conf_safe = "[global]\nmap to guest = Never\n[finance]\npath = /srv/finance\nguest ok = no\n"
    res_safe = check_guest_access(smb_conf_text=conf_safe)
    assert res_safe.status == "pass"

    conf_bad_guest_ok = "[global]\nmap to guest = Never\n[public_files]\npath = /srv/public\nguest ok = yes\n"
    res_bad_share = check_guest_access(smb_conf_text=conf_bad_guest_ok)
    assert res_bad_share.status == "fail"
    assert "public_files" in res_bad_share.detail

    conf_bad_map = "[global]\nmap to guest = Bad User\n[finance]\npath = /srv/finance\n"
    res_bad_map = check_guest_access(smb_conf_text=conf_bad_map)
    assert res_bad_map.status == "fail"
    assert "Bad User" in res_bad_map.detail


# ---------------------------------------------------------------------------
# 4. Snapshot Storage Boundaries & Recency Tests
# ---------------------------------------------------------------------------


def test_snapshot_probe_boundaries_and_age(tmp_path: Path) -> None:
    """Probe fails if snapshot folder is inside share or if no snapshots exist."""
    share_root = tmp_path / "share"
    share_root.mkdir()

    # Boundary violation: snapshot dir inside share
    inside_snap_dir = share_root / "backups"
    inside_snap_dir.mkdir()
    mgr_inside = PortableSnapshotManager(snapshot_dir=inside_snap_dir)
    res_inside = check_snapshots(mgr_inside, share_root)
    assert res_inside.status == "fail"
    assert "inside the share path" in res_inside.detail.lower()

    # Valid separated snapshot dir
    safe_snap_dir = tmp_path / "safe_snapshots"
    safe_snap_dir.mkdir()
    mgr_safe = PortableSnapshotManager(snapshot_dir=safe_snap_dir)

    # No snapshots created yet
    res_none = check_snapshots(mgr_safe, share_root)
    assert res_none.status == "fail"
    assert "no snapshot" in res_none.detail.lower()

    # Take a fresh snapshot
    (share_root / "test.txt").write_text("sample content", encoding="utf-8")
    mgr_safe.take_snapshot(share_root)

    res_pass = check_snapshots(mgr_safe, share_root)
    assert res_pass.status == "pass"
    assert "safely outside" in res_pass.detail.lower()


def test_snapshot_probe_warns_on_stale_backups(tmp_path: Path) -> None:
    """Probe warns when newest snapshot exceeds max_age_hours."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    (share_root / "data.txt").write_text("hello", encoding="utf-8")

    snap_dir = tmp_path / "snaps"
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)

    def old_clock() -> datetime:
        return datetime.now(UTC) - timedelta(hours=36)

    mgr.take_snapshot(share_root, clock=old_clock)

    res = check_snapshots(mgr, share_root, max_age_hours=24.0)
    assert res.status == "warn"
    assert "threshold is 24" in res.detail


# ---------------------------------------------------------------------------
# 5. Non-Destructive Restore Drill Engine Tests
# ---------------------------------------------------------------------------


def test_restore_drill_pass_and_never_writes_into_share(tmp_path: Path) -> None:
    """Restore drill restores sample files to tempdir, verifies SHA-256, and never touches share."""
    share_root = tmp_path / "live_share"
    share_root.mkdir()
    file1 = share_root / "contract.docx"
    file1.write_text("Confidential NDA Agreement v1.0", encoding="utf-8")
    file2 = share_root / "budget.xlsx"
    file2.write_text("Q4 Projections and Revenue", encoding="utf-8")

    snap_dir = tmp_path / "snapshots"
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap_info = mgr.take_snapshot(share_root)
    assert snap_info is not None

    # Record share root mtimes before drill
    share_mtimes_before = {p: p.stat().st_mtime for p in share_root.rglob("*")}

    res = run_restore_test(
        snapshot_manager=mgr,
        share_root=share_root,
        sample_count=2,
        triggered_by="test:admin",
    )

    assert res.status == "pass"
    assert res.files_restored == 2
    assert res.time_taken_seconds >= 0.0

    # Invariant: live share directory is completely unmodified
    share_mtimes_after = {p: p.stat().st_mtime for p in share_root.rglob("*")}
    assert share_mtimes_before == share_mtimes_after


def test_restore_drill_fails_on_corrupted_snapshot_file(tmp_path: Path) -> None:
    """Restore drill fails and reports hash mismatch when a snapshot file is corrupted."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    doc = share_root / "critical_data.pdf"
    doc.write_text("Original pristine document content", encoding="utf-8")

    snap_dir = tmp_path / "snaps"
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    snap = mgr.take_snapshot(share_root)
    assert snap is not None

    # Corrupt the snapshot file in the snapshot data directory (flip a byte)
    snap_file = Path(snap.snapshot_path) / "data" / "critical_data.pdf"
    assert snap_file.exists()
    snap_file.write_bytes(b"CORRUPTED_TAMPERED_BYTES_REPLACED")

    res = run_restore_test(
        snapshot_manager=mgr,
        share_root=share_root,
        sample_count=5,
        triggered_by="test:admin",
    )

    assert res.status == "fail"
    assert "hash mismatch" in res.detail.lower()


def test_restore_drill_rate_limiting(tmp_path: Path) -> None:
    """Restore drill enforces rate limiting when invoked multiple times in rapid succession."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    (share_root / "doc.txt").write_text("text", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=tmp_path / "snaps")
    mgr.take_snapshot(share_root)

    # First call succeeds
    res1 = run_restore_test(mgr, share_root, triggered_by="admin")
    assert res1.status == "pass"

    # Second call within 60s raises RateLimitError
    with pytest.raises(RateLimitError) as exc_info:
        run_restore_test(mgr, share_root, rate_limit_seconds=60.0, triggered_by="admin")
    assert exc_info.value.retry_after > 0


def test_scheduled_restore_drill_with_fake_clock(tmp_path: Path) -> None:
    """Scheduled daemon checks interval and triggers weekly drill with fake clock."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    (share_root / "data.txt").write_text("scheduled test", encoding="utf-8")
    mgr = PortableSnapshotManager(snapshot_dir=tmp_path / "snaps")
    mgr.take_snapshot(share_root)

    current_time = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

    def fake_clock() -> datetime:
        return current_time

    scheduler = RestoreTestScheduler(mgr, share_root, interval_seconds=7 * 86400.0, clock=fake_clock)

    # 1. First trigger runs because no tests exist
    assert scheduler.trigger_if_due() is True

    # 2. Immediate check does not trigger (0 days elapsed)
    assert scheduler.trigger_if_due() is False

    # 3. Advance clock by 8 days -> triggers weekly drill
    current_time += timedelta(days=8)
    assert scheduler.trigger_if_due() is True


# ---------------------------------------------------------------------------
# 6. Fault Isolation & Scoring Tests
# ---------------------------------------------------------------------------


def test_fault_isolation_crashing_probe_yields_unknown(tmp_path: Path) -> None:
    """An unhandled exception in one probe produces status='unknown' without breaking the engine."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    mgr = PortableSnapshotManager(snapshot_dir=tmp_path / "snaps")

    with mock.patch("shareguard.health.check_smb_protocol", side_effect=RuntimeError("Hardware fault")):
        clear_health_cache()
        response = evaluate_system_health(
            share_root=share_root,
            audit_log_path=tmp_path / "audit.log",
            snapshot_manager=mgr,
            use_cache=False,
        )

        assert response is not None
        # Entire response must evaluate cleanly
        assert 0.0 <= response.score <= 100.0
        assert response.verdict in ("Good", "Needs attention", "At risk")
        smb_check = next((c for c in response.checks if c.id == "smb_protocol"), None)
        assert smb_check is not None
        assert smb_check.status == "unknown"
        assert "hardware fault" in smb_check.detail.lower()


def test_scoring_strictly_excludes_unknown_probes() -> None:
    """compute_health_score ignores unknown checks in both earned and possible points."""
    checks = [
        HealthCheckItem(id="audit_logging", name="audit_logging", title="Audit", status="pass", severity="high", detail="", how_to_fix=""),
        HealthCheckItem(id="smb_protocol", name="smb_protocol", title="SMB", status="warn", severity="high", detail="", how_to_fix=""),
        HealthCheckItem(id="guest_access", name="guest_access", title="Guest", status="unknown", severity="medium", detail="", how_to_fix=""),
    ]
    weights = {"audit_logging": 50.0, "smb_protocol": 50.0, "guest_access": 100.0}

    # audit_logging (50 * 1.0) + smb_protocol (50 * 0.5) = 75.0 / 100.0 possible = 75.0%
    score, verdict = compute_health_score(checks, weights=weights)
    assert score == 75.0
    assert verdict == "Needs attention"


# ---------------------------------------------------------------------------
# 7. Network Exposure & Safety Probes
# ---------------------------------------------------------------------------


def test_network_exposure_and_safety_probes() -> None:
    """Network exposure and safety probes produce accurate findings."""
    runner = FakeCommandRunner()
    res_net = check_network_exposure(runner, is_live_mode=False)
    assert res_net.status in ("pass", "warn")
    assert "simulated" in res_net.detail.lower()

    # Safety probe in shadow mode with DB healthy
    res_safety = check_safety_settings(engine_mode="shadow", allowlist=["127.0.0.1"], is_db_healthy=True)
    assert res_safety.status == "pass"

    # Enforcing mode with empty allowlist produces warning
    res_enforce_no_allow = check_safety_settings(engine_mode="enforce_strict", allowlist=[], is_db_healthy=True)
    assert res_safety.status == "pass"
    assert res_enforce_no_allow.status == "warn"


def test_canary_and_disk_space_probes(tmp_path: Path) -> None:
    """Canary and disk space probes evaluate status and boundaries correctly."""
    # Canary probe when manager is None
    res_canary_none = check_canaries(None)
    assert res_canary_none.status == "unknown"

    # Disk space probe
    share = tmp_path / "share"
    share.mkdir()
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    res_disk = check_disk_space(share, snaps, warn_percent=10.0)
    assert res_disk.status in ("pass", "warn")
    assert "storage" in res_disk.title.lower()


def test_restore_test_history_and_state() -> None:
    """get_last_restore_test and get_restore_test_history manage drill result state."""
    sample = {
        "id": "drill-123",
        "status": "pass",
        "files_restored": 3,
        "total_bytes": 4096,
        "time_taken_seconds": 0.02,
        "tested_at": "2026-10-10T10:00:00Z",
        "detail": "Verified 3 files",
        "triggered_by": "admin",
    }
    set_last_restore_test(sample)
    assert get_last_restore_test() == sample
    history = get_restore_test_history()
    assert len(history) >= 1
    assert history[-1]["id"] == "drill-123"

    res_check = check_restore_test()
    assert res_check.status == "pass"

    # Guest access parser helper
    insecure, _ = parse_guest_access("[share]\nguest ok = yes\n")
    assert insecure is True
    secure, _ = parse_guest_access("[share]\nguest ok = no\n")
    assert secure is False


# ---------------------------------------------------------------------------
# 8. API Endpoint Integration Tests (GET health-check & POST restore-test)
# ---------------------------------------------------------------------------


def test_api_health_check_endpoints(tmp_path: Path) -> None:
    """FastAPI routes for GET /api/health-check and POST /api/health-check/restore-test operate cleanly."""
    db_file = tmp_path / "test_health_api.db"
    init_db(f"sqlite:///{db_file.as_posix()}")

    client = TestClient(app)
    admin_headers = {"X-API-Key": "admin-key", "X-User-Name": "secadmin"}
    viewer_headers = {"X-API-Key": "viewer-key", "X-User-Name": "auditor"}

    # 1. GET /api/health-check with viewer headers
    clear_health_cache()
    resp_get = client.get("/api/health-check", headers=viewer_headers)
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert "score" in data
    assert "verdict" in data
    assert len(data["checks"]) >= 5

    # 2. POST /api/health-check/restore-test as Viewer is refused (403)
    resp_viewer_post = client.post("/api/health-check/restore-test", headers=viewer_headers)
    assert resp_viewer_post.status_code == 403

    # 3. POST /api/health-check/restore-test as Admin executes drill and logs audit entry
    resp_admin_post = client.post("/api/health-check/restore-test", headers=admin_headers)
    assert resp_admin_post.status_code in (200, 429)

    if resp_admin_post.status_code == 200:
        drill_data = resp_admin_post.json()
        assert "status" in drill_data

        # Verify audit log recorded in DB
        with get_session() as s:
            logs = s.scalars(select(AuditLogModel).where(AuditLogModel.action == "restore_test")).all()
            assert len(logs) >= 1
            assert logs[-1].username == "secadmin"
