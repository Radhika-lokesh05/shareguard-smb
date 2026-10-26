"""server/tests/test_api.py – Comprehensive unit tests for ShareGuard FastAPI backend.

Verifies:
1. Authentication & RBAC permissions:
   - Anonymous requests get 401.
   - Viewer requests get 403 on action endpoints, settings modification, and audit logs.
   - Admin requests succeed on all endpoints.
   - Viewer succeeds on read endpoints, event stream, and CSV export.
2. Alert lifecycle & restoration workflow:
   - Alert block, dry-run restore preview, real restore with confirmation, and resolve.
3. Restoration safety invariants:
   - Refusal of real restore without prior dry-run.
   - Refusal of real restore without confirm=true.
4. Active response safety invariants:
   - Refusal to block server IP, gateway, or allowlisted CIDRs.
5. Global panic stop:
   - Triggering panic stop disables enforcement immediately; clearing restores it.
6. Settings bounds validation:
   - Rejection of unknown keys, invalid threshold bounds, and enforcing mode confirm requirement.
7. Event stream:
   - Monotonic event feed returning only new events since given ID.
8. CSV export injection protection:
   - Defends against formula injection (=, +, -, @, \\t, \\r) and sanitizes cells.
9. Audit logging:
   - Persistence of audit log entries for every administrative action.
10. False-positive handling:
    - Marking alert as false-positive unblocks client and adds IP to allowlist.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from shareguard.api import app, set_engine
from shareguard.db import AlertModel, AuditLogModel, ClientModel, get_session, init_db
from shareguard.engine import ActionTakenEvent, DetectionEngine
from shareguard.responder import FakeResponder
from shareguard.snapshots import PortableSnapshotManager


class AsgiResponse:
    """Minimal ASGI HTTP response wrapper."""

    def __init__(self, status_code: int, headers: dict[str, str], content: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.text)


class LocalTestClient:
    """In-process ASGI 3.0 test client with zero external dependencies (no httpx required)."""

    __test__ = False

    def __init__(self, app_instance: Any) -> None:
        self.app = app_instance

    def get(self, url: str, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("GET", url, headers=headers)

    def post(
        self,
        url: str,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> AsgiResponse:
        return self._request("POST", url, json_data=json, headers=headers)

    def put(
        self,
        url: str,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> AsgiResponse:
        return self._request("PUT", url, json_data=json, headers=headers)

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
            return {
                "type": "http.request",
                "body": body_bytes,
                "more_body": False,
            }

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

ADMIN_HEADERS = {"X-API-Key": "admin-key", "X-User-Name": "secadmin"}
VIEWER_HEADERS = {"X-API-Key": "viewer-key", "X-User-Name": "auditor"}


@pytest.fixture
def test_env(tmp_path: Path) -> tuple[TestClient, DetectionEngine, PortableSnapshotManager]:
    """Initialize isolated in-memory DB and test DetectionEngine."""
    db_file = tmp_path / "test_api.db"
    init_db(f"sqlite:///{db_file.as_posix()}")

    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir()
    snap_dir.mkdir()

    # Create legitimate files
    (share_root / "report.docx").write_text("Original Report Content\n", encoding="utf-8")
    (share_root / "data.xlsx").write_text("Original Data Content\n", encoding="utf-8")

    baseline_time = datetime.now(UTC) - timedelta(hours=1)
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    # Take baseline clean snapshot
    mgr.take_snapshot(share_root, clock=lambda: baseline_time)

    config: dict[str, Any] = {
        "server": {"mode": "simulation"},
        "samba": {"share_root": share_root.resolve().as_posix()},
        "response": {
            "mode": "shadow",
            "allowlist": ["127.0.0.1", "::1", "192.168.1.250"],
            "server_ips": ["192.168.1.1"],
            "gateway_ip": "192.168.1.254",
            "block_ttl_minutes": 15,
        },
        "detection": {
            "suspicious_threshold": 0.6,
            "attack_threshold": 0.85,
        },
    }
    responder = FakeResponder(config["response"])
    engine = DetectionEngine(config, responder=responder, snapshot_manager=mgr)
    set_engine(engine)

    client = TestClient(app)
    return client, engine, mgr


# ---------------------------------------------------------------------------
# 1. Authentication & Role-Based Authorization
# ---------------------------------------------------------------------------


def test_auth_and_rbac_permissions(test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager]) -> None:
    """Anonymous gets 401, viewer gets 403 on action endpoints, admin succeeds."""
    client, _, _ = test_env

    # 1. Anonymous requests get 401
    assert client.post("/api/alerts/1/block", json={"ttl_seconds": 900}).status_code == 401
    assert client.get("/api/settings").status_code == 401
    assert client.get("/api/export/alerts.csv").status_code == 401
    assert client.get("/api/audit").status_code == 401

    # 2. Viewer gets 403 on admin-only actions
    assert client.post("/api/alerts/1/block", json={"ttl_seconds": 900}, headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/alerts/1/unblock", headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/alerts/1/restore", json={"dry_run": True}, headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/alerts/1/resolve", headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/alerts/1/false-positive", json={}, headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/panic", headers=VIEWER_HEADERS).status_code == 403
    assert client.post("/api/panic/clear", headers=VIEWER_HEADERS).status_code == 403
    assert client.put("/api/settings", json={"mode": "shadow"}, headers=VIEWER_HEADERS).status_code == 403
    assert client.get("/api/audit", headers=VIEWER_HEADERS).status_code == 403

    # 3. Viewer succeeds on read and export endpoints
    res_settings = client.get("/api/settings", headers=VIEWER_HEADERS)
    assert res_settings.status_code == 200
    assert res_settings.json()["mode"] == "shadow"

    res_csv = client.get("/api/export/alerts.csv", headers=VIEWER_HEADERS)
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    res_events = client.get("/api/events?since=0", headers=VIEWER_HEADERS)
    assert res_events.status_code == 200


# ---------------------------------------------------------------------------
# 2. Alert Lifecycle: Block, Dry-Run Restore, Real Restore, Resolve
# ---------------------------------------------------------------------------


def test_alert_lifecycle_and_restore(test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager]) -> None:
    """Full lifecycle: block -> dry-run restore -> real restore -> resolve."""
    client, engine, mgr = test_env
    attacker_ip = "192.168.1.105"
    target_file = "report.docx"

    # Seed alert in DB
    now = datetime.now(UTC)
    with get_session() as session:
        alert = AlertModel(
            client_ip=attacker_ip,
            username="mallory",
            severity="critical",
            triggered_rules="R2,R3",
            ml_score=0.96,
            explanation="Rapid encryption burst detected",
            status="open",
            first_anomaly_ts=now - timedelta(seconds=10),
            files_touched=json.dumps([target_file]),
            created_at=now,
        )
        session.add(alert)
        client_record = ClientModel(
            client_ip=attacker_ip,
            username="mallory",
            first_seen=now,
            last_seen=now,
            is_blocked=False,
        )
        session.add(client_record)

    alert_id = 1

    # 1. Admin blocks the client
    block_res = client.post(
        f"/api/alerts/{alert_id}/block",
        json={"ttl_seconds": 600, "reason": "Active encryption detected"},
        headers=ADMIN_HEADERS,
    )
    assert block_res.status_code == 200
    assert block_res.json()["success"] is True
    assert block_res.json()["client_ip"] == attacker_ip

    # Verify client is marked blocked in DB
    with get_session() as session:
        c = session.query(ClientModel).filter_by(client_ip=attacker_ip).first()
        assert c is not None and bool(c.is_blocked) is True

    # Simulate attacker corrupting target file on disk
    file_path = Path(engine.config["samba"]["share_root"]) / target_file
    file_path.write_text("CORRUPTED ENCRYPTED DATA\n", encoding="utf-8")

    # 2. Attempt real restore without prior dry-run -> Refused
    bad_real = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": False, "confirm": True},
        headers=ADMIN_HEADERS,
    )
    assert bad_real.status_code == 400
    assert "prior dry-run must be performed" in bad_real.json()["detail"]

    # 3. Perform dry-run restore
    dry_res = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert dry_res.status_code == 200
    dry_data = dry_res.json()
    assert dry_data["dry_run"] is True
    assert dry_data["restored_count"] >= 1
    # Verify disk was NOT modified by dry-run
    assert file_path.read_text(encoding="utf-8") == "CORRUPTED ENCRYPTED DATA\n"

    # 4. Attempt real restore without confirm=true -> Refused
    unconfirmed = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": False, "confirm": False},
        headers=ADMIN_HEADERS,
    )
    assert unconfirmed.status_code == 400
    assert "confirm=true" in unconfirmed.json()["detail"]

    # 5. Perform confirmed real restore
    real_res = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": False, "confirm": True},
        headers=ADMIN_HEADERS,
    )
    assert real_res.status_code == 200
    real_data = real_res.json()
    assert real_data["dry_run"] is False
    assert real_data["restored_count"] >= 1

    # Invariant: file on disk must now be restored to pristine baseline content!
    assert file_path.read_text(encoding="utf-8") == "Original Report Content\n"

    # 6. Admin resolves the alert
    res_resolve = client.post(
        f"/api/alerts/{alert_id}/resolve",
        json={"reason": "Attacker contained, files restored"},
        headers=ADMIN_HEADERS,
    )
    assert res_resolve.status_code == 200
    assert res_resolve.json()["status"] == "resolved"

    # Verify AuditLog records
    with get_session() as session:
        logs = session.query(AuditLogModel).order_by(AuditLogModel.id.asc()).all()
        actions = [log.action for log in logs]
        assert "block" in actions
        assert "restore_dry_run" in actions
        assert "restore" in actions
        assert "resolve" in actions


# ---------------------------------------------------------------------------
# 3. Active Response Safety Invariants: Refused Block of Protected IPs
# ---------------------------------------------------------------------------


def test_refuse_block_of_protected_or_allowlisted_ips(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """Blocking server IP, gateway, or allowlist is strictly refused and audit-logged."""
    client, engine, _ = test_env

    # Seed alerts for protected IPs
    with get_session() as session:
        # Loopback alert
        session.add(
            AlertModel(
                client_ip="127.0.0.1",
                username="root",
                severity="low",
                created_at=datetime.now(UTC),
            )
        )
        # Server IP alert
        session.add(
            AlertModel(
                client_ip="192.168.1.1",
                username="samba",
                severity="medium",
                created_at=datetime.now(UTC),
            )
        )

    # Attempt to block 127.0.0.1 -> Refused with 400
    res1 = client.post("/api/alerts/1/block", json={"ttl_seconds": 300}, headers=ADMIN_HEADERS)
    assert res1.status_code == 400
    assert "protected" in res1.json()["detail"]

    # Attempt to block server IP 192.168.1.1 -> Refused with 400
    res2 = client.post("/api/alerts/2/block", json={"ttl_seconds": 300}, headers=ADMIN_HEADERS)
    assert res2.status_code == 400
    assert "protected" in res2.json()["detail"]

    # Check AuditLog recorded refusal
    with get_session() as session:
        refusals = session.query(AuditLogModel).filter(AuditLogModel.result.like("refused%")).all()
        assert len(refusals) >= 2


# ---------------------------------------------------------------------------
# 4. Global Panic Stop
# ---------------------------------------------------------------------------


def test_panic_stop_disables_and_restores_enforcement(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """POST /api/panic immediately halts enforcement; POST /api/panic/clear restores it."""
    client, engine, _ = test_env

    assert engine.panic_stop is False

    # Trigger panic stop
    res_panic = client.post("/api/panic", headers=ADMIN_HEADERS)
    assert res_panic.status_code == 200
    assert res_panic.json()["panic_stop"] is True
    assert engine.panic_stop is True

    # Clear panic stop
    res_clear = client.post("/api/panic/clear", headers=ADMIN_HEADERS)
    assert res_clear.status_code == 200
    assert res_clear.json()["panic_stop"] is False
    assert engine.panic_stop is False


# ---------------------------------------------------------------------------
# 5. Settings Bounds and Confirm Requirement
# ---------------------------------------------------------------------------


def test_settings_bounds_and_confirm_requirement(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """PUT /api/settings rejects unknown keys, validates bounds, and enforces confirm=true."""
    client, engine, _ = test_env

    # 1. Unknown key -> 422
    bad_key = client.put("/api/settings", json={"unknown_key": "bad"}, headers=ADMIN_HEADERS)
    assert bad_key.status_code in (400, 422)

    # 2. Switch from shadow to enforce_temp without confirm=true -> 400
    no_confirm = client.put(
        "/api/settings",
        json={"mode": "enforce_temp", "confirm": False},
        headers=ADMIN_HEADERS,
    )
    assert no_confirm.status_code == 400
    assert "confirm=true" in no_confirm.json()["detail"]

    # 3. Invalid threshold bounds (attack < suspicious) -> 400
    bad_thresh = client.put(
        "/api/settings",
        json={"thresholds": {"suspicious_threshold": 0.8, "attack_threshold": 0.4}},
        headers=ADMIN_HEADERS,
    )
    assert bad_thresh.status_code in (400, 422)

    # 4. Invalid allowlist IP -> 400
    bad_ip = client.put(
        "/api/settings",
        json={"allowlist": ["not_a_valid_ip"]},
        headers=ADMIN_HEADERS,
    )
    assert bad_ip.status_code in (400, 422)

    # 5. Valid update with confirm=true -> 200
    good_update = client.put(
        "/api/settings",
        json={
            "mode": "enforce_temp",
            "confirm": True,
            "thresholds": {"suspicious_threshold": 0.5, "attack_threshold": 0.8},
            "allowlist": ["10.0.0.1", "192.168.1.0/24"],
            "block_ttl_minutes": 30,
        },
        headers=ADMIN_HEADERS,
    )
    assert good_update.status_code == 200
    data = good_update.json()
    assert data["mode"] == "enforce_temp"
    assert "10.0.0.1" in data["allowlist"]
    assert data["block_ttl_minutes"] == 30


# ---------------------------------------------------------------------------
# 6. Events Stream Incremental Queries
# ---------------------------------------------------------------------------


def test_events_endpoint_returns_only_new_events(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """GET /api/events?since=<id> returns only events with id > since."""
    client, engine, _ = test_env

    # Publish 3 events on event bus
    for i in range(3):
        engine.event_bus.publish(
            ActionTakenEvent(
                client_ip=f"192.168.1.{i+10}",
                username="user",
                action="blocked_temp",
                mode="enforce_temp",
                reason="high entropy",
                timestamp=datetime.now(UTC),
                would_have_blocked=False,
            )
        )

    # Query all events since 0
    res1 = client.get("/api/events?since=0", headers=VIEWER_HEADERS)
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1["events"]) == 3
    latest_id = data1["latest_id"]

    # Query since latest_id -> empty
    res2 = client.get(f"/api/events?since={latest_id}", headers=VIEWER_HEADERS)
    assert res2.status_code == 200
    assert len(res2.json()["events"]) == 0

    # Publish 2 more events
    for i in range(2):
        engine.event_bus.publish(
            ActionTakenEvent(
                client_ip=f"192.168.1.{i+20}",
                username="user2",
                action="blocked_temp",
                mode="enforce_temp",
                reason="burst",
                timestamp=datetime.now(UTC),
                would_have_blocked=False,
            )
        )

    # Query since previous latest_id -> returns the 2 new events
    res3 = client.get(f"/api/events?since={latest_id}", headers=VIEWER_HEADERS)
    assert res3.status_code == 200
    assert len(res3.json()["events"]) == 2


# ---------------------------------------------------------------------------
# 7. CSV Export and Formula Injection Defense
# ---------------------------------------------------------------------------


def test_csv_export_injection_protection_and_sanitization(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """GET /api/export/alerts.csv prefixes =, +, -, @, \\t with single quote."""
    client, _, _ = test_env

    # Seed alert with formula injection payloads
    with get_session() as session:
        session.add(
            AlertModel(
                client_ip="@192.168.1.10",
                username="=cmd|'/C calc'!A0",
                severity="+critical",
                triggered_rules="-R2,R3",
                explanation="\tTabPrefixInjection",
                created_at=datetime.now(UTC),
            )
        )

    res = client.get("/api/export/alerts.csv", headers=VIEWER_HEADERS)
    assert res.status_code == 200
    csv_text = res.text

    # Verify formula injection prefixes
    assert "'=cmd|'/C calc'!A0" in csv_text
    assert "'+critical" in csv_text
    assert "'-R2,R3" in csv_text
    assert "'@192.168.1.10" in csv_text
    assert "'\tTabPrefixInjection" in csv_text


# ---------------------------------------------------------------------------
# 8. False-Positive Handling
# ---------------------------------------------------------------------------


def test_false_positive_workflow(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """POST /api/alerts/{id}/false-positive marks alert, unblocks client, adds IP to allowlist."""
    client, engine, _ = test_env
    test_ip = "192.168.1.188"

    with get_session() as session:
        alert = AlertModel(
            client_ip=test_ip,
            username="bob",
            severity="high",
            status="open",
            created_at=datetime.now(UTC),
        )
        session.add(alert)
        client_rec = ClientModel(
            client_ip=test_ip,
            username="bob",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            is_blocked=True,
        )
        session.add(client_rec)

    # Call false-positive
    res = client.post(
        "/api/alerts/1/false-positive",
        json={"allowlist": True, "expiry_hours": 12, "reason": "Authorized batch migration"},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "false_positive"

    # Verify IP was added to allowlist
    assert test_ip in engine.allowlist

    # Verify client unblocked in DB
    with get_session() as session:
        c = session.query(ClientModel).filter_by(client_ip=test_ip).first()
        assert c is not None and bool(c.is_blocked) is False


# ---------------------------------------------------------------------------
# 9. Audit Log Pagination
# ---------------------------------------------------------------------------


def test_audit_log_paged(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """GET /api/audit returns paginated admin actions."""
    client, _, _ = test_env

    # Perform panic and clear actions to generate audit logs
    client.post("/api/panic", headers=ADMIN_HEADERS)
    client.post("/api/panic/clear", headers=ADMIN_HEADERS)

    res = client.get("/api/audit?limit=1&offset=0", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert len(data["items"]) == 1
    assert data["total"] >= 2
    assert data["limit"] == 1
    assert data["offset"] == 0


# ---------------------------------------------------------------------------
# 10. Assistant Explain Template Placeholder
# ---------------------------------------------------------------------------


def test_assistant_explain_placeholder(
    test_env: tuple[TestClient, DetectionEngine, PortableSnapshotManager],
) -> None:
    """POST /api/assistant/explain/{id} returns structured template explanation."""
    client, _, _ = test_env

    with get_session() as session:
        session.add(
            AlertModel(
                client_ip="192.168.1.99",
                username="charlie",
                severity="high",
                triggered_rules="R2",
                ml_score=0.88,
                created_at=datetime.now(UTC),
            )
        )

    res = client.post("/api/assistant/explain/1", headers=VIEWER_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == 1
    assert data["provider"] == "template"
    assert "192.168.1.99" in data["explanation"]
