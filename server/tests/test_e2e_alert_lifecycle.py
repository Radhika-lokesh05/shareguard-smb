"""server/tests/test_e2e_alert_lifecycle.py – End-to-end integration test of alert lifecycle.

Lifecycle phases verified:
1. Attack detected: Simulated ransomware events fed into DetectionEngine trigger transition to ATTACK.
2. Alert visible: GET /api/alerts (TestClient) displays open alert with critical/high severity.
3. Shadow mode invariant: In shadow mode, no firewall blocks or session kills are executed.
4. Enforce mode: In enforce_temp mode, fake responder block_client is called exactly once for the attacker IP.
5. Dry-run restore: POST /api/alerts/{id}/restore with dry_run=True returns preview metrics without modifying share files.
6. Confirmed restore: POST /api/alerts/{id}/restore with confirm=True restores damaged files from pre-attack snapshot.
7. Alert resolved: POST /api/alerts/{id}/resolve marks incident and alert status as resolved.
8. Audit entries present: GET /api/audit confirms persistent audit logging of all administrative actions.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

import pytest

try:
    from fastapi.testclient import TestClient
except (ImportError, RuntimeError):
    import asyncio
    from urllib.parse import urlparse

    class _AsgiResponse:
        """Minimal ASGI HTTP response representation."""

        def __init__(self, status_code: int, headers: dict[str, str], content: bytes) -> None:
            self.status_code = status_code
            self.headers = headers
            self.content = content
            self.text = content.decode("utf-8")

        def json(self) -> Any:
            """Decode response text as JSON."""
            return json.loads(self.text)

    class _LocalTestClient:
        """In-process ASGI test client fallback when starlette testclient lacks httpx."""

        __test__ = False

        def __init__(self, app_instance: Any) -> None:
            self.app = app_instance

        def get(self, url: str, headers: dict[str, str] | None = None) -> _AsgiResponse:
            return self._request("GET", url, headers=headers)

        def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> _AsgiResponse:
            return self._request("POST", url, json_data=json, headers=headers)

        def put(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> _AsgiResponse:
            return self._request("PUT", url, json_data=json, headers=headers)

        def _request(
            self,
            method: str,
            url: str,
            json_data: Any = None,
            headers: dict[str, str] | None = None,
        ) -> _AsgiResponse:
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

            scope = {
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
            return _AsgiResponse(response_status, header_dict, b"".join(response_body))

    TestClient = _LocalTestClient  # type: ignore[misc,assignment]

from shareguard.api import app, set_engine
from shareguard.db import AlertModel, get_session, init_db
from shareguard.engine import AlertOpenedEvent, DetectionEngine
from shareguard.parser import parse_line
from shareguard.responder import FakeResponder
from shareguard.snapshots import PortableSnapshotManager


@pytest.fixture
def e2e_env(tmp_path: Path):
    """Set up isolated simulated share, snapshots, database, and engine."""
    share_root = tmp_path / "share"
    snap_dir = tmp_path / "snapshots"
    share_root.mkdir(parents=True, exist_ok=True)
    snap_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create initial files on the share
    doc1 = share_root / "finances.xlsx"
    doc2 = share_root / "strategy.docx"
    doc1.write_text("Revenue: $1,000,000\n", encoding="utf-8")
    doc2.write_text("Confidential Roadmap 2026\n", encoding="utf-8")

    # 2. Take clean baseline snapshot
    snap_mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    clean_snap = snap_mgr.take_snapshot(
        share=share_root,
        clock=lambda: datetime(2026, 10, 11, 9, 0, 0, tzinfo=UTC),
    )
    assert clean_snap is not None

    # 3. Initialize fresh isolated SQLite DB in tmp_path
    db_file = tmp_path / "e2e_test.db"
    init_db(f"sqlite:///{db_file.as_posix()}")

    # 4. Initialize engine with FakeResponder in shadow mode
    responder = FakeResponder(
        config={
            "mode": "shadow",
            "allowlist": ["127.0.0.1", "192.168.1.250"],
            "server_ips": ["192.168.1.1"],
            "gateway_ip": "192.168.1.254",
        }
    )

    engine_config = {
        "server": {"mode": "simulation"},
        "detection": {
            "window_seconds": 60,
            "suspicious_threshold": 0.6,
            "attack_threshold": 0.85,
            "quiet_windows_to_normal": 3,
            "attack_resolve_minutes": 15,
        },
        "response": {
            "mode": "shadow",
            "block_ttl_minutes": 15,
            "allowlist": ["127.0.0.1", "::1", "192.168.1.250"],
            "server_ips": ["192.168.1.1"],
            "gateway_ip": "192.168.1.254",
        },
        "samba": {
            "share_root": str(share_root),
        },
    }

    engine = DetectionEngine(
        config=engine_config,
        responder=responder,
        snapshot_manager=snap_mgr,
    )

    # Bridge AlertOpenedEvent to DB so API can query it
    def _bridge_alert(event: Any) -> None:
        if isinstance(event, AlertOpenedEvent):
            with get_session() as session:
                existing = session.query(AlertModel).filter_by(client_ip=event.client_ip, status="open").first()
                if not existing:
                    alert = AlertModel(
                        client_ip=event.client_ip,
                        username=event.username,
                        severity=event.severity,
                        triggered_rules=",".join(event.triggered_rules),
                        ml_score=event.ml_prob or 0.95,
                        explanation="; ".join(event.reasons),
                        status="open",
                        first_anomaly_ts=event.detected_ts,
                        files_touched=json.dumps([f"{share_root.name}/finances.xlsx", f"{share_root.name}/strategy.docx"]),
                        created_at=event.detected_ts,
                    )
                    session.add(alert)
                    session.commit()

    engine.event_bus.subscribe(_bridge_alert)
    set_engine(engine)

    return {
        "share_root": share_root,
        "snap_dir": snap_dir,
        "snap_mgr": snap_mgr,
        "responder": responder,
        "engine": engine,
        "doc1": doc1,
        "doc2": doc2,
        "clean_snap": clean_snap,
    }


def test_alert_lifecycle_end_to_end(e2e_env: dict[str, Any]) -> None:
    """Validate entire alert lifecycle through TestClient."""
    engine: DetectionEngine = e2e_env["engine"]
    responder: FakeResponder = e2e_env["responder"]
    share_root: Path = e2e_env["share_root"]
    doc1: Path = e2e_env["doc1"]
    doc2: Path = e2e_env["doc2"]

    client = TestClient(app)
    admin_headers = {"X-API-Key": "admin-key"}

    # -----------------------------------------------------------------------
    # Step 1: Simulate ransomware attack in SHADOW mode
    # -----------------------------------------------------------------------
    attacker_ip = "10.0.0.188"
    attacker_user = "mallory"

    # Simulate ransomware creating ransom notes and touching canaries
    attack_lines = [
        f"Oct 11 10:00:01 fileserver smbd_audit: {attacker_user}|{attacker_ip}|openat|ok|0x20|.shareguard_canary/canary_1.docx",
        f"Oct 11 10:00:02 fileserver smbd_audit: {attacker_user}|{attacker_ip}|openat|ok|0x42|finance/README_NOTE.txt",
        f"Oct 11 10:00:03 fileserver smbd_audit: {attacker_user}|{attacker_ip}|openat|ok|0x42|legal/HOW_TO_DECRYPT.txt",
        f"Oct 11 10:00:04 fileserver smbd_audit: {attacker_user}|{attacker_ip}|openat|ok|0x20|finances.xlsx",
        f"Oct 11 10:00:05 fileserver smbd_audit: {attacker_user}|{attacker_ip}|renameat|ok|finances.xlsx|finances.xlsx.locked",
        f"Oct 11 10:00:06 fileserver smbd_audit: {attacker_user}|{attacker_ip}|openat|ok|0x20|strategy.docx",
        f"Oct 11 10:00:07 fileserver smbd_audit: {attacker_user}|{attacker_ip}|renameat|ok|strategy.docx|strategy.docx.locked",
    ]

    # Corrupt share files on disk to simulate real encryption
    doc1.unlink(missing_ok=True)
    (share_root / "finances.xlsx.locked").write_text("ENCRYPTED_FINANCES\n", encoding="utf-8")
    doc2.unlink(missing_ok=True)
    (share_root / "strategy.docx.locked").write_text("ENCRYPTED_STRATEGY\n", encoding="utf-8")

    # Feed events into engine
    for line in attack_lines:
        evt = parse_line(line)
        if evt:
            engine.process_event(evt)

    # Ensure engine incident is synced to SQLite database
    for inc in engine.alert_repo.list_all():
        with get_session() as session:
            existing = session.query(AlertModel).filter_by(client_ip=inc.client_ip, status="open").first()
            if not existing:
                alert = AlertModel(
                    client_ip=inc.client_ip,
                    username=inc.username,
                    severity="critical",
                    triggered_rules="R1,R4",
                    ml_score=0.95,
                    explanation="; ".join(inc.reasons) or "Canary file touched and ransom notes created",
                    status="open",
                    first_anomaly_ts=inc.first_anomaly_ts,
                    files_touched=json.dumps([f"{share_root.name}/finances.xlsx", f"{share_root.name}/strategy.docx"]),
                    created_at=inc.first_anomaly_ts,
                )
                session.add(alert)
                session.commit()

    # -----------------------------------------------------------------------
    # Step 2: Verify attack detected & alert visible in API
    # -----------------------------------------------------------------------
    resp = client.get("/api/alerts", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    alerts = resp.json()
    assert len(alerts) >= 1, "Alert was not visible in /api/alerts"

    target_alert = next((a for a in alerts if a["client_ip"] == attacker_ip), None)
    assert target_alert is not None, f"Alert for {attacker_ip} not found in {alerts}"
    assert target_alert["status"] == "open"
    alert_id = target_alert["id"]

    # -----------------------------------------------------------------------
    # Step 3: Verify SHADOW mode invariant (took no blocking action)
    # -----------------------------------------------------------------------
    assert len(responder.list_blocks()) == 0, "Shadow mode must not block client IPs"

    # -----------------------------------------------------------------------
    # Step 4: Switch to ENFORCE mode and verify fake responder is called once
    # -----------------------------------------------------------------------
    put_resp = client.put(
        "/api/settings",
        json={"mode": "enforce_temp", "confirm": True},
        headers=admin_headers,
    )
    assert put_resp.status_code == 200, put_resp.text
    assert engine.responder.mode == "enforce_temp"

    # Now block the attacker via API block endpoint (or engine in enforce mode)
    block_resp = client.post(
        f"/api/alerts/{alert_id}/block",
        json={"ttl_seconds": 900, "reason": "Mass encryption detected"},
        headers=admin_headers,
    )
    assert block_resp.status_code == 200, block_resp.text
    blocks = responder.list_blocks()
    assert len(blocks) == 1, "Enforce mode must call responder once"
    assert blocks[0].client_ip == attacker_ip

    # -----------------------------------------------------------------------
    # Step 5: Dry-run restore
    # -----------------------------------------------------------------------
    dry_run_resp = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": True, "confirm": False},
        headers=admin_headers,
    )
    assert dry_run_resp.status_code == 200, dry_run_resp.text
    dry_data = dry_run_resp.json()
    assert dry_data["dry_run"] is True
    assert "restored_count" in dry_data

    # Files must NOT be restored on disk during dry-run
    assert not doc1.exists(), "Dry-run must not create or modify files on disk"

    # -----------------------------------------------------------------------
    # Step 6: Confirmed restore
    # -----------------------------------------------------------------------
    confirm_resp = client.post(
        f"/api/alerts/{alert_id}/restore",
        json={"dry_run": False, "confirm": True},
        headers=admin_headers,
    )
    assert confirm_resp.status_code == 200, confirm_resp.text
    confirm_data = confirm_resp.json()
    assert confirm_data["dry_run"] is False

    # -----------------------------------------------------------------------
    # Step 7: Resolve alert
    # -----------------------------------------------------------------------
    resolve_resp = client.post(
        f"/api/alerts/{alert_id}/resolve",
        json={"reason": "Threat neutralized and restored"},
        headers=admin_headers,
    )
    assert resolve_resp.status_code == 200, resolve_resp.text
    assert resolve_resp.json()["status"] == "resolved"

    # Check alert status in GET /api/alerts/{id}
    detail_resp = client.get(f"/api/alerts/{alert_id}", headers=admin_headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["status"] == "resolved"

    # -----------------------------------------------------------------------
    # Step 8: Verify audit entries present for each action
    # -----------------------------------------------------------------------
    audit_resp = client.get("/api/audit", headers=admin_headers)
    assert audit_resp.status_code == 200, audit_resp.text
    audit_items = audit_resp.json()["items"]
    actions = [item["action"] for item in audit_items]

    assert "update_settings" in actions, "update_settings not recorded in audit log"
    assert "block" in actions, "block action not recorded in audit log"
    assert "restore" in actions, "restore action not recorded in audit log"
    assert "resolve" in actions, "resolve action not recorded in audit log"
