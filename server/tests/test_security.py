"""Tests for security hardening, RBAC invariants, path traversal, and rate limiting."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

from shareguard.api import app, set_engine
from shareguard.auth import (
    check_login_rate_limit,
    create_access_token,
    decode_access_token,
    hash_password,
    record_login_attempt,
    reset_login_rate_limits,
    verify_live_mode_secrets,
    verify_password,
)
from shareguard.canary import CanaryManager
from shareguard.db import init_db
from shareguard.engine import DetectionEngine
from shareguard.health import run_restore_test
from shareguard.responder import FakeResponder
from shareguard.snapshots import PortableSnapshotManager


class AsgiResponse:
    """Wrapper for ASGI in-process test response."""

    def __init__(self, status_code: int, headers: dict[str, str], body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")


class LocalTestClient:
    """Zero-dependency in-process ASGI test client."""

    __test__ = False

    def __init__(self, app_instance: Any) -> None:
        self.app = app_instance

    def get(self, url: str, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("GET", url, headers=headers)

    def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("POST", url, json_data=json, headers=headers)

    def put(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("PUT", url, json_data=json, headers=headers)

    def delete(self, url: str, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self._request("DELETE", url, headers=headers)

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


ADMIN_HEADERS = {"X-API-Key": "admin-key", "X-User-Name": "secadmin"}
VIEWER_HEADERS = {"X-API-Key": "viewer-key", "X-User-Name": "auditor"}


@pytest.fixture
def sec_test_env(tmp_path: Path) -> tuple[LocalTestClient, DetectionEngine]:
    reset_login_rate_limits()
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_file = data_dir / "sec_test.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    init_db(db_url)

    snap_dir = tmp_path / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir, max_snapshots=5)

    config: dict[str, Any] = {
        "server": {"mode": "simulation"},
        "response": {
            "mode": "shadow",
            "allowlist": ["127.0.0.1", "::1", "192.168.1.1"],
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

    client = LocalTestClient(app)
    return client, engine


# ---------------------------------------------------------------------------
# 1. Route Enumeration & RBAC Invariant
# ---------------------------------------------------------------------------


def test_route_enumeration_rbac_invariants(sec_test_env: tuple[LocalTestClient, DetectionEngine]) -> None:
    """Every API endpoint must enforce authentication, and modifying operations require admin."""
    client, _ = sec_test_env
    exempt_unauth = {"/api/auth/login", "/health"}
    viewer_allowed_modifying = {"/api/assistant/explain/{alert_id}"}

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if not path.startswith("/api/") and not path.startswith("/alerts"):
            continue

        if path in exempt_unauth:
            continue

        test_path = re.sub(r"\{[^}]+\}", "1", path)

        # Check unauthenticated access gets rejected (401)
        for method in route.methods:
            if method == "GET":
                resp_unauth = client.get(test_path)
            elif method == "POST":
                resp_unauth = client.post(test_path, json={})
            elif method == "PUT":
                resp_unauth = client.put(test_path, json={})
            elif method == "DELETE":
                resp_unauth = client.delete(test_path)
            else:
                continue
            assert resp_unauth.status_code == 401, (
                f"Route {path} [{method}] allowed unauthenticated access (got {resp_unauth.status_code})"
            )

        # Check state-modifying methods require admin
        for method in route.methods:
            if method in {"POST", "PUT", "DELETE", "PATCH"}:
                if path in viewer_allowed_modifying:
                    continue
                # Viewer should get 403 Forbidden
                if method == "POST":
                    resp_viewer = client.post(test_path, json={}, headers=VIEWER_HEADERS)
                elif method == "PUT":
                    resp_viewer = client.put(test_path, json={}, headers=VIEWER_HEADERS)
                else:
                    resp_viewer = client.delete(test_path, headers=VIEWER_HEADERS)
                assert resp_viewer.status_code == 403, (
                    f"Route {path} [{method}] allowed viewer to perform state modification (got {resp_viewer.status_code})"
                )


# ---------------------------------------------------------------------------
# 2. Login Rate Limiting & Lockout
# ---------------------------------------------------------------------------


def test_login_rate_limiting_and_lockout(sec_test_env: tuple[LocalTestClient, DetectionEngine]) -> None:
    """Five consecutive failed attempts lock out the client IP with HTTP 429."""
    client, _ = sec_test_env
    test_ip = "192.168.1.99"

    # Reset state for test IP
    reset_login_rate_limits()

    # 5 failed attempts
    for _ in range(5):
        check_login_rate_limit(test_ip)
        record_login_attempt(test_ip, success=False)

    # 6th attempt must be locked out
    with pytest.raises(HTTPException) as exc_info:
        check_login_rate_limit(test_ip)
    assert exc_info.value.status_code == 429


def test_login_endpoint_lockout_response(sec_test_env: tuple[LocalTestClient, DetectionEngine]) -> None:
    """The /api/auth/login endpoint returns HTTP 429 when locked out."""
    client, _ = sec_test_env
    reset_login_rate_limits()

    # Pre-record 5 failures for 127.0.0.1 (client IP in LocalTestClient)
    for _ in range(5):
        record_login_attempt("127.0.0.1", success=False)

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert resp.status_code == 429
    assert "Too many failed login attempts" in resp.json()["detail"]
    assert "retry-after" in resp.headers


# ---------------------------------------------------------------------------
# 3. Password Hashing & JWT Bearer Token Security
# ---------------------------------------------------------------------------


def test_password_hashing_and_verification() -> None:
    """Passwords are hashed with PBKDF2/bcrypt salt and verified securely."""
    pwd = "CorrectHorseBatteryStaple123!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert hashed.startswith(("pbkdf2:sha256:", "$2b$", "$2a$"))

    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_creation_and_expiration() -> None:
    """Tokens include expiration timestamps and reject expired or tampered signatures."""
    token = create_access_token(username="admin", role="admin", expires_in_seconds=900)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"

    # Expired token
    expired_token = create_access_token(
        username="admin",
        role="admin",
        expires_in_seconds=-5,
    )
    assert decode_access_token(expired_token) is None

    # Tampered token
    tampered = token[:-4] + "xxxx"
    assert decode_access_token(tampered) is None


# ---------------------------------------------------------------------------
# 4. Live Mode Refusal on Weak Secrets
# ---------------------------------------------------------------------------


def test_live_mode_refuses_default_or_weak_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """In live mode, default or missing secrets must raise RuntimeError."""
    monkeypatch.setenv("SHAREGUARD_ADMIN_KEY", "admin-key")
    with pytest.raises(RuntimeError, match="FATAL SECURITY VIOLATION"):
        verify_live_mode_secrets("live")

    monkeypatch.setenv("SHAREGUARD_ADMIN_KEY", "short")
    with pytest.raises(RuntimeError, match="FATAL SECURITY VIOLATION"):
        verify_live_mode_secrets("live")

    monkeypatch.setenv("SHAREGUARD_ADMIN_KEY", "a" * 32)
    # Strong key should succeed
    verify_live_mode_secrets("live")


# ---------------------------------------------------------------------------
# 5. Path Traversal & Canary Escapes
# ---------------------------------------------------------------------------


def test_canary_rejects_path_outside_share_root(tmp_path: Path) -> None:
    """Canary operations must reject paths escaping share_root."""
    share_root = tmp_path / "shares" / "finance"
    share_root.mkdir(parents=True)
    registry_path = tmp_path / "canary_registry.json"

    mgr = CanaryManager(share_root=share_root, registry_path=registry_path)

    with pytest.raises(ValueError, match="escapes share root"):
        mgr.deploy(templates=[("../..", "escaped_canary.docx", "test decoy")])


def test_restore_drill_rejects_path_traversal(tmp_path: Path) -> None:
    """Snapshot restore drills must reject malicious relative paths escaping snapshot."""
    share_root = tmp_path / "share"
    share_root.mkdir()
    (share_root / "test.txt").write_text("data")

    snap_dir = tmp_path / "snapshots"
    snap_dir.mkdir()
    mgr = PortableSnapshotManager(snapshot_dir=snap_dir, max_snapshots=5)
    snap = mgr.take_snapshot(share_root)

    # Corrupt manifest to include a path traversal entry
    manifest_path = Path(snap.manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["files"] = [{"path": "../../etc/shadow", "sha256": "000000", "size": 100}]
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    result = run_restore_test(
        snapshot_manager=mgr,
        share_root=share_root,
        triggered_by="test:traversal",
    )
    assert result.status == "fail"
    assert "rejected" in result.detail


# ---------------------------------------------------------------------------
# 6. IP Format Validation
# ---------------------------------------------------------------------------


def test_alerts_reject_malformed_client_ip(sec_test_env: tuple[LocalTestClient, DetectionEngine]) -> None:
    """GET /api/alerts?client_ip=... rejects invalid IP addresses with HTTP 400."""
    client, _ = sec_test_env
    resp = client.get("/api/alerts?client_ip=999.999.999.999", headers=VIEWER_HEADERS)
    assert resp.status_code == 400
    assert "Invalid IP address format" in resp.json()["detail"]

    resp_valid = client.get("/api/alerts?client_ip=192.168.1.100", headers=VIEWER_HEADERS)
    assert resp_valid.status_code == 200
