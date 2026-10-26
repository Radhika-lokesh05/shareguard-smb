"""Tests for ShareGuard reliability: system status monitoring and log follower resilience."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from shareguard.api import app, set_engine
from shareguard.db import init_db
from shareguard.engine import DetectionEngine
from shareguard.parser import follow
from shareguard.responder import FakeResponder


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
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query.encode("ascii")

        raw_headers: list[tuple[bytes, bytes]] = []
        if headers:
            for k, v in headers.items():
                raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))

        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
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
            return {"type": "http.request", "body": b"", "more_body": False}

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


VIEWER_HEADERS = {"X-API-Key": "viewer-key", "X-User-Name": "auditor"}

# ---------------------------------------------------------------------------
# 1. GET /api/status Reliability Tests
# ---------------------------------------------------------------------------


def test_status_endpoint_healthy(tmp_path: Path) -> None:
    """GET /api/status returns healthy when DB and subsystems are operational."""
    db_file = tmp_path / "status_healthy.db"
    init_db(f"sqlite:///{db_file.as_posix()}")

    config: dict[str, Any] = {
        "server": {"mode": "simulation"},
        "response": {
            "mode": "shadow",
            "allowlist": ["127.0.0.1", "::1"],
        },
    }
    responder = FakeResponder(config["response"])
    engine = DetectionEngine(config, responder=responder)
    set_engine(engine)

    client = LocalTestClient(app)
    resp = client.get("/api/status", headers=VIEWER_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in {"healthy", "degraded"}
    assert data["database"] is True
    assert "reasons" in data


def test_status_endpoint_degraded_when_db_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /api/status reports degraded when database queries fail."""
    import shareguard.api as api_mod

    def fake_get_session():
        raise RuntimeError("Database pool exhausted")

    monkeypatch.setattr(api_mod, "get_session", fake_get_session)

    client = LocalTestClient(app)
    resp = client.get("/api/status", headers=VIEWER_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["database"] is False
    assert any("Database unavailable" in r for r in data["reasons"])


# ---------------------------------------------------------------------------
# 2. follow() Log Follower Resilience Tests
# ---------------------------------------------------------------------------


def test_follow_delayed_appearance(tmp_path: Path) -> None:
    """follow() handles delayed log appearance cleanly without crashing."""
    log_file = tmp_path / "delayed_audit.log"
    collected: list[str] = []
    stop_event = threading.Event()

    def _reader() -> None:
        for line in follow(log_file, poll_interval=0.02, stop_event=stop_event):
            collected.append(line.strip())
            if len(collected) >= 2:
                stop_event.set()
                break

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    # Short delay while file does not exist
    time.sleep(0.05)

    # Now create file and append lines
    log_file.write_text("line1\nline2\n", encoding="utf-8")
    t.join(timeout=3.0)

    assert not t.is_alive()
    assert collected == ["line1", "line2"]


def test_follow_truncation_recovery(tmp_path: Path) -> None:
    """follow() detects file shrinkage/truncation and reads new lines from start."""
    log_file = tmp_path / "trunc_audit.log"
    log_file.write_text("initial_long_line_1\ninitial_long_line_2\ninitial_long_line_3\n", encoding="utf-8")

    collected: list[str] = []
    stop_event = threading.Event()

    def _reader() -> None:
        for line in follow(log_file, poll_interval=0.02, stop_event=stop_event):
            collected.append(line.strip())
            if len(collected) >= 4:
                stop_event.set()
                break

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    time.sleep(0.05)

    # Truncate and write shorter content
    log_file.write_text("truncated_line_1\n", encoding="utf-8")
    t.join(timeout=3.0)

    assert "initial_long_line_1" in collected
    assert "truncated_line_1" in collected


def test_follow_rotation_and_recreation(tmp_path: Path) -> None:
    """follow() detects file replacement (rotation) and continues reading."""
    log_file = tmp_path / "rotate_audit.log"
    log_file.write_text("batch1_line1_initial_content_before_rotation\n", encoding="utf-8")

    collected: list[str] = []
    stop_event = threading.Event()

    def _reader() -> None:
        for line in follow(log_file, poll_interval=0.02, stop_event=stop_event):
            collected.append(line.strip())
            if len(collected) >= 2:
                stop_event.set()
                break

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    time.sleep(0.05)

    # Simulate rotation by writing new content (shorter, triggering rotation/shrink detection)
    log_file.write_text("batch2_line1\n", encoding="utf-8")
    t.join(timeout=3.0)

    assert not t.is_alive()
    assert len(collected) >= 2
    assert "batch1_line1_initial_content_before_rotation" in collected
    assert "batch2_line1" in collected


def test_follow_inode_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """follow() detects inode change even when file size increases."""
    log_file = tmp_path / "inode_audit.log"
    log_file.write_text("line1\n", encoding="utf-8")

    collected: list[str] = []
    stop_event = threading.Event()

    real_stat = Path.stat
    simulated_ino = [1000]

    def fake_stat(self_path: Path, *args: Any, **kwargs: Any) -> Any:
        st = real_stat(self_path, *args, **kwargs)
        if self_path == log_file:
            class FakeStat:
                st_size = st.st_size
                st_ino = simulated_ino[0]
            return FakeStat()
        return st

    monkeypatch.setattr(Path, "stat", fake_stat)

    def _reader() -> None:
        for line in follow(log_file, poll_interval=0.02, stop_event=stop_event):
            collected.append(line.strip())
            if "line2_rotated" in collected:
                stop_event.set()
                break

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    time.sleep(0.05)

    # Inode rotates from 1000 to 2000, new content written
    simulated_ino[0] = 2000
    log_file.write_text("line2_rotated\n", encoding="utf-8")
    t.join(timeout=3.0)

    assert not t.is_alive()
    assert "line1" in collected
    assert "line2_rotated" in collected


def test_follow_stops_cleanly_on_stop_event(tmp_path: Path) -> None:
    """follow() exits promptly when stop_event is set without leaking."""
    log_file = tmp_path / "stop_audit.log"
    log_file.write_text("hello\n", encoding="utf-8")

    stop_event = threading.Event()
    collected: list[str] = []

    def _reader() -> None:
        for line in follow(log_file, poll_interval=0.02, stop_event=stop_event):
            collected.append(line.strip())
            stop_event.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=2.0)

    assert not t.is_alive()
    assert collected == ["hello"]
