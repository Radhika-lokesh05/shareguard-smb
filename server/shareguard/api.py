"""shareguard.api – FastAPI detection, management, and response API.

Routes:
    GET  /health                        System health report.
    GET  /api/health-check              Component health status checks.
    GET  /api/alerts                    List alerts (paginated, filterable).
    GET  /api/alerts/{id}               Get a single alert by ID.
    POST /api/alerts/{id}/block         Block client IP associated with alert (admin only).
    POST /api/alerts/{id}/unblock       Unblock client IP associated with alert (admin only).
    POST /api/alerts/{id}/restore       Restore files touched by attacker (admin only).
    POST /api/alerts/{id}/resolve       Mark alert resolved (admin only).
    POST /api/alerts/{id}/false-positive Mark alert as false positive (admin only).
    POST /api/panic                     Trigger immediate panic stop (admin only).
    POST /api/panic/clear               Clear panic stop (admin only).
    GET  /api/settings                  Get current engine and response settings (viewer/admin).
    PUT  /api/settings                  Update settings with strict bounds (admin only).
    GET  /api/events                    Stream engine events since ID (viewer/admin).
    GET  /api/export/alerts.csv         Export alerts as CSV with formula injection defense.
    POST /api/assistant/explain/{id}    Template-based incident explanation.
    GET  /api/audit                     View admin audit logs (admin only).
    GET  /api/clients                   List known clients and their block status.
    GET  /api/blocks                    List active responder blocks.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import threading
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from shareguard.assistant import (
    explain_alert,
    generate_markdown_report,
    get_assistant_status,
)
from shareguard.auth import (
    User,
    authenticate_credentials,
    check_login_rate_limit,
    record_login_attempt,
    require_admin,
    require_viewer,
    verify_live_mode_secrets,
)
from shareguard.db import AlertModel, AuditLogModel, ClientModel, get_db, get_session, init_db
from shareguard.engine import DetectionEngine, EngineEvent
from shareguard.health import (
    HealthCheckResponse,
    RateLimitError,
    RestoreTestResult,
    RestoreTestScheduler,
    evaluate_system_health,
    run_restore_test,
)
from shareguard.responder import validate_blockable_ip

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Legacy health response schema."""

    status: str
    database: str
    log_file: str
    ml_model: str
    checked_at: str


class AlertResponse(BaseModel):
    """Single alert representation."""

    id: int
    client_ip: str
    username: str
    severity: str
    triggered_rules: list[str]
    ml_score: float | None
    explanation: str | None
    status: str
    first_anomaly_ts: str | None
    files_touched: list[str]
    created_at: str
    resolved_at: str | None


class ClientResponse(BaseModel):
    """Known client representation."""

    id: int
    client_ip: str
    username: str
    first_seen: str
    last_seen: str
    is_blocked: bool


class BlockAlertRequest(BaseModel):
    """Request to block client IP associated with alert."""

    ttl_seconds: int = Field(default=900, ge=10, le=86400, description="Block duration in seconds (10s to 24h)")
    reason: str = Field(default="Manual admin response via API", max_length=256)


class RestoreRequest(BaseModel):
    """Request to restore attacker modified files."""

    dry_run: bool = Field(default=True, description="When true, computes what would be restored without disk writes")
    confirm: bool = Field(default=False, description="Must be true for real restore (dry_run=false)")


class ResolveRequest(BaseModel):
    """Request to resolve alert."""

    reason: str = Field(default="Resolved by admin", max_length=256)


class FalsePositiveRequest(BaseModel):
    """Request to mark alert as false positive."""

    allowlist: bool = Field(default=True, description="Add client IP to allowlist")
    expiry_hours: int = Field(default=24, ge=1, le=8760, description="Hours before temporary allowlist expires")
    reason: str = Field(default="Marked as false positive by admin", max_length=256)


class SettingsThresholds(BaseModel):
    """Tunable detection thresholds."""

    model_config = ConfigDict(extra="forbid")

    suspicious_threshold: float = Field(default=0.6, ge=0.1, le=1.0)
    attack_threshold: float = Field(default=0.85, ge=0.1, le=1.0)
    rename_rate_threshold: int = Field(default=20, ge=1, le=1000)
    delete_rate_threshold: int = Field(default=15, ge=1, le=1000)
    write_rate_threshold: int = Field(default=50, ge=1, le=2000)
    entropy_threshold: float = Field(default=7.0, ge=1.0, le=8.0)


class SettingsUpdate(BaseModel):
    """Settings update payload with strict validation and no unknown keys."""

    model_config = ConfigDict(extra="forbid")

    mode: str | None = Field(default=None, pattern=r"^(shadow|enforce_temp|enforce_strict)$")
    confirm: bool = Field(default=False, description="Required true when switching to an enforcing mode")
    thresholds: SettingsThresholds | None = None
    allowlist: list[str] | None = None
    block_ttl_minutes: int | None = Field(default=None, ge=1, le=1440)


class SettingsResponse(BaseModel):
    """Current engine and response settings."""

    mode: str
    thresholds: dict[str, Any]
    allowlist: list[str]
    block_ttl_minutes: int
    panic_stop: bool


class AuditLogResponse(BaseModel):
    """Single audit log entry."""

    id: int
    username: str
    action: str
    target: str
    result: str
    details: str | None
    created_at: str


class AuditLogPage(BaseModel):
    """Paged list of audit logs."""

    items: list[AuditLogResponse]
    total: int
    limit: int
    offset: int


class EngineEventItem(BaseModel):
    """Recorded engine event item."""

    id: int
    type: str
    data: dict[str, Any]
    timestamp: str


class EventsStreamResponse(BaseModel):
    """Response containing bounded events since given ID."""

    events: list[EngineEventItem]
    latest_id: int


class ExplainResponse(BaseModel):
    """Incident explanation with structured guidance and source telemetry."""

    alert_id: int
    summary: str
    what_to_do_now: list[str] = Field(default_factory=list)
    what_not_to_do: list[str] = Field(default_factory=list)
    who_to_contact: str = ""
    report_draft: str = ""
    source: str = "template"
    model: str = "deterministic-template"
    generation_time_ms: float = 0.0
    playbooks_used: list[str] = Field(default_factory=list)
    explanation: str | None = None
    provider: str | None = None


class LoginRequest(BaseModel):
    """User login request payload."""

    username: str = ""
    password: str


class LoginResponse(BaseModel):
    """Successful authentication response."""

    token: str
    username: str
    role: str


class UserResponse(BaseModel):
    """Current authenticated user profile."""

    username: str
    role: str


# ---------------------------------------------------------------------------
# Global Application State & Lifespan
# ---------------------------------------------------------------------------

_engine_instance: DetectionEngine | None = None
_engine_lock = threading.Lock()
_event_ring_buffer: deque[EngineEventItem] = deque(maxlen=5000)
_event_counter = 0
_event_lock = threading.Lock()
_dry_run_cache: dict[str, dict[str, Any]] = {}
_dry_run_lock = threading.Lock()
_sim_stop_event = threading.Event()
_sim_thread: threading.Thread | None = None


def get_engine() -> DetectionEngine:
    """Retrieve or lazily initialize the singleton DetectionEngine."""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            config_path = Path("config/default.yaml")
            cfg: dict[str, Any] = {}
            if config_path.exists():
                import yaml

                cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            _engine_instance = DetectionEngine(cfg)
            # Subscribe to engine events for real-time dashboard API feed
            _engine_instance.event_bus.subscribe(_record_engine_event)
        return _engine_instance


def set_engine(engine: DetectionEngine) -> None:
    """Explicitly set the engine instance (used in tests and simulation)."""
    global _engine_instance
    with _engine_lock:
        _engine_instance = engine
        _engine_instance.event_bus.subscribe(_record_engine_event)


def _record_engine_event(event: EngineEvent) -> None:
    """Record an engine event into monotonic in-memory ring buffer."""
    global _event_counter
    with _event_lock:
        _event_counter += 1
        data_dict: dict[str, Any] = {}
        for k in getattr(event, "__slots__", ()):
            v = getattr(event, k, None)
            if isinstance(v, datetime):
                data_dict[k] = v.isoformat()
            else:
                data_dict[k] = v
        item = EngineEventItem(
            id=_event_counter,
            type=event.__class__.__name__,
            data=data_dict,
            timestamp=datetime.now(UTC).isoformat(),
        )
        _event_ring_buffer.append(item)


def _record_audit_log(
    db: Session,
    username: str,
    action: str,
    target: str,
    result: str,
    details: str | None = None,
) -> AuditLogModel:
    """Safely append an entry to the administrative AuditLog table."""
    entry = AuditLogModel(
        username=username,
        action=action,
        target=target,
        result=result,
        details=details,
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def _escape_csv_cell(value: Any) -> str:
    """Defend against CSV/formula injection attacks.

    Prefixes cells that start with =, +, -, @, \\t, or \\r with a single quote.
    """
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"
    return text


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI lifespan: initialize DB, engine, and optional simulation loop."""
    import os

    init_db()
    engine = get_engine()

    cfg = getattr(engine, "config", {})
    srv_mode = cfg.get("server", {}).get("mode", os.getenv("SHAREGUARD_MODE", "simulation"))
    verify_live_mode_secrets(srv_mode)

    sim_stop: threading.Event | None = None
    if os.getenv("SHAREGUARD_SIM") == "1":
        from shareguard.sim_loop import start_simulation, stop_simulation

        sim_stop = start_simulation(engine)

    # Initialize weekly restore test drill scheduler
    samba_cfg = cfg.get("samba", {})
    share_root = Path(samba_cfg.get("share_root", "/srv/samba/share"))
    snapshot_mgr = _get_snapshot_manager(engine, cfg)
    scheduler = RestoreTestScheduler(snapshot_mgr, share_root)
    scheduler.start()

    yield

    scheduler.stop()
    # Shutdown simulation thread if active
    if sim_stop is not None:
        from shareguard.sim_loop import stop_simulation

        stop_simulation()


app = FastAPI(
    title="ShareGuard API",
    description="Ransomware detection and active response API for Samba file servers.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8501",
        "http://localhost:8501",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB cap


@app.middleware("http")
async def apply_security_headers_and_size_limits(request: Request, call_next: Any) -> Response:
    content_len = request.headers.get("content-length")
    if content_len:
        try:
            if int(content_len) > MAX_REQUEST_BODY_BYTES:
                return Response(
                    content=json.dumps({"detail": "Payload too large. Request body exceeds 10 MB limit."}),
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    media_type="application/json",
                )
        except ValueError:
            pass

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    """Mask internal tracebacks and error details from API responses in production."""
    if isinstance(exc, HTTPException):
        return Response(
            content=json.dumps({"detail": exc.detail}),
            status_code=exc.status_code,
            media_type="application/json",
            headers=getattr(exc, "headers", None),
        )
    logger.exception("Internal error processing %s %s: %s", request.method, request.url.path, exc)
    return Response(
        content=json.dumps({"detail": "Internal server error."}),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Health & Status Endpoints
# ---------------------------------------------------------------------------


class SystemStatusResponse(BaseModel):
    """Reliability and degraded subsystem report."""

    status: Literal["healthy", "degraded"]
    reasons: list[str] = Field(default_factory=list)
    database: bool
    ml_model: bool
    ollama: bool
    timestamp: str


@app.get("/", tags=["system"])
def root() -> dict[str, Any]:
    """Root entrypoint with service metadata and documentation links."""
    return {
        "service": "ShareGuard API",
        "version": "0.2.0",
        "status": "running",
        "docs_url": "/docs",
        "health_url": "/health",
        "api_health_check": "/api/health-check",
    }


@app.get("/health", response_model=HealthResponse, tags=["system"])
def get_health() -> HealthResponse:
    """Return legacy system health overview."""
    return HealthResponse(
        status="ok",
        database="ok",
        log_file="ok",
        ml_model="ok",
        checked_at=datetime.now(UTC).isoformat(),
    )


@app.get("/api/status", response_model=SystemStatusResponse, tags=["system"])
def get_system_status(_user: User = Depends(require_viewer)) -> SystemStatusResponse:
    """Report whether ShareGuard is healthy or degraded if DB, ML, or Ollama is down."""
    reasons: list[str] = []
    engine = get_engine()

    # 1. Database check
    db_ok = True
    try:
        with get_session() as s:
            s.execute(select(1))
    except Exception as exc:
        db_ok = False
        reasons.append(f"Database unavailable: {str(exc)}")

    # 2. ML model check
    ml_ok = bool(getattr(getattr(engine, "detector", None), "is_ml_loaded", True))
    if not ml_ok:
        reasons.append("ML anomaly model not loaded; operating in rule-only fallback mode")

    # 3. Ollama assistant check
    ollama_ok = True
    try:
        asst_status = get_assistant_status()
        ollama_ok = bool(asst_status.get("ollama_reachable", True))
        if not ollama_ok:
            reasons.append("Ollama AI offline; incident assistant falling back to deterministic templates")
    except Exception as exc:
        ollama_ok = False
        reasons.append(f"Ollama status check failed: {str(exc)}")

    overall: Literal["healthy", "degraded"] = "degraded" if reasons else "healthy"
    return SystemStatusResponse(
        status=overall,
        reasons=reasons,
        database=db_ok,
        ml_model=ml_ok,
        ollama=ollama_ok,
        timestamp=datetime.now(UTC).isoformat(),
    )


def _get_snapshot_manager(engine: DetectionEngine, cfg: dict[str, Any]) -> Any:
    """Safely obtain snapshot manager from engine or instantiate fallback."""
    mgr = getattr(engine, "snapshot_manager", None)
    if mgr is None:
        mgr = getattr(engine, "snapshots", None)
    if mgr is None:
        from shareguard.snapshots import PortableSnapshotManager

        snap_cfg = cfg.get("snapshot", {})
        snap_dir = Path(snap_cfg.get("snapshot_dir", "snapshots/"))
        mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    return mgr


@app.get("/api/health-check", response_model=HealthCheckResponse, tags=["system"])
@app.get("/health-check", response_model=HealthCheckResponse, tags=["system"])
def get_health_checks(
    _user: User = Depends(require_viewer),
) -> HealthCheckResponse:
    """Return component status checks and system diagnostic probes."""
    engine = get_engine()
    cfg = getattr(engine, "config", {})
    samba_cfg = cfg.get("samba", {})
    share_root = Path(samba_cfg.get("share_root", "/srv/samba/share"))
    audit_log = Path(samba_cfg.get("audit_log_path", "lab/sample_audit.log"))

    # Test DB health
    db_healthy = True
    try:
        with get_session() as s:
            s.execute(select(1))
    except Exception:
        db_healthy = False

    mode_str = engine.mode.value if hasattr(engine.mode, "value") else str(engine.mode)
    allowlist = list(getattr(engine.responder, "allowlist", []))
    panic_active = getattr(engine.responder, "is_panic_stopped", False)
    is_live = cfg.get("server", {}).get("mode", "simulation") == "live"

    canary_mgr = getattr(engine, "canary_manager", None)
    snapshot_mgr = _get_snapshot_manager(engine, cfg)

    return evaluate_system_health(
        share_root=share_root,
        audit_log_path=audit_log,
        snapshot_manager=snapshot_mgr,
        runner=getattr(engine.responder, "runner", None),
        canary_manager=canary_mgr,
        engine_mode=mode_str,
        allowlist=allowlist,
        panic_stop_active=panic_active,
        is_ml_loaded=getattr(getattr(engine, "detector", None), "is_ml_loaded", True),
        is_live_mode=is_live,
        is_db_healthy=db_healthy,
    )


@app.post("/api/health-check/restore-test", response_model=RestoreTestResult, tags=["system"])
@app.post("/health-check/restore-test", response_model=RestoreTestResult, tags=["system"])
def run_restore_drill_endpoint(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> RestoreTestResult:
    """Execute an automated synthetic restore test drill (admin only)."""
    engine = get_engine()
    cfg = getattr(engine, "config", {})
    samba_cfg = cfg.get("samba", {})
    share_root = Path(samba_cfg.get("share_root", "/srv/samba/share"))
    snapshot_mgr = _get_snapshot_manager(engine, cfg)

    try:
        result = run_restore_test(
            snapshot_manager=snapshot_mgr,
            share_root=share_root,
            triggered_by=f"admin:{user.username}",
        )
    except RateLimitError as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: A restore drill was run recently. Please wait {err.retry_after} seconds before running another drill.",
        ) from err
    except Exception as err:
        _record_audit_log(
            db,
            username=user.username,
            action="restore_test",
            target="snapshots",
            result="fail",
            details=f"Unexpected error: {str(err)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Restore drill failed: {str(err)}",
        ) from err

    _record_audit_log(
        db,
        username=user.username,
        action="restore_test",
        target=f"snapshot:{result.id}",
        result=result.status.upper(),
        details=f"restored_count={result.files_restored}, time_taken={result.time_taken_seconds}s, detail={result.detail}",
    )
    return result


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------


@app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
def login(body: LoginRequest, request: Request) -> LoginResponse:
    """Exchange credentials for an API Bearer token and role."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_login_rate_limit(client_ip)
    result = authenticate_credentials(body.username.strip(), body.password.strip())
    if not result:
        record_login_attempt(client_ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    record_login_attempt(client_ip, success=True)
    token, username, role = result
    return LoginResponse(token=token, username=username, role=role)


@app.get("/api/auth/me", response_model=UserResponse, tags=["auth"])
def get_me(user: User = Depends(require_viewer)) -> UserResponse:
    """Return the currently authenticated user identity and role."""
    return UserResponse(username=user.username, role=user.role)


# ---------------------------------------------------------------------------
# Alert Read Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/alerts", response_model=list[AlertResponse], tags=["alerts"])
@app.get("/alerts", response_model=list[AlertResponse], tags=["alerts"])
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status"),
    client_ip: str | None = None,
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> list[AlertResponse]:
    """Return a paginated list of alerts."""
    stmt = select(AlertModel)
    if status_filter:
        stmt = stmt.where(AlertModel.status == status_filter)
    if client_ip:
        try:
            validated_ip = str(ipaddress.ip_address(client_ip.strip()))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address format: {client_ip}",
            ) from exc
        stmt = stmt.where(AlertModel.client_ip == validated_ip)
    stmt = stmt.order_by(desc(AlertModel.created_at)).limit(limit).offset(offset)
    rows = db.scalars(stmt).all()

    results: list[AlertResponse] = []
    for a in rows:
        files: list[str] = []
        if a.files_touched:
            try:
                files = json.loads(a.files_touched)
            except Exception:
                files = [f.strip() for f in a.files_touched.split(",") if f.strip()]
        results.append(
            AlertResponse(
                id=a.id,
                client_ip=a.client_ip,
                username=a.username,
                severity=a.severity,
                triggered_rules=[r.strip() for r in a.triggered_rules.split(",") if r.strip()],
                ml_score=a.ml_score,
                explanation=a.explanation,
                status=a.status,
                first_anomaly_ts=a.first_anomaly_ts.isoformat() if a.first_anomaly_ts else None,
                files_touched=files,
                created_at=a.created_at.isoformat(),
                resolved_at=a.resolved_at.isoformat() if a.resolved_at else None,
            )
        )
    return results


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse, tags=["alerts"])
@app.get("/alerts/{alert_id}", response_model=AlertResponse, tags=["alerts"])
def get_alert(
    alert_id: int,
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Return a single alert by ID."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    files: list[str] = []
    if alert.files_touched:
        try:
            files = json.loads(alert.files_touched)
        except Exception:
            files = [f.strip() for f in alert.files_touched.split(",") if f.strip()]

    return AlertResponse(
        id=alert.id,
        client_ip=alert.client_ip,
        username=alert.username,
        severity=alert.severity,
        triggered_rules=[r.strip() for r in alert.triggered_rules.split(",") if r.strip()],
        ml_score=alert.ml_score,
        explanation=alert.explanation,
        status=alert.status,
        first_anomaly_ts=alert.first_anomaly_ts.isoformat() if alert.first_anomaly_ts else None,
        files_touched=files,
        created_at=alert.created_at.isoformat(),
        resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
    )


# ---------------------------------------------------------------------------
# Action Endpoints (Admin Only, Audit Logged)
# ---------------------------------------------------------------------------


@app.post("/api/alerts/{alert_id}/block", tags=["actions"])
def block_alert_client(
    alert_id: int,
    body: BlockAlertRequest,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Block the client IP associated with *alert_id* via the active responder."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    target_ip = alert.client_ip
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address associated with alert: {target_ip}",
        ) from exc

    # Security Invariant: NEVER block server, gateway, loopback, or allowlisted IPs
    is_protected = engine.is_ip_allowlisted(target_ip)
    if not is_protected:
        resp_cfg = engine.config.get("response", {})
        server_ips = set(resp_cfg.get("server_ips", []))
        if hasattr(engine.responder, "server_ips"):
            server_ips.update(engine.responder.server_ips)
        gateway_ip = resp_cfg.get("gateway_ip") or getattr(engine.responder, "gateway_ip", None)
        allowlist = set(engine.allowlist)
        if hasattr(engine.responder, "allowlist"):
            allowlist.update(engine.responder.allowlist)
        try:
            validate_blockable_ip(
                target_ip,
                allowlist=allowlist,
                server_ips=server_ips,
                gateway_ip=gateway_ip,
            )
        except ValueError:
            is_protected = True

    if is_protected:
        _record_audit_log(
            db,
            username=user.username,
            action="block",
            target=f"alert:{alert_id}:{target_ip}",
            result="refused: allowlisted/protected IP",
            details=f"Refused block request: {target_ip} is protected by allowlist/safety rules",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Refused: IP address {target_ip} is protected (server, gateway, or allowlist) and cannot be blocked.",
        )

    # Execute block via responder
    record = engine.responder.block_client(
        ip=target_ip,
        ttl_seconds=body.ttl_seconds,
        reason=body.reason,
        username=alert.username,
    )

    if record is None and engine.responder.mode != "shadow":
        _record_audit_log(
            db,
            username=user.username,
            action="block",
            target=f"alert:{alert_id}:{target_ip}",
            result="refused: responder rejected block",
            details="Responder rejected block (rate limit or safety check)",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Responder refused to block {target_ip} (rate limit or safety violation).",
        )

    # Update client blocked status in DB if record exists
    client = db.scalar(select(ClientModel).where(ClientModel.client_ip == target_ip))
    if client:
        client.is_blocked = True
        db.commit()

    _record_audit_log(
        db,
        username=user.username,
        action="block",
        target=f"alert:{alert_id}:{target_ip}",
        result="success",
        details=f"ttl_seconds={body.ttl_seconds}, reason={body.reason}",
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "client_ip": target_ip,
        "ttl_seconds": body.ttl_seconds,
        "reason": body.reason,
        "expires_at": record.expires_at.isoformat() if record else None,
    }


@app.post("/api/alerts/{alert_id}/unblock", tags=["actions"])
def unblock_alert_client(
    alert_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Unblock the client IP associated with *alert_id*."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    target_ip = alert.client_ip
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address associated with alert: {target_ip}",
        ) from exc
    success = engine.responder.unblock_client(target_ip)

    client = db.scalar(select(ClientModel).where(ClientModel.client_ip == target_ip))
    if client:
        client.is_blocked = False
        db.commit()

    _record_audit_log(
        db,
        username=user.username,
        action="unblock",
        target=f"alert:{alert_id}:{target_ip}",
        result="success" if success else "not_blocked",
        details=f"Unblocked client {target_ip}",
    )

    return {"success": True, "alert_id": alert_id, "client_ip": target_ip, "unblocked": success}


@app.post("/api/alerts/{alert_id}/restore", tags=["actions"])
def restore_alert_files(
    alert_id: int,
    body: RestoreRequest,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Restore files encrypted or damaged by the attacker during *alert_id* incident."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    alert_key = str(alert_id)

    # Locate incident record or parse touched files from alert
    files_to_restore: list[str] = []
    before_ts: datetime = alert.created_at
    incident = engine.alert_repo.get(alert_key)
    if incident:
        files_to_restore = list(incident.files_touched)
        before_ts = incident.first_anomaly_ts
    elif alert.files_touched:
        try:
            files_to_restore = json.loads(alert.files_touched)
        except Exception:
            files_to_restore = [f.strip() for f in alert.files_touched.split(",") if f.strip()]
    if alert.first_anomaly_ts:
        before_ts = alert.first_anomaly_ts
    if before_ts.tzinfo is None:
        before_ts = before_ts.replace(tzinfo=UTC)

    share_root = engine.config.get("samba", {}).get("share_root", ".")

    # 1. Find clean baseline snapshot created before anomaly began
    clean_snap = engine.snapshot_manager.find_clean_snapshot(share_root, before_ts)
    if not clean_snap:
        _record_audit_log(
            db,
            username=user.username,
            action="restore_dry_run" if body.dry_run else "restore",
            target=f"alert:{alert_id}",
            result="failed: no clean snapshot",
            details=f"No clean snapshot exists prior to {before_ts.isoformat()}",
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No clean snapshot exists prior to first anomaly timestamp ({before_ts.isoformat()}).",
        )

    # 2. DRY-RUN MODE: Safe simulated restoration preview
    if body.dry_run:
        report = engine.snapshot_manager.restore_files(
            share=share_root,
            snapshot_id=clean_snap.snapshot_id,
            paths=files_to_restore,
            dry_run=True,
            first_anomaly_ts=before_ts,
        )
        # Cache dry-run result for real confirmation window (15 minutes)
        with _dry_run_lock:
            _dry_run_cache[alert_key] = {
                "timestamp": datetime.now(UTC),
                "snapshot_id": clean_snap.snapshot_id,
                "files": files_to_restore,
                "report": report,
            }

        total_bytes = getattr(report, "restored_bytes", getattr(report, "total_bytes", 0))
        restored_files = getattr(report, "restored_paths", getattr(report, "restored_files", []))
        skipped_files = [
            p["path"] if isinstance(p, dict) else str(p)
            for p in getattr(report, "skipped_paths", getattr(report, "skipped_files", []))
        ]
        errors = [
            f["reason"] if isinstance(f, dict) else str(f)
            for f in getattr(report, "failed_paths", getattr(report, "errors", []))
        ]

        _record_audit_log(
            db,
            username=user.username,
            action="restore_dry_run",
            target=f"alert:{alert_id}",
            result="success",
            details=f"Dry-run: restored={report.restored_count}, skipped={report.skipped_count}, bytes={total_bytes}",
        )

        return {
            "dry_run": True,
            "alert_id": alert_id,
            "snapshot_id": clean_snap.snapshot_id,
            "restored_count": report.restored_count,
            "skipped_count": report.skipped_count,
            "failed_count": report.failed_count,
            "total_bytes": total_bytes,
            "restored_files": restored_files,
            "skipped_files": skipped_files,
            "errors": errors,
        }

    # 3. REAL RESTORE: Strict confirmation & prior dry-run validation
    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Real restore requires explicit confirmation: confirm=true must be provided.",
        )

    with _dry_run_lock:
        cached = _dry_run_cache.get(alert_key)
        if not cached:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Real restore refused: a prior dry-run must be performed for this alert first.",
            )
        elapsed = (datetime.now(UTC) - cached["timestamp"]).total_seconds()
        if elapsed > 900:  # 15 minutes window
            _dry_run_cache.pop(alert_key, None)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Prior dry-run expired (> 15 minutes ago). Perform a new dry-run before real restoration.",
            )
        # Pop cache so dry run cannot be replayed repeatedly
        _dry_run_cache.pop(alert_key, None)

    real_report = engine.snapshot_manager.restore_files(
        share=share_root,
        snapshot_id=clean_snap.snapshot_id,
        paths=cached["files"],
        dry_run=False,
        first_anomaly_ts=before_ts,
    )

    real_bytes = getattr(real_report, "restored_bytes", getattr(real_report, "total_bytes", 0))
    real_restored_files = getattr(real_report, "restored_paths", getattr(real_report, "restored_files", []))
    real_skipped_files = [
        p["path"] if isinstance(p, dict) else str(p)
        for p in getattr(real_report, "skipped_paths", getattr(real_report, "skipped_files", []))
    ]
    real_errors = [
        f["reason"] if isinstance(f, dict) else str(f)
        for f in getattr(real_report, "failed_paths", getattr(real_report, "errors", []))
    ]

    _record_audit_log(
        db,
        username=user.username,
        action="restore",
        target=f"alert:{alert_id}",
        result="success",
        details=f"Real restore: restored={real_report.restored_count}, skipped={real_report.skipped_count}, bytes={real_bytes}",
    )

    return {
        "dry_run": False,
        "alert_id": alert_id,
        "snapshot_id": clean_snap.snapshot_id,
        "restored_count": real_report.restored_count,
        "skipped_count": real_report.skipped_count,
        "failed_count": real_report.failed_count,
        "total_bytes": real_bytes,
        "restored_files": real_restored_files,
        "skipped_files": real_skipped_files,
        "errors": real_errors,
    }


@app.post("/api/alerts/{alert_id}/resolve", tags=["actions"])
def resolve_alert(
    alert_id: int,
    body: ResolveRequest | None = None,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Mark an alert and associated incident resolved."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    reason = body.reason if body else "Resolved by admin"
    alert.status = "resolved"
    alert.resolved_at = datetime.now(UTC)
    db.commit()

    engine = get_engine()
    if hasattr(engine, "resolve_client"):
        engine.resolve_client(alert.client_ip, alert.username or "", reason=reason)
    elif hasattr(engine, "resolve_incident"):
        engine.resolve_incident(alert.client_ip, alert.username, reason=reason)

    _record_audit_log(
        db,
        username=user.username,
        action="resolve",
        target=f"alert:{alert_id}",
        result="success",
        details=reason,
    )

    return {"success": True, "alert_id": alert_id, "status": "resolved", "reason": reason}


@app.post("/api/alerts/{alert_id}/false-positive", tags=["actions"])
def mark_false_positive(
    alert_id: int,
    body: FalsePositiveRequest,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Mark alert as false positive, unblock client, and optionally add to temporary allowlist."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    target_ip = alert.client_ip

    alert.status = "false_positive"
    alert.resolved_at = datetime.now(UTC)
    db.commit()

    # Unblock client
    engine.responder.unblock_client(target_ip)
    client = db.scalar(select(ClientModel).where(ClientModel.client_ip == target_ip))
    if client:
        client.is_blocked = False
        db.commit()

    # Add to allowlist if requested
    if body.allowlist:
        engine.allowlist.add(target_ip)

    if hasattr(engine, "resolve_client"):
        engine.resolve_client(target_ip, alert.username or "", reason="false_positive")
    elif hasattr(engine, "resolve_incident"):
        engine.resolve_incident(target_ip, alert.username, reason="false_positive")

    _record_audit_log(
        db,
        username=user.username,
        action="false_positive",
        target=f"alert:{alert_id}:{target_ip}",
        result="success",
        details=f"allowlist={body.allowlist}, expiry_hours={body.expiry_hours}, reason={body.reason}",
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "status": "false_positive",
        "client_ip": target_ip,
        "allowlisted": body.allowlist,
    }


@app.post("/api/panic", tags=["actions"])
def trigger_panic_stop(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Immediately disable all active enforcement and blocking actions."""
    engine = get_engine()
    engine.set_panic_stop(True)

    _record_audit_log(
        db,
        username=user.username,
        action="panic",
        target="global",
        result="panic stop enabled",
        details="Administrator engaged emergency panic stop: all enforcement actions suppressed.",
    )

    return {"panic_stop": True, "message": "Global panic stop enabled: all enforcement actions suppressed."}


@app.post("/api/panic/clear", tags=["actions"])
def clear_panic_stop(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Clear emergency panic stop and restore active enforcement."""
    engine = get_engine()
    engine.set_panic_stop(False)

    _record_audit_log(
        db,
        username=user.username,
        action="panic_clear",
        target="global",
        result="panic stop cleared",
        details="Administrator cleared emergency panic stop: enforcement actions restored.",
    )

    return {"panic_stop": False, "message": "Emergency panic stop cleared: enforcement restored."}


# ---------------------------------------------------------------------------
# Settings Endpoints (Viewer GET, Admin PUT)
# ---------------------------------------------------------------------------


@app.get("/api/settings", response_model=SettingsResponse, tags=["settings"])
def get_settings(
    _user: User = Depends(require_viewer),
) -> SettingsResponse:
    """Retrieve current detection and response settings."""
    engine = get_engine()
    det_cfg = engine.config.get("detection", {})
    rules_cfg = det_cfg.get("rules", {})
    resp_cfg = engine.config.get("response", {})

    return SettingsResponse(
        mode=engine.mode.value if hasattr(engine.mode, "value") else str(engine.mode),
        thresholds={
            "suspicious_threshold": float(det_cfg.get("suspicious_threshold", 0.6)),
            "attack_threshold": float(det_cfg.get("attack_threshold", 0.85)),
            "rename_rate_threshold": int(det_cfg.get("rename_rate_threshold", 20)),
            "delete_rate_threshold": int(det_cfg.get("delete_rate_threshold", 15)),
            "write_rate_threshold": int(det_cfg.get("write_rate_threshold", 50)),
            "entropy_threshold": float(det_cfg.get("entropy_threshold", 7.0)),
            "rules": rules_cfg,
        },
        allowlist=sorted(engine.allowlist),
        block_ttl_minutes=int(resp_cfg.get("block_ttl_minutes", 15)),
        panic_stop=engine.panic_stop,
    )


@app.put("/api/settings", response_model=SettingsResponse, tags=["settings"])
def update_settings(
    body: SettingsUpdate,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> SettingsResponse:
    """Update engine settings with strict bounds checking.

    Rejects unknown keys. Switching to enforcing mode requires ``confirm=true``.
    """
    engine = get_engine()
    current_mode = engine.mode.value if hasattr(engine.mode, "value") else str(engine.mode)

    # Enforce confirm=true when switching to enforcing mode
    if body.mode in ("enforce_temp", "enforce_strict") and current_mode == "shadow" and not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Switching from shadow mode to an enforcing mode requires confirm=true.",
        )

    # Validate allowlist format
    if body.allowlist is not None:
        validated_allowlist: set[str] = set()
        for ip_item in body.allowlist:
            clean = ip_item.strip()
            try:
                if "/" in clean:
                    ipaddress.ip_network(clean, strict=False)
                else:
                    ipaddress.ip_address(clean)
                validated_allowlist.add(clean)
            except ValueError as err:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid allowlist IP or CIDR '{clean}': {err}",
                ) from err
        engine.allowlist = validated_allowlist

    # Update mode
    if body.mode is not None:
        engine.mode = body.mode  # type: ignore[assignment]
        if hasattr(engine.responder, "mode"):
            engine.responder.mode = body.mode

    # Update thresholds
    if body.thresholds is not None:
        if body.thresholds.attack_threshold < body.thresholds.suspicious_threshold:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="attack_threshold must be greater than or equal to suspicious_threshold.",
            )
        det_cfg = engine.config.setdefault("detection", {})
        det_cfg["suspicious_threshold"] = body.thresholds.suspicious_threshold
        det_cfg["attack_threshold"] = body.thresholds.attack_threshold
        det_cfg["rename_rate_threshold"] = body.thresholds.rename_rate_threshold
        det_cfg["delete_rate_threshold"] = body.thresholds.delete_rate_threshold
        det_cfg["write_rate_threshold"] = body.thresholds.write_rate_threshold
        det_cfg["entropy_threshold"] = body.thresholds.entropy_threshold

    # Update block TTL
    if body.block_ttl_minutes is not None:
        resp_cfg = engine.config.setdefault("response", {})
        resp_cfg["block_ttl_minutes"] = body.block_ttl_minutes
        if hasattr(engine.responder, "block_ttl_minutes"):
            engine.responder.block_ttl_minutes = body.block_ttl_minutes

    _record_audit_log(
        db,
        username=user.username,
        action="update_settings",
        target="settings",
        result="success",
        details=json.dumps(body.model_dump(exclude_unset=True)),
    )

    return get_settings(_user=user)


# ---------------------------------------------------------------------------
# Events, Export & Assistant Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/events", response_model=EventsStreamResponse, tags=["events"])
def get_events(
    since: int = Query(0, ge=0, description="Return events strictly newer than this sequence ID"),
    limit: int = Query(100, ge=1, le=500, description="Max events to return"),
    _user: User = Depends(require_viewer),
) -> EventsStreamResponse:
    """Return bounded sequence of new engine events since ID for live dashboard updates."""
    with _event_lock:
        all_events = list(_event_ring_buffer)
        latest_id = _event_counter

    filtered = [ev for ev in all_events if ev.id > since][:limit]
    return EventsStreamResponse(events=filtered, latest_id=latest_id)


@app.get("/api/export/alerts.csv", tags=["export"])
def export_alerts_csv(
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> Response:
    """Export alerts as CSV with CSV/formula injection prevention."""
    stmt = select(AlertModel).order_by(desc(AlertModel.created_at)).limit(2000)
    alerts = db.scalars(stmt).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)

    # Headers
    writer.writerow(
        [
            "ID",
            "Client IP",
            "Username",
            "Severity",
            "Triggered Rules",
            "ML Score",
            "Status",
            "First Anomaly TS",
            "Created At (UTC)",
            "Resolved At (UTC)",
            "Explanation",
        ]
    )

    for a in alerts:
        # Sanitize and defend against formula injection for every cell
        writer.writerow(
            [
                _escape_csv_cell(a.id),
                _escape_csv_cell(a.client_ip),
                _escape_csv_cell(a.username),
                _escape_csv_cell(a.severity),
                _escape_csv_cell(a.triggered_rules),
                _escape_csv_cell(f"{a.ml_score:.3f}" if a.ml_score is not None else ""),
                _escape_csv_cell(a.status),
                _escape_csv_cell(a.first_anomaly_ts.isoformat() if a.first_anomaly_ts else ""),
                _escape_csv_cell(a.created_at.isoformat()),
                _escape_csv_cell(a.resolved_at.isoformat() if a.resolved_at else ""),
                _escape_csv_cell(a.explanation or ""),
            ]
        )

    content = buffer.getvalue()
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@app.post("/api/assistant/explain/{alert_id}", response_model=ExplainResponse, tags=["assistant"])
def explain_alert_endpoint(
    alert_id: int,
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> ExplainResponse:
    """Generate structured plain-language incident explanation using local Ollama or template fallback."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    mode_str = engine.mode.value if hasattr(engine.mode, "value") else str(engine.mode)

    raw_files: list[str] = []
    if alert.files_touched:
        try:
            raw_files = json.loads(alert.files_touched)
        except Exception:
            raw_files = [f.strip() for f in alert.files_touched.split(",") if f.strip()]

    alert_dict = {
        "id": alert.id,
        "client_ip": alert.client_ip,
        "username": alert.username,
        "severity": alert.severity,
        "triggered_rules": [r.strip() for r in (alert.triggered_rules or "").split(",") if r.strip()],
        "ml_score": alert.ml_score,
        "explanation": alert.explanation,
        "status": alert.status,
        "first_anomaly_ts": alert.first_anomaly_ts.isoformat() if alert.first_anomaly_ts else None,
        "files_touched": raw_files,
        "created_at": alert.created_at.isoformat(),
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
    }

    result = explain_alert(alert_dict, engine_mode=mode_str)
    return ExplainResponse(
        alert_id=result["alert_id"],
        summary=result["summary"],
        what_to_do_now=result.get("what_to_do_now", []),
        what_not_to_do=result.get("what_not_to_do", []),
        who_to_contact=result.get("who_to_contact", ""),
        report_draft=result.get("report_draft", ""),
        source=result.get("source", "template"),
        model=result.get("model", "deterministic-template"),
        generation_time_ms=result.get("generation_time_ms", 0.0),
        playbooks_used=result.get("playbooks_used", []),
        explanation=result["summary"],
        provider=result.get("source", "template"),
    )


@app.get("/api/assistant/status", tags=["assistant"])
def get_assistant_health_status(
    _user: User = Depends(require_viewer),
) -> dict[str, Any]:
    """Check local Ollama reachability and required model availability."""
    return get_assistant_status()


@app.get("/api/alerts/{alert_id}/report.md", tags=["export"])
def export_alert_report_markdown(
    alert_id: int,
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> Response:
    """Export formatted Markdown security incident report with legal disclaimer."""
    alert = db.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    engine = get_engine()
    mode_str = engine.mode.value if hasattr(engine.mode, "value") else str(engine.mode)

    raw_files: list[str] = []
    if alert.files_touched:
        try:
            raw_files = json.loads(alert.files_touched)
        except Exception:
            raw_files = [f.strip() for f in alert.files_touched.split(",") if f.strip()]

    alert_dict = {
        "id": alert.id,
        "client_ip": alert.client_ip,
        "username": alert.username,
        "severity": alert.severity,
        "triggered_rules": [r.strip() for r in (alert.triggered_rules or "").split(",") if r.strip()],
        "ml_score": alert.ml_score,
        "explanation": alert.explanation,
        "status": alert.status,
        "first_anomaly_ts": alert.first_anomaly_ts.isoformat() if alert.first_anomaly_ts else None,
        "files_touched": raw_files,
        "created_at": alert.created_at.isoformat(),
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
    }

    explanation_data = explain_alert(alert_dict, engine_mode=mode_str)
    report_content = generate_markdown_report(alert_dict, explanation_data, engine_mode=mode_str)

    return Response(
        content=report_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=incident_report_{alert_id}.md"},
    )


@app.get("/api/audit", response_model=AuditLogPage, tags=["audit"])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AuditLogPage:
    """Return paged audit log records (admin only)."""
    total = db.scalar(select(func.count(AuditLogModel.id))) or 0
    stmt = select(AuditLogModel).order_by(desc(AuditLogModel.created_at)).limit(limit).offset(offset)
    rows = db.scalars(stmt).all()

    items = [
        AuditLogResponse(
            id=r.id,
            username=r.username,
            action=r.action,
            target=r.target,
            result=r.result,
            details=r.details,
            created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]

    return AuditLogPage(items=items, total=total, limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# Clients & Blocks Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/clients", response_model=list[ClientResponse], tags=["clients"])
@app.get("/clients", response_model=list[ClientResponse], tags=["clients"])
def list_clients(
    _user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> list[ClientResponse]:
    """Return known clients."""
    rows = db.scalars(select(ClientModel).order_by(desc(ClientModel.last_seen))).all()
    return [
        ClientResponse(
            id=c.id,
            client_ip=c.client_ip,
            username=c.username,
            first_seen=c.first_seen.isoformat(),
            last_seen=c.last_seen.isoformat(),
            is_blocked=bool(c.is_blocked),
        )
        for c in rows
    ]


@app.get("/api/blocks", response_model=list[dict[str, Any]], tags=["response"])
@app.get("/blocks", response_model=list[dict[str, Any]], tags=["response"])
def list_blocks(
    _user: User = Depends(require_viewer),
) -> list[dict[str, Any]]:
    """Return active blocks from responder."""
    engine = get_engine()
    blocks = engine.responder.list_blocks()
    return [
        {
            "client_ip": b.client_ip,
            "username": b.username,
            "blocked_at": b.blocked_at.isoformat(),
            "expires_at": b.expires_at.isoformat(),
            "reason": b.reason,
            "backend_type": b.backend_type,
        }
        for b in blocks
    ]
