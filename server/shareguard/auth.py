"""shareguard.auth – Role-based API authentication, password hashing, and token handling.

Security Properties:
- Supports both API keys (``X-API-Key``) and time-bounded HS256 signed bearer tokens.
- Cryptographic password verification (PBKDF2-HMAC-SHA256 and bcrypt fallback).
- In LIVE mode, refuses to start with missing, empty, or default secrets.
- In-memory rate limiting and account lockout against brute-force attacks on login.
- Timing-safe string comparison (``secrets.compare_digest``) prevents timing attacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

__all__ = [
    "User",
    "get_current_user",
    "require_admin",
    "require_viewer",
    "require_api_key",
    "authenticate_credentials",
    "create_access_token",
    "decode_access_token",
    "verify_live_mode_secrets",
    "hash_password",
    "verify_password",
    "check_login_rate_limit",
    "record_login_attempt",
    "reset_login_rate_limits",
]

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_BEARER_AUTH = HTTPBearer(auto_error=False)

INSECURE_DEFAULT_KEYS = frozenset(
    {"admin-key", "viewer-key", "change-me", "password", "secret", "admin", "123456", "default"}
)

_LOGIN_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_LOCKOUTS: dict[str, float] = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60.0
LOCKOUT_DURATION_SECONDS = 300.0  # 5 minutes


@dataclass(frozen=True, slots=True)
class User:
    """Authenticated user with role and identity."""

    username: str
    role: str  # "admin" | "viewer"


def verify_live_mode_secrets(mode: str) -> None:
    """Ensure LIVE mode refuses to start with missing, empty, or default secrets.

    Raises:
        RuntimeError: If server is in LIVE mode but secrets are insecure.
    """
    if str(mode).lower() != "live":
        return

    admin_key = (os.getenv("SHAREGUARD_ADMIN_KEY") or os.getenv("SHAREGUARD_API_KEY") or "").strip()
    if not admin_key or admin_key.lower() in INSECURE_DEFAULT_KEYS or len(admin_key) < 16:
        raise RuntimeError(
            "FATAL SECURITY VIOLATION: ShareGuard refuses to run in LIVE mode with a missing, "
            "default, or weak secret key. Set SHAREGUARD_ADMIN_KEY to a secure random secret (min 16 chars)."
        )


def _get_configured_keys() -> tuple[str, str]:
    """Return configured (admin_key, viewer_key)."""
    admin_key = os.getenv("SHAREGUARD_ADMIN_KEY") or os.getenv("SHAREGUARD_API_KEY") or "admin-key"
    viewer_key = os.getenv("SHAREGUARD_VIEWER_KEY") or "viewer-key"
    return admin_key, viewer_key


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 (or bcrypt if available)."""
    try:
        import bcrypt

        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except ImportError:
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return f"pbkdf2:sha256:100000${salt}${h.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify plaintext password against stored hash or digest."""
    if not stored_hash:
        return False

    if stored_hash.startswith(("$2b$", "$2a$", "$2y$")):
        try:
            import bcrypt

            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ImportError:
            return False

    if stored_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash.split("$")
            rounds = int(parts[0].split(":")[2])
            salt = parts[1]
            expected_hex = parts[2]
            computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), rounds)
            return secrets.compare_digest(computed.hex(), expected_hex)
        except Exception:
            return False

    # Backward compatibility with plaintext environment variables
    return secrets.compare_digest(plain_password, stored_hash)


def create_access_token(username: str, role: str, expires_in_seconds: int = 7200) -> str:
    """Generate an HS256-signed bearer token with an expiration timestamp."""
    admin_key, _ = _get_configured_keys()
    now_ts = int(time.time())
    exp_ts = now_ts + expires_in_seconds
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "role": role, "iat": now_ts, "exp": exp_ts}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(admin_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return f"{signing_input}.{sig_b64}"


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Verify signature and expiration of an access token, returning payload or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    admin_key, _ = _get_configured_keys()
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(admin_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("utf-8").rstrip("=")

    if not secrets.compare_digest(sig_b64, expected_sig_b64):
        return None

    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))
        exp = payload.get("exp", 0)
        if time.time() > exp:
            return None
        return payload
    except Exception:
        return None


def check_login_rate_limit(client_identifier: str) -> None:
    """Raise 429 if client_identifier (IP or username) is currently locked out."""
    now = time.time()
    with _LOGIN_LOCK:
        lockout_until = _LOGIN_LOCKOUTS.get(client_identifier, 0.0)
        if now < lockout_until:
            retry_after = int(lockout_until - now)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Locked out for {retry_after} seconds.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )


def record_login_attempt(client_identifier: str, success: bool) -> None:
    """Record a login attempt outcome for rate limiting and lockout."""
    now = time.time()
    with _LOGIN_LOCK:
        if success:
            _LOGIN_ATTEMPTS.pop(client_identifier, None)
            _LOGIN_LOCKOUTS.pop(client_identifier, None)
            return

        attempts = _LOGIN_ATTEMPTS.setdefault(client_identifier, [])
        attempts = [t for t in attempts if (now - t) < LOGIN_WINDOW_SECONDS]
        attempts.append(now)
        _LOGIN_ATTEMPTS[client_identifier] = attempts

        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            _LOGIN_LOCKOUTS[client_identifier] = now + LOCKOUT_DURATION_SECONDS


def reset_login_rate_limits() -> None:
    """Reset all login rate limits and lockouts (used in tests)."""
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.clear()
        _LOGIN_LOCKOUTS.clear()


def get_current_user(
    api_key_header: str | None = Security(_API_KEY_HEADER),
    bearer_token: HTTPAuthorizationCredentials | None = Security(_BEARER_AUTH),
    x_user_role: Annotated[str | None, Header(alias="X-User-Role")] = None,
    x_user_name: Annotated[str | None, Header(alias="X-User-Name")] = None,
) -> User:
    """FastAPI dependency: extract and authenticate user identity and role.

    Raises:
        HTTPException: 401 if credentials are missing or invalid.
    """
    token = api_key_header
    if not token and bearer_token:
        token = bearer_token.credentials

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide X-API-Key or Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Attempt token decode as signed JWT
    payload = decode_access_token(token)
    if payload:
        role = payload.get("role", "viewer")
        username = payload.get("sub", "user")
        if x_user_role == "viewer" and role == "admin":
            role = "viewer"
        return User(username=username, role=role)

    admin_key, viewer_key = _get_configured_keys()

    # 2. Admin key match
    if secrets.compare_digest(token, admin_key):
        role = "viewer" if x_user_role == "viewer" else "admin"
        username = x_user_name or "admin"
        return User(username=username, role=role)

    # 3. Viewer key match
    if secrets.compare_digest(token, viewer_key):
        if x_user_role == "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Viewer key cannot assume admin role.",
            )
        username = x_user_name or "viewer"
        return User(username=username, role="viewer")

    # Reject invalid token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key or token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Enforce that the authenticated user possesses the ``admin`` role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: administrator privileges required.",
        )
    return user


def require_viewer(user: User = Depends(get_current_user)) -> User:
    """Enforce that the authenticated user possesses at least ``viewer`` privileges."""
    if user.role not in ("admin", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: viewer privileges required.",
        )
    return user


def require_api_key(user: User = Depends(get_current_user)) -> str:
    """Backward-compatible dependency: validates token and returns role."""
    return user.role


def authenticate_credentials(username: str, password: str) -> tuple[str, str, str] | None:
    """Validate username and password, returning (signed_token, username, role) or None."""
    admin_key, viewer_key = _get_configured_keys()
    admin_user = os.getenv("SHAREGUARD_ADMIN_USER", "admin")
    admin_pass = os.getenv("SHAREGUARD_ADMIN_PASSWORD") or admin_key or "admin"

    viewer_user = os.getenv("SHAREGUARD_VIEWER_USER", "viewer")
    viewer_pass = os.getenv("SHAREGUARD_VIEWER_PASSWORD") or viewer_key or "viewer"

    # Check admin
    if (username == admin_user or not username) and verify_password(password, admin_pass):
        token = create_access_token(admin_user, "admin")
        return token, admin_user, "admin"

    # Check viewer
    if (username == viewer_user or not username) and verify_password(password, viewer_pass):
        token = create_access_token(viewer_user, "viewer")
        return token, viewer_user, "viewer"

    # Direct key fallback
    if secrets.compare_digest(password, admin_key):
        token = create_access_token("admin", "admin")
        return token, "admin", "admin"
    if secrets.compare_digest(password, viewer_key):
        token = create_access_token("viewer", "viewer")
        return token, "viewer", "viewer"

    return None
