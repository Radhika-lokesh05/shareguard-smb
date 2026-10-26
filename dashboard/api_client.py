"""dashboard/api_client.py – Pure-Python HTTP client for the ShareGuard REST API.

All dashboard pages interact with the backend exclusively via this client.
Security & Privacy Invariants:
- JWT / Bearer tokens are kept ONLY in ``st.session_state`` (never written to disk,
  logs, or URL parameters).
- ZERO usage of ``st.cache_data`` or ``st.cache_resource`` for API responses.
  A lightweight per-session cache is stored in ``st.session_state`` with a 3s TTL.
- Friendly, typed exceptions: :class:`ApiUnavailable`, :class:`Unauthorized`,
  :class:`Forbidden`, :class:`APIClientError`.
- On 401 Unauthorized or expired token, clears session authentication state.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests
import streamlit as st

__all__ = [
    "APIClient",
    "APIClientError",
    "ApiUnavailable",
    "Unauthorized",
    "Forbidden",
]

_DEFAULT_API_URL = "http://127.0.0.1:8000/api"
_DEFAULT_TIMEOUT = 5.0


class APIClientError(Exception):
    """Base exception for all ShareGuard API client errors."""


class ApiUnavailable(APIClientError):
    """Raised when the backend API server is unreachable, down, or timing out."""


class Unauthorized(APIClientError):
    """Raised on HTTP 401: missing, invalid, or expired credentials."""


class Forbidden(APIClientError):
    """Raised on HTTP 403: insufficient role privileges."""


class APIClient:
    """Synchronous HTTP client for ShareGuard API communicating over requests.Session.

    Args:
        base_url: Root API URL (defaults to SHAREGUARD_API_URL or http://127.0.0.1:8000/api).
        timeout: Request timeout in seconds (default 5.0s).
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        raw_url = base_url or os.getenv("SHAREGUARD_API_URL", _DEFAULT_API_URL)
        self.base_url: str = raw_url.rstrip("/")
        self.timeout: float = timeout
        self._session = requests.Session()

    def _get_headers(self) -> dict[str, str]:
        """Construct request headers with authorization token from session state."""
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "ShareGuard-Dashboard/0.2.0",
        }
        # JWT / token is stored strictly in st.session_state
        try:
            token = st.session_state.get("_auth_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        except Exception:
            # When run outside Streamlit runtime (e.g. standalone test)
            pass
        return headers

    def _get_cached(self, key: str) -> Any | None:
        """Retrieve per-session cached response if still fresh."""
        try:
            cache = st.session_state.get("_api_cache", {})
            entry = cache.get(key)
            if entry and time.time() < entry.get("expires", 0):
                return entry.get("data")
        except Exception:
            pass
        return None

    def _set_cached(self, key: str, data: Any, ttl: float = 3.0) -> None:
        """Store response in per-session cache."""
        try:
            if "_api_cache" not in st.session_state:
                st.session_state["_api_cache"] = {}
            st.session_state["_api_cache"][key] = {
                "data": data,
                "expires": time.time() + ttl,
            }
        except Exception:
            pass

    def clear_cache(self) -> None:
        """Clear all entries in the per-session cache."""
        try:
            if "_api_cache" in st.session_state:
                st.session_state["_api_cache"].clear()
        except Exception:
            pass

    def _request(
        self,
        method: str,
        path: str,
        json_data: Any = None,
        params: dict[str, Any] | None = None,
        use_cache: bool = False,
        cache_ttl: float = 3.0,
    ) -> Any:
        """Execute HTTP request with error translation and optional per-session cache."""
        clean_path = path.lstrip("/")
        url = f"{self.base_url}/{clean_path}"

        cache_key = f"{method}:{url}:{params}"
        if use_cache and method.upper() == "GET":
            cached_val = self._get_cached(cache_key)
            if cached_val is not None:
                return cached_val

        headers = self._get_headers()

        try:
            resp = self._session.request(
                method=method.upper(),
                url=url,
                json=json_data,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as err:
            raise ApiUnavailable("ShareGuard API is currently unreachable. Reconnecting...") from err
        except requests.exceptions.RequestException as err:
            raise APIClientError(f"HTTP communication error: {err}") from err

        if resp.status_code == 401:
            # Clear authentication credentials from session state
            try:
                st.session_state.pop("_auth_token", None)
                st.session_state.pop("_auth_user", None)
                st.session_state.pop("_auth_role", None)
            except Exception:
                pass
            raise Unauthorized("Session expired or unauthorized. Please log in.")

        if resp.status_code == 403:
            detail = "Forbidden: Insufficient privileges."
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise Forbidden(detail)

        if resp.status_code >= 400:
            detail = f"Request failed with status {resp.status_code}"
            try:
                data = resp.json()
                detail = data.get("detail", detail)
            except Exception:
                detail = resp.text or detail
            raise APIClientError(f"API Error ({resp.status_code}): {detail}")

        # Non-JSON responses (e.g. CSV or Markdown exports)
        content_type = resp.headers.get("content-type", "")
        if "text/csv" in content_type or "text/plain" in content_type or "text/markdown" in content_type:
            return resp.text

        try:
            result = resp.json()
        except Exception:
            result = resp.text

        if use_cache and method.upper() == "GET":
            self._set_cached(cache_key, result, ttl=cache_ttl)

        return result

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    def login(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate with username and password, returning token, username, and role."""
        return self._request(
            "POST",
            "/auth/login",
            json_data={"username": username, "password": password},
        )

    def get_me(self) -> dict[str, Any]:
        """Retrieve current authenticated user profile."""
        return self._request("GET", "/auth/me")

    # -----------------------------------------------------------------------
    # Health & System
    # -----------------------------------------------------------------------

    def get_health(self) -> dict[str, Any]:
        """Retrieve component health status."""
        return self._request("GET", "/health-check", use_cache=True, cache_ttl=2.0)

    def run_restore_test(self) -> dict[str, Any]:
        """Trigger an automated synthetic restore test drill (admin only)."""
        return self._request("POST", "/health-check/restore-test")

    # -----------------------------------------------------------------------
    # Alerts
    # -----------------------------------------------------------------------

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        client_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch list of alerts."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if client_ip:
            params["client_ip"] = client_ip
        return self._request("GET", "/alerts", params=params, use_cache=True, cache_ttl=2.0)

    def get_alert(self, alert_id: int) -> dict[str, Any]:
        """Fetch detail for a single alert."""
        return self._request("GET", f"/alerts/{alert_id}", use_cache=True, cache_ttl=2.0)

    # -----------------------------------------------------------------------
    # Clients & Active Blocks
    # -----------------------------------------------------------------------

    def list_clients(self) -> list[dict[str, Any]]:
        """Fetch known client connections and their block status."""
        return self._request("GET", "/clients", use_cache=True, cache_ttl=2.0)

    def list_blocks(self) -> list[dict[str, Any]]:
        """Fetch currently active firewall blocks."""
        return self._request("GET", "/blocks", use_cache=True, cache_ttl=2.0)

    # -----------------------------------------------------------------------
    # Settings & Panic
    # -----------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        """Retrieve current runtime settings."""
        return self._request("GET", "/settings", use_cache=True, cache_ttl=2.0)

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Update detection thresholds and response settings (Admin only)."""
        self.clear_cache()
        return self._request("PUT", "/settings", json_data=payload)

    def trigger_panic(self) -> dict[str, Any]:
        """Trigger global panic stop (Admin only)."""
        self.clear_cache()
        return self._request("POST", "/panic")

    def clear_panic(self) -> dict[str, Any]:
        """Clear global panic stop (Admin only)."""
        self.clear_cache()
        return self._request("POST", "/panic/clear")

    # -----------------------------------------------------------------------
    # Incident Actions
    # -----------------------------------------------------------------------

    def block_client(self, alert_id: int, ttl_seconds: int = 900, reason: str = "") -> dict[str, Any]:
        """Block client associated with alert (Admin only)."""
        self.clear_cache()
        return self._request(
            "POST",
            f"/alerts/{alert_id}/block",
            json_data={"ttl_seconds": ttl_seconds, "reason": reason},
        )

    def unblock_client(self, alert_id: int) -> dict[str, Any]:
        """Unblock client associated with alert (Admin only)."""
        self.clear_cache()
        return self._request("POST", f"/alerts/{alert_id}/unblock")

    def restore_files(
        self,
        alert_id: int,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Restore files touched by attacker (Admin only)."""
        self.clear_cache()
        return self._request(
            "POST",
            f"/alerts/{alert_id}/restore",
            json_data={"dry_run": dry_run, "confirm": confirm},
        )

    def resolve_alert(self, alert_id: int, reason: str = "") -> dict[str, Any]:
        """Mark alert as resolved (Admin only)."""
        self.clear_cache()
        return self._request(
            "POST",
            f"/alerts/{alert_id}/resolve",
            json_data={"reason": reason},
        )

    def mark_false_positive(
        self,
        alert_id: int,
        allowlist: bool = True,
        expiry_hours: int = 24,
        reason: str = "",
    ) -> dict[str, Any]:
        """Mark alert as false positive and unblock (Admin only)."""
        self.clear_cache()
        return self._request(
            "POST",
            f"/alerts/{alert_id}/false-positive",
            json_data={"allowlist": allowlist, "expiry_hours": expiry_hours, "reason": reason},
        )

    # -----------------------------------------------------------------------
    # Events, Audit & Exports
    # -----------------------------------------------------------------------

    def get_events(self, since: int = 0) -> dict[str, Any]:
        """Fetch incremental engine events since event ID."""
        return self._request("GET", "/events", params={"since": since})

    def get_audit_logs(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Fetch paginated administrative audit logs (Admin only)."""
        return self._request("GET", "/audit", params={"limit": limit, "offset": offset})

    def export_alerts_csv(self) -> str:
        """Download sanitized alerts CSV export."""
        return self._request("GET", "/export/alerts.csv")

    def explain_alert(self, alert_id: int) -> dict[str, Any]:
        """Retrieve natural language explanation for an alert."""
        return self._request("POST", f"/assistant/explain/{alert_id}")

    def get_assistant_status(self) -> dict[str, Any]:
        """Fetch status of the local Ollama incident assistant backend."""
        return self._request("GET", "/assistant/status", use_cache=True, cache_ttl=5.0)

    def get_alert_report_md(self, alert_id: int) -> str:
        """Download markdown incident report for an alert."""
        return self._request("GET", f"/alerts/{alert_id}/report.md")
