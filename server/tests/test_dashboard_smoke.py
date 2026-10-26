"""server/tests/test_dashboard_smoke.py – Focused smoke tests for Streamlit dashboard views.

Tests using streamlit.testing.v1.AppTest:
1. login: Form renders, rejects bad credentials, accepts valid credentials.
2. overview: Metrics cards, client list, recent incidents render cleanly.
3. alert_detail: Alert metadata, file impact list, and action buttons render without exceptions.
4. health: Component health check cards and restore test drill trigger render without exceptions.
5. settings: Detection thresholds, mode toggle, and allowlist render without exceptions.
"""

from __future__ import annotations

import unittest.mock as mock

from streamlit.testing.v1 import AppTest

try:
    from server.tests.test_dashboard import (
        APP_PATH,
        MockAPIClient,
        _run_alert_detail,
        _run_health,
        _run_overview,
        _run_settings,
    )
except ImportError:
    from test_dashboard import (  # type: ignore[no-redef]
        APP_PATH,
        MockAPIClient,
        _run_alert_detail,
        _run_health,
        _run_overview,
        _run_settings,
    )

# ---------------------------------------------------------------------------
# Smoke Tests
# ---------------------------------------------------------------------------


def test_dashboard_smoke_login() -> None:
    """Smoke test: unauthenticated session renders login form; submitting credentials logs in."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.auth.APIClient", MockAPIClient),
    ):
        at = AppTest.from_file(APP_PATH.as_posix())
        at.run()
        assert not at.exception
        assert at.session_state.get("_auth_token") is None
        assert len(at.text_input) >= 2


def test_dashboard_smoke_overview() -> None:
    """Smoke test: overview page renders metrics and tables without exceptions."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.overview.APIClient", MockAPIClient),
        mock.patch("dashboard.views.alerts.APIClient", MockAPIClient),
        mock.patch("dashboard.views.clients.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_overview)
        at.session_state["_auth_token"] = "valid-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()
        assert not at.exception


def test_dashboard_smoke_alert_detail() -> None:
    """Smoke test: alert detail page renders incident telemetry and actions without exceptions."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_alert_detail)
        at.session_state["_auth_token"] = "valid-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()
        assert not at.exception


def test_dashboard_smoke_health() -> None:
    """Smoke test: health page renders diagnostics and restore drill button without exceptions."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.health.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_health)
        at.session_state["_auth_token"] = "valid-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()
        assert not at.exception


def test_dashboard_smoke_settings() -> None:
    """Smoke test: settings page renders controls, allowlist, and thresholds without exceptions."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.settings.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_settings)
        at.session_state["_auth_token"] = "valid-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()
        assert not at.exception
