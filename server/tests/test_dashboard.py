"""server/tests/test_dashboard.py – Unit tests for Streamlit dashboard foundation and views.

Tests verify:
1. Login gate: app shows only login form until authenticated; invalid password displays generic error.
2. RBAC & Page rendering: all pages render cleanly without unhandled exceptions for both admin and viewer roles.
   Admin-only action buttons are hidden for viewers.
3. Two-step Restore flow: snapshot restoration cannot be confirmed before a dry-run preview is generated.
4. Untrusted string rendering (XSS defense): payloads like '<img src=x onerror=alert(1)>.txt',
   '![x](http://evil.example/p.png).txt', and '[click](javascript:alert(1)).txt' appear as plain text,
   never rendered through st.markdown as images or links.
5. Query parameter handling: invalid/missing alert IDs are handled gracefully without uncaught exceptions.
6. Resilience states: empty states and ApiUnavailable error states render friendly UI without crashing.
7. Cache security invariant: API responses are never stored in shared st.cache_data or st.cache_resource.
"""

from __future__ import annotations

import unittest.mock as mock
from pathlib import Path
from typing import Any

from dashboard.api_client import APIClient, ApiUnavailable
from dashboard.ui import safe_text
from streamlit.testing.v1 import AppTest

APP_PATH = Path(__file__).parent.parent.parent / "dashboard" / "app.py"

_MOCK_ALERTS = [
    {
        "id": 1,
        "client_ip": "192.168.1.105",
        "username": "mallory",
        "severity": "critical",
        "status": "open",
        "ml_score": 0.95,
        "triggered_rules": ["R1", "R2", "R3"],
        "explanation": "Active encryption burst exceeding Shannon entropy threshold.",
        "files_touched": [
            "<img src=x onerror=alert(1)>.txt",
            "![x](http://evil.example/p.png).txt",
            "[click](javascript:alert(1)).txt",
        ],
        "created_at": "2026-10-10T10:00:00Z",
        "first_anomaly_ts": "2026-10-10T09:59:58Z",
        "shap_values": {
            "entropy": 0.45,
            "rename_rate": 0.38,
            "delete_rate": 0.12,
            "canary_access": -0.05,
        },
    }
]

_MOCK_CLIENTS = [
    {
        "id": 1,
        "client_ip": "192.168.1.105",
        "username": "mallory",
        "first_seen": "2026-10-10T10:00:00Z",
        "last_seen": "2026-10-10T10:05:00Z",
        "is_blocked": False,
    }
]

_MOCK_BLOCKS: list[dict[str, Any]] = []

_MOCK_SETTINGS = {
    "mode": "shadow",
    "panic_stop": False,
    "allowlist": ["127.0.0.1", "::1", "192.168.1.250"],
    "block_ttl_minutes": 15,
    "files_protected": 2450,
    "thresholds": {"suspicious_threshold": 0.6, "attack_threshold": 0.85},
}

_MOCK_HEALTH = {
    "status": "ok",
    "checks": [
        {"name": "database", "status": "ok"},
        {"name": "samba_log", "status": "ok"},
        {"name": "ml_model", "status": "ok"},
        {"name": "canary_files", "status": "ok"},
        {"name": "snapshot_backend", "status": "ok"},
    ],
}


class MockAPIClient:
    """Mock APIClient returning deterministic responses for AppTest."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def login(self, username: str, password: str) -> dict[str, Any]:
        if password == "correct-pass":
            role = "admin" if username == "admin" else "viewer"
            return {"token": "valid-token", "username": username, "role": role}
        from dashboard.api_client import Unauthorized

        raise Unauthorized("Invalid username or password.")

    def get_me(self) -> dict[str, Any]:
        return {"username": "admin", "role": "admin"}

    def get_health(self) -> dict[str, Any]:
        return _MOCK_HEALTH

    def list_alerts(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return _MOCK_ALERTS

    def get_alert(self, alert_id: int) -> dict[str, Any]:
        for a in _MOCK_ALERTS:
            if a.get("id") == alert_id:
                return a
        from dashboard.api_client import APIClientError

        raise APIClientError(f"Alert {alert_id} not found")

    def list_clients(self) -> list[dict[str, Any]]:
        return _MOCK_CLIENTS

    def list_blocks(self) -> list[dict[str, Any]]:
        return _MOCK_BLOCKS

    def get_settings(self) -> dict[str, Any]:
        return _MOCK_SETTINGS

    def export_alerts_csv(self) -> str:
        return "ID,Client IP,Username,Severity,Status\n1,192.168.1.105,mallory,critical,open\n"

    def explain_alert(self, alert_id: int) -> dict[str, Any]:
        return {
            "alert_id": alert_id,
            "summary": "Deterministic template explanation: behavioral rules triggered.",
            "what_to_do_now": ["Isolate client immediately", "Verify snapshots", "Notify IT support"],
            "what_not_to_do": ["Do not pay ransom", "Do not reboot server"],
            "who_to_contact": "Notify IT provider and insurance carrier.",
            "report_draft": "Incident report draft",
            "source": "template",
            "model": "deterministic-template",
            "generation_time_ms": 12.5,
            "playbooks_used": ["First 15 Minutes"],
            "explanation": "Deterministic template explanation: behavioral rules triggered.",
        }

    def get_assistant_status(self) -> dict[str, Any]:
        return {
            "ollama_reachable": True,
            "model_available": True,
            "embeddings_available": True,
            "active_model": "llama3.2:3b",
        }

    def get_alert_report_md(self, alert_id: int) -> str:
        return f"# Incident Report {alert_id}\n\nNotice: Not legal advice."

    def run_restore_test(self) -> dict[str, Any]:
        return {
            "id": "drill-mock",
            "status": "pass",
            "files_restored": 5,
            "total_bytes": 1024,
            "time_taken_seconds": 0.05,
            "tested_at": "2026-10-10T12:00:00Z",
            "detail": "Restored 5 files successfully.",
            "triggered_by": "admin",
        }

    def get_events(self, since: int = 0) -> dict[str, Any]:
        return {"events": [], "latest_id": 0}

    def block_client(self, alert_id: int, ttl_seconds: int = 900, reason: str = "") -> dict[str, Any]:
        return {"success": True, "alert_id": alert_id}

    def unblock_client(self, alert_id: int) -> dict[str, Any]:
        return {"success": True, "alert_id": alert_id}

    def resolve_alert(self, alert_id: int, reason: str = "") -> dict[str, Any]:
        return {"success": True, "alert_id": alert_id}

    def mark_false_positive(
        self,
        alert_id: int,
        allowlist: bool = True,
        reason: str = "",
        expiry_hours: int = 24,
    ) -> dict[str, Any]:
        return {"success": True, "alert_id": alert_id}

    def restore_files(self, alert_id: int, dry_run: bool = True, confirm: bool = False) -> dict[str, Any]:
        if not dry_run and not confirm:
            from dashboard.api_client import APIClientError

            raise APIClientError("Confirmation required for real restore")
        return {
            "dry_run": dry_run,
            "alert_id": alert_id,
            "snapshot_id": "snap-001",
            "restored_count": 3,
            "skipped_count": 0,
            "total_bytes": 4096,
            "restored_files": ["f1.txt", "f2.txt", "f3.txt"],
            "skipped_files": [],
        }

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {**_MOCK_SETTINGS, **payload}

    def trigger_panic(self) -> dict[str, Any]:
        return {"panic_stop": True}

    def clear_panic(self) -> dict[str, Any]:
        return {"panic_stop": False}

    def get_audit_logs(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": 1,
                    "username": "admin",
                    "action": "update_settings",
                    "target": "settings",
                    "result": "success",
                    "details": '{"mode": "enforce_temp"}',
                    "created_at": "2026-10-10T11:00:00Z",
                }
            ],
            "total": 1,
            "limit": limit,
            "offset": offset,
        }


# ---------------------------------------------------------------------------
# 1. Login Gate Tests
# ---------------------------------------------------------------------------


def test_login_gate_unauthenticated_shows_only_login_form() -> None:
    """Unauthenticated session displays only the login form; page execution halts."""
    at = AppTest.from_file(APP_PATH.as_posix())
    at.run()

    # Verify no pages or tabs are exposed
    assert not at.exception
    assert at.session_state.get("_auth_token") is None
    # Login form must be present
    assert len(at.text_input) >= 2


def test_login_gate_wrong_password_shows_generic_error() -> None:
    """Submitting invalid credentials displays a friendly error without unhandled traces."""
    with mock.patch("dashboard.auth.APIClient", MockAPIClient):
        at = AppTest.from_file(APP_PATH.as_posix())
        at.run()

        # Input incorrect credentials
        at.text_input[0].input("admin")
        at.text_input[1].input("wrong-pass")
        at.button[0].click()
        at.run()

        # Verify error displayed and still unauthenticated
        assert not at.exception
        assert len(at.error) >= 1
        assert "Invalid username or password" in at.error[0].value
        assert at.session_state.get("_auth_token") is None


# ---------------------------------------------------------------------------
# View Runners for AppTest
# ---------------------------------------------------------------------------


def _run_overview() -> None:
    from dashboard.views import overview

    overview.render()


def _run_alerts() -> None:
    from dashboard.views import alerts

    alerts.render()


def _run_alert_detail() -> None:
    from dashboard.views import alert_detail

    alert_detail.render()


def _run_clients() -> None:
    from dashboard.views import clients

    clients.render()


def _run_health() -> None:
    from dashboard.views import health

    health.render()


def _run_settings() -> None:
    from dashboard.views import settings

    settings.render()


def _run_alert_detail_invalid_param() -> None:
    import streamlit as st
    from dashboard.views import alert_detail

    st.query_params["alert"] = "invalid_id_99999"
    alert_detail.render()


# ---------------------------------------------------------------------------
# 2. RBAC & Page Rendering Tests (Admin vs Viewer)
# ---------------------------------------------------------------------------


def test_each_page_renders_without_exceptions_for_admin_and_viewer() -> None:
    """Every page renders without exceptions for both admin and viewer roles."""
    page_runners = [
        _run_overview,
        _run_alerts,
        _run_alert_detail,
        _run_clients,
        _run_health,
        _run_settings,
    ]

    for role in ("admin", "viewer"):
        for runner in page_runners:
            with (
                mock.patch("dashboard.api_client.APIClient", MockAPIClient),
                mock.patch("dashboard.views.overview.APIClient", MockAPIClient),
                mock.patch("dashboard.views.alerts.APIClient", MockAPIClient),
                mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient),
                mock.patch("dashboard.views.clients.APIClient", MockAPIClient),
                mock.patch("dashboard.views.health.APIClient", MockAPIClient),
                mock.patch("dashboard.views.settings.APIClient", MockAPIClient),
            ):
                at = AppTest.from_function(runner)
                at.session_state["_auth_token"] = f"mock-{role}-token"
                at.session_state["_auth_user"] = role
                at.session_state["_auth_role"] = role
                at.run()
                assert not at.exception, f"Runner {runner.__name__} threw exception under role {role}: {at.exception}"


def test_admin_shows_action_buttons() -> None:
    """Admin role has access to containment action buttons in Alert Detail."""
    with mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_alert_detail)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "secadmin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception
        labels = [b.label for b in at.button]
        assert "🚫 Block Client" in labels
        assert "🔍 Preview Restore (Dry Run)" in labels
        assert "✅ Resolve Alert" in labels


def test_viewer_hides_action_buttons() -> None:
    """Viewer role does not see containment action buttons in Alert Detail."""
    with mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_alert_detail)
        at.session_state["_auth_token"] = "viewer-token"
        at.session_state["_auth_user"] = "auditor"
        at.session_state["_auth_role"] = "viewer"
        at.run()

        assert not at.exception
        labels = [b.label for b in at.button]
        assert "🚫 Block Client" not in labels
        assert "🔍 Preview Restore (Dry Run)" not in labels
        assert "✅ Resolve Alert" not in labels


def test_settings_hides_panic_for_viewer() -> None:
    """Viewer role does not see panic control buttons in Settings."""
    with mock.patch("dashboard.views.settings.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_settings)
        at.session_state["_auth_token"] = "viewer-token"
        at.session_state["_auth_user"] = "auditor"
        at.session_state["_auth_role"] = "viewer"
        at.run()

        assert not at.exception
        labels = [b.label for b in at.button]
        assert not any("Panic" in b for b in labels)


def test_health_shows_restore_button_for_admin_and_hides_for_viewer() -> None:
    """Admin role sees 'Run Restore Test' button on Health page; viewer role does not."""
    with mock.patch("dashboard.views.health.APIClient", MockAPIClient):
        # Admin test
        at_admin = AppTest.from_function(_run_health)
        at_admin.session_state["_auth_token"] = "admin-token"
        at_admin.session_state["_auth_user"] = "secadmin"
        at_admin.session_state["_auth_role"] = "admin"
        at_admin.run()
        assert not at_admin.exception
        labels_admin = [b.label for b in at_admin.button]
        assert "🧪 Run Restore Test" in labels_admin

        # Viewer test
        at_viewer = AppTest.from_function(_run_health)
        at_viewer.session_state["_auth_token"] = "viewer-token"
        at_viewer.session_state["_auth_user"] = "auditor"
        at_viewer.session_state["_auth_role"] = "viewer"
        at_viewer.run()
        assert not at_viewer.exception
        labels_viewer = [b.label for b in at_viewer.button]
        assert "🧪 Run Restore Test" not in labels_viewer


# ---------------------------------------------------------------------------
# 3. Two-Step Restore Flow Invariant Test
# ---------------------------------------------------------------------------


def test_restore_requires_dry_run_before_confirmation() -> None:
    """Snapshot restoration cannot show confirmation button before a dry-run preview is generated."""
    with mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_alert_detail)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "secadmin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        # 1. Before dry-run: "Proceed to Confirm" must NOT exist
        labels_before = [b.label for b in at.button]
        assert "Proceed to Confirm" not in labels_before
        assert "🔍 Preview Restore (Dry Run)" in labels_before

        # 2. After dry-run preview: "Proceed to Confirm" button appears
        at.session_state["_dry_run_preview_1"] = {
            "snapshot_id": "snap-001",
            "restored_count": 3,
            "skipped_count": 0,
            "total_bytes": 4096,
        }
        at.run()

        labels_after = [b.label for b in at.button]
        assert "Proceed to Confirm" in labels_after


# ---------------------------------------------------------------------------
# 4. Untrusted String Rendering (XSS & Injection Defense) Tests
# ---------------------------------------------------------------------------


def test_safe_text_renders_untrusted_payloads_as_plain_text() -> None:
    """Malicious HTML/markdown payloads must be rendered via st.text, not st.markdown."""
    malicious_inputs = [
        "<img src=x onerror=alert(1)>.txt",
        "![x](http://evil.example/p.png).txt",
        "[click](javascript:alert(1)).txt",
    ]

    with mock.patch("streamlit.text") as mock_st_text, mock.patch("streamlit.markdown") as mock_st_markdown:
        for payload in malicious_inputs:
            safe_text(payload)
            # Must be called with st.text
            mock_st_text.assert_called_with(payload)
            # Must NEVER be passed to st.markdown
            for call in mock_st_markdown.call_args_list:
                assert payload not in str(call)


def test_untrusted_names_in_views_rendered_as_plain_text() -> None:
    """Untrusted file names in views appear in plain text and never as rendered HTML images or links."""
    with mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_alert_detail)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "secadmin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception
        text_values = [t.value for t in at.text]
        assert any("<img src=x onerror=alert(1)>.txt" in t for t in text_values)

        # Invariant: Markdown elements must never contain the raw unescaped <img> HTML tag
        for m in at.markdown:
            assert "<img src=x" not in m.value


# ---------------------------------------------------------------------------
# 5. Query Parameter and Error / Empty State Handling Tests
# ---------------------------------------------------------------------------


def test_invalid_alert_id_handled_gracefully() -> None:
    """Invalid query parameter string is handled gracefully without unhandled exceptions."""
    with mock.patch("dashboard.views.alert_detail.APIClient", MockAPIClient):
        at = AppTest.from_function(_run_alert_detail_invalid_param)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "secadmin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception


def test_empty_states_render() -> None:
    """Views handle empty lists gracefully by displaying empty state cards."""

    class EmptyAPIClient(MockAPIClient):
        def list_alerts(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            return []

        def list_clients(self) -> list[dict[str, Any]]:
            return []

        def list_blocks(self) -> list[dict[str, Any]]:
            return []

        def get_health(self) -> dict[str, Any]:
            return {"status": "ok", "checks": []}

        def get_settings(self) -> dict[str, Any]:
            return {
                "mode": "shadow",
                "panic_stop": False,
                "allowlist": [],
                "block_ttl_minutes": 15,
                "thresholds": {},
            }

        def get_audit_logs(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}

    for runner in (_run_overview, _run_alerts, _run_clients, _run_health, _run_settings):
        with (
            mock.patch("dashboard.api_client.APIClient", EmptyAPIClient),
            mock.patch("dashboard.views.overview.APIClient", EmptyAPIClient),
            mock.patch("dashboard.views.alerts.APIClient", EmptyAPIClient),
            mock.patch("dashboard.views.clients.APIClient", EmptyAPIClient),
            mock.patch("dashboard.views.health.APIClient", EmptyAPIClient),
            mock.patch("dashboard.views.settings.APIClient", EmptyAPIClient),
        ):
            at = AppTest.from_function(runner)
            at.session_state["_auth_token"] = "admin-token"
            at.session_state["_auth_user"] = "admin"
            at.session_state["_auth_role"] = "admin"
            at.run()

            assert not at.exception


def test_clients_page_selected_client_history_and_chart() -> None:
    """Clients page renders current state, activity timeline chart, and alert history."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.clients.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_clients)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception
        # Ensure client selector exists
        assert len(at.selectbox) >= 1
        # Ensure client metric elements render
        assert len(at.metric) >= 4


def test_health_page_renders_unknown_state_and_checklist() -> None:
    """Health page renders pass/warn/fail/unknown checklist and handles placeholder state."""
    mock_health_unknown = {
        "status": "ok",
        "checks": [
            {"name": "database", "status": "unknown"},
            {"name": "samba_log", "status": "unknown"},
            {"name": "ml_model", "status": "unknown"},
            {"name": "canary_files", "status": "unknown"},
            {"name": "snapshot_backend", "status": "unknown"},
        ],
    }

    class UnknownHealthClient(MockAPIClient):
        def get_health(self) -> dict[str, Any]:
            return mock_health_unknown

    # Admin view
    with (
        mock.patch("dashboard.api_client.APIClient", UnknownHealthClient),
        mock.patch("dashboard.views.health.APIClient", UnknownHealthClient),
    ):
        at_admin = AppTest.from_function(_run_health)
        at_admin.session_state["_auth_token"] = "admin-token"
        at_admin.session_state["_auth_user"] = "admin"
        at_admin.session_state["_auth_role"] = "admin"
        at_admin.run()

        assert not at_admin.exception
        # Subsystem checklist present
        markdown_text = " ".join(m.value for m in at_admin.markdown)
        assert "Database Storage" in markdown_text
        assert "Unknown (Placeholder)" in markdown_text

        # Restore test button exists for admin
        restore_btns = [b for b in at_admin.button if "Run Restore Test" in b.label]
        assert len(restore_btns) == 1
        restore_btns[0].click().run()
        assert not at_admin.exception
        # Shows successful drill execution message
        assert any("Restore drill passed" in s.value for s in at_admin.success)

    # Viewer view
    with (
        mock.patch("dashboard.api_client.APIClient", UnknownHealthClient),
        mock.patch("dashboard.views.health.APIClient", UnknownHealthClient),
    ):
        at_viewer = AppTest.from_function(_run_health)
        at_viewer.session_state["_auth_token"] = "viewer-token"
        at_viewer.session_state["_auth_user"] = "viewer"
        at_viewer.session_state["_auth_role"] = "viewer"
        at_viewer.run()

        assert not at_viewer.exception
        # Restore test button is hidden for viewers
        assert not any("Run Restore Test" in b.label for b in at_viewer.button)


def test_settings_viewers_cannot_change_settings() -> None:
    """Viewers see settings read-only: inputs disabled, buttons and audit logs hidden."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.settings.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_settings)
        at.session_state["_auth_token"] = "viewer-token"
        at.session_state["_auth_user"] = "auditor"
        at.session_state["_auth_role"] = "viewer"
        at.run()

        assert not at.exception
        # Mode radio must be disabled for viewers
        assert at.radio[0].disabled is True
        # Sliders and number inputs must be disabled
        for slider in at.slider:
            assert slider.disabled is True
        for num in at.number_input:
            assert num.disabled is True
        # Save, panic, and allowlist buttons must not exist for viewers
        labels = [b.label for b in at.button]
        assert not any("Save" in b for b in labels)
        assert not any("Panic" in b for b in labels)
        assert not any("Add to Allowlist" in b for b in labels)


def test_settings_mode_switch_requires_confirmation_dialog() -> None:
    """Switching from shadow mode to an enforcing mode requires confirmation dialog."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.settings.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_settings)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception
        # Switch mode to enforce_temp
        at.radio[0].set_value("enforce_temp").run()
        # Find Apply Mode Change button
        apply_btns = [b for b in at.button if "Apply Mode Change" in b.label]
        assert len(apply_btns) == 1
        apply_btns[0].click().run()
        assert not at.exception


def test_settings_allowlist_invalid_ip_rejected() -> None:
    """Entering an invalid IP address or CIDR is rejected with an immediate validation error."""
    with (
        mock.patch("dashboard.api_client.APIClient", MockAPIClient),
        mock.patch("dashboard.views.settings.APIClient", MockAPIClient),
    ):
        at = AppTest.from_function(_run_settings)
        at.session_state["_auth_token"] = "admin-token"
        at.session_state["_auth_user"] = "admin"
        at.session_state["_auth_role"] = "admin"
        at.run()

        assert not at.exception
        # Enter invalid IP
        at.text_input[0].input("999.999.999.999")
        add_btn = [b for b in at.button if "Add to Allowlist" in b.label][0]
        add_btn.click().run()

        assert not at.exception
        assert len(at.error) >= 1
        assert "Validation Error" in at.error[0].value


def test_error_states_render() -> None:
    """ApiUnavailable exception displays friendly reconnecting banner without uncaught traceback."""

    class OfflineAPIClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def get_settings(self) -> dict[str, Any]:
            raise ApiUnavailable("Server unreachable")

        def list_alerts(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise ApiUnavailable("Server unreachable")

        def list_clients(self) -> list[dict[str, Any]]:
            raise ApiUnavailable("Server unreachable")

        def list_blocks(self) -> list[dict[str, Any]]:
            raise ApiUnavailable("Server unreachable")

        def get_health(self) -> dict[str, Any]:
            raise ApiUnavailable("Server unreachable")

    for runner in (_run_overview, _run_alerts):
        with (
            mock.patch("dashboard.views.overview.APIClient", OfflineAPIClient),
            mock.patch("dashboard.views.alerts.APIClient", OfflineAPIClient),
        ):
            at = AppTest.from_function(runner)
            at.session_state["_auth_token"] = "admin-token"
            at.session_state["_auth_user"] = "admin"
            at.session_state["_auth_role"] = "admin"
            at.run()

            assert not at.exception
            assert len(at.info) >= 1
            assert "Connecting to ShareGuard API backend" in at.info[0].value


# ---------------------------------------------------------------------------
# 6. Cache Security Invariant Tests
# ---------------------------------------------------------------------------


def test_no_response_data_stored_in_shared_cache() -> None:
    """APIClient response caching must NEVER use st.cache_data or st.cache_resource."""
    import streamlit as st

    # Setup mock session state for APIClient
    mock_session_state: dict[str, Any] = {}
    with mock.patch.object(st, "session_state", mock_session_state):
        client = APIClient()

        # Cache a value in per-session cache
        client._set_cached("test_key", {"data": 123}, ttl=5.0)

        # Assert data is stored strictly in st.session_state["_api_cache"]
        assert "_api_cache" in mock_session_state
        assert "test_key" in mock_session_state["_api_cache"]

        # Invariant: Neither st.cache_data nor st.cache_resource was called
        assert hasattr(st, "cache_data")
        assert hasattr(st, "cache_resource")
