"""dashboard/auth.py – Authentication gate and session state management for Streamlit.

Security & Invariants:
- Uses ``st.form`` for credential input (password masked).
- Role is determined strictly by the API response payload (never decoded on the client).
- Token is kept ONLY in ``st.session_state``; never written to disk or logs.
- Viewers are prevented from seeing or executing admin-only operations.
"""

from __future__ import annotations

import streamlit as st
from dashboard.api_client import APIClient, APIClientError

__all__ = [
    "is_authenticated",
    "current_user",
    "current_role",
    "is_admin",
    "require_auth",
    "render_login_gate",
    "render_user_sidebar",
    "logout",
]


def is_authenticated() -> bool:
    """Return True if the current user session holds an active auth token."""
    return bool(st.session_state.get("_auth_token"))


def current_user() -> str:
    """Return the username of the currently logged in user."""
    return str(st.session_state.get("_auth_user", "anonymous"))


def current_role() -> str:
    """Return the role of the currently logged in user ('admin' | 'viewer')."""
    return str(st.session_state.get("_auth_role", "viewer"))


def is_admin() -> bool:
    """Return True if the currently authenticated user possesses admin privileges."""
    return current_role() == "admin"


def logout() -> None:
    """Clear all authentication and cached data from the session state."""
    st.session_state.pop("_auth_token", None)
    st.session_state.pop("_auth_user", None)
    st.session_state.pop("_auth_role", None)
    st.session_state.pop("_api_cache", None)
    st.rerun()


def render_login_gate(client: APIClient | None = None) -> None:
    """Render a dedicated login form and halt page execution if unauthenticated."""
    if is_authenticated():
        return

    api = client or APIClient()

    with st.container(border=True):
        st.markdown("### 🛡️ ShareGuard Login")
        st.caption("Sign in to access the Samba ransomware protection dashboard.")

        with st.form("shareguard_login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="admin or viewer", key="login_username")
            password = st.text_input("Password / API Key", type="password", key="login_password")
            submit = st.form_submit_button("Sign In", use_container_width=True)

            if submit:
                if not password:
                    st.error("Please enter a password or API key.")
                else:
                    try:
                        res = api.login(username=username, password=password)
                        # Invariant: Read the role from API response, NOT client-side token parsing
                        st.session_state["_auth_token"] = res.get("token")
                        st.session_state["_auth_user"] = res.get("username", username or "user")
                        st.session_state["_auth_role"] = res.get("role", "viewer")
                        st.rerun()
                    except APIClientError:
                        st.error("Invalid username or password.")

    # Halt execution of the rest of the application until authenticated
    st.stop()


def require_auth(client: APIClient | None = None) -> None:
    """Alias for render_login_gate."""
    render_login_gate(client)


def render_user_sidebar() -> None:
    """Render current user profile badge and logout button in the sidebar."""
    if not is_authenticated():
        return

    user = current_user()
    role = current_role()
    role_badge = "🛡️ Administrator" if role == "admin" else "👁️ Viewer (Read-only)"

    with st.sidebar:
        st.divider()
        st.caption("Logged in as:")
        st.text(f"👤 {user}")
        st.caption(role_badge)
        if st.button("Log Out", key="sidebar_logout_btn", use_container_width=True):
            logout()
