"""dashboard/app.py – ShareGuard Streamlit dashboard entry point.

Multipage application architecture:
- Page configuration: wide layout, title 'ShareGuard', icon '🛡️'.
- Mandatory login gate runs before any pages or data queries.
- Navigation using Streamlit's official ``st.navigation`` + ``st.Page`` API.
- All backend access is through ``dashboard.api_client.APIClient``.
"""

from __future__ import annotations

import streamlit as st
from dashboard.auth import render_login_gate, render_user_sidebar
from dashboard.views import alert_detail, alerts, clients, health, overview, settings

st.set_page_config(
    page_title="ShareGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main() -> None:
    """Run the ShareGuard dashboard application."""
    # 1. Login gate runs before any page or data access
    render_login_gate()

    # 2. Render sidebar user information and logout button
    render_user_sidebar()

    # 3. Configure multipage navigation
    pages = [
        st.Page(overview.render, title="Overview", icon="📊", default=True),
        st.Page(alerts.render, title="Alerts", icon="🚨"),
        st.Page(alert_detail.render, title="Alert Detail", icon="🔍"),
        st.Page(clients.render, title="Clients", icon="💻"),
        st.Page(health.render, title="System Health", icon="🩺"),
        st.Page(settings.render, title="Settings", icon="⚙️"),
    ]

    nav = st.navigation(pages)
    nav.run()


if __name__ == "__main__":
    main()
