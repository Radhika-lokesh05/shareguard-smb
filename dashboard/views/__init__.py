"""dashboard/views – Multipage views for the ShareGuard Streamlit dashboard."""

from __future__ import annotations

from dashboard.views import alert_detail, alerts, clients, health, overview, settings

__all__ = [
    "overview",
    "alerts",
    "alert_detail",
    "clients",
    "health",
    "settings",
]
