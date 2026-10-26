"""dashboard/views/clients.py – Monitored Samba clients, client history, and firewall blocks view."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dashboard.api_client import APIClient, ApiUnavailable
from dashboard.auth import is_admin
from dashboard.ui import (
    empty_state,
    reconnecting_banner,
    severity_badge,
    stat_row,
    state_badge,
)


def _build_client_activity_chart(
    alerts: list[dict[str, Any]],
    client_info: dict[str, Any],
) -> go.Figure:
    """Create a compact Plotly chart showing alert history and risk timeline for a client."""
    fig = go.Figure()

    if alerts:
        # Sort by timestamp ascending
        sorted_alerts = sorted(alerts, key=lambda a: a.get("created_at", ""))
        times = [a.get("created_at", "")[:19].replace("T", " ") for a in sorted_alerts]
        scores = [
            float(a.get("ml_score")) if a.get("ml_score") is not None else 0.85
            for a in sorted_alerts
        ]
        severities = [a.get("severity", "medium").upper() for a in sorted_alerts]
        rules_list = [
            ", ".join(a.get("triggered_rules", [])) if isinstance(a.get("triggered_rules"), list) else str(a.get("triggered_rules", ""))
            for a in sorted_alerts
        ]

        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
        }
        marker_colors = [color_map.get(s, "#38bdf8") for s in severities]

        # Activity line
        fig.add_trace(
            go.Scatter(
                x=times,
                y=scores,
                mode="lines+markers",
                name="Incident Risk Score",
                line={"color": "#f87171", "width": 2},
                marker={"size": 10, "color": marker_colors, "line": {"color": "#ffffff", "width": 1}},
                customdata=list(zip(severities, rules_list, strict=False)),
                hovertemplate="<b>%{customdata[0]} Alert</b><br>Time: %{x}<br>Score: %{y:.2f}<br>Rules: %{customdata[1]}<extra></extra>",
            )
        )

        fig.update_layout(
            template="plotly_dark",
            height=200,
            margin={"l": 35, "r": 20, "t": 25, "b": 30},
            xaxis={"title": None, "showgrid": True, "gridcolor": "#334155"},
            yaxis={
                "title": {"text": "Risk Score", "font": {"color": "#94a3b8"}},
                "range": [0.0, 1.05],
                "showgrid": True,
                "gridcolor": "#334155",
            },
            hovermode="closest",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
    else:
        # Baseline normal activity display
        now_str = datetime.now().strftime("%H:%M:%S")
        last_seen = str(client_info.get("last_seen", now_str))[:19].replace("T", " ")
        fig.add_trace(
            go.Scatter(
                x=[client_info.get("first_seen", "First Seen")[:19].replace("T", " "), last_seen],
                y=[0.05, 0.05],
                mode="lines+markers",
                name="Baseline Traffic",
                line={"color": "#22c55e", "width": 2},
                marker={"size": 6, "color": "#22c55e"},
                hovertemplate="Traffic Normal<br>No anomalies detected<extra></extra>",
            )
        )
        fig.update_layout(
            template="plotly_dark",
            height=140,
            margin={"l": 35, "r": 20, "t": 20, "b": 25},
            xaxis={"title": None, "showgrid": True, "gridcolor": "#334155"},
            yaxis={
                "title": {"text": "Risk", "font": {"color": "#94a3b8"}},
                "range": [0.0, 1.0],
                "showgrid": True,
                "gridcolor": "#334155",
            },
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )

    return fig


@st.fragment(run_every="3s")
def render_live_clients(client: APIClient, paused: bool) -> None:
    """Render clients, selected client history, and active firewall blocks refreshed every 3s."""
    try:
        with st.spinner("Updating client telemetry..."):
            clients = client.list_clients()
            blocks = client.list_blocks()

        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

        # Top summary stats
        stat_row(
            [
                {"label": "Known Clients", "value": len(clients)},
                {"label": "Active Blocks", "value": len(blocks)},
                {"label": "Normal Clients", "value": sum(1 for c in clients if not c.get("is_blocked"))},
                {"label": "Blocked Clients", "value": sum(1 for c in clients if c.get("is_blocked"))},
            ]
        )

        # Active Blocks Card
        with st.container(border=True):
            st.subheader(f"Active Firewall Blocks ({len(blocks)})")
            if blocks:
                block_rows = [
                    {
                        "Client IP": b.get("client_ip"),
                        "Username": b.get("username") or "N/A",
                        "Expires At": b.get("expires_at"),
                        "Reason": b.get("reason"),
                        "Backend": b.get("backend_type"),
                    }
                    for b in blocks
                ]
                st.dataframe(pd.DataFrame(block_rows), use_container_width=True)
            else:
                st.caption("No clients are currently blocked by firewall containment.")

        # Known Clients Card
        with st.container(border=True):
            st.subheader(f"Known Clients Directory ({len(clients)})")
            if clients:
                client_rows = [
                    {
                        "Client IP": c.get("client_ip"),
                        "Username": c.get("username"),
                        "Status": state_badge("blocked" if c.get("is_blocked") else "normal"),
                        "First Seen": c.get("first_seen"),
                        "Last Seen": c.get("last_seen"),
                    }
                    for c in clients
                ]
                df = pd.DataFrame(client_rows)
                st.dataframe(df[["Client IP", "Username", "Status", "Last Seen"]], use_container_width=True)
            else:
                empty_state("No Clients Connected", "No Samba client sessions recorded yet.")

        # Per-Client Deep Dive & History
        if clients:
            with st.container(border=True):
                st.subheader("🔍 Client Inspection & Activity History")
                client_ips = [c.get("client_ip") for c in clients if c.get("client_ip")]

                selected_ip = st.selectbox(
                    "Select client IP to inspect",
                    options=client_ips,
                    key="clients_select_inspect_ip",
                )

                selected_client = next((c for c in clients if c.get("client_ip") == selected_ip), clients[0])

                # Current State Overview for selected client
                st.markdown(f"#### Current State: `{selected_ip}`")
                c_status = "blocked" if selected_client.get("is_blocked") else "normal"

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Status", state_badge(c_status))
                with col2:
                    st.metric("Username", str(selected_client.get("username") or "unknown"))
                with col3:
                    st.metric("First Seen", str(selected_client.get("first_seen") or "N/A")[:19].replace("T", " "))
                with col4:
                    st.metric("Last Seen", str(selected_client.get("last_seen") or "N/A")[:19].replace("T", " "))

                # Fetch alerts for this client
                try:
                    client_alerts = client.list_alerts(client_ip=selected_ip)
                except Exception:
                    client_alerts = []

                # Small Chart: Activity & Risk Timeline
                st.markdown("##### 📈 Risk & Activity Timeline")
                chart = _build_client_activity_chart(client_alerts, selected_client)
                st.plotly_chart(chart, use_container_width=True, config={"displayModeBar": False})

                # Alert History for this client
                st.markdown(f"##### 🚨 Incident History ({len(client_alerts)})")
                if client_alerts:
                    alert_items = [
                        {
                            "ID": a.get("id"),
                            "Severity": severity_badge(a.get("severity", "medium")),
                            "Rules": ", ".join(a.get("triggered_rules", [])) if isinstance(a.get("triggered_rules"), list) else str(a.get("triggered_rules", "")),
                            "Status": state_badge(a.get("status", "open")),
                            "Created At": str(a.get("created_at", ""))[:19].replace("T", " "),
                        }
                        for a in client_alerts
                    ]
                    st.dataframe(pd.DataFrame(alert_items), use_container_width=True)
                else:
                    st.info(f"🟢 No alerts recorded for client {selected_ip}. Operating within baseline thresholds.")

                # Last states timeline
                with st.expander("🕒 State History Details"):
                    st.text(f"Client IP: {selected_ip}")
                    st.text(f"Username: {selected_client.get('username')}")
                    st.text(f"Session State: {'Blocked (Active Firewall Rule)' if selected_client.get('is_blocked') else 'Normal (Clear)'}")
                    st.text(f"Initial Session: {selected_client.get('first_seen')}")
                    st.text(f"Latest Activity: {selected_client.get('last_seen')}")

    except ApiUnavailable:
        reconnecting_banner()
        empty_state("API Unreachable", "Cannot communicate with the ShareGuard API server.")


def render() -> None:
    """Render the Clients page."""
    st.header("💻 Monitored Samba Clients")
    st.caption("Real-time client connections, incident history, and active firewall block enforcement.")

    col1, col2 = st.columns([3, 1])
    with col2:
        paused = st.toggle("Pause live updates", value=False, key="toggle_pause_clients")

    client = APIClient()
    render_live_clients(client, paused=paused)

    if not is_admin():
        st.caption("Viewer mode: Client block modifications restricted to administrators.")
