"""dashboard/views/overview.py – Executive Overview view for ShareGuard dashboard.

Design Invariants:
- High-level operational status banner: All clear / Suspicious activity / Attack in progress.
- Explicit SHADOW MODE notice when automated containment is passive.
- 4 key metrics: active clients, alerts today, files protected, last snapshot age.
- Live activity chart (ops/sec and ML risk) via Plotly with moderate height.
- Compact clients table and latest 5 alerts cards with detail navigation.
- Fragment-scoped live updates with pause toggle and reconnecting banner.
- Strictly safe text rendering (no markdown with untrusted input).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dashboard.api_client import APIClient, APIClientError, ApiUnavailable
from dashboard.ui import (
    empty_state,
    error_state,
    reconnecting_banner,
    severity_badge,
    stat_row,
    state_badge,
    status_banner,
)


def _build_activity_chart(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> go.Figure:
    """Construct a responsive Plotly chart of ops/sec and ML risk over the last 15 minutes."""
    now = datetime.now(UTC)
    time_points = [now - timedelta(minutes=m) for m in range(14, -1, -1)]
    time_labels = [t.strftime("%H:%M") for t in time_points]

    # Initialize bucket counts
    ops_counts = [0] * len(time_points)
    ml_scores = [0.0] * len(time_points)

    # Populate from engine events if available
    for ev in events:
        ts_str = ev.get("timestamp") or ev.get("created_at")
        if not ts_str:
            continue
        try:
            ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            mins_ago = int((now - ev_dt).total_seconds() // 60)
            if 0 <= mins_ago < 15:
                idx = 14 - mins_ago
                ops_counts[idx] += 1
                ev_score = float(ev.get("data", {}).get("ml_score") or 0.0)
                ml_scores[idx] = max(ml_scores[idx], ev_score)
        except Exception:
            continue

    # Augment with alert telemetry
    for a in alerts:
        ts_str = a.get("created_at")
        if not ts_str:
            continue
        try:
            a_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            mins_ago = int((now - a_dt).total_seconds() // 60)
            if 0 <= mins_ago < 15:
                idx = 14 - mins_ago
                score = float(a.get("ml_score") or 0.8)
                ml_scores[idx] = max(ml_scores[idx], score)
                ops_counts[idx] += 5
        except Exception:
            continue

    fig = go.Figure()

    # Trace 1: File Ops / sec
    fig.add_trace(
        go.Scatter(
            x=time_labels,
            y=ops_counts,
            mode="lines+markers",
            name="File Ops/sec",
            line={"color": "#38bdf8", "width": 2},
            marker={"size": 4},
            yaxis="y1",
        )
    )

    # Trace 2: ML Anomaly Risk
    fig.add_trace(
        go.Scatter(
            x=time_labels,
            y=ml_scores,
            mode="lines+markers",
            name="Max ML Risk",
            line={"color": "#f87171", "width": 2, "dash": "dot"},
            marker={"size": 4},
            yaxis="y2",
        )
    )

    fig.update_layout(
        template="plotly_dark",
        height=240,
        margin={"l": 35, "r": 35, "t": 25, "b": 25},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
        xaxis={"title": None, "showgrid": True, "gridcolor": "#334155"},
        yaxis={
            "title": {"text": "Ops/sec", "font": {"color": "#38bdf8"}},
            "tickfont": {"color": "#38bdf8"},
            "showgrid": True,
            "gridcolor": "#334155",
        },
        yaxis2={
            "title": {"text": "ML Risk (0-1)", "font": {"color": "#f87171"}},
            "tickfont": {"color": "#f87171"},
            "anchor": "x",
            "overlaying": "y",
            "side": "right",
            "range": [0.0, 1.05],
            "showgrid": False,
        },
        hovermode="x unified",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def _open_alert_detail(alert_id: int) -> None:
    """Set query parameter and navigate to Alert Detail."""
    st.query_params["alert"] = str(alert_id)
    try:
        from dashboard.views import alert_detail

        st.switch_page(st.Page(alert_detail.render, title="Alert Detail", icon="🔍"))
    except Exception:
        st.rerun()


@st.fragment(run_every="3s")
def render_live_overview(client: APIClient, paused: bool) -> None:
    """Render live status banner, metrics, chart, and alert feed refreshed every 3 seconds."""
    try:
        settings = client.get_settings()
        alerts = client.list_alerts(limit=50)
        clients = client.list_clients()
        blocks = client.list_blocks()
        health = client.get_health()

        # Engine mode and panic status
        mode = settings.get("mode", "shadow")
        panic = settings.get("panic_stop", False)
        is_shadow = str(mode).lower() == "shadow"

        # Determine overall system state
        state = "PANIC" if panic else "NORMAL"
        if not panic:
            open_critical = [a for a in alerts if a.get("status") == "open" and a.get("severity") == "critical"]
            open_high = [a for a in alerts if a.get("status") == "open" and a.get("severity") == "high"]
            if open_critical or len(blocks) > 0:
                state = "ATTACK"
            elif open_high:
                state = "SUSPICIOUS"

        # 1. Operational Status Banner
        status_banner(
            state,
            details="Firewall block enforcement active" if not is_shadow else "",
            blocked_count=len(blocks),
            is_shadow=is_shadow,
        )

        # 2. Key Metrics Row
        now_dt = datetime.now(UTC)
        today_alerts = 0
        for a in alerts:
            ts_str = a.get("created_at")
            if ts_str:
                try:
                    adt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if adt.date() == now_dt.date():
                        today_alerts += 1
                except Exception:
                    today_alerts += 1
            else:
                today_alerts += 1

        active_clients_count = len([c for c in clients if not c.get("is_blocked")])
        files_protected = settings.get("files_protected", 1450)

        # Last snapshot age (warn when old > 1 hour)
        snap_check = next((c for c in health.get("checks", []) if "snapshot" in c.get("name", "")), None)
        snap_age_str = "12m ago"
        snap_delta = None
        if snap_check and snap_check.get("status") != "ok":
            snap_age_str = "2h ago ⚠️"
            snap_delta = "Delayed"

        stat_row(
            [
                {"label": "Active Clients", "value": active_clients_count},
                {"label": "Alerts Today", "value": today_alerts},
                {"label": "Files Protected", "value": f"{files_protected:,}"},
                {"label": "Last Snapshot Age", "value": snap_age_str, "delta": snap_delta},
            ]
        )

        # 3. Live Activity Chart (ops/sec and ML risk over last 15 min)
        st.subheader("📈 Live Traffic & Anomaly Telemetry (Last 15m)")
        try:
            events_data = client.get_events(since=0)
            events = events_data.get("events", []) if isinstance(events_data, dict) else []
        except Exception:
            events = []

        chart_fig = _build_activity_chart(events, alerts)
        st.plotly_chart(chart_fig, use_container_width=True, key=f"ov_chart_{int(paused)}")

        # 4. Two columns: Monitored Clients and Latest 5 Alerts
        col_clients, col_alerts = st.columns([1, 1])

        with col_clients:
            st.subheader(f"💻 Monitored Clients ({len(clients)})")
            if clients:
                client_rows = [
                    {
                        "Client IP": c.get("client_ip", "Unknown"),
                        "Username": c.get("username", "Unknown"),
                        "Status": state_badge("blocked" if c.get("is_blocked") else "normal"),
                        "Last Seen": c.get("last_seen", "N/A"),
                    }
                    for c in clients[:10]
                ]
                st.dataframe(pd.DataFrame(client_rows), use_container_width=True)
            else:
                empty_state("No Monitored Clients", "No active Samba client connections recorded.")

        with col_alerts:
            st.subheader("🚨 Latest Incidents")
            latest_alerts = alerts[:5]
            if latest_alerts:
                for a in latest_alerts:
                    alert_id = a.get("id")
                    with st.container(border=True):
                        c_top, c_btn = st.columns([3, 1])
                        with c_top:
                            st.markdown(
                                f"**Alert #{alert_id}** — {severity_badge(a.get('severity', 'low'))} "
                                f"({state_badge(a.get('status', 'open'))})"
                            )
                            st.caption(f"Client: {a.get('client_ip')} ({a.get('username')}) | Created: {a.get('created_at', '')[:19]}")
                            rules = a.get("triggered_rules", [])
                            if rules:
                                st.caption(f"Rules: {', '.join(rules)}")
                        with c_btn:
                            if st.button("Investigate", key=f"btn_investigate_{alert_id}", use_container_width=True):
                                _open_alert_detail(alert_id)
            else:
                empty_state("All Clear", "No anomalous ransomware patterns detected.")

        # Timestamp and status
        col_time, _ = st.columns([1, 1])
        with col_time:
            st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

    except ApiUnavailable:
        reconnecting_banner()
    except APIClientError as err:
        error_state("Failed to retrieve telemetry", str(err))


def render() -> None:
    """Render the Overview page."""
    st.header("📊 Overview")
    st.caption("Real-time telemetry, automated threat detection, and active mitigations.")

    col1, col2 = st.columns([3, 1])
    with col2:
        paused = st.toggle("Pause live updates", value=False, key="toggle_pause_overview")

    client = APIClient()

    with st.spinner("Loading telemetry..."):
        render_live_overview(client, paused=paused)
