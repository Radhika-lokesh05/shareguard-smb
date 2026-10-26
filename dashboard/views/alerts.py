"""dashboard/views/alerts.py – Alerts feed view for the ShareGuard dashboard.

Design Invariants:
- Filterable by state, client IP, date range, and text search box.
- Exportable via CSV download button using API export endpoint.
- Displays 5 key columns first, with expandable row-level details.
- Pagination controls for high-volume environments.
- Untrusted file and user strings rendered strictly via safe_text / st.text / dataframes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pandas as pd
import streamlit as st
from dashboard.api_client import APIClient, APIClientError, ApiUnavailable
from dashboard.ui import (
    empty_state,
    error_state,
    reconnecting_banner,
    safe_text,
    severity_badge,
    state_badge,
)


def _open_alert_detail(alert_id: int) -> None:
    """Set query parameter and navigate to Alert Detail."""
    st.query_params["alert"] = str(alert_id)
    try:
        from dashboard.views import alert_detail

        st.switch_page(st.Page(alert_detail.render, title="Alert Detail", icon="🔍"))
    except Exception:
        st.rerun()


def render() -> None:
    """Render the Alerts Feed page."""
    st.header("🚨 Incident Alerts")
    st.caption("Active and historical ransomware anomaly alerts detected across Samba shares.")

    client = APIClient()

    # 1. Fetch Raw Data with Spinner
    with st.spinner("Loading incident alerts feed..."):
        try:
            raw_alerts = client.list_alerts(limit=500)
        except ApiUnavailable:
            reconnecting_banner()
            return
        except APIClientError as err:
            error_state("Failed to retrieve alerts", str(err))
            return

    # 2. Filters & Search Controls
    with st.expander("🔍 Filter & Search Incidents", expanded=True):
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)

        with col_f1:
            status_options = ["All", "open", "resolved", "false_positive"]
            status_filter = st.selectbox("Status", status_options, index=0, key="alerts_filter_status")

        with col_f2:
            unique_ips = sorted({a.get("client_ip") for a in raw_alerts if a.get("client_ip")})
            ip_options = ["All Clients", *unique_ips]
            ip_filter = st.selectbox("Client IP", ip_options, index=0, key="alerts_filter_ip")

        with col_f3:
            date_options = ["All Time", "Today", "Last 7 Days", "Last 30 Days"]
            date_filter = st.selectbox("Time Window", date_options, index=0, key="alerts_filter_date")

        with col_f4:
            search_query = st.text_input("Search (keyword, file, rule)", value="", key="alerts_search_query").strip().lower()

    # 3. Apply Filters
    now_utc = datetime.now(UTC)
    filtered = raw_alerts

    if status_filter != "All":
        filtered = [a for a in filtered if a.get("status") == status_filter]

    if ip_filter != "All Clients":
        filtered = [a for a in filtered if a.get("client_ip") == ip_filter]

    if date_filter != "All Time":
        days_limit = 0 if date_filter == "Today" else (7 if date_filter == "Last 7 Days" else 30)
        cutoff = now_utc - timedelta(days=days_limit)
        time_filtered = []
        for a in filtered:
            ts = a.get("created_at")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if date_filter == "Today":
                        if dt.date() == now_utc.date():
                            time_filtered.append(a)
                    elif dt >= cutoff:
                        time_filtered.append(a)
                except Exception:
                    time_filtered.append(a)
            else:
                time_filtered.append(a)
        filtered = time_filtered

    if search_query:
        query_filtered = []
        for a in filtered:
            ip = str(a.get("client_ip", "")).lower()
            usr = str(a.get("username", "")).lower()
            rules = " ".join(a.get("triggered_rules", [])).lower()
            expl = str(a.get("explanation", "")).lower()
            files = " ".join(a.get("files_touched", [])).lower()
            if (
                search_query in ip
                or search_query in usr
                or search_query in rules
                or search_query in expl
                or search_query in files
            ):
                query_filtered.append(a)
        filtered = query_filtered

    # 4. Top Actions Bar: Results count & CSV Export
    col_count, col_exp = st.columns([3, 1])
    with col_count:
        st.markdown(f"**Showing {len(filtered)} incidents** (of {len(raw_alerts)} total)")
    with col_exp:
        try:
            csv_data = client.export_alerts_csv()
            st.download_button(
                label="📥 Export Alerts (CSV)",
                data=csv_data,
                file_name=f"shareguard_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="btn_export_alerts_csv",
            )
        except Exception:
            st.caption("CSV export unavailable")

    if not filtered:
        empty_state("No Incidents Found", "No alerts matched the specified filtering and search parameters.")
        return

    # 5. Pagination
    col_p1, col_p2, col_p3 = st.columns([1, 1, 2])
    with col_p1:
        page_size = st.selectbox("Items per page", [10, 25, 50], index=0, key="alerts_page_size")
    total_pages = max(1, (len(filtered) + page_size - 1) // page_size)
    with col_p2:
        current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="alerts_page_num")

    start_idx = (current_page - 1) * page_size
    end_idx = start_idx + page_size
    page_items = filtered[start_idx:end_idx]

    # 6. Primary 5 Columns Table
    table_rows = [
        {
            "ID": a.get("id"),
            "Time": str(a.get("created_at", ""))[:19].replace("T", " "),
            "Client IP": a.get("client_ip", "Unknown"),
            "User": a.get("username", "Unknown"),
            "State": state_badge(a.get("status", "open")),
            "Severity": severity_badge(a.get("severity", "low")),
            "ML Score": f"{float(a.get('ml_score') or 0.0):.2f}",
        }
        for a in page_items
    ]
    df_primary = pd.DataFrame(table_rows)
    st.dataframe(df_primary, use_container_width=True)

    # 7. Row-Level Incident Inspector Expander
    st.subheader("🔎 Incident Details & Artifacts")
    for a in page_items:
        alert_id = a.get("id")
        with st.expander(f"Incident #{alert_id} — {a.get('client_ip')} ({a.get('status', 'open').upper()})"):
            c1, c2 = st.columns([3, 1])
            with c1:
                st.markdown("**Explanation:**")
                safe_text(a.get("explanation", "Behavioral rule detection triggered."))
                rules = a.get("triggered_rules", [])
                if rules:
                    st.caption(f"Triggered detection rules: {', '.join(rules)}")

                files = a.get("files_touched", [])
                if files:
                    st.caption(f"Touched files ({len(files)} recorded):")
                    for fn in files[:5]:
                        safe_text(fn)
                    if len(files) > 5:
                        st.caption(f"...and {len(files) - 5} more files.")
                else:
                    st.caption("No modified files recorded.")

            with c2:
                if st.button("Investigate Detail", key=f"btn_alerts_investigate_{alert_id}", use_container_width=True):
                    _open_alert_detail(alert_id)
