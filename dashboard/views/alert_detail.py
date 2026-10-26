"""dashboard/views/alert_detail.py – Individual alert investigation and incident action view.

Design Invariants:
- Selected via st.query_params (?alert=<id>), with graceful handling of missing/invalid IDs.
- Incident timeline showing first anomaly, detection, blocking, restoration, resolution, and TTD.
- SHAP feature contribution horizontal bar chart + plain-word rule reasons.
- Paged files touched list rendered strictly as safe text.
- Admin containment actions (hidden for viewers): Block, Unblock, False Positive, and two-step Restore.
- Two-step Restore flow: dry-run preview followed by st.dialog confirmation and report.
- Natural language 'Explain in plain words' section with friendly fallback.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import plotly.graph_objects as go
import streamlit as st
from dashboard.api_client import APIClient, APIClientError, ApiUnavailable
from dashboard.auth import is_admin
from dashboard.ui import (
    empty_state,
    error_state,
    reconnecting_banner,
    safe_text,
    severity_badge,
    state_badge,
)

_RULE_DESCRIPTIONS: dict[str, str] = {
    "R1": "Mass file extension modification burst matching known ransomware patterns (.locked, .crypt, .enc).",
    "R2": "High Shannon entropy write burst indicative of cryptographic payload encryption.",
    "R3": "Rapid file deletion burst following batch encryption operations.",
    "R4": "Canary file modification or unauthorized file header wipe detected.",
    "R5": "Unusual volume of directory traversal and discovery across sensitive shares.",
}


def _render_shap_chart(shap_data: dict[str, float] | list[dict[str, Any]]) -> go.Figure:
    """Build a horizontal bar chart of top SHAP feature contributions."""
    features: list[str] = []
    values: list[float] = []

    if isinstance(shap_data, dict):
        for k, v in shap_data.items():
            features.append(k.replace("_", " ").title())
            values.append(float(v))
    elif isinstance(shap_data, list):
        for item in shap_data:
            features.append(str(item.get("feature", "Unknown")).replace("_", " ").title())
            values.append(float(item.get("value", 0.0)))

    # Sort by absolute impact
    combined = sorted(zip(features, values, strict=False), key=lambda x: abs(x[1]))
    features = [c[0] for c in combined]
    values = [c[1] for c in combined]

    # Colors: positive pushes toward attack (red), negative pushes toward normal (green/blue)
    colors = ["#f87171" if v > 0 else "#38bdf8" for v in values]

    fig = go.Figure(
        go.Bar(
            x=values,
            y=features,
            orientation="h",
            marker={"color": colors},
            text=[f"{v:+.2f}" for v in values],
            textposition="auto",
        )
    )

    fig.update_layout(
        template="plotly_dark",
        height=max(180, len(features) * 32),
        margin={"l": 120, "r": 25, "t": 25, "b": 25},
        xaxis={"title": "SHAP Impact (← Pushes Normal | Pushes Attack →)", "showgrid": True, "gridcolor": "#334155"},
        yaxis={"title": None},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def _calculate_ttd(first_anomaly_ts: str | None, created_at: str | None) -> str:
    """Compute human-friendly Time-To-Detect (TTD) latency."""
    if not first_anomaly_ts or not created_at:
        return "N/A"
    try:
        t0 = datetime.fromisoformat(first_anomaly_ts.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        delta_s = (t1 - t0).total_seconds()
        if delta_s < 1.0:
            return f"{int(delta_s * 1000)}ms"
        if delta_s < 60.0:
            return f"{delta_s:.1f}s"
        return f"{int(delta_s // 60)}m {int(delta_s % 60)}s"
    except Exception:
        return "N/A"


@st.dialog("Confirm Snapshot File Restoration")
def _show_restore_confirmation_dialog(alert_id: int, client: APIClient, preview: dict[str, Any]) -> None:
    """Confirmation modal dialog for executing snapshot restoration."""
    st.warning("⚠️ You are about to restore modified files to their pre-incident clean state.")
    st.write(
        f"**Target Alert:** #{alert_id}\n\n"
        f"**Clean Snapshot ID:** `{preview.get('snapshot_id', 'latest')}`\n\n"
        f"**Files to Revert:** {preview.get('restored_count', 0)} files ({preview.get('total_bytes', 0):,} bytes)\n\n"
        f"**Files Skipped:** {preview.get('skipped_count', 0)}"
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Confirm & Restore Now", type="primary", use_container_width=True, key=f"btn_confirm_restore_{alert_id}"):
            try:
                result = client.restore_files(alert_id, dry_run=False, confirm=True)
                st.session_state[f"_restore_result_{alert_id}"] = result
                st.session_state.pop(f"_dry_run_preview_{alert_id}", None)
                st.rerun()
            except APIClientError as err:
                st.error(f"Restoration failed: {err}")
    with col2:
        if st.button("Cancel", use_container_width=True, key=f"btn_cancel_restore_{alert_id}"):
            st.rerun()


def render() -> None:
    """Render the Alert Detail page."""
    st.header("🔍 Alert Investigation & Response")

    client = APIClient()

    # 1. Resolve Alert ID from Query Params or Fallback Dropdown
    raw_query_id = st.query_params.get("alert")
    selected_id: int | None = None

    if raw_query_id is not None:
        try:
            selected_id = int(raw_query_id)
        except ValueError:
            selected_id = None

    # Fetch alerts list for fallback selector
    try:
        available_alerts = client.list_alerts(limit=50)
    except ApiUnavailable:
        reconnecting_banner()
        return
    except APIClientError as err:
        error_state("Failed to retrieve incident alerts", str(err))
        return

    if not available_alerts:
        empty_state("No Incidents Recorded", "No ransomware alerts have been registered in the system.")
        return

    # If query param is missing or invalid, display graceful picker
    alert_ids = [a.get("id") for a in available_alerts if a.get("id")]
    if selected_id not in alert_ids:
        st.info("💡 Select an incident below or navigate from the Overview / Alerts feed.")
        selected_id = st.selectbox(
            "Select Alert ID to investigate",
            alert_ids,
            index=0 if alert_ids else 0,
            key="sb_alert_detail_id",
        )
        if selected_id:
            st.query_params["alert"] = str(selected_id)

    if not selected_id:
        empty_state("No Alert Selected", "Please choose an alert ID to inspect.")
        return

    # 2. Fetch Single Alert Details
    with st.spinner(f"Loading incident #{selected_id} telemetry..."):
        try:
            alert = client.get_alert(selected_id)
        except ApiUnavailable:
            reconnecting_banner()
            return
        except APIClientError:
            error_state(
                "Incident Not Found",
                f"Alert ID #{selected_id} could not be located on the server. It may have been cleared or removed.",
            )
            return

    # 3. Incident Summary Header Card
    with st.container(border=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Client IP", alert.get("client_ip", "Unknown"))
        with col2:
            st.metric("Username", alert.get("username", "Unknown"))
        with col3:
            st.metric("Severity", severity_badge(alert.get("severity", "low")))
        with col4:
            st.metric("Current State", state_badge(alert.get("status", "open")))

    # 4. Incident Timeline
    st.subheader("⏱️ Incident Response Timeline")
    ttd_str = _calculate_ttd(alert.get("first_anomaly_ts"), alert.get("created_at"))
    t_col1, t_col2, t_col3, t_col4 = st.columns(4)
    with t_col1:
        st.caption("1️⃣ First Anomaly")
        st.text(str(alert.get("first_anomaly_ts") or "N/A")[:19].replace("T", " "))
    with t_col2:
        st.caption("2️⃣ Detection Triggered")
        st.text(str(alert.get("created_at") or "N/A")[:19].replace("T", " "))
    with t_col3:
        st.caption("⚡ Time to Detect (TTD)")
        st.markdown(f"**{ttd_str}**")
    with t_col4:
        st.caption("3️⃣ Resolved At")
        st.text(str(alert.get("resolved_at") or "Ongoing incident")[:19].replace("T", " "))

    st.divider()

    # 5. 'Why Was This Flagged?' Explanation Section
    st.subheader("🧠 Why Was This Flagged?")

    shap_data = alert.get("shap_values") or alert.get("feature_importances")
    if shap_data:
        st.caption("SHAP Feature Contributions (Direction of influence):")
        chart_fig = _render_shap_chart(shap_data)
        st.plotly_chart(chart_fig, use_container_width=True, key=f"shap_chart_{selected_id}")
    else:
        st.info("ℹ️ Rules-based detection only: No ML/SHAP model explanation generated for this incident.")

    rules = alert.get("triggered_rules", [])
    if rules:
        st.markdown("**Triggered Detection Rules (Plain Language):**")
        for r in rules:
            desc = _RULE_DESCRIPTIONS.get(r, f"Behavioral heuristic rule {r} exceeded threshold.")
            st.markdown(f"- **`{r}`**: {desc}")
    else:
        st.caption("No specific heuristic rules flagged; detected via general anomaly model.")

    st.divider()

    # 6. Paged Touched Files List
    st.subheader("📂 Affected File Artifacts")
    files = alert.get("files_touched", [])
    total_files = len(files)
    st.markdown(f"**Files Touched ({total_files} total):**")

    if files:
        page_size = 10
        total_file_pages = max(1, (total_files + page_size - 1) // page_size)
        f_page = 1
        if total_file_pages > 1:
            f_page = st.number_input(
                f"Page (1 to {total_file_pages})",
                min_value=1,
                max_value=total_file_pages,
                value=1,
                key=f"file_page_num_{selected_id}",
            )
        start_f = (f_page - 1) * page_size
        end_f = start_f + page_size
        display_files = files[start_f:end_f]

        st.caption("Untrusted filenames logged during anomaly window (rendered safely as text):")
        for f in display_files:
            safe_text(f)
    else:
        st.info("No file modifications recorded for this incident.")

    st.divider()

    # 7. 'Explain in Plain Words' Assistant Section
    st.subheader("💬 Incident Summary (Plain-Language Assistant)")
    st.caption("Local AI guidance and emergency response playbooks for non-technical office staff.")

    expl_key = f"_expl_{selected_id}"
    explanation = st.session_state.get(expl_key)

    with st.container(border=True):
        if not explanation:
            st.markdown("Generate an immediate plain-language breakdown of this incident with emergency steps and playbook guidance.")
            if st.button("🤖 Generate Incident Explanation", key=f"btn_explain_alert_{selected_id}", type="primary", use_container_width=True):
                with st.spinner("Consulting local incident assistant and knowledge playbooks..."):
                    try:
                        explanation = client.explain_alert(selected_id)
                        st.session_state[expl_key] = explanation
                        st.rerun()
                    except Exception as err:
                        st.error(f"Failed to generate explanation: {err}")
        else:
            # Source indicator badge
            source = explanation.get("source", "template")
            model_name = explanation.get("model", "template")
            gen_ms = explanation.get("generation_time_ms", 0.0)

            if source == "llm":
                st.success(f"🤖 Generated by Local AI ({model_name}) in {gen_ms:.0f}ms", icon="🧠")
            else:
                st.info(f"📋 Generated by Deterministic Template Engine (Local AI offline or unavailable: {model_name})", icon="ℹ️")

            st.markdown("#### Overview")
            st.text(explanation.get("summary", "No summary provided."))

            # Checklist: What to do now
            st.markdown("#### 🚨 Emergency Action Plan (What to Do Now)")
            todo_steps = explanation.get("what_to_do_now", [])
            for idx, step in enumerate(todo_steps):
                st.checkbox(step, value=False, key=f"chk_todo_{selected_id}_{idx}")

            # What NOT to do
            st.markdown("#### ⚠️ What NOT to Do")
            not_to_do_items = explanation.get("what_not_to_do", [])
            for item in not_to_do_items:
                st.text(f"🚫 {item}")

            # Who to contact
            st.markdown("#### 📞 Who to Contact & Legal Guidance")
            st.text(explanation.get("who_to_contact", ""))

            # Referenced playbooks
            playbooks_cited = explanation.get("playbooks_used", [])
            if playbooks_cited:
                st.caption(f"Referenced Playbooks: {', '.join(playbooks_cited)}")

            st.divider()

            # Report download button and refresh button
            c_down, c_ref = st.columns([2, 1])
            with c_down:
                try:
                    report_md = client.get_alert_report_md(selected_id)
                    st.download_button(
                        label="📥 Download Incident Report (.md)",
                        data=report_md,
                        file_name=f"shareguard_incident_report_{selected_id}.md",
                        mime="text/markdown",
                        key=f"btn_download_report_{selected_id}",
                        use_container_width=True,
                    )
                except Exception:
                    st.caption("Report download temporarily unavailable.")
            with c_ref:
                if st.button("🔄 Regenerate", key=f"btn_regen_expl_{selected_id}", use_container_width=True):
                    st.session_state.pop(expl_key, None)
                    st.rerun()

    st.divider()

    # 8. Administrator Containment & Mitigation Actions
    if is_admin():
        st.subheader("🛡️ Administrator Containment Actions")

        # Display previous restoration report if exists
        restore_result = st.session_state.get(f"_restore_result_{selected_id}")
        if restore_result:
            with st.container(border=True):
                st.success(f"✅ Restoration Completed! {restore_result.get('restored_count', 0)} files reverted.")
                if restore_result.get("skipped_files"):
                    st.caption("Skipped files:")
                    for sf in restore_result.get("skipped_files", [])[:5]:
                        safe_text(sf)
                if st.button("Dismiss Restoration Report", key=f"btn_dismiss_rep_{selected_id}"):
                    st.session_state.pop(f"_restore_result_{selected_id}", None)
                    st.rerun()

        act_col1, act_col2 = st.columns([1, 1])

        # Column 1: Blocking & Unblocking
        with act_col1, st.container(border=True):
            st.markdown("#### 🚫 Firewall Containment")
            duration_opts = {
                300: "5 minutes",
                900: "15 minutes (Default)",
                3600: "1 hour",
                86400: "24 hours",
            }
            block_ttl = st.selectbox(
                "Block Duration",
                options=list(duration_opts.keys()),
                format_func=lambda x: duration_opts[x],
                index=1,
                key=f"sb_ttl_{selected_id}",
            )
            block_reason = st.text_input(
                "Containment Reason",
                value=f"Automated ransomware mitigation for Alert #{selected_id}",
                key=f"txt_reason_{selected_id}",
            )

            b_col1, b_col2 = st.columns(2)
            with b_col1:
                if st.button("🚫 Block Client", key=f"btn_block_{selected_id}", use_container_width=True):
                    try:
                        client.block_client(selected_id, ttl_seconds=block_ttl, reason=block_reason)
                        st.success(f"Client {alert.get('client_ip')} blocked successfully.")
                        st.rerun()
                    except APIClientError as err:
                        st.error(f"Action refused: {err}")

            with b_col2:
                if st.button("🟢 Unblock Client", key=f"btn_unblock_{selected_id}", use_container_width=True):
                    try:
                        client.unblock_client(selected_id)
                        st.success(f"Client {alert.get('client_ip')} unblocked.")
                        st.rerun()
                    except APIClientError as err:
                        st.error(f"Action refused: {err}")

        # Column 2: Incident Status Resolution & Two-Step Restore
        with act_col2:
            with st.container(border=True):
                st.markdown("#### 🔄 Snapshot Restoration")
                st.caption("Revert modified files to the clean pre-incident snapshot.")

                dry_run_preview = st.session_state.get(f"_dry_run_preview_{selected_id}")

                if dry_run_preview:
                    st.info(
                        f"**Dry Run Preview Ready:**\n\n"
                        f"- Would Restore: {dry_run_preview.get('restored_count', 0)} files\n"
                        f"- Would Skip: {dry_run_preview.get('skipped_count', 0)} files\n"
                        f"- Total Size: {dry_run_preview.get('total_bytes', 0):,} bytes"
                    )
                    r_col1, r_col2 = st.columns(2)
                    with r_col1:
                        if st.button("Proceed to Confirm", type="primary", use_container_width=True, key=f"btn_open_dialog_{selected_id}"):
                            _show_restore_confirmation_dialog(selected_id, client, dry_run_preview)
                    with r_col2:
                        if st.button("Cancel Dry Run", use_container_width=True, key=f"btn_cancel_dry_{selected_id}"):
                            st.session_state.pop(f"_dry_run_preview_{selected_id}", None)
                            st.rerun()
                else:
                    if st.button("🔍 Preview Restore (Dry Run)", use_container_width=True, key=f"btn_restore_{selected_id}"):
                        try:
                            preview = client.restore_files(selected_id, dry_run=True, confirm=False)
                            st.session_state[f"_dry_run_preview_{selected_id}"] = preview
                            st.rerun()
                        except APIClientError as err:
                            st.error(f"Restore preview refused: {err}")

            with st.container(border=True):
                st.markdown("#### ⚖️ Incident Resolution")
                res_col1, res_col2 = st.columns(2)
                with res_col1:
                    if st.button("✅ Resolve Alert", key=f"btn_resolve_{selected_id}", use_container_width=True):
                        try:
                            client.resolve_alert(selected_id, reason="Resolved by SecOps Administrator")
                            st.success(f"Alert #{selected_id} marked as resolved.")
                            st.rerun()
                        except APIClientError as err:
                            st.error(f"Resolution failed: {err}")
                with res_col2:
                    if st.button("⚪ False Positive", key=f"btn_fp_{selected_id}", use_container_width=True):
                        try:
                            client.mark_false_positive(selected_id, allowlist=True, reason="Verified benign admin activity")
                            st.success(f"Alert #{selected_id} classified as false positive and client allowlisted.")
                            st.rerun()
                        except APIClientError as err:
                            st.error(f"Action failed: {err}")
    else:
        st.caption("🔒 Incident response and containment actions are restricted to administrators.")
