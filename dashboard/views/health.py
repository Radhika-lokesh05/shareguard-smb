"""dashboard/views/health.py – System health, component diagnostics, and recovery drills."""

from __future__ import annotations

from typing import Any

import streamlit as st
from dashboard.api_client import APIClient, ApiUnavailable
from dashboard.auth import is_admin
from dashboard.ui import empty_state, reconnecting_banner, safe_text, stat_row

_FIX_GUIDES: dict[str, dict[str, str]] = {
    # Probes by ID
    "audit_logging": {
        "title": "Samba Audit Logging",
        "desc": "Ingests real-time file access events from the Samba full_audit VFS plugin.",
        "fix": (
            "1. Verify that 'vfs objects = full_audit' is configured in your Samba share definition in smb.conf.\n"
            "2. Confirm that the log file exists, is non-empty, and is receiving write events.\n"
            "For your IT person: Add 'vfs objects = full_audit' to [shares] in /etc/samba/smb.conf and reload Samba."
        ),
    },
    "smb_protocol": {
        "title": "SMB Protocol Version",
        "desc": "Ensures obsolete SMB1/NT1 protocols are disabled to prevent WannaCry-style lateral movement.",
        "fix": (
            "1. Check your Samba global configuration for server min protocol.\n"
            "2. Disable legacy SMB1/NT1 and require modern SMB2 or SMB3 dialects.\n"
            "For your IT person: Set 'server min protocol = SMB2' in [global] in /etc/samba/smb.conf and restart smbd."
        ),
    },
    "guest_access": {
        "title": "Guest & Anonymous Access",
        "desc": "Guarantees unauthenticated network users cannot read or write office files.",
        "fix": (
            "1. Ensure no shares permit guest or anonymous access without login credentials.\n"
            "2. Ensure unknown user logins are not automatically mapped to the guest account.\n"
            "For your IT person: Remove 'guest ok = yes' from shares and set 'map to guest = Never' in smb.conf."
        ),
    },
    "snapshots": {
        "title": "Snapshot Storage & Boundaries",
        "desc": "Verifies that backups exist, are recent, and are stored strictly outside live share paths.",
        "fix": (
            "1. Ensure automated snapshot backups are running on an hourly or daily schedule.\n"
            "2. Verify snapshot storage is on a separate partition and is not exported over SMB.\n"
            "For your IT person: Store snapshots outside the share root and ensure snapshot directories are read-only."
        ),
    },
    "restore_test": {
        "title": "Automated Restore Drill",
        "desc": "Verifies that files from backup snapshots can be recovered without corruption.",
        "fix": (
            "1. Run an on-demand synthetic recovery drill to verify snapshot integrity.\n"
            "2. Review restore drill logs for hash verification mismatches or read errors.\n"
            "For your IT person: Click 'Run restore test' in the dashboard or run 'POST /api/health-check/restore-test'."
        ),
    },
    "canary_files": {
        "title": "Canary Bait File Tripwires",
        "desc": "Monitors hidden canary decoy files in share roots for unauthorized tampering or deletion.",
        "fix": (
            "1. Verify that canary decoy files exist in configured SMB share roots.\n"
            "2. If canaries were modified or deleted, investigate recent SMB activity immediately.\n"
            "For your IT person: Deploy or re-seed canary decoy files using 'shareguard canaries deploy'."
        ),
    },
    "disk_space": {
        "title": "Storage & Volume Free Space",
        "desc": "Monitors free space on file share and snapshot storage volumes.",
        "fix": (
            "1. Ensure sufficient free disk space is available for new files and delta snapshots.\n"
            "2. Free space below 15% can cause file writes to freeze or snapshot failures.\n"
            "For your IT person: Expand storage capacity or prune older unneeded files and obsolete archives."
        ),
    },
    "network_exposure": {
        "title": "Network Exposure & Firewall",
        "desc": "Checks SMB listening socket bindings (ports 139/445) and host firewall enforcement.",
        "fix": (
            "1. Ensure file sharing ports are restricted strictly to internal office network interfaces.\n"
            "2. Ensure an active host firewall (UFW or nftables) blocks external traffic.\n"
            "For your IT person: Set 'bind interfaces only = yes' in smb.conf and enable UFW or nftables."
        ),
    },
    "safety_settings": {
        "title": "ShareGuard Engine Safety",
        "desc": "Verifies engine operating mode, IP allowlists, panic controls, and database health.",
        "fix": (
            "1. Verify that the server's own IP and default gateway are listed in the allowlist.\n"
            "2. Ensure the SQLite database file is accessible and writable by the service.\n"
            "For your IT person: Review config/default.yaml to ensure response.allowlist contains necessary network IPs."
        ),
    },
    # Backwards-compatibility aliases for legacy probe names
    "database": {
        "title": "Database Storage (SQLite)",
        "desc": "Stores alerts, client tracking, firewall blocks, and administrative audit trails.",
        "fix": (
            "1. Verify that 'shareguard.db' exists and is writable by the ShareGuard server process.\n"
            "2. Ensure sufficient disk space is available on the host filesystem.\n"
            "For your IT person: Check file permissions on shareguard.db and verify the disk is not full."
        ),
    },
    "samba_log": {
        "title": "Samba Audit Log Stream",
        "desc": "Ingests real-time file access events from the Samba full_audit VFS plugin.",
        "fix": (
            "1. Ensure Samba (smbd) is running and active on the host.\n"
            "2. Verify that 'vfs objects = full_audit' is configured in your Samba share definition in smb.conf.\n"
            "For your IT person: Ensure the audit log file exists and is readable by ShareGuard."
        ),
    },
    "ml_model": {
        "title": "Machine Learning Detection Models",
        "desc": "Executes Isolation Forest anomaly detection and XGBoost behavioral classification.",
        "fix": (
            "1. Ensure trained model files are present in the models directory.\n"
            "2. Verify scikit-learn, XGBoost, and SHAP runtime dependencies are installed.\n"
            "For your IT person: Train or place model weights into ml/artifacts/model.json."
        ),
    },
    "snapshot_backend": {
        "title": "Btrfs Snapshot Backend",
        "desc": "Performs instant subvolume snapshots and rollbacks of compromised files.",
        "fix": (
            "1. Confirm that SMB shares reside on a supported snapshot filesystem.\n"
            "2. Verify that ShareGuard has permissions to execute snapshot commands.\n"
            "For your IT person: Configure the snapshot backend in config/default.yaml."
        ),
    },
}


def _format_status_badge(status: str) -> tuple[str, str]:
    """Return an accessible icon and formatted label for a subsystem status."""
    s = str(status).lower()
    if s in ("ok", "healthy", "pass"):
        return "✅", "Pass (Operational)"
    if s in ("warn", "warning"):
        return "⚠️", "Warn (Needs Attention)"
    if s in ("fail", "error", "unhealthy"):
        return "❌", "Fail (At Risk)"
    return "❔", "Unknown (Placeholder)"


def _format_severity_badge(severity: str) -> str:
    """Return formatted severity label."""
    sev = str(severity).lower()
    if sev == "high":
        return "High Severity"
    if sev == "medium":
        return "Medium Severity"
    return "Low Severity"


def _sort_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort checks primarily by severity (high > medium > low), secondarily by status (fail > warn > unknown > pass)."""
    sev_map = {"high": 0, "medium": 1, "low": 2}
    stat_map = {"fail": 0, "warn": 1, "unknown": 2, "pass": 3, "ok": 3, "healthy": 3}

    def key_fn(c: dict[str, Any]) -> tuple[int, int, str]:
        s = str(c.get("severity", "medium")).lower()
        st_val = str(c.get("status", "unknown")).lower()
        title = str(c.get("title", c.get("name", "")))
        return (sev_map.get(s, 1), stat_map.get(st_val, 2), title)

    return sorted(checks, key=key_fn)


def render() -> None:
    """Render the System Health page."""
    st.header("🩺 System Health & Status")
    st.caption("Diagnostic telemetry, component health checklist, and automated recovery drills.")

    client = APIClient()

    try:
        with st.spinner("Querying subsystem health probes..."):
            health_data = client.get_health()
    except ApiUnavailable:
        reconnecting_banner()
        empty_state("API Unreachable", "Cannot fetch system component health diagnostics.")
        return

    checks: list[dict[str, Any]] = health_data.get("checks", [])
    total_checks = len(checks)

    # Calculate or retrieve weighted score and verdict
    pass_count = sum(1 for c in checks if str(c.get("status")).lower() in ("ok", "healthy", "pass"))
    warn_count = sum(1 for c in checks if str(c.get("status")).lower() in ("warn", "warning"))
    fail_count = sum(1 for c in checks if str(c.get("status")).lower() in ("fail", "error", "unhealthy"))
    unknown_count = health_data.get(
        "unknown_count",
        sum(1 for c in checks if str(c.get("status")).lower() in ("unknown", "")),
    )

    all_unknown = total_checks > 0 and unknown_count == total_checks

    if "score" in health_data:
        score_val = float(health_data["score"])
        score_display = f"{score_val:.0f}%"
        score_ratio = min(max(score_val / 100.0, 0.0), 1.0)
    elif all_unknown:
        score_display = "Placeholder Telemetry"
        score_ratio = 0.0
    else:
        score_ratio = (pass_count + (0.5 * warn_count)) / max(total_checks - unknown_count, 1)
        score_display = f"{int(score_ratio * 100)}%"

    verdict_raw = str(health_data.get("verdict", "")).strip()
    if not verdict_raw:
        if fail_count > 0 or score_ratio < 0.6:
            verdict_raw = "At risk"
        elif warn_count > 0 or score_ratio < 0.8:
            verdict_raw = "Needs attention"
        else:
            verdict_raw = "Good"

    verdict_badge = "🟢 Good" if verdict_raw == "Good" else ("🟡 Needs attention" if verdict_raw == "Needs attention" else "🔴 At risk")

    # Overview Telemetry Card
    with st.container(border=True):
        st.subheader("Subsystem Health Overview")

        stat_row(
            [
                {"label": "System Verdict", "value": verdict_badge},
                {"label": "Subsystems Monitored", "value": total_checks},
                {"label": "Passing Probes", "value": pass_count},
                {"label": "Health Score", "value": score_display},
            ]
        )

        st.markdown("#### Overall Health Score")
        if all_unknown:
            st.progress(0.0)
            st.caption("ℹ️ Probes are currently running in **Unknown (Placeholder)** mode returned by the API.")
        else:
            st.progress(score_ratio)
            st.caption(f"Weighted Score: {score_display} — System verdict: **{verdict_raw}** ({pass_count} passed, {warn_count} warned, {fail_count} failed).")

        if unknown_count > 0 and not all_unknown:
            st.info(f"ℹ️ Note: {unknown_count} probe(s) could not be evaluated and are excluded from the score calculation.")

        # Local Incident AI status line
        try:
            as_status = client.get_assistant_status()
        except Exception:
            as_status = {}

        ai_reachable = as_status.get("ollama_reachable", False)
        ai_model = as_status.get("active_model", "llama3.2:3b")
        ai_has_model = as_status.get("model_available", False)

        if ai_reachable and ai_has_model:
            st.caption(f"🧠 Local Incident AI: 🟢 Ready (`{ai_model}` on Ollama)")
        elif ai_reachable:
            st.caption(f"🧠 Local Incident AI: 🟡 Ollama online, model `{ai_model}` pending (Template fallback active)")
        else:
            st.caption("🧠 Local Incident AI: ⚪ Offline – Deterministic template guidance active")

    # Diagnostic Checklist with Icons and Plain-Words Fix Guides
    with st.container(border=True):
        st.subheader("Subsystem Diagnostics Checklist")
        st.caption("Probes sorted by severity and status. Review details and remediation steps below.")

        sorted_checks = _sort_checks(checks)

        if sorted_checks:
            for idx, check in enumerate(sorted_checks):
                raw_id = str(check.get("id", check.get("name", f"probe_{idx}")))
                raw_status = str(check.get("status", "unknown"))
                raw_severity = str(check.get("severity", "medium"))
                raw_title = check.get("title")

                icon, status_label = _format_status_badge(raw_status)
                sev_label = _format_severity_badge(raw_severity)

                guide = _FIX_GUIDES.get(raw_id, {})
                title = raw_title or guide.get("title", raw_id.replace("_", " ").title())
                desc = guide.get("desc", "Subsystem diagnostic probe.")
                detail = check.get("detail", "")
                fix_text = check.get("how_to_fix") or guide.get("fix", "Review server configuration and logs.")

                st.markdown(f"**{title}** — {icon} `{status_label}` · *{sev_label}*")
                st.caption(desc)

                if detail:
                    safe_text(detail)

                with st.expander(f"🛠️ How to fix: {title}"):
                    if raw_status.lower() == "unknown":
                        st.info("ℹ️ This probe reported 'unknown'. Once configured in your deployment, verify the following steps:")
                    safe_text(fix_text)
                st.divider()
        else:
            empty_state("No Subsystems Reported", "No individual health checks were returned by the API.")

    # Administrative Restore Drill Section
    with st.container(border=True):
        st.subheader("🔄 Automated Recovery & Snapshot Drill")
        st.caption("Validates backup integrity by executing an isolated non-destructive restoration drill into a temporary folder.")

        last_drill = health_data.get("last_restore_test")
        if last_drill:
            d_status = str(last_drill.get("status", "unknown")).upper()
            d_time = last_drill.get("tested_at", "")
            d_files = last_drill.get("files_restored", 0)
            d_duration = last_drill.get("time_taken_seconds", 0.0)
            d_detail = last_drill.get("detail", "")

            badge = "🟢 PASS" if d_status == "PASS" else ("🔴 FAIL" if d_status == "FAIL" else "⚪ " + d_status)
            stat_row(
                [
                    {"label": "Last Drill Result", "value": badge},
                    {"label": "Files Verified", "value": d_files},
                    {"label": "Duration", "value": f"{d_duration:.2f}s"},
                    {"label": "Executed At", "value": d_time[:19].replace("T", " ") if d_time else "N/A"},
                ]
            )
            if d_detail:
                st.caption("Drill Outcome Observation:")
                safe_text(d_detail)
        else:
            st.info("ℹ️ No snapshot restore test drills have been recorded yet.")

        if is_admin():
            st.markdown("Run a synthetic drill to verify that snapshot archives are healthy and can be restored.")
            if st.button("🧪 Run Restore Test", key="btn_run_restore_test", type="primary"):
                with st.spinner("Executing non-destructive restore drill..."):
                    try:
                        res = client.run_restore_test()
                        drill_status = str(res.get("status", "unknown")).upper()
                        if drill_status == "PASS":
                            st.success(f"Restore drill passed! Verified {res.get('files_restored', 0)} files in {res.get('time_taken_seconds', 0.0):.2f}s.")
                        else:
                            st.warning(f"Restore drill completed with status: {drill_status}. Detail: {res.get('detail', '')}")
                    except Exception as err:
                        err_str = str(err)
                        if "429" in err_str or "rate limit" in err_str.lower():
                            st.warning("⏳ Restore drill rate limit: Please wait 60 seconds between drill executions.")
                        else:
                            st.error(f"Restore drill failed: {err_str}")
        else:
            st.caption("🔒 Backup restore drills can only be executed by administrators.")
