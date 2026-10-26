"""dashboard/views/settings.py – Detection thresholds, mode policy, and emergency controls view."""

from __future__ import annotations

import ipaddress
from typing import Any

import pandas as pd
import streamlit as st
from dashboard.api_client import APIClient, ApiUnavailable
from dashboard.auth import is_admin
from dashboard.ui import empty_state, reconnecting_banner, stat_row


@st.dialog("⚠️ Confirm Switch to Enforcing Mode")
def _confirm_enforce_dialog(client: APIClient, target_mode: str) -> None:
    """Dialog explaining the plain-language implications of switching to an enforcing mode."""
    st.warning(
        "You are about to activate automated firewall containment. "
        "In Enforcing Mode, ShareGuard actively disconnects SMB sessions and executes "
        "firewall blocking commands when ransomware patterns are detected."
    )
    st.markdown(
        "**Operating Mode Differences:**\n"
        "- **Enforce Temporary (`enforce_temp`)**: Attacking client IP addresses are blocked "
        "automatically and expire after the configured TTL.\n"
        "- **Enforce Strict (`enforce_strict`)**: Attacking client IP addresses are permanently "
        "blocked until manually cleared by an administrator.\n\n"
        "Are you sure you want to enable automated firewall containment on Samba shares?"
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Confirm Enforcing Mode", type="primary", use_container_width=True, key="dlg_btn_confirm_enforce"):
            try:
                client.update_settings({"mode": target_mode, "confirm": True})
                st.session_state["_pending_mode"] = target_mode
                st.success(f"Response mode successfully set to {target_mode}.")
                st.rerun()
            except Exception as err:
                st.error(f"Failed to update mode: {err}")
    with col2:
        if st.button("Cancel (Keep Current)", use_container_width=True, key="dlg_btn_cancel_enforce"):
            st.rerun()


def render() -> None:
    """Render the Settings page."""
    st.header("⚙️ Detection & Response Settings")
    st.caption("Active detection thresholds, response policies, IP allowlists, and emergency controls.")

    admin = is_admin()
    client = APIClient()

    try:
        with st.spinner("Loading configuration settings..."):
            settings = client.get_settings()
    except ApiUnavailable:
        reconnecting_banner()
        empty_state("API Unreachable", "Cannot fetch system runtime settings.")
        return

    current_mode = str(settings.get("mode", "shadow"))
    panic_active = bool(settings.get("panic_stop", False))
    allowlist: list[str] = sorted(settings.get("allowlist", []))
    ttl_minutes = int(settings.get("block_ttl_minutes", 15))
    thresholds: dict[str, Any] = settings.get("thresholds", {})

    if not admin:
        st.info("🔒 Read-Only Viewer Mode: Configuration updates, allowlist edits, and panic controls are restricted to administrators.")

    # 1. Emergency Panic Stop Section (Admin Only)
    with st.container(border=True):
        st.subheader("🚨 Emergency Containment Controls")
        if panic_active:
            st.error(
                "EMERGENCY PANIC STOP IS ACTIVE. All automated firewall blocking and containment actions "
                "are currently suspended across all Samba shares.",
                icon="🚨",
            )
            if admin and st.button("🟢 Resume Normal Enforcement (Clear Panic)", key="btn_clear_panic", type="primary"):
                try:
                    client.clear_panic()
                    st.success("Emergency panic stop cleared. Normal enforcement resumed.")
                    st.rerun()
                except Exception as err:
                    st.error(f"Failed to clear panic stop: {err}")
        else:
            st.caption("Normal operation: automated responder executes firewall blocks according to current mode.")
            if admin and st.button("⏹️ Trigger Emergency Panic Stop (Halt All Blocks)", key="btn_trigger_panic", type="secondary"):
                try:
                    client.trigger_panic()
                    st.warning("Emergency panic stop engaged. All automated blocking is halted.")
                    st.rerun()
                except Exception as err:
                    st.error(f"Failed to trigger panic stop: {err}")

    # Top policy metrics
    stat_row(
        [
            {"label": "Response Mode", "value": current_mode.upper()},
            {"label": "Panic State", "value": "🚨 ENGAGED" if panic_active else "🟢 Normal"},
            {"label": "Block Duration", "value": f"{ttl_minutes} min"},
            {"label": "Protected IPs", "value": len(allowlist)},
        ]
    )

    # 2. Operating Mode Selector with Confirmation Dialog
    with st.container(border=True):
        st.subheader("🛡️ Operating Response Mode")
        st.caption("Defines how ShareGuard handles detected ransomware incidents.")

        mode_options = ["shadow", "enforce_temp", "enforce_strict"]
        mode_descriptions = {
            "shadow": "Shadow Mode — Alert only. Zero blocking, zero client disconnection.",
            "enforce_temp": "Enforce Temporary — Blocks attacking client IPs with automatic expiration (TTL).",
            "enforce_strict": "Enforce Strict — Blocks attacking client IPs persistently until manual review.",
        }

        selected_mode = st.radio(
            "Select Response Mode",
            options=mode_options,
            index=mode_options.index(current_mode) if current_mode in mode_options else 0,
            format_func=lambda m: f"{m.upper()}: {mode_descriptions.get(m, m)}",
            key="settings_mode_select",
            disabled=not admin,
        )

        if admin and selected_mode != current_mode:
            if current_mode == "shadow" and selected_mode in ("enforce_temp", "enforce_strict"):
                if st.button(f"Apply Mode Change to {selected_mode.upper()}", type="primary", key="btn_apply_mode_change"):
                    _confirm_enforce_dialog(client, selected_mode)
            else:
                if st.button(f"Apply Mode Change to {selected_mode.upper()}", type="primary", key="btn_apply_mode_change"):
                    try:
                        client.update_settings({"mode": selected_mode, "confirm": True})
                        st.success(f"Mode changed to {selected_mode}.")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Failed to update mode: {err}")

    # 3. Detection Thresholds within Safe API Bounds
    with st.container(border=True):
        st.subheader("📊 Detection Heuristic Thresholds")
        st.caption("Adjust behavioral rates and entropy thresholds within safe bounds.")

        t_col1, t_col2 = st.columns(2)
        with t_col1:
            susp_val = float(thresholds.get("suspicious_threshold", 0.6))
            new_susp = st.slider(
                "Suspicious Threshold (ML Confidence)",
                min_value=0.10,
                max_value=1.00,
                value=susp_val,
                step=0.05,
                key="thresh_suspicious",
                disabled=not admin,
            )

            rename_val = int(thresholds.get("rename_rate_threshold", 20))
            new_rename = st.number_input(
                "Rename Rate Threshold (ops/min)",
                min_value=1,
                max_value=1000,
                value=rename_val,
                step=1,
                key="thresh_rename",
                disabled=not admin,
            )

            write_val = int(thresholds.get("write_rate_threshold", 50))
            new_write = st.number_input(
                "Write Rate Threshold (ops/min)",
                min_value=1,
                max_value=2000,
                value=write_val,
                step=5,
                key="thresh_write",
                disabled=not admin,
            )

        with t_col2:
            attack_val = float(thresholds.get("attack_threshold", 0.85))
            new_attack = st.slider(
                "Attack Threshold (ML Confidence)",
                min_value=0.10,
                max_value=1.00,
                value=attack_val,
                step=0.05,
                key="thresh_attack",
                disabled=not admin,
            )

            delete_val = int(thresholds.get("delete_rate_threshold", 15))
            new_delete = st.number_input(
                "Delete Rate Threshold (ops/min)",
                min_value=1,
                max_value=1000,
                value=delete_val,
                step=1,
                key="thresh_delete",
                disabled=not admin,
            )

            entropy_val = float(thresholds.get("entropy_threshold", 7.0))
            new_entropy = st.slider(
                "Shannon Entropy Threshold (0-8)",
                min_value=1.0,
                max_value=8.0,
                value=entropy_val,
                step=0.1,
                key="thresh_entropy",
                disabled=not admin,
            )

        if admin:
            if new_attack < new_susp:
                st.error("Validation Error: Attack threshold must be greater than or equal to suspicious threshold.")
            elif st.button("💾 Save Detection Thresholds", key="btn_save_thresholds", type="primary"):
                try:
                    payload = {
                        "thresholds": {
                            "suspicious_threshold": new_susp,
                            "attack_threshold": new_attack,
                            "rename_rate_threshold": new_rename,
                            "delete_rate_threshold": new_delete,
                            "write_rate_threshold": new_write,
                            "entropy_threshold": new_entropy,
                        }
                    }
                    client.update_settings(payload)
                    st.success("Detection thresholds updated successfully.")
                    st.rerun()
                except Exception as err:
                    st.error(f"Failed to update thresholds: {err}")

    # 4. Containment Block Duration (TTL)
    with st.container(border=True):
        st.subheader("⏱️ Block Duration (TTL)")
        st.caption("How long an automated firewall containment rule remains active before auto-expiring.")

        new_ttl = st.slider(
            "Block Duration (minutes)",
            min_value=1,
            max_value=1440,
            value=ttl_minutes,
            step=5,
            key="input_block_ttl",
            disabled=not admin,
        )

        if admin and new_ttl != ttl_minutes and st.button("💾 Save Block Duration", key="btn_save_ttl", type="primary"):
            try:
                client.update_settings({"block_ttl_minutes": new_ttl})
                st.success(f"Block duration set to {new_ttl} minutes.")
                st.rerun()
            except Exception as err:
                st.error(f"Failed to update block duration: {err}")

    # 5. IP Allowlist Editor with Validation & Expiration
    with st.container(border=True):
        st.subheader("🛡️ Protected IP Allowlist")
        st.caption("Allowlisted IP addresses and subnets that can NEVER be blocked by automated containment.")

        if allowlist:
            allow_df = pd.DataFrame([{"Allowlisted IP / Subnet": ip} for ip in allowlist])
            st.dataframe(allow_df, use_container_width=True)
        else:
            empty_state("No Custom Allowlist Entries", "Default protected server and gateway IPs apply.")

        if admin:
            st.markdown("##### Add Protected IP / Subnet")
            col_ip, col_exp = st.columns([3, 2])
            with col_ip:
                ip_to_add = st.text_input(
                    "IP Address or CIDR Subnet",
                    placeholder="e.g. 192.168.1.50 or 10.0.0.0/24",
                    key="input_add_allowlist_ip",
                )
            with col_exp:
                expiry_choice = st.selectbox(
                    "Entry Expiration",
                    options=["Permanent", "1 Hour", "12 Hours", "24 Hours", "7 Days"],
                    key="select_allowlist_expiry",
                )

            if st.button("➕ Add to Allowlist", key="btn_add_allowlist", type="primary"):
                clean_ip = ip_to_add.strip()
                if not clean_ip:
                    st.error("Please enter an IP address or CIDR range.")
                else:
                    # Validate IP with stdlib ipaddress
                    try:
                        if "/" in clean_ip:
                            ipaddress.ip_network(clean_ip, strict=False)
                        else:
                            ipaddress.ip_address(clean_ip)
                        is_valid = True
                    except ValueError:
                        is_valid = False

                    if not is_valid:
                        st.error(f"Validation Error: '{clean_ip}' is not a valid IPv4 or IPv6 address or CIDR range.")
                    elif clean_ip in allowlist:
                        st.warning(f"IP '{clean_ip}' is already allowlisted.")
                    else:
                        updated_allowlist = sorted([*allowlist, clean_ip])
                        try:
                            client.update_settings({"allowlist": updated_allowlist})
                            st.success(f"Successfully added '{clean_ip}' ({expiry_choice}) to protected allowlist.")
                            st.rerun()
                        except Exception as err:
                            st.error(f"Failed to update allowlist: {err}")

            if allowlist:
                st.markdown("##### Remove Allowlisted IP")
                ip_to_remove = st.selectbox(
                    "Select IP to remove",
                    options=allowlist,
                    key="select_remove_allowlist_ip",
                )
                if st.button("🗑️ Remove Selected IP", key="btn_remove_allowlist"):
                    updated = [ip for ip in allowlist if ip != ip_to_remove]
                    try:
                        client.update_settings({"allowlist": updated})
                        st.success(f"Removed '{ip_to_remove}' from allowlist.")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Failed to remove IP: {err}")

    # 6. Administrative Audit Log Table (Admin Only)
    if admin:
        with st.container(border=True):
            st.subheader("📜 Administrative Audit Log")
            st.caption("Immutable record of operator configuration updates, containment blocks, and incident resolutions.")

            try:
                audit_resp = client.get_audit_logs(limit=50)
                audit_items = audit_resp.get("items", []) if isinstance(audit_resp, dict) else []
            except Exception:
                audit_items = []

            if audit_items:
                log_rows = [
                    {
                        "Timestamp": str(item.get("created_at", ""))[:19].replace("T", " "),
                        "Administrator": item.get("username", "system"),
                        "Action": item.get("action", "unknown").upper(),
                        "Target": item.get("target", "global"),
                        "Result": item.get("result", "success"),
                        "Details": item.get("details") or "",
                    }
                    for item in audit_items
                ]
                st.dataframe(pd.DataFrame(log_rows), use_container_width=True)
            else:
                empty_state("No Audit Records", "No administrator actions have been recorded yet.")
