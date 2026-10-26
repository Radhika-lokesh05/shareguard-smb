"""dashboard/ui.py – Shared UI components and strict XSS defense for Streamlit.

Design Invariants:
- All untrusted input (e.g. file names from alerts, user inputs) is rendered
  EXCLUSIVELY through ``st.text``, ``st.code``, or ``st.dataframe``.
- ``st.markdown`` is reserved strictly for trusted, hardcoded static labels.
- State badges use icon + text (never colour alone) for accessibility.
- Responsive layout: max 4 columns per row, stacking safely on mobile.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import streamlit as st

__all__ = [
    "status_banner",
    "state_badge",
    "severity_badge",
    "stat_row",
    "safe_text",
    "empty_state",
    "error_state",
    "confirm_dialog",
    "reconnecting_banner",
]


def status_banner(
    state: str,
    details: str = "",
    blocked_count: int = 0,
    is_shadow: bool = False,
) -> None:
    """Render a prominent system operational status banner.

    Args:
        state: Operational state ('NORMAL', 'SUSPICIOUS', 'ATTACK', 'PANIC').
        details: Optional supplementary detail text.
        blocked_count: Number of currently blocked clients.
        is_shadow: True if the engine is running in shadow mode.
    """
    clean_state = state.upper()
    if clean_state == "PANIC":
        st.error(
            f"⏹️ Panic Stop Active – All automated firewall blocking is halted. {details}".strip(),
            icon="🚨",
        )
    elif clean_state == "ATTACK":
        msg = f"🔴 Attack in progress, {blocked_count} blocked" if blocked_count > 0 else "🔴 Attack in progress"
        if details:
            msg = f"{msg}. {details}"
        st.error(msg, icon="🚨")
    elif clean_state == "SUSPICIOUS":
        msg = f"🟡 Suspicious activity. {details}".strip() if details else "🟡 Suspicious activity"
        st.warning(msg, icon="⚠️")
    else:
        msg = f"🟢 All clear. {details}".strip() if details else "🟢 All clear – Samba file shares protected"
        st.success(msg, icon="✅")

    if is_shadow:
        st.info("🛡️ SHADOW MODE: alerts only, nothing is blocked", icon="ℹ️")


def reconnecting_banner() -> None:
    """Render a calm, non-intrusive reconnection banner when the API is unreachable."""
    st.info("🔄 Connecting to ShareGuard API backend... Retrying automatically.", icon="📡")


def state_badge(state: str) -> str:
    """Return an accessible icon + text string representation of a state.

    Never uses color alone to communicate state.
    """
    s = str(state).lower()
    mapping = {
        "normal": "🟢 Normal",
        "suspicious": "🟡 Suspicious",
        "attack": "🔴 Attack",
        "panic": "⏹️ Panic Stop",
        "blocked": "🚫 Blocked",
        "active": "🚨 Active",
        "resolved": "✅ Resolved",
        "false_positive": "⚪ False Positive",
        "open": "🚨 Open",
    }
    return mapping.get(s, f"ℹ️ {state.capitalize()}")


def severity_badge(severity: str) -> str:
    """Return an accessible icon + text string representation of alert severity."""
    s = str(severity).lower()
    mapping = {
        "critical": "🔴 Critical",
        "high": "🟠 High",
        "medium": "🟡 Medium",
        "low": "🟢 Low",
    }
    return mapping.get(s, f"⚪ {severity.capitalize()}")


def stat_row(metrics: list[dict[str, Any]]) -> None:
    """Render a responsive row of metrics using ``st.metric``.

    Enforces responsiveness: no more than 4 columns per row.
    """
    if not metrics:
        return

    # Chunk into rows of at most 4 items
    chunk_size = 4
    for i in range(0, len(metrics), chunk_size):
        chunk = metrics[i : i + chunk_size]
        cols = st.columns(len(chunk))
        for col, m in zip(cols, chunk, strict=False):
            with col:
                st.metric(
                    label=m.get("label", ""),
                    value=m.get("value", 0),
                    delta=m.get("delta"),
                    help=m.get("help"),
                )


def safe_text(value: Any, max_len: int = 512, code: bool = False) -> None:
    """Safely render an untrusted string via ``st.text`` or ``st.code``.

    SAFETY INVARIANT:
    Never renders untrusted strings with ``st.markdown`` or ``unsafe_allow_html=True``
    to prevent XSS and payload rendering (e.g. `<img onerror>`, `![x]()`, `[click]()`).
    """
    text = "" if value is None else str(value)

    truncated = text[:max_len]
    if code:
        st.code(truncated, language="text")
    else:
        st.text(truncated)


def empty_state(title: str, message: str = "") -> None:
    """Render a friendly, clean empty-state card."""
    with st.container(border=True):
        st.markdown(f"#### 📭 {title}")
        if message:
            st.caption(message)


def error_state(title: str, message: str = "") -> None:
    """Render a friendly error message without internal stack traces."""
    with st.container(border=True):
        st.markdown(f"#### ⚠️ {title}")
        if message:
            st.caption(message)


def confirm_dialog(
    title: str,
    message: str,
    on_confirm: Callable[[], None],
    confirm_label: str = "Confirm Action",
    is_destructive: bool = False,
) -> None:
    """Render a confirmation modal dialog using ``st.dialog``."""
    @st.dialog(title)
    def _dialog() -> None:
        st.write(message)
        col1, col2 = st.columns(2)
        with col1:
            btn_type = "primary" if not is_destructive else "secondary"
            if st.button(confirm_label, type=btn_type, use_container_width=True, key=f"dlg_conf_{title}"):
                on_confirm()
                st.rerun()
        with col2:
            if st.button("Cancel", use_container_width=True, key=f"dlg_canc_{title}"):
                st.rerun()

    _dialog()
