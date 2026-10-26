"""
shareguard – Ransomware guard for Samba (SMB) file servers.

Package layout:
    parser      – vfs_full_audit log parser
    features    – per-client feature aggregation
    entropy     – Shannon entropy helpers
    rules       – rule-based detector
    ml          – ML model wrapper (XGBoost + SHAP)
    engine      – detection orchestrator
    snapshots   – snapshot interface (fake + btrfs backends)
    responder   – block interface (fake + iptables backends)
    health      – health-check helpers
    assistant   – plain-language explanation
    api         – FastAPI application
    db          – SQLAlchemy models + session factory
    auth        – API-key auth dependency
    canary      – canary decoy management
    tools       – CLI utilities and replay tools
"""

__version__ = "0.1.0"

__all__ = [
    "parser",
    "features",
    "entropy",
    "rules",
    "ml",
    "engine",
    "snapshots",
    "responder",
    "health",
    "assistant",
    "api",
    "db",
    "auth",
    "canary",
    "tools",
    "run",
]
