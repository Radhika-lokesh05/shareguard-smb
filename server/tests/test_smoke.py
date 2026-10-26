"""
server/tests/test_smoke.py – Trivial smoke tests that verify the package
structure is importable.  These are the CI gate: if these pass, the scaffold
is valid.
"""

from __future__ import annotations


def test_package_imports() -> None:
    """All shareguard sub-modules must be importable without error."""
    import shareguard  # noqa: F401
    import shareguard.api  # noqa: F401
    import shareguard.assistant  # noqa: F401
    import shareguard.auth  # noqa: F401
    import shareguard.canary  # noqa: F401
    import shareguard.db  # noqa: F401
    import shareguard.engine  # noqa: F401
    import shareguard.entropy  # noqa: F401
    import shareguard.features  # noqa: F401
    import shareguard.health  # noqa: F401
    import shareguard.ml  # noqa: F401
    import shareguard.parser  # noqa: F401
    import shareguard.responder  # noqa: F401
    import shareguard.rules  # noqa: F401
    import shareguard.run  # noqa: F401
    import shareguard.snapshots  # noqa: F401
    import shareguard.tools  # noqa: F401


def test_version_string() -> None:
    """Package should expose a __version__ string."""
    import shareguard

    assert isinstance(shareguard.__version__, str)
    assert len(shareguard.__version__) > 0


def test_alert_severity_values() -> None:
    """AlertSeverity enum must include expected values."""
    from shareguard.rules import AlertSeverity

    assert AlertSeverity.LOW == "low"
    assert AlertSeverity.CRITICAL == "critical"


def test_feature_columns_not_empty() -> None:
    """ML FEATURE_COLUMNS must be a non-empty list of strings."""
    from shareguard.ml import FEATURE_COLUMNS

    assert isinstance(FEATURE_COLUMNS, list)
    assert len(FEATURE_COLUMNS) > 0
    assert all(isinstance(col, str) for col in FEATURE_COLUMNS)


def test_api_app_instantiated() -> None:
    """The FastAPI app object must be importable and have routes registered."""
    from shareguard.api import app

    routes = [r.path for r in app.routes]  # type: ignore[attr-defined]
    assert "/health" in routes
