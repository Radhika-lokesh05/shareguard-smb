"""
lab/tests/conftest.py – pytest configuration for the lab/tests suite.

Adds both ``server/`` and the workspace root to sys.path so that
``import shareguard`` and ``import lab`` both resolve correctly.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Workspace root: lab/tests/ -> lab/ -> shareguard/
_WORKSPACE = Path(__file__).parent.parent.parent
_SERVER = _WORKSPACE / "server"

for _p in [str(_WORKSPACE), str(_SERVER)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest


@pytest.fixture(autouse=True)
def configure_lab_test_env(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow pytest's temporary directory hierarchy for lab tests."""
    base_temp = tmp_path_factory.getbasetemp()
    monkeypatch.setenv("SHAREGUARD_LAB_ALLOWED_PREFIX", str(base_temp.resolve()))
