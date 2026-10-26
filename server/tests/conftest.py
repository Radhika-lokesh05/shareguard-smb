"""
conftest.py – pytest configuration for the server/tests suite.

Adds ``server/`` and the workspace root to sys.path so that
``import shareguard`` and ``import lab`` both work without an editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path

_WORKSPACE = Path(__file__).parent.parent.parent
_SERVER = _WORKSPACE / "server"

for _p in [str(_WORKSPACE), str(_SERVER)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
