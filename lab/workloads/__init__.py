"""
lab/workloads/__init__.py – Registry of normal-activity workload modules.

Each workload is a Python module that exposes a ``run(target, duration)``
callable and can also be invoked as a script::

    python -m lab.workloads.<name> --target /mnt/share --duration 120

Importing from production code is forbidden.
"""

from __future__ import annotations

# Map workload name → module path (relative to lab/).
WORKLOAD_NAMES: tuple[str, ...] = (
    "office_edit",
    "bulk_copy",
    "zip_unzip",
    "backup_rsync",
    "many_small_files",
    "photo_import",
    "mixed",
)

__all__ = ["WORKLOAD_NAMES"]
