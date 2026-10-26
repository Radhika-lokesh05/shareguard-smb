"""
lab/safety.py – Safety preconditions and Windows SMB helpers for lab tools.

⚠️  LAB ONLY – never import from production code.

Enforces strict safety barriers:
1. Target must be a subfolder (never a filesystem root like Z:\\, C:\\, or /).
2. Target must never be a user home directory, Desktop, Documents, or Windows system directory.
3. Target must not contain '..' path traversal sequences.
4. Target must be explicitly allowed by ``allowed_target_prefix`` in ``lab/config.yaml``
   (default is empty, refusing all operations until the user opts in).
5. Target must contain ``.shareguard_lab_marker`` (or ``SHAREGUARD_LAB_MARKER``).
6. Target must contain ``manifest.json`` (when required by the tool).
7. Must be confirmed with ``confirmed=True`` or CLI ``--i-understand-this-is-a-lab``.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

__all__ = [
    "LabSafetyError",
    "MARKER_FILENAME",
    "MARKER_LEGACY",
    "MANIFEST_FILENAME",
    "KEY_FILENAME",
    "load_lab_config",
    "check_safety",
    "retry_on_windows_busy",
]

MARKER_FILENAME = ".shareguard_lab_marker"
MARKER_LEGACY = "SHAREGUARD_LAB_MARKER"
MANIFEST_FILENAME = "manifest.json"
KEY_FILENAME = "manifest.key"

_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

T = TypeVar("T")


class LabSafetyError(RuntimeError):
    """Raised when a lab safety precondition fails."""


def load_lab_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load lab configuration from YAML file or environment overrides."""
    cfg_file = config_path or _CONFIG_PATH
    data: dict[str, Any] = {
        "allowed_target_prefix": "",
        "pause_between_runs_seconds": 5.0,
        "client_machine_name": "client-pc",
    }
    if cfg_file.exists():
        try:
            import yaml  # type: ignore[import-untyped]

            loaded = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass

    # Environment override takes precedence
    env_prefix = os.environ.get("SHAREGUARD_LAB_ALLOWED_PREFIX")
    if env_prefix is not None:
        data["allowed_target_prefix"] = env_prefix

    return data


def _paths_overlap_or_relative(a: Path, b: Path) -> bool:
    """Return True if a == b, a is subpath of b, or b is subpath of a."""
    try:
        ra = a.resolve()
        rb = b.resolve()
        if ra == rb:
            return True
        if ra.is_relative_to(rb) or rb.is_relative_to(ra):
            return True
    except (ValueError, AttributeError):
        pass
    # Case-insensitive parts comparison for Windows
    try:
        pa = [p.lower() for p in a.resolve().parts]
        pb = [p.lower() for p in b.resolve().parts]
        if pa == pb:
            return True
        if len(pa) >= len(pb) and pa[: len(pb)] == pb:
            return True
        if len(pb) >= len(pa) and pb[: len(pa)] == pa:
            return True
    except Exception:
        pass
    return False


def _is_root(target: Path) -> bool:
    """Return True if target is a filesystem root (e.g. Z:\\, C:\\, /, or \\\\server\\share)."""
    try:
        resolved = target.resolve()
        if resolved == resolved.parent:
            return True
        if len(resolved.parts) <= 1:
            return True
        # On Windows, "Z:\" or "C:\" has parts ('Z:\\',) or ('C:\\',)
        if len(resolved.parts) == 1 and resolved.drive:
            return True
        # UNC root: e.g. \\192.168.56.101\Finance\
        if resolved.drive and resolved.drive.startswith(("\\\\", "//")):
            drive_clean = resolved.drive.rstrip("\\/")
            if resolved == Path(drive_clean).resolve() or len(resolved.parts) <= 1:
                return True
    except (RuntimeError, ValueError):
        return True
    return False


def _is_sensitive_dir(target: Path) -> bool:
    """Return True if target is (or is inside, or contains) user home, system, or personal folders."""
    try:
        resolved = target.resolve()

        # Check user home directory
        home = Path.home().resolve()
        if _paths_overlap_or_relative(resolved, home):
            return True

        # Check well-known user personal folders
        for folder_name in ("Desktop", "Documents", "Downloads", "Pictures", "Videos"):
            candidate = (home / folder_name).resolve()
            if candidate.exists() and _paths_overlap_or_relative(resolved, candidate):
                return True

        # Check Windows system roots and Users root
        if sys.platform == "win32":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_root = Path(f"{system_drive}\\Users").resolve()
            if users_root.exists() and _paths_overlap_or_relative(resolved, users_root):
                return True

            for sys_dir in (
                f"{system_drive}\\Windows",
                f"{system_drive}\\Program Files",
                f"{system_drive}\\Program Files (x86)",
            ):
                sys_path = Path(sys_dir).resolve()
                if sys_path.exists() and _paths_overlap_or_relative(resolved, sys_path):
                    return True
    except (RuntimeError, ValueError):
        pass
    return False


def _is_inside_prefix(target: Path, prefix: Path) -> bool:
    """Return True if target is equal to or a subfolder of prefix."""
    try:
        if target.resolve().is_relative_to(prefix.resolve()):
            return True
    except (ValueError, AttributeError):
        pass
    try:
        t_parts = [p.lower() for p in target.resolve().parts]
        p_parts = [p.lower() for p in prefix.resolve().parts]
        return len(t_parts) >= len(p_parts) and t_parts[: len(p_parts)] == p_parts
    except Exception:
        return False


def check_safety(
    target: Path | str,
    confirmed: bool = False,
    require_marker: bool = True,
    require_manifest: bool = True,
    config_path: Path | None = None,
) -> None:
    """Validate all safety gates before any lab file modification occurs.

    Args:
        target: Target directory path.
        confirmed: Must be True (replaces CLI --i-understand-this-is-a-lab).
        require_marker: Whether .shareguard_lab_marker must exist in target.
        require_manifest: Whether manifest.json must exist in target.
        config_path: Optional path to custom lab configuration.

    Raises:
        LabSafetyError: When any safety check fails.
    """
    if not confirmed:
        raise LabSafetyError(
            "Safety gate refused: pass confirmed=True (API) or "
            "--i-understand-this-is-a-lab (CLI) to confirm this is an isolated lab."
        )

    p_str = str(target)
    raw_parts = p_str.replace("\\", "/").split("/")
    if ".." in raw_parts or any(part == ".." for part in Path(target).parts):
        raise LabSafetyError(f"REFUSED: target '{target}' contains '..' path traversal sequences.")

    p = Path(target)
    if require_marker:
        if not p.exists():
            raise LabSafetyError(f"REFUSED: target '{target}' does not exist.")
        if not p.is_dir():
            raise LabSafetyError(f"REFUSED: target '{target}' is not a directory.")
    elif p.exists() and not p.is_dir():
        raise LabSafetyError(f"REFUSED: target '{target}' exists and is not a directory.")

    resolved = p.resolve()

    if _is_root(resolved):
        raise LabSafetyError(
            f"REFUSED: target '{resolved}' is a filesystem or drive root. "
            "Operations must target an isolated subfolder (e.g. Z:\\sgtest)."
        )

    if _is_sensitive_dir(resolved):
        raise LabSafetyError(
            f"REFUSED: target '{resolved}' is (or contains) a user home directory, Users, Documents, Desktop, or system folder."
        )

    # Validate against allowed_target_prefix
    cfg = load_lab_config(config_path)
    allowed_prefix = str(cfg.get("allowed_target_prefix", "")).strip()
    if not allowed_prefix:
        raise LabSafetyError(
            "REFUSED: 'allowed_target_prefix' is empty in lab config. "
            "You must explicitly configure an allowed target prefix in lab/config.yaml "
            "(e.g. allowed_target_prefix: 'Z:\\\\sgtest') or via SHAREGUARD_LAB_ALLOWED_PREFIX."
        )

    resolved_prefix = Path(allowed_prefix).resolve()
    if not _is_inside_prefix(resolved, resolved_prefix):
        raise LabSafetyError(
            f"REFUSED: target '{resolved}' is not inside allowed prefix '{resolved_prefix}'."
        )

    # Check marker file
    if require_marker:
        has_marker = (resolved / MARKER_FILENAME).exists() or (resolved / MARKER_LEGACY).exists()
        if not has_marker:
            raise LabSafetyError(
                f"REFUSED: neither '{MARKER_FILENAME}' nor '{MARKER_LEGACY}' found in '{resolved}'. "
                "Seed the directory first with make_fake_files.py."
            )

    # Check manifest.json if required
    if require_manifest:
        manifest_path = resolved / MANIFEST_FILENAME
        if not manifest_path.exists():
            raise LabSafetyError(
                f"REFUSED: '{MANIFEST_FILENAME}' not found in '{resolved}'. "
                "Run make_fake_files.py first."
            )


def retry_on_windows_busy(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = 5,
    base_delay: float = 0.05,
    **kwargs: Any,
) -> T:
    """Execute func with short exponential retries on Windows SMB busy/locking errors.

    Catches PermissionError (WinError 32: sharing violation) and OSError.
    """
    last_err: Exception | None = None
    delay = base_delay
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except (PermissionError, OSError) as e:
            last_err = e
            if attempt == max_retries - 1:
                break
            time.sleep(delay)
            delay *= 2.0
    if last_err is not None:
        raise last_err
    raise RuntimeError("Retry loop exhausted without result")
