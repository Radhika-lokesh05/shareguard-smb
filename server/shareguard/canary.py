"""
shareguard.canary – Canary (decoy) file management for Samba shares.

Deploys and monitors decoy files with believable names in strategic directories.
If a non-allowlisted client touches (reads, modifies, renames, or unlinks) a
canary file, it is a high-confidence indicator of unauthorized scanning or
ransomware activity.

Safety:
- Canary files contain only benign, non-executable dummy text.
- Paths are strictly validated against share roots using :mod:`pathlib`.
- Client IPs are validated using :mod:`ipaddress`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "CanaryEntry",
    "CanaryManager",
    "deploy_canaries",
    "verify_canaries",
    "is_canary_path",
    "is_client_allowlisted",
]

# Believable decoy filenames by subdirectory context
DEFAULT_CANARY_TEMPLATES: list[tuple[str, str, str]] = [
    (
        "documents/finance",
        "budget_2025_preliminary.xlsx",
        "CONFIDENTIAL FINANCIAL PLANNING DRAFT - SHAREGUARD LAB CANARY DECOY",
    ),
    (
        "documents/hr",
        "executive_payroll_summary.pdf",
        "CONFIDENTIAL HR RECORD - SHAREGUARD LAB CANARY DECOY",
    ),
    (
        "documents",
        "passwords_vault_export.txt",
        "INTERNAL IT SYSTEM ACCESS KEYS - SHAREGUARD LAB CANARY DECOY",
    ),
    (
        "shared",
        "client_contracts_archive.docx",
        "LEGAL CONTRACT ARCHIVE - SHAREGUARD LAB CANARY DECOY",
    ),
    (
        "projects",
        "database_credentials.json",
        '{"warning": "DECOY", "comment": "SHAREGUARD LAB CANARY DECOY"}',
    ),
]


@dataclass(frozen=True, slots=True)
class CanaryEntry:
    """Metadata recorded for each deployed canary file.

    Attributes:
        relative_path: Path relative to the share root (using forward slashes).
        created_at: ISO-8601 UTC timestamp when deployed.
        sha256: Hexadecimal SHA-256 digest of the canary content.
        size_bytes: Size of the decoy content in bytes.
    """

    relative_path: str
    created_at: str
    sha256: str
    size_bytes: int


def _compute_hash(content: bytes) -> str:
    """Calculate SHA-256 hex digest of bytes."""
    return hashlib.sha256(content).hexdigest()


class CanaryManager:
    """Manages canary file deployment, verification, and access inspection.

    Args:
        share_root: Root directory of the Samba share.
        registry_path: Path to the JSON file where canary entries are tracked.
        allowlist: List of IP addresses or subnets permitted to touch canaries.
    """

    def __init__(
        self,
        share_root: Path,
        registry_path: Path,
        allowlist: list[str] | None = None,
    ) -> None:
        self.share_root = Path(share_root).resolve()
        self.registry_path = Path(registry_path).resolve()
        self.allowlist: list[str] = allowlist or []

    def deploy(
        self,
        templates: list[tuple[str, str, str]] | None = None,
    ) -> list[CanaryEntry]:
        """Deploy decoy files into the share root and write the registry JSON.

        Args:
            templates: List of (relative_directory, filename, content) tuples.
                If None, uses DEFAULT_CANARY_TEMPLATES.

        Returns:
            List of deployed CanaryEntry objects.
        """
        self.share_root.mkdir(parents=True, exist_ok=True)
        deployed: list[CanaryEntry] = []
        templates_to_use = templates or DEFAULT_CANARY_TEMPLATES

        now_iso = datetime.now(tz=UTC).isoformat()

        for rel_dir, filename, content_str in templates_to_use:
            target_dir = (self.share_root / rel_dir).resolve()
            # Safety check: target directory must be inside share_root
            if not target_dir.is_relative_to(self.share_root):
                raise ValueError(f"Directory {rel_dir!r} escapes share root {self.share_root}")

            target_file = (target_dir / filename).resolve()
            # Safety check: target file must remain strictly inside share_root
            if not target_file.is_relative_to(self.share_root):
                raise ValueError(f"Canary file {filename!r} escapes share root {self.share_root}")

            target_dir.mkdir(parents=True, exist_ok=True)
            content_bytes = content_str.encode("utf-8")
            target_file.write_bytes(content_bytes)

            rel_path = target_file.relative_to(self.share_root).as_posix()
            deployed.append(
                CanaryEntry(
                    relative_path=rel_path,
                    created_at=now_iso,
                    sha256=_compute_hash(content_bytes),
                    size_bytes=len(content_bytes),
                )
            )

        # Write registry file
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "updated_at": now_iso,
            "share_root": self.share_root.as_posix(),
            "canaries": [asdict(entry) for entry in deployed],
        }
        self.registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return deployed

    def load_registry(self) -> list[CanaryEntry]:
        """Load registered canaries from the registry JSON file."""
        if not self.registry_path.exists():
            return []
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
            canaries_raw = data.get("canaries", [])
            return [CanaryEntry(**entry) for entry in canaries_raw]
        except (json.JSONDecodeError, TypeError, KeyError):
            return []

    def verify(self) -> dict[str, Any]:
        """Verify the integrity and presence of all registered canaries.

        Returns:
            Dict containing:
            - "intact": list of relative paths that are intact.
            - "modified": list of relative paths with content mismatch.
            - "missing": list of relative paths that no longer exist.
            - "all_intact": bool indicating if all are present and unmodified.
        """
        entries = self.load_registry()
        intact: list[str] = []
        modified: list[str] = []
        missing: list[str] = []

        for entry in entries:
            file_path = (self.share_root / entry.relative_path).resolve()
            if not file_path.is_relative_to(self.share_root):
                modified.append(entry.relative_path)
                continue

            if not file_path.exists():
                missing.append(entry.relative_path)
            else:
                data = file_path.read_bytes()
                if _compute_hash(data) == entry.sha256:
                    intact.append(entry.relative_path)
                else:
                    modified.append(entry.relative_path)

        return {
            "intact": intact,
            "modified": modified,
            "missing": missing,
            "all_intact": (len(missing) == 0 and len(modified) == 0),
        }

    def is_canary(self, path: str | Path) -> bool:
        """Check if *path* matches any registered or default canary.

        Args:
            path: Relative path or filename as logged by Samba.

        Returns:
            True if path matches a known canary file.
        """
        norm_path = Path(path).as_posix().lstrip("/")
        entries = self.load_registry()
        if entries:
            for entry in entries:
                if norm_path == entry.relative_path or norm_path.endswith("/" + entry.relative_path):
                    return True
                # Match by filename as well
                if Path(norm_path).name == Path(entry.relative_path).name:
                    return True

        # Fallback check against default templates and canary markers
        filename = Path(norm_path).name.lower()
        if "canary" in filename:
            return True
        return any(filename == default_fn.lower() for _, default_fn, _ in DEFAULT_CANARY_TEMPLATES)

    def is_client_allowlisted(self, ip_str: str) -> bool:
        """Check if a client IP is allowed to access canary files.

        Validates *ip_str* and allowlist entries using :mod:`ipaddress`.

        Args:
            ip_str: Client IP address string.

        Returns:
            True if the IP is validated and matches an allowlisted address or network.
        """
        try:
            client_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        for allowed in self.allowlist:
            try:
                if "/" in allowed:
                    net = ipaddress.ip_network(allowed.strip(), strict=False)
                    if client_ip in net:
                        return True
                else:
                    allowed_ip = ipaddress.ip_address(allowed.strip())
                    if client_ip == allowed_ip:
                        return True
            except ValueError:
                continue

        return False


# ---------------------------------------------------------------------------
# Convenience standalone functions
# ---------------------------------------------------------------------------


def deploy_canaries(
    share_root: Path,
    registry_path: Path,
    templates: list[tuple[str, str, str]] | None = None,
) -> list[CanaryEntry]:
    """Deploy canaries into share_root and save registry."""
    mgr = CanaryManager(share_root, registry_path)
    return mgr.deploy(templates)


def verify_canaries(
    share_root: Path,
    registry_path: Path,
) -> dict[str, Any]:
    """Verify registered canaries against disk."""
    mgr = CanaryManager(share_root, registry_path)
    return mgr.verify()


_DEFAULT_CANARY_FILENAMES: frozenset[str] = frozenset(
    fn.lower() for _, fn, _ in DEFAULT_CANARY_TEMPLATES
)


def is_canary_path(
    path: str | Path,
    registry_path: Path | None = None,
    share_root: Path | None = None,
) -> bool:
    """Check if *path* is a canary file."""
    if registry_path and share_root:
        mgr = CanaryManager(share_root, registry_path)
        return mgr.is_canary(path)

    p_str = path.as_posix().lower() if isinstance(path, Path) else str(path).replace("\\", "/").lower()
    if "canary" in p_str:
        return True
    filename = p_str.rsplit("/", 1)[-1]
    return filename in _DEFAULT_CANARY_FILENAMES


def is_client_allowlisted(ip_str: str, allowlist: list[str]) -> bool:
    """Check if client IP is present in allowlist."""
    mgr = CanaryManager(Path("."), Path("."), allowlist=allowlist)
    return mgr.is_client_allowlisted(ip_str)
