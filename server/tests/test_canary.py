"""
server/tests/test_canary.py – Unit tests for canary file management.

Verifies:
- Deploying canaries to temporary folders.
- Safe dummy content only.
- JSON registry generation and structure.
- Verification detecting intact, modified, and deleted canaries.
- Path recognition (is_canary).
- IP allowlist checks with ipaddress validation.
"""

from __future__ import annotations

import json
from pathlib import Path

from shareguard.canary import (
    CanaryManager,
    deploy_canaries,
    is_client_allowlisted,
)


def test_deploy_canaries_to_temp_directory(tmp_path: Path) -> None:
    """Canaries are deployed with harmless text and recorded in the JSON registry."""
    share_root = tmp_path / "share"
    registry_file = tmp_path / "canaries.json"

    entries = deploy_canaries(share_root, registry_file)
    assert len(entries) >= 3

    # Check files exist on disk
    for entry in entries:
        file_path = share_root / entry.relative_path
        assert file_path.exists()
        content = file_path.read_text(encoding="utf-8")
        assert "CANARY" in content or "DECOY" in content
        # Ensure harmless content
        assert "rm " not in content
        assert "format" not in content

    # Check registry JSON
    assert registry_file.exists()
    data = json.loads(registry_file.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert len(data["canaries"]) == len(entries)


def test_verify_detects_intact_canaries(tmp_path: Path) -> None:
    """Verifying an untouched share reports all_intact True."""
    share_root = tmp_path / "share"
    registry_file = tmp_path / "canaries.json"

    mgr = CanaryManager(share_root, registry_file)
    mgr.deploy()

    status = mgr.verify()
    assert status["all_intact"] is True
    assert len(status["missing"]) == 0
    assert len(status["modified"]) == 0
    assert len(status["intact"]) > 0


def test_verify_detects_deleted_and_modified_canaries(tmp_path: Path) -> None:
    """Deleting or altering a canary file is detected during verification."""
    share_root = tmp_path / "share"
    registry_file = tmp_path / "canaries.json"

    mgr = CanaryManager(share_root, registry_file)
    entries = mgr.deploy()

    # Delete first canary
    first_path = share_root / entries[0].relative_path
    first_path.unlink()

    # Modify second canary
    second_path = share_root / entries[1].relative_path
    second_path.write_text("TAMPERED_ENCRYPTED_DATA", encoding="utf-8")

    status = mgr.verify()
    assert status["all_intact"] is False
    assert entries[0].relative_path in status["missing"]
    assert entries[1].relative_path in status["modified"]


def test_is_canary_recognition(tmp_path: Path) -> None:
    """Recognises canary paths from filenames and registry."""
    share_root = tmp_path / "share"
    registry_file = tmp_path / "canaries.json"

    mgr = CanaryManager(share_root, registry_file)
    entries = mgr.deploy()

    for entry in entries:
        assert mgr.is_canary(entry.relative_path)
        assert mgr.is_canary(f"share/{entry.relative_path}")

    # Decoy patterns
    assert mgr.is_canary("documents/canary_SENTINEL.docx")
    assert mgr.is_canary("canary_test.txt")

    # Regular files must not match
    assert not mgr.is_canary("documents/report.docx")
    assert not mgr.is_canary("shared/regular_presentation.pptx")


def test_canary_allowlist_ip_validation() -> None:
    """Allowlist correctly validates allowed backup software vs attackers."""
    allowlist = ["192.168.1.250", "10.0.1.0/24"]

    # Authorized backup IPs
    assert is_client_allowlisted("192.168.1.250", allowlist)
    assert is_client_allowlisted("10.0.1.42", allowlist)

    # Unauthorized client / attacker IPs
    assert not is_client_allowlisted("192.168.1.10", allowlist)
    assert not is_client_allowlisted("10.0.0.55", allowlist)
    assert not is_client_allowlisted("172.16.0.1", allowlist)

    # Malformed IPs safely return False
    assert not is_client_allowlisted("not-an-ip", allowlist)
    assert not is_client_allowlisted("999.999.999.999", allowlist)
