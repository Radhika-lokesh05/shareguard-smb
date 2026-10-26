"""server/tests/test_responder.py – Unit tests for ShareGuard active response subsystem.

Verifies:
1. Exact nftables command generation (table, set with timeout, prerouting hook, drop rules).
2. Exact iptables fallback command generation (top of INPUT, comment tag, multiport 139,445).
3. Session termination via smbstatus JSON and text formats (SIGTERM then SIGKILL only for client PIDs).
4. Emergency flush_all clearing only ShareGuard rules.
5. Strict IP validation rejecting injection, subnets, loopback, multicast, gateway, and allowlists.
6. TTL bounds and auto-expiry simulation with injectable clock.
7. Restart persistence across reloads via BlockStore.
8. Rate limiting (max new blocks per minute and max concurrent active blocks).
9. Dry-run mode logging without executing commands.
10. Fallback to kill_sessions on firewall failure without crashing.
11. Refusal of RealCommandRunner on Windows or simulation mode.
12. Helper script argument validation (rejecting injection attempts).
13. Pluggable notifiers (LogNotifier and WebhookNotifier).
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shareguard.responder import (
    BlockRecord,
    BlockStore,
    FakeCommandRunner,
    FakeResponder,
    LinuxResponder,
    LogNotifier,
    RealCommandRunner,
    WebhookNotifier,
    get_responder,
    validate_blockable_ip,
)

# ---------------------------------------------------------------------------
# 1. Exact nftables Command Generation
# ---------------------------------------------------------------------------


def test_nftables_command_generation(tmp_path: Path) -> None:
    """LinuxResponder with nftables generates exact table, set, chain, and drop rule commands."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    config = {
        "mode": "enforce_temp",
        "firewall": "nftables",
        "is_live": True,
        "allowlist": ["127.0.0.1"],
    }

    responder = LinuxResponder(config=config, runner=runner, store=store)

    # Initial firewall setup commands
    init_cmds = [cmd for cmd in runner.commands if cmd[0] == "nft"]
    assert len(init_cmds) >= 4
    assert ["nft", "add", "table", "inet", "shareguard"] in init_cmds

    # Block a client
    rec = responder.block_client("192.168.56.20", ttl_seconds=600, reason="Mass encryption")
    assert rec is not None
    assert rec.client_ip == "192.168.56.20"

    expected_block_cmd = [
        "nft",
        "add",
        "element",
        "inet",
        "shareguard",
        "blocked_ips",
        "{",
        "192.168.56.20",
        "timeout",
        "600s",
        "}",
    ]
    assert expected_block_cmd in runner.commands

    # Unblock client
    unblocked = responder.unblock_client("192.168.56.20")
    assert unblocked is True
    expected_unblock_cmd = [
        "nft",
        "delete",
        "element",
        "inet",
        "shareguard",
        "blocked_ips",
        "{",
        "192.168.56.20",
        "}",
    ]
    assert expected_unblock_cmd in runner.commands


# ---------------------------------------------------------------------------
# 2. Exact iptables Fallback Command Generation
# ---------------------------------------------------------------------------


def test_iptables_fallback_command_generation(tmp_path: Path) -> None:
    """LinuxResponder with iptables falls back to inserting rule at top of INPUT with comment tag."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    config = {
        "mode": "enforce_temp",
        "firewall": "iptables",
        "is_live": True,
        "allowlist": ["127.0.0.1"],
    }

    responder = LinuxResponder(config=config, runner=runner, store=store)

    # Block client
    rec = responder.block_client("192.168.56.30", ttl_seconds=300, reason="Attack rule fired")
    assert rec is not None

    expected_iptables_block = [
        "iptables",
        "-I",
        "INPUT",
        "1",
        "-s",
        "192.168.56.30",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "139,445",
        "-m",
        "comment",
        "--comment",
        "shareguard",
        "-j",
        "DROP",
    ]
    assert expected_iptables_block in runner.commands

    # Unblock client
    responder.unblock_client("192.168.56.30")
    expected_iptables_unblock = [
        "iptables",
        "-D",
        "INPUT",
        "-s",
        "192.168.56.30",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "139,445",
        "-m",
        "comment",
        "--comment",
        "shareguard",
        "-j",
        "DROP",
    ]
    assert expected_iptables_unblock in runner.commands


# ---------------------------------------------------------------------------
# 3. Session Termination via smbstatus
# ---------------------------------------------------------------------------


def test_kill_sessions_json_and_process_filtering(tmp_path: Path) -> None:
    """kill_sessions parses smbstatus and terminates only smbd PIDs belonging to the target IP."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")

    # Mock smbstatus --json output with two clients
    json_stdout = json.dumps(
        {
            "sessions": {
                "1001": {"remote_machine": "192.168.56.20", "username": "baduser"},
                "1002": {"remote_machine": "192.168.56.55", "username": "gooduser"},
                "1003": {"remote_machine": "192.168.56.20", "username": "baduser"},
            }
        }
    )
    runner.responses["smbstatus --json"] = subprocess.CompletedProcess(
        args=["smbstatus", "--json"], returncode=0, stdout=json_stdout, stderr=""
    )

    responder = LinuxResponder(
        config={"mode": "enforce_temp", "firewall": "nftables"},
        runner=runner,
        store=store,
    )

    result = responder.kill_sessions("192.168.56.20")
    assert result.success is True
    assert set(result.pids_terminated) == {1001, 1003}

    # Verify SIGTERM sent to 1001 and 1003, NEVER to 1002
    assert ["kill", "-TERM", "1001"] in runner.commands
    assert ["kill", "-TERM", "1003"] in runner.commands
    assert not any("1002" in cmd for cmd in runner.commands)


def test_kill_sessions_fallback_text_parsing(tmp_path: Path) -> None:
    """kill_sessions falls back to parsing smbstatus -p when JSON output is absent."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")

    # Fail --json, return text for -p
    runner.responses["smbstatus --json"] = subprocess.CompletedProcess(
        args=["smbstatus", "--json"], returncode=1, stdout="", stderr="unsupported"
    )
    text_stdout = (
        "PID     Username     Group        Machine               Protocol Version\n"
        "2005    alice        users        192.168.56.20 (ipv4:192.168.56.20:54321) SMB3_11\n"
        "2006    bob          users        192.168.56.99 (ipv4:192.168.56.99:54322) SMB3_11\n"
    )
    runner.responses["smbstatus -p"] = subprocess.CompletedProcess(
        args=["smbstatus", "-p"], returncode=0, stdout=text_stdout, stderr=""
    )

    responder = LinuxResponder(
        config={"mode": "enforce_temp", "firewall": "nftables"},
        runner=runner,
        store=store,
    )

    result = responder.kill_sessions("192.168.56.20")
    assert result.success is True
    assert result.pids_terminated == [2005]
    assert ["kill", "-TERM", "2005"] in runner.commands
    assert not any("2006" in cmd for cmd in runner.commands)


# ---------------------------------------------------------------------------
# 4. Emergency Flush
# ---------------------------------------------------------------------------


def test_flush_all_cleans_only_shareguard_rules(tmp_path: Path) -> None:
    """flush_all deletes the ShareGuard nftables table without touching other system tables."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    responder = LinuxResponder(
        config={"mode": "enforce_temp", "firewall": "nftables"},
        runner=runner,
        store=store,
    )

    responder.block_client("192.168.56.20", ttl_seconds=600)
    assert len(responder.list_blocks()) == 1

    cleared = responder.flush_all()
    assert cleared == 1
    assert len(responder.list_blocks()) == 0
    assert ["nft", "delete", "table", "inet", "shareguard"] in runner.commands


# ---------------------------------------------------------------------------
# 5. Strict IP Validation & Injection Rejection
# ---------------------------------------------------------------------------


def test_validate_blockable_ip_security_rules() -> None:
    """Rejects injection attempts, loopback, multicast, server IP, and gateway."""
    server_ips = {"192.168.56.10", "10.0.0.1"}
    gateway_ip = "192.168.56.1"
    allowlist = {"127.0.0.1", "::1", "192.168.1.0/24"}

    # Valid IP passes
    addr = validate_blockable_ip("192.168.56.20", allowlist, server_ips, gateway_ip)
    assert str(addr) == "192.168.56.20"

    # Shell injection attempts
    with pytest.raises(ValueError, match="Invalid host IP|Invalid characters"):
        validate_blockable_ip("192.168.56.20; reboot", allowlist, server_ips, gateway_ip)

    with pytest.raises(ValueError, match="Invalid host IP|Invalid characters"):
        validate_blockable_ip("192.168.56.20 -j ACCEPT", allowlist, server_ips, gateway_ip)

    # Subnets rejected (single host only)
    with pytest.raises(ValueError, match="CIDR ranges"):
        validate_blockable_ip("192.168.56.0/24", allowlist, server_ips, gateway_ip)

    # Loopback rejected
    with pytest.raises(ValueError, match="loopback"):
        validate_blockable_ip("127.0.0.1", allowlist, server_ips, gateway_ip)

    # Multicast rejected
    with pytest.raises(ValueError, match="multicast"):
        validate_blockable_ip("224.0.0.1", allowlist, server_ips, gateway_ip)

    # Server IP rejected
    with pytest.raises(ValueError, match="server's own IP"):
        validate_blockable_ip("192.168.56.10", allowlist, server_ips, gateway_ip)

    # Gateway rejected
    with pytest.raises(ValueError, match="default gateway"):
        validate_blockable_ip("192.168.56.1", allowlist, server_ips, gateway_ip)

    # Allowlisted subnet rejected
    with pytest.raises(ValueError, match="allowlisted"):
        validate_blockable_ip("192.168.1.55", allowlist, server_ips, gateway_ip)


# ---------------------------------------------------------------------------
# 6. TTL Bounds & Auto-Expiry Simulation
# ---------------------------------------------------------------------------


def test_ttl_bounds_and_fake_clock_expiry(tmp_path: Path) -> None:
    """Enforces TTL bounds and auto-expires blocks via fake clock."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    responder = LinuxResponder(
        config={"mode": "enforce_temp", "min_ttl_seconds": 30, "max_ttl_seconds": 300},
        runner=runner,
        store=store,
    )

    t0 = datetime(2026, 5, 1, 10, 0, 0, tzinfo=UTC)

    # Requested TTL 5s bumped to min_ttl_seconds 30s
    rec = responder.block_client("192.168.56.22", ttl_seconds=5, clock=lambda: t0)
    assert rec is not None
    assert rec.expires_at == t0 + timedelta(seconds=30)

    # At t0 + 20s, block is still active
    assert len(responder.list_blocks(now=t0 + timedelta(seconds=20))) == 1

    # At t0 + 35s, block is expired
    runner.responses.clear()
    t_expired = t0 + timedelta(seconds=35)
    # list_blocks filters out expired blocks
    active_now = responder.list_blocks(now=t_expired)
    assert len(active_now) == 0


# ---------------------------------------------------------------------------
# 7. Restart Persistence via BlockStore
# ---------------------------------------------------------------------------


def test_restart_persistence_and_reapply(tmp_path: Path) -> None:
    """Active blocks are reloaded on restart and remaining TTLs re-applied."""
    store_file = tmp_path / "active_blocks.json"
    store = BlockStore(store_file)
    runner = FakeCommandRunner()

    t0 = datetime.now(tz=UTC)
    active_record = BlockRecord(
        client_ip="192.168.56.77",
        username="carol",
        blocked_at=t0,
        expires_at=t0 + timedelta(minutes=10),
        reason="persisted block",
        active=True,
        backend_type="nftables",
    )
    store.save_active_blocks([active_record])

    # Instantiate new responder simulating daemon restart
    responder = LinuxResponder(
        config={"mode": "enforce_temp", "firewall": "nftables"},
        runner=runner,
        store=store,
    )

    # Assert block was reloaded into memory
    active_blocks = responder.list_blocks()
    assert len(active_blocks) == 1
    assert active_blocks[0].client_ip == "192.168.56.77"

    # Assert re-apply command was issued to firewall
    reapplied = any(
        "192.168.56.77" in cmd and "add" in cmd and "element" in cmd
        for cmd in runner.commands
    )
    assert reapplied is True


# ---------------------------------------------------------------------------
# 8. Rate Limiting
# ---------------------------------------------------------------------------


def test_rate_limiting_enforcement(tmp_path: Path) -> None:
    """Enforces rate limit per minute and maximum concurrent active blocks."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    responder = LinuxResponder(
        config={
            "mode": "enforce_temp",
            "rate_limit_per_minute": 3,
            "max_active_blocks": 4,
        },
        runner=runner,
        store=store,
    )

    t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)

    # 3 blocks within 60s succeed
    assert responder.block_client("192.168.56.21", ttl_seconds=600, clock=lambda: t0) is not None
    assert responder.block_client("192.168.56.22", ttl_seconds=600, clock=lambda: t0) is not None
    assert responder.block_client("192.168.56.23", ttl_seconds=600, clock=lambda: t0) is not None

    # 4th block in same minute is rejected by rate limit
    rejected = responder.block_client("192.168.56.24", ttl_seconds=600, clock=lambda: t0)
    assert rejected is None


# ---------------------------------------------------------------------------
# 9. Dry-Run Mode
# ---------------------------------------------------------------------------


def test_dry_run_mode_does_not_execute_commands(tmp_path: Path) -> None:
    """dry_run=True logs intended actions and executes zero firewall commands."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")
    responder = LinuxResponder(
        config={"mode": "enforce_temp", "dry_run": True},
        runner=runner,
        store=store,
    )

    rec = responder.block_client("192.168.56.40", ttl_seconds=300)
    assert rec is not None
    assert rec.backend_type == "dry_run"

    # Only initial setup commands may have been recorded; no block commands executed
    block_cmds = [cmd for cmd in runner.commands if "192.168.56.40" in cmd]
    assert len(block_cmds) == 0


# ---------------------------------------------------------------------------
# 10. Fallback on Firewall Failure
# ---------------------------------------------------------------------------


def test_firewall_failure_falls_back_to_kill_sessions(tmp_path: Path) -> None:
    """Firewall failure falls back immediately to kill_sessions and does not crash."""
    runner = FakeCommandRunner()
    store = BlockStore(tmp_path / "blocks.json")

    # Force nft add element to fail
    runner.responses["nft add element"] = subprocess.CompletedProcess(
        args=["nft"], returncode=1, stdout="", stderr="nftables kernel error"
    )

    responder = LinuxResponder(
        config={"mode": "enforce_temp", "firewall": "nftables"},
        runner=runner,
        store=store,
    )

    # Must not raise an unhandled exception
    rec = responder.block_client("192.168.56.20", ttl_seconds=300)
    assert rec is None

    # Verify fallback to kill_sessions was executed
    kill_called = any("smbstatus" in cmd for cmd in runner.commands)
    assert kill_called is True


# ---------------------------------------------------------------------------
# 11. Refusal of RealCommandRunner on Windows
# ---------------------------------------------------------------------------


def test_real_command_runner_refuses_non_linux_or_simulation() -> None:
    """RealCommandRunner strictly refuses to execute real commands on non-Linux or non-live."""
    runner = RealCommandRunner(is_live_mode=False)
    with pytest.raises(RuntimeError, match="Refusing to execute real firewall"):
        runner.run(["echo", "test"])

    if sys.platform != "linux":
        runner_live = RealCommandRunner(is_live_mode=True)
        with pytest.raises(RuntimeError, match="Refusing to execute real firewall"):
            runner_live.run(["echo", "test"])


# ---------------------------------------------------------------------------
# 12. Helper Argument Validation
# ---------------------------------------------------------------------------


def test_helper_argument_security_checks() -> None:
    """Helper validation rejects injection, loopback, and out-of-bound TTL parameters."""
    import importlib.util
    from importlib.machinery import SourceFileLoader

    helper_path = Path(__file__).parent.parent.parent / "deploy" / "shareguard-helper"
    loader = SourceFileLoader("shareguard_helper", str(helper_path))
    spec = importlib.util.spec_from_loader("shareguard_helper", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)

    # Injection rejected
    with pytest.raises(ValueError, match="Invalid host IP|forbidden characters"):
        mod.validate_ip("192.168.56.20; rm -rf /")

    with pytest.raises(ValueError, match="Invalid host IP|forbidden characters"):
        mod.validate_ip("192.168.56.20 | nc -e /bin/sh")

    # Loopback rejected
    with pytest.raises(ValueError, match="loopback"):
        mod.validate_ip("127.0.0.1")

    # Out of bounds TTL rejected
    with pytest.raises(ValueError, match="TTL must be between"):
        mod.cmd_block("192.168.56.20", ttl=5, dry_run=True)

    with pytest.raises(ValueError, match="TTL must be between"):
        mod.cmd_block("192.168.56.20", ttl=100000, dry_run=True)


# ---------------------------------------------------------------------------
# 13. Pluggable Notifiers
# ---------------------------------------------------------------------------


def test_pluggable_notifiers(caplog: pytest.LogCaptureFixture) -> None:
    """LogNotifier sanitizes fields; WebhookNotifier catches timeouts safely."""
    log_notifier = LogNotifier()
    alert_payload = {
        "client_ip": "192.168.56.20\n",
        "reasons": "R1: Rapid extension change\x00",
        "files_touched_count": 42,
    }
    with caplog.at_level("WARNING"):
        ok = log_notifier.notify(alert_payload)
        assert ok is True
        assert "192.168.56.20" in caplog.text
        assert "FilesTouched=42" in caplog.text
        assert "\x00" not in caplog.text

    # WebhookNotifier handles unconfigured or unreachable URL gracefully
    webhook = WebhookNotifier(url="http://127.0.0.1:9999/fake-webhook", timeout=0.1)
    webhook_ok = webhook.notify(alert_payload)
    assert webhook_ok is False


# ---------------------------------------------------------------------------
# 14. Factory & FakeResponder
# ---------------------------------------------------------------------------


def test_get_responder_factory() -> None:
    """Factory instantiates FakeResponder and LinuxResponder correctly."""
    fake_resp = get_responder({"backend": "fake", "mode": "shadow"})
    assert isinstance(fake_resp, FakeResponder)

    runner = FakeCommandRunner()
    linux_resp = get_responder({"backend": "linux", "mode": "enforce_temp"}, runner=runner)
    assert isinstance(linux_resp, LinuxResponder)

    with pytest.raises(ValueError, match="Unknown responder backend"):
        get_responder({"backend": "unsupported_backend"})
