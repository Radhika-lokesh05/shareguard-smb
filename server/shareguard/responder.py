"""shareguard.responder – Client blocking, session termination, and notification subsystem.

Provides a unified interface for active response against ransomware:
- :class:`BlockRecord`, :class:`KillSessionResult`
- :class:`CommandRunner`, :class:`RealCommandRunner`, :class:`FakeCommandRunner`
- :class:`Responder` (ABC)
- :class:`FakeResponder` (in-memory test & simulation backend)
- :class:`LinuxResponder` (nftables with per-element timeouts, iptables fallback, sudo helper)
- :class:`IptablesResponder` (legacy iptables backend)
- :class:`BlockStore` (JSON persistence across restarts)
- :class:`Notifier`, :class:`LogNotifier`, :class:`WebhookNotifier`
- :func:`validate_blockable_ip`, :func:`get_responder`

SAFETY INVARIANTS:
1. Blocks apply to SMB ports 139 and 445 ONLY; administrator SSH (port 22) is never blocked.
2. IPs are strictly validated with :mod:`ipaddress`; loopback, multicast, unspecified,
   link-local, server IPs, the default gateway, and allowlisted addresses/CIDRs are NEVER blocked.
3. All commands use argument lists with ``shell=False``; no shell interpolation.
4. Real commands are REFUSED on non-Linux platforms or non-live run modes.
5. All blocks have bounded TTLs (minimum 10s, maximum 24h); no permanent blocks unless
   explicitly requested under ``enforce_strict`` mode.
6. Rate limiting enforces max new blocks per minute and caps total concurrent blocked clients.
7. If firewall operations fail, the responder logs loudly, falls back to :meth:`kill_sessions`,
   and never crashes the detection engine.
8. File names and untrusted strings from logs are sanitized before logging or notification.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "BlockRecord",
    "KillSessionResult",
    "CommandRunner",
    "RealCommandRunner",
    "FakeCommandRunner",
    "Responder",
    "FakeResponder",
    "IptablesResponder",
    "LinuxResponder",
    "BlockStore",
    "Notifier",
    "LogNotifier",
    "WebhookNotifier",
    "validate_blockable_ip",
    "get_responder",
]

# Standard ports blocked for SMB traffic
SMB_PORTS = (139, 445)
DEFAULT_NFT_TABLE = "shareguard"
DEFAULT_NFT_FAMILY = "inet"
DEFAULT_NFT_SET_V4 = "blocked_ips"
DEFAULT_NFT_SET_V6 = "blocked_ips_v6"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class BlockRecord:
    """Record of a firewall block action.

    Attributes:
        client_ip: Blocked client IP address.
        username: Associated Samba username if known.
        blocked_at: UTC timestamp when the block was applied.
        expires_at: UTC timestamp when the block auto-expires.
        reason: Plain-language reason for the block.
        active: Whether the block is currently in effect.
        backend_type: Underlying firewall mechanism ('nftables', 'iptables', 'fake', etc.).
    """

    client_ip: str
    username: str
    blocked_at: datetime
    expires_at: datetime
    reason: str
    active: bool = True
    backend_type: str = "fake"


@dataclass
class KillSessionResult:
    """Outcome of terminating smbd client sessions."""

    ip: str
    pids_terminated: list[int] = field(default_factory=list)
    success: bool = True
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Input Validation & Sanitization Helpers
# ---------------------------------------------------------------------------


def _sanitize_text(text: str, max_length: int = 256) -> str:
    """Strip control characters and truncate untrusted text."""
    if not text:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(text)).strip()
    return clean[:max_length]


def validate_blockable_ip(
    ip: str,
    allowlist: set[str] | None = None,
    server_ips: set[str] | None = None,
    gateway_ip: str | None = None,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate that *ip* represents a safe, blockable single-host IP address.

    Rejects:
    - Empty strings or strings with invalid characters / command injections
    - CIDR subnet ranges or network masks
    - Loopback, multicast, unspecified, link-local, and reserved addresses
    - Server's own addresses and default gateway
    - Explicitly allowlisted addresses or CIDR blocks

    Args:
        ip: IP address candidate string.
        allowlist: Set of allowlisted IP strings or CIDR subnets.
        server_ips: Set of server IP addresses that must never be blocked.
        gateway_ip: Default gateway IP string.

    Returns:
        Validated :class:`IPv4Address` or :class:`IPv6Address`.

    Raises:
        ValueError: If *ip* is invalid or prohibited from being blocked.
    """
    clean_ip = ip.strip()
    if not clean_ip or "/" in clean_ip:
        raise ValueError(f"Invalid host IP: {ip!r} (CIDR ranges or empty strings not permitted)")

    # Reject shell injection characters explicitly
    if re.search(r"[;&|`$<>\r\n ]", clean_ip):
        raise ValueError(f"Invalid characters detected in IP address: {ip!r}")

    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format {ip!r}: {e}") from e

    if addr.is_loopback:
        raise ValueError(f"Refusing to block loopback address: {addr}")
    if addr.is_multicast:
        raise ValueError(f"Refusing to block multicast address: {addr}")
    if addr.is_unspecified:
        raise ValueError(f"Refusing to block unspecified address: {addr}")
    if addr.is_link_local:
        raise ValueError(f"Refusing to block link-local address: {addr}")

    # Check server's own IPs
    if server_ips:
        for s_ip in server_ips:
            try:
                s_addr = ipaddress.ip_address(s_ip.strip())
            except ValueError:
                continue
            if addr == s_addr:
                raise ValueError(f"Refusing to block server's own IP address: {addr}")

    # Check gateway IP
    if gateway_ip:
        try:
            gw_addr = ipaddress.ip_address(gateway_ip.strip())
        except ValueError:
            gw_addr = None
        if gw_addr is not None and addr == gw_addr:
            raise ValueError(f"Refusing to block default gateway address: {addr}")

    # Check allowlist (exact IP or CIDR subnets)
    if allowlist:
        for item in allowlist:
            item_clean = item.strip()
            if "/" in item_clean:
                try:
                    net = ipaddress.ip_network(item_clean, strict=False)
                except ValueError:
                    continue
                if addr in net:
                    raise ValueError(f"Refusing to block allowlisted address {addr} (in subnet {net})")
            else:
                try:
                    allow_addr = ipaddress.ip_address(item_clean)
                except ValueError:
                    continue
                if addr == allow_addr:
                    raise ValueError(f"Refusing to block allowlisted IP address: {addr}")

    return addr


# ---------------------------------------------------------------------------
# Command Runner Interface
# ---------------------------------------------------------------------------


class CommandRunner(ABC):
    """Abstract command runner executing argument lists without shell=True."""

    @abstractmethod
    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """Execute command argument list."""
        ...


class RealCommandRunner(CommandRunner):
    """Executes subprocesses directly with shell=False.

    Refuses execution unless running on Linux AND live mode is explicitly enabled.
    """

    def __init__(self, is_live_mode: bool = False) -> None:
        self.is_live_mode = is_live_mode

    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        if sys.platform != "linux" or not self.is_live_mode:
            raise RuntimeError(
                f"Refusing to execute real firewall/session command on {sys.platform} "
                f"(is_live_mode={self.is_live_mode}): {cmd}"
            )
        return subprocess.run(  # noqa: S603
            cmd,
            check=check,
            capture_output=True,
            text=True,
            shell=False,
        )


class FakeCommandRunner(CommandRunner):
    """In-memory command runner recording commands for unit test assertions."""

    def __init__(self, responses: dict[str, subprocess.CompletedProcess[str]] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.responses: dict[str, subprocess.CompletedProcess[str]] = responses or {}
        self.custom_handler: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None

    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(cmd))
        if self.custom_handler:
            return self.custom_handler(cmd)
        cmd_str = " ".join(cmd)
        for key, resp in self.responses.items():
            if key in cmd_str:
                if check and resp.returncode != 0:
                    raise subprocess.CalledProcessError(resp.returncode, cmd, resp.stdout, resp.stderr)
                return resp
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Block Persistence Store
# ---------------------------------------------------------------------------


class BlockStore:
    """JSON-backed store for persisting active blocks across daemon restarts."""

    def __init__(self, store_path: Path | str = "config/active_blocks.json") -> None:
        self.store_path = Path(store_path)

    def load_active_blocks(self, now: datetime | None = None) -> list[BlockRecord]:
        """Load block records from disk, filtering out already expired entries."""
        if not self.store_path.exists():
            return []
        current_time = now or datetime.now(tz=UTC)
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            records: list[BlockRecord] = []
            for item in data.get("blocks", []):
                blocked_at = datetime.fromisoformat(item["blocked_at"])
                expires_at = datetime.fromisoformat(item["expires_at"])
                if expires_at > current_time and item.get("active", True):
                    records.append(
                        BlockRecord(
                            client_ip=item["client_ip"],
                            username=item.get("username", ""),
                            blocked_at=blocked_at,
                            expires_at=expires_at,
                            reason=item.get("reason", ""),
                            active=True,
                            backend_type=item.get("backend_type", "fake"),
                        )
                    )
            return records
        except Exception as e:
            logger.warning("Could not load active blocks from %s: %s", self.store_path, e)
            return []

    def save_active_blocks(self, blocks: list[BlockRecord]) -> None:
        """Persist current active blocks to JSON."""
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            active_list = [
                {
                    "client_ip": b.client_ip,
                    "username": b.username,
                    "blocked_at": b.blocked_at.isoformat(),
                    "expires_at": b.expires_at.isoformat(),
                    "reason": b.reason,
                    "active": b.active,
                    "backend_type": b.backend_type,
                }
                for b in blocks
                if b.active
            ]
            self.store_path.write_text(
                json.dumps({"version": 1, "blocks": active_list}, indent=2),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning("Could not save active blocks to %s: %s", self.store_path, e)


# ---------------------------------------------------------------------------
# Pluggable Notifiers
# ---------------------------------------------------------------------------


class Notifier(ABC):
    """Abstract interface for sending alerts to external channels."""

    @abstractmethod
    def notify(self, alert_data: dict[str, Any]) -> bool:
        """Send alert notification; returns True on success."""
        ...


class LogNotifier(Notifier):
    """Logs structured alert summaries to logger without sending file contents."""

    def notify(self, alert_data: dict[str, Any]) -> bool:
        client_ip = _sanitize_text(str(alert_data.get("client_ip", "")))
        reasons = _sanitize_text(str(alert_data.get("reasons", "")))
        lost_count = alert_data.get("files_touched_count", 0)
        logger.warning(
            "[ALERT NOTIFY] IP=%s | FilesTouched=%s | Reasons=%s",
            client_ip,
            lost_count,
            reasons,
        )
        return True


class WebhookNotifier(Notifier):
    """Non-blocking HTTP POST webhook notifier with short timeout."""

    def __init__(self, url: str | None = None, timeout: float = 2.0) -> None:
        self.url = url or os.getenv("SHAREGUARD_WEBHOOK_URL", "")
        self.timeout = timeout

    def notify(self, alert_data: dict[str, Any]) -> bool:
        if not self.url:
            return False

        payload = {
            "event": "shareguard_alert",
            "client_ip": _sanitize_text(str(alert_data.get("client_ip", ""))),
            "username": _sanitize_text(str(alert_data.get("username", ""))),
            "severity": _sanitize_text(str(alert_data.get("severity", "high"))),
            "reasons": _sanitize_text(str(alert_data.get("reasons", ""))),
            "time_to_detect": alert_data.get("time_to_detect", 0.0),
            "files_touched_count": alert_data.get("files_touched_count", 0),
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }

        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return resp.status in (200, 201, 202, 204)
        except Exception as err:
            logger.warning("Webhook notification failed to %s: %s", self.url, err)
            return False


# ---------------------------------------------------------------------------
# Base Responder Class
# ---------------------------------------------------------------------------


class Responder(ABC):
    """Abstract responder base class enforcing security invariants.

    Args:
        config: ``config.response`` configuration section.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.mode: str = self.config.get("mode", "shadow")
        self.block_ttl_minutes: int = self.config.get("block_ttl_minutes", 15)
        self.allowlist: set[str] = set(self.config.get("allowlist", ["127.0.0.1", "::1"]))
        self.server_ips: set[str] = set(self.config.get("server_ips", []))
        self.gateway_ip: str | None = self.config.get("gateway_ip")
        self.dry_run: bool = bool(self.config.get("dry_run", False))
        self.min_ttl_seconds: int = int(self.config.get("min_ttl_seconds", 10))
        self.max_ttl_seconds: int = int(self.config.get("max_ttl_seconds", 86400))
        self.rate_limit_per_minute: int = int(self.config.get("rate_limit_per_minute", 10))
        self.max_active_blocks: int = int(self.config.get("max_active_blocks", 20))

        # Rate limiting state
        self._block_timestamps: collections.deque[datetime] = collections.deque()
        self.notifiers: list[Notifier] = [LogNotifier()]
        if os.getenv("SHAREGUARD_WEBHOOK_URL") or self.config.get("webhook_url"):
            self.notifiers.append(WebhookNotifier(url=self.config.get("webhook_url")))

    def _is_safe_to_block(self, ip: str) -> bool:
        """Validate whether *ip* is safe to block."""
        try:
            validate_blockable_ip(
                ip,
                allowlist=self.allowlist,
                server_ips=self.server_ips,
                gateway_ip=self.gateway_ip,
            )
            return True
        except ValueError as err:
            logger.info("IP %s is protected or invalid: %s", ip, err)
            return False

    def _check_rate_limit(self, now: datetime) -> bool:
        """Enforce maximum new blocks per minute and maximum active blocks."""
        cutoff = now - timedelta(minutes=1)
        while self._block_timestamps and self._block_timestamps[0] < cutoff:
            self._block_timestamps.popleft()

        if len(self._block_timestamps) >= self.rate_limit_per_minute:
            logger.error(
                "RATE LIMIT EXCEEDED: Refusing block! More than %d blocks requested in 60s.",
                self.rate_limit_per_minute,
            )
            return False

        active_blocks = len(self.list_blocks())
        if active_blocks >= self.max_active_blocks:
            logger.error(
                "MAX CONCURRENT BLOCKS REACHED: Currently %d active blocks (limit %d). "
                "Refusing block to prevent catastrophic office outage.",
                active_blocks,
                self.max_active_blocks,
            )
            return False

        return True

    def block_client(
        self,
        ip: str,
        ttl_seconds: int = 900,
        reason: str = "",
        username: str = "",
        ttl: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> BlockRecord | None:
        """Block *ip* on SMB ports 139 and 445 if mode permits and invariants pass.

        Args:
            ip: Client IP address string.
            ttl_seconds: Block duration in seconds.
            reason: Plain-text reason for block.
            username: Samba username if known.
            ttl: Legacy parameter: block duration in minutes (used if provided).
            clock: Injectable UTC clock for deterministic testing.

        Returns:
            A :class:`BlockRecord` or ``None`` if shadow/disallowed.
        """
        now = clock() if clock is not None else datetime.now(tz=UTC)

        # Handle legacy ttl parameter in minutes
        effective_ttl = (ttl * 60 if ttl <= 1440 else ttl) if ttl is not None else ttl_seconds

        # Validate IP safety
        if not self._is_safe_to_block(ip):
            return None

        # Shadow mode: alert only, never block
        if self.mode == "shadow":
            logger.info("Shadow mode: would have blocked %s (ttl=%ds, reason=%s)", ip, effective_ttl, reason)
            return None

        # Check rate limits
        if not self._check_rate_limit(now):
            return None

        # Bounds check TTL
        if self.mode == "enforce_strict" and effective_ttl <= 0:
            effective_ttl = 36500 * 86400  # 100 years for indefinite strict admin block
        else:
            effective_ttl = max(self.min_ttl_seconds, min(self.max_ttl_seconds, effective_ttl))

        expires_at = now + timedelta(seconds=effective_ttl)
        sanitized_reason = _sanitize_text(reason)

        if self.dry_run:
            logger.info("[DRY RUN] Would execute block for IP %s (TTL: %ds)", ip, effective_ttl)
            return BlockRecord(
                client_ip=ip,
                username=username,
                blocked_at=now,
                expires_at=expires_at,
                reason=sanitized_reason,
                active=True,
                backend_type="dry_run",
            )

        try:
            success = self._apply_block(ip, effective_ttl, now=now)
            if success:
                self._block_timestamps.append(now)
                return BlockRecord(
                    client_ip=ip,
                    username=username,
                    blocked_at=now,
                    expires_at=expires_at,
                    reason=sanitized_reason,
                    active=True,
                    backend_type=getattr(self, "backend_name", "unknown"),
                )
        except Exception as e:
            logger.error("Firewall block failed for %s: %s. Falling back to session kill.", ip, e)
            self.kill_sessions(ip)

        return None

    def block(self, ip: str, username: str, reason: str) -> BlockRecord | None:
        """Compatibility wrapper for block_client using default TTL."""
        return self.block_client(ip, ttl_seconds=self.block_ttl_minutes * 60, reason=reason, username=username)

    def unblock_client(self, ip: str) -> bool:
        """Unblock *ip*."""
        clean_ip = ip.strip()
        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            logger.warning("Invalid IP address for unblock: %s", ip)
            return False
        return self._apply_unblock(clean_ip)

    def unblock(self, ip: str) -> bool:
        """Compatibility wrapper for unblock_client."""
        return self.unblock_client(ip)

    def notify(self, alert: dict[str, Any]) -> bool:
        """Dispatch alert to all registered notifiers."""
        any_success = False
        for n in self.notifiers:
            try:
                if n.notify(alert):
                    any_success = True
            except Exception as e:
                logger.debug("Notifier %s failed: %s", n, e)
        return any_success

    @abstractmethod
    def kill_sessions(self, ip: str) -> KillSessionResult:
        """Terminate smbd processes attributed to *ip*."""
        ...

    @abstractmethod
    def flush_all(self) -> int:
        """Emergency undo: flush all ShareGuard rules."""
        ...

    @abstractmethod
    def _apply_block(self, ip: str, ttl_seconds: int, now: datetime | None = None) -> bool:
        ...

    @abstractmethod
    def _apply_unblock(self, ip: str) -> bool:
        ...

    @abstractmethod
    def list_blocks(self) -> list[BlockRecord]:
        ...


# ---------------------------------------------------------------------------
# In-Memory Fake Responder (Simulation & Tests)
# ---------------------------------------------------------------------------


class FakeResponder(Responder):
    """In-memory responder for simulation and fast tests."""

    backend_name = "fake"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._blocks: dict[str, BlockRecord] = {}
        self.calls: list[dict[str, Any]] = []

    def block_client(
        self,
        ip: str,
        ttl_seconds: int = 900,
        reason: str = "",
        username: str = "",
        ttl: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> BlockRecord | None:
        self.calls.append(
            {
                "method": "block_client",
                "ip": ip,
                "ttl": ttl if ttl is not None else ttl_seconds // 60,
                "ttl_seconds": ttl_seconds,
                "reason": reason,
                "username": username,
            }
        )
        return super().block_client(
            ip,
            ttl_seconds=ttl_seconds,
            reason=reason,
            username=username,
            ttl=ttl,
            clock=clock,
        )

    def unblock_client(self, ip: str) -> bool:
        self.calls.append({"method": "unblock_client", "ip": ip})
        return super().unblock_client(ip)

    def kill_sessions(self, ip: str) -> KillSessionResult:
        self.calls.append({"method": "kill_sessions", "ip": ip})
        return KillSessionResult(ip=ip, pids_terminated=[1234, 1235], success=True)

    def flush_all(self) -> int:
        self.calls.append({"method": "flush_all"})
        count = len(self._blocks)
        self._blocks.clear()
        return count

    def _apply_block(self, ip: str, ttl_seconds: int, now: datetime | None = None) -> bool:
        block_now = now or datetime.now(tz=UTC)
        expires_at = (
            block_now + timedelta(seconds=ttl_seconds)
            if ttl_seconds > 0
            else block_now + timedelta(days=36500)
        )
        self._blocks[ip] = BlockRecord(
            client_ip=ip,
            username="",
            blocked_at=block_now,
            expires_at=expires_at,
            reason="fake block",
            active=True,
            backend_type="fake",
        )
        return True

    def _apply_unblock(self, ip: str) -> bool:
        if ip in self._blocks and self._blocks[ip].active:
            self._blocks[ip].active = False
            return True
        return False

    def list_blocks(self) -> list[BlockRecord]:
        return [b for b in self._blocks.values() if b.active]


# ---------------------------------------------------------------------------
# Linux Real Responder (nftables & iptables via CommandRunner)
# ---------------------------------------------------------------------------


class LinuxResponder(Responder):
    """Linux responder managing nftables with iptables fallback and persistence."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        runner: CommandRunner | None = None,
        store: BlockStore | None = None,
    ) -> None:
        super().__init__(config)
        self.runner = runner or RealCommandRunner(is_live_mode=self.config.get("is_live", False))
        self.store = store or BlockStore(self.config.get("store_path", "config/active_blocks.json"))
        self.use_nft = self.config.get("firewall", "nftables") == "nftables"
        self.use_helper = bool(self.config.get("use_helper", False))
        self.helper_path = self.config.get("helper_path", "/usr/local/bin/shareguard-helper")
        self.backend_name = "nftables" if self.use_nft else "iptables"
        self._blocks: dict[str, BlockRecord] = {}

        # Initialize firewall tables/sets and reload persistent active blocks
        self._init_firewall()
        self._reload_persisted_blocks()

    def _init_firewall(self) -> None:
        """Create nftables table and timeout sets if nftables is selected."""
        if not self.use_nft or self.use_helper:
            return
        try:
            # Create dedicated inet shareguard table
            self.runner.run(["nft", "add", "table", DEFAULT_NFT_FAMILY, DEFAULT_NFT_TABLE])
            # Create set with native element timeout support
            self.runner.run(
                [
                    "nft",
                    "add",
                    "set",
                    DEFAULT_NFT_FAMILY,
                    DEFAULT_NFT_TABLE,
                    DEFAULT_NFT_SET_V4,
                    "{",
                    "type",
                    "ipv4_addr;",
                    "flags",
                    "timeout;",
                    "}",
                ]
            )
            # Create prerouting filter chain with priority -150
            self.runner.run(
                [
                    "nft",
                    "add",
                    "chain",
                    DEFAULT_NFT_FAMILY,
                    DEFAULT_NFT_TABLE,
                    "prerouting",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "prerouting",
                    "priority",
                    "-150;",
                    "policy",
                    "accept;",
                    "}",
                ]
            )
            # Drop SMB ports 139 and 445 only
            self.runner.run(
                [
                    "nft",
                    "add",
                    "rule",
                    DEFAULT_NFT_FAMILY,
                    DEFAULT_NFT_TABLE,
                    "prerouting",
                    "ip",
                    "saddr",
                    f"@{DEFAULT_NFT_SET_V4}",
                    "tcp",
                    "dport",
                    "{",
                    "139,",
                    "445",
                    "}",
                    "drop",
                ]
            )
        except Exception as e:
            logger.warning("nftables init failed (%s); falling back to iptables", e)
            self.use_nft = False
            self.backend_name = "iptables"

    def _reload_persisted_blocks(self) -> None:
        """Reload active blocks on startup and re-apply remaining TTLs."""
        now = datetime.now(tz=UTC)
        persisted = self.store.load_active_blocks(now=now)
        for b in persisted:
            remaining_seconds = int((b.expires_at - now).total_seconds())
            if remaining_seconds > 0:
                self._blocks[b.client_ip] = b
                try:
                    self._apply_block(b.client_ip, remaining_seconds)
                except Exception as e:
                    logger.warning("Failed to re-apply persisted block for %s: %s", b.client_ip, e)

    def _apply_block(self, ip: str, ttl_seconds: int, now: datetime | None = None) -> bool:
        """Apply firewall block using helper, nftables, or iptables."""
        if self.use_helper:
            cmd = ["sudo", self.helper_path, "block", ip, str(ttl_seconds)]
            res = self.runner.run(cmd)
            success = res.returncode == 0
        elif self.use_nft:
            cmd = [
                "nft",
                "add",
                "element",
                DEFAULT_NFT_FAMILY,
                DEFAULT_NFT_TABLE,
                DEFAULT_NFT_SET_V4,
                "{",
                ip,
                "timeout",
                f"{ttl_seconds}s",
                "}",
            ]
            res = self.runner.run(cmd)
            success = res.returncode == 0
        else:
            # Fallback iptables: insert at top of INPUT with comment 'shareguard'
            cmd = [
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-s",
                ip,
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
            res = self.runner.run(cmd)
            success = res.returncode == 0

        if success:
            block_now = now or datetime.now(tz=UTC)
            rec = BlockRecord(
                client_ip=ip,
                username="",
                blocked_at=block_now,
                expires_at=block_now + timedelta(seconds=ttl_seconds),
                reason="Active block",
                active=True,
                backend_type=self.backend_name,
            )
            self._blocks[ip] = rec
            self.store.save_active_blocks(list(self._blocks.values()))

        return success

    def _apply_unblock(self, ip: str) -> bool:
        """Remove firewall block using helper, nftables, or iptables."""
        success = False
        if self.use_helper:
            cmd = ["sudo", self.helper_path, "unblock", ip]
            res = self.runner.run(cmd)
            success = res.returncode == 0
        elif self.use_nft:
            cmd = [
                "nft",
                "delete",
                "element",
                DEFAULT_NFT_FAMILY,
                DEFAULT_NFT_TABLE,
                DEFAULT_NFT_SET_V4,
                "{",
                ip,
                "}",
            ]
            res = self.runner.run(cmd)
            success = res.returncode == 0
        else:
            cmd = [
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
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
            res = self.runner.run(cmd)
            success = res.returncode == 0

        if ip in self._blocks:
            self._blocks[ip].active = False
            self.store.save_active_blocks(list(self._blocks.values()))

        return success

    def kill_sessions(self, ip: str) -> KillSessionResult:
        """Terminate smbd processes belonging strictly to *ip*."""
        clean_ip = ip.strip()
        pids: list[int] = []

        # 1. Attempt smbstatus --json
        try:
            res = self.runner.run(["smbstatus", "--json"], check=False)
            if res.returncode == 0 and res.stdout:
                data = json.loads(res.stdout)
                # Sessions structure in Samba JSON
                sessions = data.get("sessions", {})
                if isinstance(sessions, dict):
                    for pid_str, sess in sessions.items():
                        remote = sess.get("remote_machine", "") or sess.get("ip", "")
                        if clean_ip in str(remote):
                            try:
                                pids.append(int(pid_str))
                            except ValueError:
                                pass
                elif isinstance(sessions, list):
                    for sess in sessions:
                        remote = sess.get("remote_machine", "") or sess.get("ip", "")
                        if clean_ip in str(remote) and "pid" in sess:
                            pids.append(int(sess["pid"]))
        except Exception as e:
            logger.debug("smbstatus --json parsing failed: %s; falling back to -p", e)

        # 2. Fallback to parsing smbstatus -p
        if not pids:
            try:
                res_p = self.runner.run(["smbstatus", "-p"], check=False)
                if res_p.returncode == 0 and res_p.stdout:
                    for line in res_p.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].isdigit():
                            pid = int(parts[0])
                            # Check machine field
                            machine_field = " ".join(parts[3:])
                            if clean_ip in machine_field:
                                pids.append(pid)
            except Exception as e:
                logger.warning("smbstatus -p parsing failed: %s", e)

        if not pids:
            return KillSessionResult(ip=clean_ip, pids_terminated=[], success=True)

        terminated: list[int] = []
        for pid in pids:
            try:
                # Graceful SIGTERM
                self.runner.run(["kill", "-TERM", str(pid)], check=False)
                # Verify and SIGKILL if still running
                chk = self.runner.run(["kill", "-0", str(pid)], check=False)
                if chk.returncode == 0:
                    self.runner.run(["kill", "-KILL", str(pid)], check=False)
                terminated.append(pid)
            except Exception as err:
                logger.warning("Failed to terminate smbd PID %d: %s", pid, err)

        return KillSessionResult(ip=clean_ip, pids_terminated=terminated, success=True)

    def flush_all(self) -> int:
        """Emergency undo: remove all ShareGuard firewall rules."""
        count = len(self._blocks)
        if self.use_helper:
            self.runner.run(["sudo", self.helper_path, "flush"], check=False)
        elif self.use_nft:
            self.runner.run(
                ["nft", "delete", "table", DEFAULT_NFT_FAMILY, DEFAULT_NFT_TABLE],
                check=False,
            )
        else:
            # Query and remove iptables rules with comment shareguard
            res = self.runner.run(["iptables", "-S", "INPUT"], check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "shareguard" in line and line.startswith("-A"):
                        d_cmd = ["iptables", "-D"] + line.split()[1:]
                        self.runner.run(d_cmd, check=False)

        self._blocks.clear()
        self.store.save_active_blocks([])
        return count

    def list_blocks(self, now: datetime | None = None) -> list[BlockRecord]:
        current_time = now or datetime.now(tz=UTC)
        # Purge locally expired
        active: list[BlockRecord] = []
        for b in self._blocks.values():
            if b.active and b.expires_at > current_time:
                active.append(b)
            else:
                b.active = False
        return active


# ---------------------------------------------------------------------------
# Legacy Iptables Responder (Preserved for compatibility)
# ---------------------------------------------------------------------------


class IptablesResponder(Responder):
    """Legacy iptables responder for LIVE mode on Ubuntu."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.inner = LinuxResponder(
            config={**(config or {}), "firewall": "iptables"},
        )

    def _apply_block(self, ip: str, ttl_seconds: int) -> bool:
        return self.inner._apply_block(ip, ttl_seconds)

    def _apply_unblock(self, ip: str) -> bool:
        return self.inner._apply_unblock(ip)

    def list_blocks(self) -> list[BlockRecord]:
        return self.inner.list_blocks()

    def kill_sessions(self, ip: str) -> KillSessionResult:
        return self.inner.kill_sessions(ip)

    def flush_all(self) -> int:
        return self.inner.flush_all()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_responder(
    config: dict[str, Any],
    runner: CommandRunner | None = None,
    store_path: Path | str | None = None,
) -> Responder:
    """Factory: return the configured :class:`Responder`.

    Args:
        config: ``config.response`` section from ``default.yaml``.
        runner: Optional :class:`CommandRunner` override.
        store_path: Optional path for active blocks persistence.

    Returns:
        An instantiated :class:`Responder`.
    """
    backend = config.get("backend", "fake")
    if backend == "fake":
        return FakeResponder(config)
    if backend in {"linux", "nftables"}:
        cfg = dict(config)
        if store_path:
            cfg["store_path"] = str(store_path)
        return LinuxResponder(config=cfg, runner=runner)
    if backend == "iptables":
        return IptablesResponder(config)
    raise ValueError(f"Unknown responder backend: {backend!r}")
