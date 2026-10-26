"""
shareguard.parser – Parse vfs_full_audit log lines into structured events.

Samba's ``vfs_full_audit`` module writes one line per file-system operation.
Two prefix formats are supported, controlled by ``full_audit:prefix`` in smb.conf:

**Short prefix** (user|ip only)::

    Oct  3 12:01:05 fileserver smbd_audit: alice|192.168.1.10|openat|ok|0x20|docs/file.docx

**Full prefix** (``%u|%I|%m|%S``)::

    Oct  3 12:01:05 fileserver smbd_audit: alice|192.168.1.10|PC|share|openat|ok|0x20|docs/file.docx

``renameat`` lines have an extra trailing field for the new path::

    ... renameat|ok|src.docx|src.docx.locked

All parsing is concentrated in :func:`_split_fields` so the format can be
adjusted in one place without touching any other logic.

Public API
----------
- :class:`AuditEvent` — typed, frozen dataclass for one event.
- :func:`parse_line` — parse a single raw log line → ``AuditEvent | None``.
- :func:`parse_lines` — batch parse, skipping malformed lines.
- :func:`follow` — tail a file like ``tail -F`` (rotation/truncation aware, Windows-safe).
- :func:`replay` — replay a log file with optional speed multiplier.
- :data:`malformed_count` — running count of lines that could not be parsed.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

__all__ = [
    "AuditEvent",
    "parse_line",
    "parse_lines",
    "follow",
    "replay",
    "malformed_count",
    "reset_malformed_count",
    "outside_share_count",
    "reset_outside_share_count",
    "get_share_roots",
    "set_share_roots",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum byte-length kept for any single untrusted string field.
_MAX_FIELD_LEN = 512

# Samba operations that the scanner cares about.
KNOWN_OPS: frozenset[str] = frozenset(
    {"openat", "close", "renameat", "unlinkat", "mkdirat", "write", "read", "open", "unlink", "rename"}
)

# Module-level counters.
malformed_count: int = 0
outside_share_count: int = 0
_share_roots: dict[str, str] | None = None


def reset_malformed_count() -> None:
    """Reset :data:`malformed_count` to zero (useful in tests)."""
    global malformed_count  # noqa: PLW0603
    malformed_count = 0


def reset_outside_share_count() -> None:
    """Reset :data:`outside_share_count` to zero (useful in tests)."""
    global outside_share_count  # noqa: PLW0603
    outside_share_count = 0


def set_share_roots(roots: dict[str, str] | None) -> None:
    """Manually configure share roots mapping (share_name -> root_path)."""
    global _share_roots  # noqa: PLW0603
    _share_roots = roots


def get_share_roots() -> dict[str, str]:
    """Load and return configured share roots.

    Reads config/default.yaml if not explicitly set.
    """
    global _share_roots  # noqa: PLW0603
    if _share_roots is not None:
        return _share_roots

    cfg_file = Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml"
    roots: dict[str, str] = {}
    if cfg_file.exists():
        try:
            import yaml

            data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            samba_cfg = data.get("samba", {}) if isinstance(data, dict) else {}
            shares = samba_cfg.get("shares")
            if isinstance(shares, dict):
                for k, v in shares.items():
                    clean_root = str(v).replace("\\", "/").rstrip("/")
                    roots[str(k).lower()] = clean_root
                    roots[str(k)] = clean_root
            if "share_root" in samba_cfg:
                sr = str(samba_cfg["share_root"]).replace("\\", "/").rstrip("/")
                roots[""] = sr
                if not roots:
                    roots["finance"] = sr
                    roots["Finance"] = sr
        except Exception:
            pass

    if not roots:
        roots = {
            "finance": "/srv/shares/Finance",
            "Finance": "/srv/shares/Finance",
            "": "/srv/shares/Finance",
        }

    _share_roots = roots
    return _share_roots


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A single parsed vfs_full_audit log entry.

    Attributes:
        ts:           UTC datetime of the event (best-effort; year inferred for syslog format).
        host:         Syslog hostname.
        user:         Samba username (untrusted, sanitised).
        ip:           Client IP address string (validate with :mod:`ipaddress` before use).
        machine:      NetBIOS machine name — empty string if short prefix used.
        share:        Samba share name — empty string if short prefix used.
        op:           Operation name, e.g. ``"openat"``, ``"renameat"``, ``"unlinkat"``.
        result:       ``"ok"`` or ``"err"``.
        args:         Any extra flag-like fields between result and path (e.g. ``"r"``, ``"w"``).
        path:         Absolute server path (untrusted, truncated, never executed).
        rel_path:     Path relative to the share root (empty string for share root dir).
        new_path:     Destination absolute path for rename operations; empty string otherwise.
        new_rel_path: Destination relative path for rename operations; empty string otherwise.
        raw:          Original log line, kept for debugging.
    """

    ts: datetime
    host: str
    user: str
    ip: str
    machine: str
    share: str
    op: str
    result: str
    args: str
    path: str
    rel_path: str = ""
    new_path: str = ""
    new_rel_path: str = ""
    raw: str = ""

    @property
    def relative_path(self) -> str:
        """Backwards-compatible alias for rel_path."""
        return self.rel_path or self.path

    @property
    def new_relative_path(self) -> str:
        """Backwards-compatible alias for new_rel_path."""
        return self.new_rel_path or self.new_path


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

# Matches syslog-style: "Oct  3 12:01:05" or "Oct 03 12:01:05"
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+",
)

# Month abbreviation → month number
_MONTHS: dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


@lru_cache(maxsize=4096)
def _parse_timestamp(raw_ts: str) -> datetime:
    """Parse a timestamp string into a UTC-aware :class:`datetime`.

    Supports:
    - ISO-8601 (``2024-10-03T12:01:05+00:00``)
    - Syslog (``Oct  3 12:01:05``) — year inferred as *current year*, rolling back
      one year if the result would be in the future.

    Args:
        raw_ts: Raw timestamp string extracted from the log line prefix.

    Returns:
        A timezone-aware :class:`datetime` in UTC.

    Raises:
        ValueError: If the string cannot be recognised as either format.
    """
    raw_ts = raw_ts.strip()

    # Try ISO-8601 first.
    try:
        dt = datetime.fromisoformat(raw_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        pass

    # Try syslog format.
    m = _SYSLOG_RE.match(raw_ts + " ")  # trailing space makes the pattern work on short strings
    if m:
        mon = _MONTHS.get(m.group("mon").lower())
        if mon is None:
            raise ValueError(f"Unknown month abbreviation: {m.group('mon')!r}")
        day = int(m.group("day"))
        h, mi, s = (int(x) for x in m.group("time").split(":"))
        now = datetime.now(tz=UTC)
        year = now.year
        dt = datetime(year, mon, day, h, mi, s, tzinfo=UTC)
        # Roll back one year if the parsed date is more than 1 day in the future.
        if dt > now.replace(hour=23, minute=59, second=59) and (dt - now).days > 1:
            dt = dt.replace(year=year - 1)
        return dt

    raise ValueError(f"Cannot parse timestamp: {raw_ts!r}")


# ---------------------------------------------------------------------------
# Field splitting — isolate format details here
# ---------------------------------------------------------------------------

_SMBD_AUDIT_RE = re.compile(
    r"^(?P<ts_host>.+?)\s+smbd_audit:\s+(?P<payload>.+)$"
)
_REPEATED_MSG_RE = re.compile(
    r"^message repeated \d+ times:\s*\[\s*(.*?)\s*\]$"
)


def _sanitise(value: str) -> str:
    """Truncate *value* to ``_MAX_FIELD_LEN`` characters."""
    return value[:_MAX_FIELD_LEN]


def _split_fields(line: str) -> dict[str, str] | None:  # noqa: C901
    """Isolate Samba log-line format details.

    Parses a single raw log line and returns a flat dict of field names →
    string values.  Returns ``None`` if the line cannot be parsed.

    Supports:
    - Real Samba full_audit log lines with syslog or ISO-8601 microseconds timestamps.
    - Rsyslog repeated message compression ("message repeated X times: [...]").
    - Real Samba field patterns:
        openat|ok|r|<path>
        openat|ok|w|<path>
        close|ok|<path>
        mkdirat|ok|<path>
        unlinkat|ok|<path>
        renameat|ok|<old_path>|<new_path>
    - Short-prefix format: user|ip|op|result|...

    Args:
        line: Raw log line string.

    Returns:
        A dict with keys ``ts_raw``, ``host``, ``user``, ``ip``, ``machine``,
        ``share``, ``op``, ``result``, ``args``, ``path``, ``new_path``;
        or ``None`` on parse failure.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _SMBD_AUDIT_RE.match(line)
    if not m:
        return None

    ts_host_raw = m.group("ts_host").strip()
    payload = m.group("payload").strip()

    # Unwrap rsyslog repeated message compression if present
    rep_m = _REPEATED_MSG_RE.match(payload)
    if rep_m:
        payload = rep_m.group(1).strip()

    # Split ts_host_raw into timestamp + hostname.
    parts_th = ts_host_raw.rsplit(None, 1)
    if len(parts_th) != 2:
        return None
    ts_raw, host = parts_th

    # Pipe-split the payload.
    fields = payload.split("|")

    # --- Operation-position sniffing ---
    # Short prefix:  user|ip|op|result|[flags|]path[|new_path]    → op at index 2
    # Full prefix:   user|ip|machine|share|op|result|[flags|]path[|new_path] → op at index 4
    machine = ""
    share = ""
    op_idx: int | None = None

    if len(fields) >= 4 and fields[2].lower() in KNOWN_OPS:
        op_idx = 2  # short prefix
    elif len(fields) >= 6 and fields[4].lower() in KNOWN_OPS:
        op_idx = 4  # full prefix
        machine = _sanitise(fields[2])
        share = _sanitise(fields[3])
    else:
        # Fall back: scan first 6 positions for a known op.
        for i in range(min(6, len(fields))):
            if fields[i].lower() in KNOWN_OPS:
                op_idx = i
                if i >= 4 and len(fields) > 3:
                    machine = _sanitise(fields[2])
                    share = _sanitise(fields[3])
                break

    if op_idx is None or len(fields) < op_idx + 2:
        return None

    user = _sanitise(fields[0])
    ip = _sanitise(fields[1])
    op = fields[op_idx].lower()
    result = fields[op_idx + 1].lower() if len(fields) > op_idx + 1 else ""

    # Everything after result
    remaining = fields[op_idx + 2 :]

    if op in {"renameat", "rename"}:
        if len(remaining) >= 2:
            args_parts = remaining[:-2]
            path = _sanitise(remaining[-2])
            new_path = _sanitise(remaining[-1])
        else:
            return None
    elif op in {"close", "mkdirat", "unlinkat"}:
        if len(remaining) == 1:
            args_parts = []
            path = _sanitise(remaining[0])
            new_path = ""
        elif len(remaining) > 1:
            args_parts = remaining[:-1]
            path = _sanitise(remaining[-1])
            new_path = ""
        else:
            return None
    elif op in {"openat", "open"}:
        if len(remaining) >= 2:
            args_parts = remaining[:-1]
            path = _sanitise(remaining[-1])
            new_path = ""
        elif len(remaining) == 1:
            args_parts = []
            path = _sanitise(remaining[0])
            new_path = ""
        else:
            return None
    else:
        args_parts = remaining[:-1] if len(remaining) > 1 else []
        path = _sanitise(remaining[-1]) if remaining else ""
        new_path = ""

    args = "|".join(args_parts)

    return {
        "ts_raw": ts_raw,
        "host": _sanitise(host),
        "user": user,
        "ip": ip,
        "machine": machine,
        "share": share,
        "op": op,
        "result": result,
        "args": args,
        "path": path,
        "new_path": new_path,
    }


def _resolve_path_and_rel(
    raw_path: str,
    share: str,
    roots: dict[str, str],
) -> tuple[bool, str, str]:
    """Validate path against configured share roots and return (is_valid, abs_path, rel_path)."""
    if not raw_path:
        return False, "", ""

    norm = raw_path.replace("\\", "/")
    clean = norm.rstrip("/")
    if not clean:
        clean = "/"

    # Determine candidate share roots
    candidate_roots: list[str] = []
    if share in roots:
        candidate_roots.append(roots[share])
    elif share.lower() in roots:
        candidate_roots.append(roots[share.lower()])
    else:
        candidate_roots = [r for r in roots.values() if r]

    # Check if absolute path
    is_absolute = norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":")
    if is_absolute:
        for root in candidate_roots:
            clean_root = root.rstrip("/")
            if clean == clean_root:
                # Target is the share root directory itself
                return True, raw_path, ""
            if clean.startswith(clean_root + "/"):
                rel = clean[len(clean_root) + 1 :]
                if ".." in rel.split("/"):
                    return False, "", ""
                return True, raw_path, rel
        # Absolute path outside every candidate share root
        return False, "", ""

    # Relative path (e.g. from unit tests or relative logs)
    parts = [p for p in norm.split("/") if p and p != "."]
    if ".." in parts:
        return False, "", ""
    rel = "/".join(parts)
    return True, raw_path, rel


# ---------------------------------------------------------------------------
# Public parse functions
# ---------------------------------------------------------------------------


def parse_line(line: str) -> AuditEvent | None:
    """Parse a single vfs_full_audit log line.

    Args:
        line: Raw log line (may be untrusted; file names are sanitised and
              never executed).

    Returns:
        An :class:`AuditEvent` if the line is parseable, ``None`` otherwise.
        Increments :data:`malformed_count` for every unparseable non-blank,
        non-comment line, and :data:`outside_share_count` for paths escaping
        all configured share roots.
    """
    global malformed_count, outside_share_count  # noqa: PLW0603
    fields = _split_fields(line)
    if fields is None:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            malformed_count += 1
        return None

    try:
        ts = _parse_timestamp(fields["ts_raw"])
    except ValueError:
        malformed_count += 1
        return None

    roots = get_share_roots()
    ok_path, abs_path, rel_path = _resolve_path_and_rel(fields["path"], fields["share"], roots)
    if not ok_path:
        outside_share_count += 1
        return None

    abs_new_path = ""
    new_rel_path = ""
    if fields["new_path"]:
        ok_new, abs_new, new_rel = _resolve_path_and_rel(fields["new_path"], fields["share"], roots)
        if not ok_new:
            outside_share_count += 1
            return None
        abs_new_path = abs_new
        new_rel_path = new_rel

    return AuditEvent(
        ts=ts,
        host=fields["host"],
        user=fields["user"],
        ip=fields["ip"],
        machine=fields["machine"],
        share=fields["share"],
        op=fields["op"],
        result=fields["result"],
        args=fields["args"],
        path=abs_path,
        rel_path=rel_path,
        new_path=abs_new_path,
        new_rel_path=new_rel_path,
        raw=line.rstrip("\n"),
    )


def parse_lines(lines: list[str]) -> list[AuditEvent]:
    """Parse multiple log lines, silently skipping unparseable ones.

    Malformed lines increment :data:`malformed_count` rather than raising.

    Args:
        lines: Sequence of raw log lines.

    Returns:
        List of successfully parsed :class:`AuditEvent` objects in input order.
    """
    events: list[AuditEvent] = []
    for line in lines:
        event = parse_line(line)
        if event is not None:
            events.append(event)
    return events


# ---------------------------------------------------------------------------
# follow() – tail-F style file follower
# ---------------------------------------------------------------------------


def follow(
    path: Path | str,
    poll_interval: float = 0.25,
    *,
    reopen_on_shrink: bool = True,
    stop_event: threading.Event | None = None,
) -> Generator[str, None, None]:
    """Yield new log lines from *path* as they are appended, like ``tail -F``.

    Handles file rotation and truncation by re-opening the file when it
    shrinks (common on Linux logrotate and Windows log-roll setups) or when
    its inode/file identity changes.
    Supports cooperative cancellation via ``stop_event``.

    Args:
        path:             Path to the log file to follow.
        poll_interval:    Seconds between polls when no new data arrives.
        reopen_on_shrink: If ``True`` (default), re-open the file from the
                          beginning when its size decreases or inode changes (rotation detected).
        stop_event:       Optional threading.Event to signal termination.

    Yields:
        Raw log lines (including the newline character).
    """
    p = Path(path)
    fh = None
    last_size: int = 0
    last_ino: int | None = None

    def _sleep_poll() -> None:
        if stop_event is not None:
            stop_event.wait(poll_interval)
        else:
            time.sleep(poll_interval)

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break

            try:
                st = p.stat()
                current_size = st.st_size
                current_ino = getattr(st, "st_ino", None)
            except (FileNotFoundError, PermissionError):
                # File doesn't exist yet (pre-rotation gap or delayed appearance) — wait.
                if fh is not None:
                    fh.close()
                    fh = None
                    last_size = 0
                    last_ino = None
                _sleep_poll()
                continue

            # Detect truncation / rotation.
            rotated = bool(
                (last_ino is not None and current_ino is not None and current_ino != last_ino)
                or (reopen_on_shrink and current_size < last_size)
            )

            if rotated and fh is not None:
                try:
                    remaining = fh.readlines()
                    if remaining:
                        yield from remaining
                except Exception:
                    pass
                fh.close()
                fh = None

            if stop_event is not None and stop_event.is_set():
                break

            if fh is None:
                try:
                    fh = p.open("r", encoding="utf-8", errors="replace")
                    last_size = 0
                    last_ino = current_ino
                except (FileNotFoundError, PermissionError):
                    _sleep_poll()
                    continue

            # Read any new content.
            new_lines = fh.readlines()
            if new_lines:
                last_size = fh.tell()
                last_ino = current_ino
                yield from new_lines
            else:
                _sleep_poll()
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# replay() – log-file replayer with speed control
# ---------------------------------------------------------------------------


def replay(
    path: Path,
    speed: float = 1.0,
) -> Generator[tuple[AuditEvent, float], None, None]:
    """Replay a log file, yielding ``(event, sleep_seconds)`` pairs.

    The caller is responsible for calling ``time.sleep(sleep_seconds)`` to
    honour the original event cadence at the chosen speed multiplier.

    Args:
        path:  Path to a log file to replay.
        speed: Speed multiplier.  ``1.0`` = real time, ``10.0`` = 10× faster.

    Yields:
        ``(AuditEvent, sleep_seconds)`` — parsed event and seconds to sleep
        *before* processing the next event to maintain the original timing.
    """
    p = Path(path)
    prev_ts: datetime | None = None
    for raw_line in p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True):
        event = parse_line(raw_line)
        if event is None:
            continue
        if prev_ts is not None:
            delta = (event.ts - prev_ts).total_seconds()
            sleep_secs = max(0.0, delta / speed)
        else:
            sleep_secs = 0.0
        prev_ts = event.ts
        yield event, sleep_secs
