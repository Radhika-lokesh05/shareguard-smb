"""
server/tests/test_parser.py – Unit tests for shareguard.parser.

Covers:
- Parsing each real line from lab/sample_audit.log.
- Short-prefix vs full-prefix format detection.
- ISO-8601 and syslog timestamp parsing.
- Malformed lines return None and increment malformed_count.
- rename / renameat path extraction.
- replay() yields events in chronological order.
- follow() detects truncation (rotation simulation).
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

import shareguard.parser as parser_mod
from shareguard.parser import (
    AuditEvent,
    follow,
    parse_line,
    parse_lines,
    replay,
    reset_malformed_count,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Path to the shared sample log file (relative to workspace root).
_SAMPLE_LOG = Path(__file__).parent.parent.parent / "lab" / "sample_audit.log"

# Marker string present in a placeholder (not-yet-real) sample log.
_PLACEHOLDER_MARKERS = {"TODO", "placeholder", "PLACEHOLDER"}


def _is_placeholder(path: Path) -> bool:
    """Return True if sample_audit.log is still the original placeholder."""
    if not path.exists():
        return True
    text = path.read_text(encoding="utf-8")
    return all(m not in text for m in {"smbd_audit"})


# ---------------------------------------------------------------------------
# sample_audit.log round-trip
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    _is_placeholder(_SAMPLE_LOG),
    reason="lab/sample_audit.log is still the placeholder — add real log lines to enable this test.",
)
def test_sample_log_parses_all_non_comment_lines() -> None:
    """Every non-blank, non-comment line in sample_audit.log must parse cleanly."""
    reset_malformed_count()
    parser_mod.reset_outside_share_count()
    lines = _SAMPLE_LOG.read_text(encoding="utf-8").splitlines(keepends=True)
    data_lines = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    events = parse_lines(data_lines)
    assert len(events) == len(data_lines), (
        f"Expected {len(data_lines)} events, got {len(events)}. "
        f"Malformed count: {parser_mod.malformed_count}, "
        f"Outside share count: {parser_mod.outside_share_count}"
    )
    assert parser_mod.malformed_count == 0
    assert parser_mod.outside_share_count == 0


@pytest.mark.skipif(
    _is_placeholder(_SAMPLE_LOG),
    reason="lab/sample_audit.log is still the placeholder.",
)
def test_sample_log_full_prefix_fields() -> None:
    """Real full-prefix lines should populate machine, share, and user fields."""
    lines = _SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    full_lines = [ln for ln in lines if "client-pc|Finance" in ln and "openat" in ln]
    assert full_lines, "No full-prefix client-pc|Finance line found in sample_audit.log"
    evt = parse_line(full_lines[0])
    assert evt is not None
    assert evt.machine == "client-pc"
    assert evt.share == "Finance"
    assert evt.user == "alice"
    assert evt.ip == "192.168.56.1"
    assert evt.op == "openat"


@pytest.mark.skipif(
    _is_placeholder(_SAMPLE_LOG),
    reason="lab/sample_audit.log is still the placeholder.",
)
def test_sample_log_rename_new_path() -> None:
    """renameat lines must populate both path and new_path and relative paths."""
    lines = _SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    rename_lines = [ln for ln in lines if "renameat" in ln]
    assert rename_lines, "No renameat line found in sample_audit.log"
    evt = parse_line(rename_lines[0])
    assert evt is not None
    assert evt.op == "renameat"
    assert evt.path != ""
    assert evt.new_path != ""
    assert evt.path != evt.new_path
    assert evt.rel_path != ""
    assert evt.new_rel_path != ""


@pytest.mark.skipif(
    _is_placeholder(_SAMPLE_LOG),
    reason="lab/sample_audit.log is still the placeholder.",
)
def test_sample_log_iso_timestamp() -> None:
    """ISO-8601 timestamp lines with microseconds parse with correct UTC datetime."""
    lines = _SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    iso_lines = [ln for ln in lines if ln.startswith("2026-")]
    assert iso_lines, "No ISO-8601 timestamp line found in sample_audit.log"
    evt = parse_line(iso_lines[0])
    assert evt is not None
    assert evt.ts.year == 2026
    assert evt.ts.tzinfo is not None
    assert evt.ts.microsecond > 0


def test_real_line_openat_read() -> None:
    """Real openat read line parses correct mode and share root directory."""
    line = "2026-10-11T12:57:58.739451+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "openat"
    assert evt.result == "ok"
    assert evt.args == "r"
    assert evt.path == "/srv/shares/Finance"
    assert evt.rel_path == ""  # share root itself
    assert evt.user == "alice"
    assert evt.ip == "192.168.56.1"
    assert evt.machine == "client-pc"
    assert evt.share == "Finance"


def test_real_line_openat_write() -> None:
    """Real openat write line parses 'w' argument and relative path."""
    line = "2026-10-11T12:58:52.353669+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|w|/srv/shares/Finance/test/a.txt"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "openat"
    assert evt.result == "ok"
    assert evt.args == "w"
    assert evt.path == "/srv/shares/Finance/test/a.txt"
    assert evt.rel_path == "test/a.txt"


def test_real_line_close() -> None:
    """Real close line has no flag field and parses path cleanly."""
    line = "2026-10-11T12:57:58.752634+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|close|ok|/srv/shares/Finance"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "close"
    assert evt.result == "ok"
    assert evt.args == ""
    assert evt.path == "/srv/shares/Finance"
    assert evt.rel_path == ""


def test_real_line_mkdirat() -> None:
    """Real mkdirat line parses path without flags."""
    line = "2026-10-11T12:59:41.705239+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|mkdirat|ok|/srv/shares/Finance/samples"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "mkdirat"
    assert evt.result == "ok"
    assert evt.args == ""
    assert evt.path == "/srv/shares/Finance/samples"
    assert evt.rel_path == "samples"


def test_real_line_unlinkat() -> None:
    """Real unlinkat line parses target path without flags."""
    line = "2026-10-11T12:58:52.743693+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|unlinkat|ok|/srv/shares/Finance/test/b.txt"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "unlinkat"
    assert evt.result == "ok"
    assert evt.args == ""
    assert evt.path == "/srv/shares/Finance/test/b.txt"
    assert evt.rel_path == "test/b.txt"


def test_real_line_renameat() -> None:
    """Real renameat line parses old and new paths and relative destinations."""
    line = "2026-10-11T12:58:52.389421+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|renameat|ok|/srv/shares/Finance/test/a.txt|/srv/shares/Finance/test/b.txt"
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "renameat"
    assert evt.result == "ok"
    assert evt.args == ""
    assert evt.path == "/srv/shares/Finance/test/a.txt"
    assert evt.new_path == "/srv/shares/Finance/test/b.txt"
    assert evt.rel_path == "test/a.txt"
    assert evt.new_rel_path == "test/b.txt"


def test_real_line_rsyslog_message_repeated() -> None:
    """Rsyslog 'message repeated X times: [...]' wrapper is unwrapped and parsed."""
    line = "2026-10-11T12:59:41.698637+00:00 fileserver smbd_audit: message repeated 2 times: [ alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance]"
    evt = parse_line(line)
    assert evt is not None
    assert evt.user == "alice"
    assert evt.ip == "192.168.56.1"
    assert evt.machine == "client-pc"
    assert evt.share == "Finance"
    assert evt.op == "openat"
    assert evt.args == "r"
    assert evt.path == "/srv/shares/Finance"
    assert evt.rel_path == ""


def test_path_outside_share_root_rejected_and_counted() -> None:
    """Paths escaping configured share roots return None and increment outside_share_count."""
    parser_mod.reset_outside_share_count()
    line = "2026-10-11T12:57:58.739451+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/etc/passwd"
    evt = parse_line(line)
    assert evt is None
    assert parser_mod.outside_share_count == 1


def test_directory_noise_handling() -> None:
    """Folder opens/closes from Windows Explorer do not count as file reads."""
    from shareguard.features import compute_features

    raw_lines = [
        "2026-10-11T12:57:58.739451+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance",
        "2026-10-11T12:57:58.752476+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance/",
        "2026-10-11T12:57:58.752634+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|close|ok|/srv/shares/Finance",
        "2026-10-11T12:58:52.142480+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance/test",
        "2026-10-11T12:58:52.146204+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|close|ok|/srv/shares/Finance/test",
        # Real file open and close
        "2026-10-11T12:58:52.382054+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|openat|ok|r|/srv/shares/Finance/test/a.txt",
        "2026-10-11T12:58:52.382323+00:00 fileserver smbd_audit: alice|192.168.56.1|client-pc|Finance|close|ok|/srv/shares/Finance/test/a.txt",
    ]
    events = [parse_line(ln) for ln in raw_lines]
    valid_events = [e for e in events if e is not None]
    assert len(valid_events) == len(raw_lines)

    features = compute_features(valid_events, client_ip="192.168.56.1", username="alice")
    # Only test/a.txt is a file read; folder opens on /srv/shares/Finance and /srv/shares/Finance/test are filtered out
    assert features.read_count == 1


def test_simulator_output_parses_with_real_parser() -> None:
    """Simulator output lines parse cleanly with the real parser."""
    from lab.simulate_log import scenario_attack_fast, scenario_normal_office

    reset_malformed_count()
    parser_mod.reset_outside_share_count()

    now = datetime.now(tz=UTC)
    sim_lines = [
        sl.line
        for sl in list(scenario_normal_office(now, duration=5.0, seed=42))
        + list(scenario_attack_fast(now, duration=5.0, seed=42))
    ]
    parsed_events = [parse_line(ln) for ln in sim_lines]
    assert all(e is not None for e in parsed_events)
    assert parser_mod.malformed_count == 0
    assert parser_mod.outside_share_count == 0


# ---------------------------------------------------------------------------
# Inline unit tests (no file dependency)
# ---------------------------------------------------------------------------


def _make_syslog_line(
    user: str = "alice",
    ip: str = "192.168.1.10",
    op: str = "openat",
    path: str = "docs/file.docx",
    new_path: str = "",
    result: str = "ok",
    flags: str = "0x20",
    machine: str = "",
    share: str = "",
) -> str:
    """Build a synthetic log line for testing."""
    ts = "Oct  3 12:01:05"
    host = "fileserver"
    if machine and share:
        if op in {"renameat", "rename"} and new_path:
            payload = f"{user}|{ip}|{machine}|{share}|{op}|{result}|{path}|{new_path}"
        else:
            payload = f"{user}|{ip}|{machine}|{share}|{op}|{result}|{flags}|{path}"
    else:
        if op in {"renameat", "rename"} and new_path:
            payload = f"{user}|{ip}|{op}|{result}|{path}|{new_path}"
        else:
            payload = f"{user}|{ip}|{op}|{result}|{flags}|{path}"
    return f"{ts} {host} smbd_audit: {payload}"


def test_parse_line_short_prefix_openat() -> None:
    """Short-prefix openat line parses all fields correctly."""
    line = _make_syslog_line()
    evt = parse_line(line)
    assert evt is not None
    assert isinstance(evt, AuditEvent)
    assert evt.user == "alice"
    assert evt.ip == "192.168.1.10"
    assert evt.op == "openat"
    assert evt.result == "ok"
    assert evt.path == "docs/file.docx"
    assert evt.new_path == ""
    assert evt.machine == ""
    assert evt.share == ""
    assert evt.host == "fileserver"


def test_parse_line_full_prefix_openat() -> None:
    """Full-prefix openat line populates machine and share."""
    line = _make_syslog_line(machine="MYPC", share="data")
    evt = parse_line(line)
    assert evt is not None
    assert evt.machine == "MYPC"
    assert evt.share == "data"
    assert evt.op == "openat"


def test_parse_line_renameat_short_prefix() -> None:
    """Short-prefix renameat line: path and new_path are distinct."""
    line = _make_syslog_line(op="renameat", path="a/b.docx", new_path="a/b.docx.locked")
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "renameat"
    assert evt.path == "a/b.docx"
    assert evt.new_path == "a/b.docx.locked"


def test_parse_line_renameat_full_prefix() -> None:
    """Full-prefix renameat line: path and new_path are distinct."""
    line = _make_syslog_line(
        op="renameat", path="a/b.docx", new_path="a/b.docx.locked", machine="PC", share="share1"
    )
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "renameat"
    assert evt.path == "a/b.docx"
    assert evt.new_path == "a/b.docx.locked"


def test_parse_line_iso_timestamp() -> None:
    """ISO-8601 timestamp is parsed correctly."""
    line = "2024-10-03T12:01:05+00:00 fileserver smbd_audit: alice|192.168.1.10|openat|ok|0x20|docs/f.pdf"
    evt = parse_line(line)
    assert evt is not None
    assert evt.ts == datetime(2024, 10, 3, 12, 1, 5, tzinfo=UTC)


def test_parse_line_syslog_year_inference() -> None:
    """Syslog timestamp without year: inferred year must be current or prior year."""
    line = _make_syslog_line()
    evt = parse_line(line)
    assert evt is not None
    now = datetime.now(tz=UTC)
    assert evt.ts.year in {now.year, now.year - 1}


def test_parse_line_malformed_returns_none_and_increments() -> None:
    """Malformed lines return None and increment malformed_count."""
    reset_malformed_count()
    result = parse_line("this is not a valid log line at all!!!")
    assert result is None
    assert parser_mod.malformed_count == 1


def test_parse_line_blank_returns_none_no_increment() -> None:
    """Blank lines return None without incrementing malformed_count."""
    reset_malformed_count()
    result = parse_line("   ")
    assert result is None
    assert parser_mod.malformed_count == 0


def test_parse_line_comment_returns_none_no_increment() -> None:
    """Comment lines (starting with #) return None without incrementing."""
    reset_malformed_count()
    result = parse_line("# this is a comment")
    assert result is None
    assert parser_mod.malformed_count == 0


def test_parse_lines_batch() -> None:
    """parse_lines skips malformed entries and returns only valid events."""
    reset_malformed_count()
    lines = [
        _make_syslog_line(op="openat"),
        "garbage line !!!",
        _make_syslog_line(op="close"),
        "   ",
    ]
    events = parse_lines(lines)
    assert len(events) == 2
    assert parser_mod.malformed_count == 1


def test_parse_line_unlinkat() -> None:
    """unlinkat lines parse correctly with an empty new_path."""
    line = _make_syslog_line(op="unlinkat", path="docs/old.docx")
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "unlinkat"
    assert evt.new_path == ""


def test_parse_line_mkdirat() -> None:
    """mkdirat lines parse correctly."""
    line = _make_syslog_line(op="mkdirat", path="docs/new_dir")
    evt = parse_line(line)
    assert evt is not None
    assert evt.op == "mkdirat"


def test_field_sanitisation_truncates_long_strings() -> None:
    """Untrusted fields longer than _MAX_FIELD_LEN are truncated."""
    long_path = "a/" + "x" * 600
    line = _make_syslog_line(path=long_path)
    evt = parse_line(line)
    assert evt is not None
    assert len(evt.path) <= 512


def test_raw_field_preserved() -> None:
    """The raw field on AuditEvent contains the original line."""
    line = _make_syslog_line()
    evt = parse_line(line)
    assert evt is not None
    assert evt.raw == line.rstrip("\n")


# ---------------------------------------------------------------------------
# replay() tests
# ---------------------------------------------------------------------------


def _write_sample_log(path: Path, n: int = 5) -> None:
    """Write *n* consecutive synthetic log lines to *path*."""
    with path.open("w", encoding="utf-8") as fh:
        for i in range(n):
            ts = f"Oct  3 12:01:{i + 1:02d}"
            line = f"{ts} fileserver smbd_audit: alice|192.168.1.10|openat|ok|0x20|docs/file_{i}.docx\n"
            fh.write(line)


def test_replay_yields_events_in_order(tmp_path: Path) -> None:
    """replay() yields AuditEvent objects in timestamp order."""
    log = tmp_path / "test.log"
    _write_sample_log(log, n=5)
    results = list(replay(log, speed=1000.0))
    assert len(results) == 5
    timestamps = [evt.ts for evt, _ in results]
    assert timestamps == sorted(timestamps)


def test_replay_first_sleep_is_zero(tmp_path: Path) -> None:
    """The first yielded event has zero sleep time."""
    log = tmp_path / "test.log"
    _write_sample_log(log, n=3)
    results = list(replay(log, speed=1.0))
    assert results[0][1] == 0.0


def test_replay_sleep_compressed_by_speed(tmp_path: Path) -> None:
    """Higher speed → smaller sleep values."""
    log = tmp_path / "test.log"
    _write_sample_log(log, n=3)
    results_slow = list(replay(log, speed=1.0))
    results_fast = list(replay(log, speed=10.0))
    slow_sleeps = [s for _, s in results_slow if s > 0]
    fast_sleeps = [s for _, s in results_fast if s > 0]
    if slow_sleeps:
        assert all(f < s for f, s in zip(fast_sleeps, slow_sleeps, strict=False))


def test_replay_skips_malformed(tmp_path: Path) -> None:
    """replay() silently skips malformed lines."""
    log = tmp_path / "mixed.log"
    log.write_text(
        "Oct  3 12:01:01 fileserver smbd_audit: alice|192.168.1.10|openat|ok|0x20|file.docx\n"
        "this is garbage\n"
        "Oct  3 12:01:02 fileserver smbd_audit: alice|192.168.1.10|close|ok|0x20|file.docx\n",
        encoding="utf-8",
    )
    results = list(replay(log, speed=1000.0))
    assert len(results) == 2


# ---------------------------------------------------------------------------
# follow() rotation/truncation test
# ---------------------------------------------------------------------------


def test_follow_detects_truncation(tmp_path: Path) -> None:
    """follow() re-reads from the beginning when the file shrinks."""
    log = tmp_path / "follow_test.log"

    collected: list[str] = []
    stop_event = threading.Event()

    def _follow_thread() -> None:
        gen = follow(log, poll_interval=0.05)
        for line in gen:
            collected.append(line.strip())
            if len(collected) >= 4:
                stop_event.set()
                break

    # Write 2 initial lines, then truncate (rotation) and write 2 new lines.
    log.write_text(
        "Oct  3 12:01:01 fileserver smbd_audit: alice|192.168.1.10|openat|ok|0x20|a.docx\n"
        "Oct  3 12:01:02 fileserver smbd_audit: alice|192.168.1.10|close|ok|0x20|a.docx\n",
        encoding="utf-8",
    )

    t = threading.Thread(target=_follow_thread, daemon=True)
    t.start()
    time.sleep(0.2)

    # Simulate rotation: truncate and write new lines.
    log.write_text(
        "Oct  3 12:01:03 fileserver smbd_audit: bob|192.168.1.11|openat|ok|0x20|b.xlsx\n"
        "Oct  3 12:01:04 fileserver smbd_audit: bob|192.168.1.11|close|ok|0x20|b.xlsx\n",
        encoding="utf-8",
    )

    stop_event.wait(timeout=3.0)
    t.join(timeout=1.0)

    assert len(collected) >= 4, f"Expected ≥4 lines, got {len(collected)}: {collected}"
    assert any("alice" in ln for ln in collected)
    assert any("bob" in ln for ln in collected)
