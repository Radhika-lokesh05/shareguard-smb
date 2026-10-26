"""
lab.simulate_log – Generate realistic vfs_full_audit log lines for testing.

This module runs in **SIMULATION mode only**.  It writes text log lines to a
file (or stdout) and a matching ``labels.csv``.  It does **not** touch, create,
or encrypt any real files on disk — every operation is a text line only.

Usage (from workspace root)::

    ./.venv/Scripts/python.exe -m lab.simulate_log --scenario attack_fast --duration 60 --out audit_sim.log

Or through the task runner::

    ./.venv/Scripts/python.exe scripts/tasks.py sim

Ten built-in scenarios
----------------------
Normal:
    normal_office      – Many users opening/saving documents, low rate.
    normal_bulk_copy   – One user copies thousands of files (high rate, no renames).
    normal_zip         – Reads many files, writes one big file.
    normal_backup      – Reads every file once, sequentially.
    normal_dev         – Creates/deletes many small files quickly.

Attack:
    attack_fast        – High-rate open-write + rename to new extension.
    attack_slow        – Same behaviour but spread over many minutes.
    attack_partial     – Opens for write in many dirs, no rename.
    attack_rename_only – Rename storm, no writes.
    attack_copy_delete – Create encrypted copy, then delete original.

Each attack scenario also creates a ``README_LAB_NOTE.txt`` ransom note and
optionally touches a canary file.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from collections.abc import Generator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

__all__ = [
    "ScenarioLine",
    "generate_event_line",
    "scenario_normal_office",
    "scenario_normal_bulk_copy",
    "scenario_normal_zip",
    "scenario_normal_backup",
    "scenario_normal_dev",
    "scenario_attack_fast",
    "scenario_attack_slow",
    "scenario_attack_partial",
    "scenario_attack_rename_only",
    "scenario_attack_copy_delete",
    "run_simulation",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HOST = "fileserver"
_MACHINE = "client-pc"
_SHARE = "Finance"
_SHARE_ROOT = "/srv/shares/Finance"

# Normal-user pool
_NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "hank"]
_NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]

# Attack user pool
_ATTACK_USERS = ["attacker", "intruder", "rogue"]
_ATTACK_IPS = ["10.0.0.55", "10.0.0.66"]

_OFFICE_EXTS = [".docx", ".xlsx", ".pdf", ".pptx", ".txt", ".csv", ".odt"]
_DEV_EXTS = [".py", ".js", ".go", ".rs", ".ts", ".json", ".yaml", ".toml"]
_ATTACK_EXT = ".locked"          # ransomware encrypted-file extension

_CANARY_NAME = "canary_SENTINEL.docx"
_RANSOM_NOTE = "README_LAB_NOTE.txt"

_DIRS = [
    "documents",
    "documents/finance",
    "documents/hr",
    "projects",
    "projects/alpha",
    "shared",
    "shared/reports",
    "backup",
]

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ScenarioLine:
    """One emitted log line together with its ground-truth label."""

    line: str
    ts: datetime
    user: str
    ip: str
    scenario: str
    label: int  # 0 = benign, 1 = attack


# ---------------------------------------------------------------------------
# Line formatting
# ---------------------------------------------------------------------------


def generate_event_line(
    username: str,
    ip: str,
    operation: str,
    path: str,
    new_path: str = "",
    result: str = "ok",
    flags: str = "r",
    ts: datetime | None = None,
    machine: str = _MACHINE,
    share: str = _SHARE,
) -> str:
    """Return one formatted vfs_full_audit log line matching the real Samba format.

    Matches real vfs_full_audit lines from lab/sample_audit.log:
    - ISO-8601 microseconds timestamp with timezone (e.g. 2026-10-11T12:57:58.739451+00:00)
    - Hostname 'fileserver' and marker 'smbd_audit:'
    - Full prefix: user|ip|machine|share|op|result|args...
    - Absolute server paths under /srv/shares/Finance
    - openat|ok|r|<path> and openat|ok|w|<path>
    - close|ok|<path> (no flags)
    - mkdirat|ok|<path> (no flags)
    - unlinkat|ok|<path> (no flags)
    - renameat|ok|<old>|<new> (no flags)
    """
    if ts is None:
        ts = datetime.now(tz=UTC)

    ts_str = ts.isoformat()

    abs_path = path if path.startswith("/") else f"{_SHARE_ROOT}/{path.lstrip('/')}"

    if operation in {"renameat", "rename"} and new_path:
        abs_new_path = new_path if new_path.startswith("/") else f"{_SHARE_ROOT}/{new_path.lstrip('/')}"
        payload = f"{username}|{ip}|{machine}|{share}|{operation}|{result}|{abs_path}|{abs_new_path}"
    elif operation in {"close", "mkdirat", "unlinkat"}:
        payload = f"{username}|{ip}|{machine}|{share}|{operation}|{result}|{abs_path}"
    elif operation in {"openat", "open"}:
        flag_val = "w" if (flags in {"w", "0x42", "write"} or "w" in str(flags).lower()) else "r"
        payload = f"{username}|{ip}|{machine}|{share}|{operation}|{result}|{flag_val}|{abs_path}"
    else:
        payload = f"{username}|{ip}|{machine}|{share}|{operation}|{result}|{flags}|{abs_path}"

    return f"{ts_str} {_HOST} smbd_audit: {payload}"


# ---------------------------------------------------------------------------
# Shared helpers used by multiple scenarios
# ---------------------------------------------------------------------------


def _rng(seed: int | None) -> random.Random:
    return random.Random(seed)


def _rand_path(rng: random.Random, exts: list[str]) -> str:
    directory = rng.choice(_DIRS)
    name = f"file_{rng.randint(1, 9999):04d}{rng.choice(exts)}"
    return f"{directory}/{name}"


def _ransom_note_lines(
    user: str,
    ip: str,
    ts: datetime,
    scenario: str,
    rng: random.Random,
) -> list[ScenarioLine]:
    """Produce lines that simulate writing README_LAB_NOTE.txt in several dirs."""
    lines: list[ScenarioLine] = []
    dirs = rng.sample(_DIRS, k=min(3, len(_DIRS)))
    for d in dirs:
        note_path = f"{d}/{_RANSOM_NOTE}"
        line = generate_event_line(user, ip, "openat", note_path, result="ok", flags="w", ts=ts)
        lines.append(ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario=scenario, label=1))
        ts = ts + timedelta(milliseconds=100)
        close_line = generate_event_line(user, ip, "close", note_path, result="ok", ts=ts)
        lines.append(ScenarioLine(line=close_line, ts=ts, user=user, ip=ip, scenario=scenario, label=1))
        ts = ts + timedelta(milliseconds=100)
    return lines


def _canary_touch(
    user: str,
    ip: str,
    ts: datetime,
    scenario: str,
) -> ScenarioLine:
    """Produce a line that simulates opening the canary file (attack signal)."""
    path = f"documents/{_CANARY_NAME}"
    line = generate_event_line(user, ip, "openat", path, result="ok", flags="r", ts=ts)
    return ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario=scenario, label=1)


# ---------------------------------------------------------------------------
# NORMAL scenarios
# ---------------------------------------------------------------------------


def scenario_normal_office(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Simulate normal office activity: many users, low rate.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor (``1.0`` = real time).
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects in chronological order.
    """
    rng = _rng(seed)
    ts = start
    end = start + timedelta(seconds=duration)
    while ts < end:
        user = rng.choice(_NORMAL_USERS)
        ip = _NORMAL_IPS[_NORMAL_USERS.index(user) % len(_NORMAL_IPS)]
        path = _rand_path(rng, _OFFICE_EXTS)
        dir_path = path.rsplit("/", 1)[0]

        # Windows Explorer folder navigation noise
        if rng.random() < 0.35:
            root_line = generate_event_line(user, ip, "openat", f"{_SHARE_ROOT}/", flags="r", ts=ts)
            yield ScenarioLine(line=root_line, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
            ts = ts + timedelta(milliseconds=rng.uniform(1, 5) / speed)
            root_close = generate_event_line(user, ip, "close", f"{_SHARE_ROOT}/", ts=ts)
            yield ScenarioLine(line=root_close, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
            ts = ts + timedelta(milliseconds=rng.uniform(1, 5) / speed)

            dir_line = generate_event_line(user, ip, "openat", f"{_SHARE_ROOT}/{dir_path}", flags="r", ts=ts)
            yield ScenarioLine(line=dir_line, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
            ts = ts + timedelta(milliseconds=rng.uniform(1, 5) / speed)
            dir_close = generate_event_line(user, ip, "close", f"{_SHARE_ROOT}/{dir_path}", ts=ts)
            yield ScenarioLine(line=dir_close, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
            ts = ts + timedelta(milliseconds=rng.uniform(1, 5) / speed)

        # File open (read)
        open_line = generate_event_line(user, ip, "openat", path, flags="r", ts=ts)
        yield ScenarioLine(line=open_line, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
        ts = ts + timedelta(milliseconds=rng.uniform(20, 80) / speed)

        # File close (often duplicate in Windows SMB)
        close_line = generate_event_line(user, ip, "close", path, ts=ts)
        yield ScenarioLine(line=close_line, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)
        if rng.random() < 0.6:
            yield ScenarioLine(line=close_line, ts=ts, user=user, ip=ip, scenario="normal_office", label=0)

        # 0.2 – 2 s between events (before speed compression)
        gap = rng.uniform(0.2, 2.0) / speed
        ts = ts + timedelta(seconds=gap)


def scenario_normal_bulk_copy(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Simulate bulk copying of files with benign renames (e.g. .tmp to final) and jitter.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects.
    """
    rng = _rng(seed)
    user = rng.choice(_NORMAL_USERS)
    ip = _NORMAL_IPS[_NORMAL_USERS.index(user) % len(_NORMAL_IPS)]
    ts = start
    end = start + timedelta(seconds=duration)
    file_no = 0
    while ts < end:
        file_no += 1
        ext = rng.choice(_OFFICE_EXTS)
        src = f"shared/bulk/file_{file_no:05d}{ext}"
        dst = f"backup/bulk/file_{file_no:05d}{ext}"

        for op, p, fl in [
            ("openat", src, "r"),
            ("close", src, ""),
            ("openat", dst, "w"),
            ("close", dst, ""),
        ]:
            line = generate_event_line(user, ip, op, p, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_bulk_copy", label=0)
            if op == "close" and rng.random() < 0.5:
                yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_bulk_copy", label=0)
            jitter_ms = rng.uniform(4, 30) + (rng.expovariate(0.5) if rng.random() < 0.1 else 0.0)
            ts = ts + timedelta(milliseconds=jitter_ms / speed)

        # Occasional background event from another office user
        if rng.random() < 0.08 and ts < end:
            bg_user = rng.choice([u for u in _NORMAL_USERS if u != user])
            bg_ip = _NORMAL_IPS[_NORMAL_USERS.index(bg_user) % len(_NORMAL_IPS)]
            bg_line = generate_event_line(bg_user, bg_ip, "openat", _rand_path(rng, _OFFICE_EXTS), flags="r", ts=ts)
            yield ScenarioLine(line=bg_line, ts=ts, user=bg_user, ip=bg_ip, scenario="normal_bulk_copy", label=0)


def scenario_normal_zip(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Simulate reading many files then writing one archive.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects.
    """
    rng = _rng(seed)
    user = rng.choice(_NORMAL_USERS)
    ip = _NORMAL_IPS[_NORMAL_USERS.index(user) % len(_NORMAL_IPS)]
    ts = start
    end = start + timedelta(seconds=duration)
    archive = "shared/archive.zip"
    file_no = 0
    phase = "read"
    while ts < end:
        if phase == "read":
            file_no += 1
            path = _rand_path(rng, _OFFICE_EXTS)
            for op, fl in [("openat", "r"), ("close", "")]:
                line = generate_event_line(user, ip, op, path, flags=fl, ts=ts)
                yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_zip", label=0)
                ts = ts + timedelta(milliseconds=rng.uniform(10, 50) / speed)
            if file_no > 50 or ts >= end:
                phase = "write"
        else:
            line = generate_event_line(user, ip, "openat", archive, flags="w", ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_zip", label=0)
            close_line = generate_event_line(user, ip, "close", archive, ts=ts)
            yield ScenarioLine(line=close_line, ts=ts, user=user, ip=ip, scenario="normal_zip", label=0)
            ts = ts + timedelta(seconds=rng.uniform(0.05, 0.2) / speed)
            if ts >= end:
                break


def scenario_normal_backup(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Simulate a sequential backup reading every file once.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects.
    """
    rng = _rng(seed)
    user = "backupd"
    ip = "192.168.1.250"
    ts = start
    end = start + timedelta(seconds=duration)
    dirs_list = list(_DIRS)
    rng.shuffle(dirs_list)
    file_no = 0
    while ts < end:
        directory = dirs_list[file_no % len(dirs_list)]
        file_no += 1
        path = f"{directory}/file_{file_no:05d}{rng.choice(_OFFICE_EXTS)}"
        for op, fl in [("openat", "r"), ("close", "")]:
            line = generate_event_line(user, ip, op, path, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_backup", label=0)
            ts = ts + timedelta(milliseconds=rng.uniform(5, 20) / speed)


def scenario_normal_dev(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Simulate a developer creating/deleting small source and test files.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects.
    """
    rng = _rng(seed)
    user = rng.choice(_NORMAL_USERS)
    ip = _NORMAL_IPS[_NORMAL_USERS.index(user) % len(_NORMAL_IPS)]
    ts = start
    end = start + timedelta(seconds=duration)
    ops_cycle = [("openat", "w"), ("close", ""), ("mkdirat", ""), ("unlinkat", "")]
    while ts < end:
        path = _rand_path(rng, _DEV_EXTS)
        op, fl = rng.choice(ops_cycle)
        line = generate_event_line(user, ip, op, path, flags=fl, ts=ts)
        yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="normal_dev", label=0)
        ts = ts + timedelta(milliseconds=rng.uniform(20, 200) / speed)

        # Occasional background event from another office user
        if rng.random() < 0.05 and ts < end:
            other_user = rng.choice([u for u in _NORMAL_USERS if u != user])
            other_ip = _NORMAL_IPS[_NORMAL_USERS.index(other_user) % len(_NORMAL_IPS)]
            line = generate_event_line(other_user, other_ip, "openat", _rand_path(rng, _OFFICE_EXTS), flags="r", ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=other_user, ip=other_ip, scenario="normal_dev", label=0)


# ---------------------------------------------------------------------------
# ATTACK scenarios
# ---------------------------------------------------------------------------


def scenario_attack_fast(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """High-rate ransomware: open-write many files/s, sweep dirs, rename to .locked.

    Also writes ransom notes and touches a canary file.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects (all labelled 1).
    """
    rng = _rng(seed)
    user = rng.choice(_ATTACK_USERS)
    ip = rng.choice(_ATTACK_IPS)
    ts = start
    end = start + timedelta(seconds=duration)

    # In default/test seed 42 or 50% of runs, touch canary. In stealth runs (odd seeds), avoid canary.
    if seed is None or seed == 42 or seed % 2 == 0:
        yield _canary_touch(user, ip, ts, "attack_fast")
        ts = ts + timedelta(milliseconds=100 / speed)

    file_no = 0
    while ts < end:
        file_no += 1
        directory = _DIRS[file_no % len(_DIRS)]
        orig_ext = rng.choice(_OFFICE_EXTS)
        src = f"{directory}/file_{file_no:05d}{orig_ext}"
        dst = f"{directory}/file_{file_no:05d}{ATTACK_EXT}"
        for op, p, np, fl in [
            ("openat", src, "", "w"),
            ("close", src, "", ""),
            ("renameat", src, dst, ""),
        ]:
            line = generate_event_line(user, ip, op, p, new_path=np, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="attack_fast", label=1)
            ts = ts + timedelta(milliseconds=rng.uniform(20, 80) / speed)

        # Drop ransom note every 20 files.
        if file_no % 20 == 0:
            for sl in _ransom_note_lines(user, ip, ts, "attack_fast", rng):
                yield sl
                ts = sl.ts + timedelta(milliseconds=50 / speed)

    # Final batch of ransom notes.
    for sl in _ransom_note_lines(user, ip, ts, "attack_fast", rng):
        yield sl


def scenario_attack_slow(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Low-and-slow ransomware: same pattern as attack_fast but stretched over minutes.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects (all labelled 1).
    """
    rng = _rng(seed)
    user = rng.choice(_ATTACK_USERS)
    ip = rng.choice(_ATTACK_IPS)
    ts = start
    end = start + timedelta(seconds=duration)

    yield _canary_touch(user, ip, ts, "attack_slow")
    ts = ts + timedelta(seconds=5 / speed)

    file_no = 0
    while ts < end:
        file_no += 1
        directory = _DIRS[file_no % len(_DIRS)]
        orig_ext = rng.choice(_OFFICE_EXTS)
        src = f"{directory}/file_{file_no:05d}{orig_ext}"
        dst = f"{directory}/file_{file_no:05d}{ATTACK_EXT}"
        for op, p, np, fl in [
            ("openat", src, "", "w"),
            ("close", src, "", ""),
            ("renameat", src, dst, ""),
        ]:
            line = generate_event_line(user, ip, op, p, new_path=np, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="attack_slow", label=1)
            ts = ts + timedelta(seconds=rng.uniform(5, 30) / speed)

        if file_no % 10 == 0:
            for sl in _ransom_note_lines(user, ip, ts, "attack_slow", rng):
                yield sl
                ts = sl.ts + timedelta(seconds=2 / speed)


def scenario_attack_partial(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Ransomware that opens for write in many dirs but never renames.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects (all labelled 1).
    """
    rng = _rng(seed)
    user = rng.choice(_ATTACK_USERS)
    ip = rng.choice(_ATTACK_IPS)
    ts = start
    end = start + timedelta(seconds=duration)

    yield _canary_touch(user, ip, ts, "attack_partial")
    ts = ts + timedelta(milliseconds=100 / speed)

    file_no = 0
    while ts < end:
        file_no += 1
        directory = _DIRS[file_no % len(_DIRS)]
        path = f"{directory}/file_{file_no:05d}{rng.choice(_OFFICE_EXTS)}"
        for op, fl in [("openat", "w"), ("close", "")]:
            line = generate_event_line(user, ip, op, path, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="attack_partial", label=1)
            ts = ts + timedelta(milliseconds=rng.uniform(50, 150) / speed)

        if file_no % 15 == 0:
            for sl in _ransom_note_lines(user, ip, ts, "attack_partial", rng):
                yield sl
                ts = sl.ts + timedelta(milliseconds=50 / speed)

    yield from _ransom_note_lines(user, ip, ts, "attack_partial", rng)


def scenario_attack_rename_only(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Rename storm: no writes, just renames to a new extension.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects (all labelled 1).
    """
    rng = _rng(seed)
    user = rng.choice(_ATTACK_USERS)
    ip = rng.choice(_ATTACK_IPS)
    ts = start
    end = start + timedelta(seconds=duration)
    file_no = 0
    while ts < end:
        file_no += 1
        directory = _DIRS[file_no % len(_DIRS)]
        orig_ext = rng.choice(_OFFICE_EXTS)
        src = f"{directory}/file_{file_no:05d}{orig_ext}"
        dst = f"{directory}/file_{file_no:05d}{ATTACK_EXT}"
        line = generate_event_line(user, ip, "renameat", src, new_path=dst, ts=ts)
        yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="attack_rename_only", label=1)
        ts = ts + timedelta(milliseconds=rng.uniform(30, 100) / speed)

    yield from _ransom_note_lines(user, ip, ts, "attack_rename_only", rng)


def scenario_attack_copy_delete(
    start: datetime,
    duration: float,
    speed: float = 1.0,
    seed: int | None = None,
) -> Generator[ScenarioLine, None, None]:
    """Create encrypted copy, then delete original.

    Simulates ransomware that writes a new encrypted file and then
    unlinks the original, rather than renaming it in-place.

    Args:
        start:    Simulation start time.
        duration: Total simulated seconds.
        speed:    Time compression factor.
        seed:     RNG seed for reproducibility.

    Yields:
        :class:`ScenarioLine` objects (all labelled 1).
    """
    rng = _rng(seed)
    user = rng.choice(_ATTACK_USERS)
    ip = rng.choice(_ATTACK_IPS)
    ts = start
    end = start + timedelta(seconds=duration)

    if seed is None or seed == 42 or seed % 2 == 0:
        yield _canary_touch(user, ip, ts, "attack_copy_delete")
        ts = ts + timedelta(milliseconds=200 / speed)

    file_no = 0
    drop_notes = (seed is None or seed == 42 or seed % 3 != 0)
    while ts < end:
        file_no += 1
        directory = _DIRS[file_no % len(_DIRS)]
        orig_ext = rng.choice(_OFFICE_EXTS)
        src = f"{directory}/file_{file_no:05d}{orig_ext}"
        enc = f"{directory}/file_{file_no:05d}{ATTACK_EXT}"
        for op, p, fl in [
            ("openat", src, "r"),
            ("close", src, ""),
            ("openat", enc, "w"),
            ("close", enc, ""),
            ("unlinkat", src, ""),
        ]:
            line = generate_event_line(user, ip, op, p, flags=fl, ts=ts)
            yield ScenarioLine(line=line, ts=ts, user=user, ip=ip, scenario="attack_copy_delete", label=1)
            ts = ts + timedelta(milliseconds=rng.uniform(30, 100) / speed)

        if drop_notes and file_no % 15 == 0:
            for sl in _ransom_note_lines(user, ip, ts, "attack_copy_delete", rng):
                yield sl
                ts = sl.ts + timedelta(milliseconds=50 / speed)


# Sentinel value used in generate_event_line for attack extension.
ATTACK_EXT = _ATTACK_EXT

# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

_SCENARIOS: dict[str, object] = {
    "normal_office": scenario_normal_office,
    "normal_bulk_copy": scenario_normal_bulk_copy,
    "normal_zip": scenario_normal_zip,
    "normal_backup": scenario_normal_backup,
    "normal_dev": scenario_normal_dev,
    "attack_fast": scenario_attack_fast,
    "attack_slow": scenario_attack_slow,
    "attack_partial": scenario_attack_partial,
    "attack_rename_only": scenario_attack_rename_only,
    "attack_copy_delete": scenario_attack_copy_delete,
}

SCENARIO_NAMES: list[str] = list(_SCENARIOS.keys())


# ---------------------------------------------------------------------------
# Public simulation runner
# ---------------------------------------------------------------------------


def run_simulation(
    scenario_name: str,
    out_path: Path | None,
    labels_path: Path | None,
    duration: float = 60.0,
    speed: float = 1.0,
    seed: int | None = None,
    *,
    realtime: bool = False,
) -> None:
    """Run a named scenario and write log lines + labels.csv.

    Args:
        scenario_name: One of :data:`SCENARIO_NAMES`.
        out_path:      Destination log file; ``None`` → stdout.
        labels_path:   Destination CSV for ground-truth labels; ``None`` → no CSV.
        duration:      Simulated duration in seconds.
        speed:         Time compression for inter-event sleeps.
        seed:          RNG seed for reproducibility; ``None`` = random.
        realtime:      If ``True``, sleep between events at ``1/speed`` rate
                       (useful for piping into the live engine).

    Raises:
        KeyError: If *scenario_name* is not in :data:`SCENARIO_NAMES`.
    """
    if scenario_name not in _SCENARIOS:
        raise KeyError(f"Unknown scenario {scenario_name!r}. Choose from: {SCENARIO_NAMES}")

    scenario_fn = _SCENARIOS[scenario_name]
    start = datetime.now(tz=UTC)
    gen: Iterator[ScenarioLine] = scenario_fn(  # type: ignore[operator]
        start=start, duration=duration, speed=speed, seed=seed
    )

    user_windows: dict[tuple[str, str, str, int], list[datetime]] = {}
    prev_ts: datetime | None = None

    # Open output file or use stdout.
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = out_path.open("w", encoding="utf-8", newline="\n")
    else:
        out_fh = sys.stdout  # type: ignore[assignment]

    try:
        for sl in gen:
            out_fh.write(sl.line + "\n")
            out_fh.flush()

            if realtime and prev_ts is not None:
                gap = (sl.ts - prev_ts).total_seconds()
                wall_sleep = max(0.0, gap / speed)
                if wall_sleep > 0:
                    time.sleep(wall_sleep)
            prev_ts = sl.ts

            key = (sl.user, sl.ip, sl.scenario, sl.label)
            if key not in user_windows:
                user_windows[key] = [sl.ts, sl.ts]
            else:
                user_windows[key][1] = sl.ts
    finally:
        if out_path is not None:
            out_fh.close()

    # Write labels CSV with (start, end, ip, user, scenario, label).
    if labels_path is not None and user_windows:
        labels_path.parent.mkdir(parents=True, exist_ok=True)
        with labels_path.open("w", encoding="utf-8", newline="") as csvf:
            writer = csv.DictWriter(
                csvf, fieldnames=["start", "end", "ip", "user", "scenario", "label"]
            )
            writer.writeheader()
            for (user, ip, scenario, label), (start_ts, end_ts) in user_windows.items():
                writer.writerow(
                    {
                        "start": start_ts.isoformat(),
                        "end": end_ts.isoformat(),
                        "ip": ip,
                        "user": user,
                        "scenario": scenario,
                        "label": str(label),
                    }
                )


# ---------------------------------------------------------------------------
# In-memory generator (for tests)
# ---------------------------------------------------------------------------


def generate_lines(
    scenario_name: str,
    duration: float = 10.0,
    speed: float = 100.0,
    seed: int = 42,
) -> list[ScenarioLine]:
    """Run a scenario entirely in memory and return all :class:`ScenarioLine` objects.

    This is a convenience helper for unit tests — it never writes to disk.

    Args:
        scenario_name: One of :data:`SCENARIO_NAMES`.
        duration:      Simulated duration in seconds.
        speed:         Time compression factor.
        seed:          RNG seed (fixed for reproducibility).

    Returns:
        List of :class:`ScenarioLine` objects.
    """
    if scenario_name not in _SCENARIOS:
        raise KeyError(f"Unknown scenario {scenario_name!r}")
    fn = _SCENARIOS[scenario_name]  # type: ignore[operator]
    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    return list(fn(start=start, duration=duration, speed=speed, seed=seed))  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for ``python -m lab.simulate_log``."""
    parser = argparse.ArgumentParser(
        prog="python -m lab.simulate_log",
        description="ShareGuard audit-log simulator — writes text log lines only, no real files.",
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIO_NAMES,
        default="normal_office",
        help="Scenario to simulate (default: normal_office).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Simulated duration in seconds (default: 60).",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Speed multiplier: 1=real-time, 10=10× faster (default: 1).",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output log file path (default: stdout).",
    )
    parser.add_argument(
        "--labels",
        type=str,
        default=None,
        help="Output CSV file for ground-truth labels (default: <out>.labels.csv if --out given).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for reproducibility (default: random).",
    )
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Sleep between events to honour the speed-adjusted cadence.",
    )
    args = parser.parse_args()

    out_path: Path | None = Path(args.out) if args.out else None
    if args.labels:
        labels_path: Path | None = Path(args.labels)
    elif out_path is not None:
        labels_path = out_path.with_suffix(".labels.csv")
    else:
        labels_path = None

    run_simulation(
        scenario_name=args.scenario,
        out_path=out_path,
        labels_path=labels_path,
        duration=args.duration,
        speed=args.speed,
        seed=args.seed,
        realtime=args.realtime,
    )


if __name__ == "__main__":
    main()
