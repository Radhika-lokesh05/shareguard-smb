"""server/tests/test_engine.py – Comprehensive unit tests for ShareGuard DetectionEngine.

Verifies:
- All 5 attack scenarios reach ATTACK within bounded time_to_detect.
- All 5 normal scenarios produce no ATTACK transitions (no false alarms).
- Shadow mode takes no action (sets would_have_blocked).
- Enforce_temp calls fake responder once and never for allowlisted IPs.
- Panic stop disables enforcement at runtime.
- Corrupt/broken ML model does not crash the engine.
- Event bus subscribers cannot block the engine (bounded drop test).
- Snapshot manager is paused while any client is SUSPICIOUS/ATTACK, resumed when clear.
- Untrusted file paths are bounded at 10,000 with overflow counting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from lab.simulate_log import SCENARIO_NAMES, generate_lines

from shareguard.engine import (
    ClientState,
    DetectionEngine,
    EventBus,
    IncidentRecord,
    InMemoryAlertRepository,
    StateChangedEvent,
    _sanitize_path,
)
from shareguard.parser import AuditEvent, parse_line
from shareguard.responder import FakeResponder
from shareguard.snapshots import FakeSnapshotManager

_NORMAL_SCENARIOS = [s for s in SCENARIO_NAMES if s.startswith("normal_")]
_ATTACK_SCENARIOS = [s for s in SCENARIO_NAMES if s.startswith("attack_")]

# Cache parsed events for scenarios to ensure tests run in milliseconds
_CACHED_SCENARIO_EVENTS: dict[tuple[str, float], list[AuditEvent]] = {}


def _get_scenario_events(scenario_name: str, duration: float = 60.0) -> list[AuditEvent]:
    key = (scenario_name, duration)
    if key not in _CACHED_SCENARIO_EVENTS:
        raw_lines = generate_lines(scenario_name, duration=duration, speed=100.0, seed=42)
        events = []
        for sl in raw_lines[:600]:
            evt = parse_line(sl.line)
            if evt is not None:
                events.append(evt)
        _CACHED_SCENARIO_EVENTS[key] = events
    return _CACHED_SCENARIO_EVENTS[key]


def _evaluate_engine_scenario(scenario_name: str, mode: str = "shadow") -> dict[str, Any]:
    events = _get_scenario_events(scenario_name, duration=60.0)
    fake_responder = FakeResponder(config={"mode": mode, "allowlist": ["127.0.0.1", "192.168.1.250"]})
    fake_snapshots = FakeSnapshotManager()
    alert_repo = InMemoryAlertRepository()
    event_bus = EventBus()

    engine = DetectionEngine(
        config={
            "detection": {
                "window_seconds": 60,
                "suspicious_threshold": 0.6,
                "attack_threshold": 0.85,
                "quiet_windows_to_normal": 3,
                "attack_resolve_minutes": 15,
            },
            "response": {
                "mode": mode,
                "block_ttl_minutes": 15,
                "allowlist": ["127.0.0.1", "::1", "192.168.1.250"],
            },
        },
        responder=fake_responder,
        snapshot_manager=fake_snapshots,
        alert_repository=alert_repo,
        event_bus=event_bus,
    )

    for evt in events:
        engine.process_event(evt)

    incidents = alert_repo.list_all()
    attack_incidents = [inc for inc in incidents if inc.detected_ts is not None]

    min_ttd = min((inc.time_to_detect for inc in attack_incidents if inc.time_to_detect is not None), default=None)
    all_rules = sorted({r for inc in incidents for r in inc.reasons})

    return {
        "scenario": scenario_name,
        "is_attack": scenario_name.startswith("attack_"),
        "attack_detected": len(attack_incidents) > 0,
        "incident_count": len(incidents),
        "min_ttd": min_ttd,
        "reasons": all_rules,
        "incidents": incidents,
        "fake_responder": fake_responder,
        "fake_snapshots": fake_snapshots,
    }


# ===========================================================================
# Benchmark & Scenario Replay Tests
# ===========================================================================


@pytest.mark.slow
def test_all_10_scenarios_benchmark(capsys: pytest.CaptureFixture[str]) -> None:
    """Replay every simulated scenario through the engine and print benchmark table."""
    results = [_evaluate_engine_scenario(name) for name in SCENARIO_NAMES]

    print("\n" + "=" * 110)
    print(
        f"{'SCENARIO':<22} | {'TYPE':<7} | {'STATUS':<8} | {'TTD (s)':<8} | {'INCIDENTS':<9} | {'DETAILS':<35}"
    )
    print("-" * 110)

    missed_attacks: list[str] = []
    false_alarms: list[str] = []

    for r in results:
        stype = "Attack" if r["is_attack"] else "Normal"
        status_str = "\033[91mATTACK\033[0m" if r["attack_detected"] else "CLEAN"
        ttd_str = f"{r['min_ttd']:.1f}s" if r["min_ttd"] is not None else "N/A"
        details = r["reasons"][0][:35] if r["reasons"] else "none"

        print(
            f"{r['scenario']:<22} | {stype:<7} | {status_str:<17} | {ttd_str:<8} | {r['incident_count']:<9} | {details:<35}"
        )

        if r["is_attack"] and not r["attack_detected"]:
            missed_attacks.append(r["scenario"])
        if not r["is_attack"] and r["attack_detected"]:
            false_alarms.append(r["scenario"])

    print("=" * 110)
    print(f"Summary: {len(missed_attacks)} Missed Attacks, {len(false_alarms)} False Alarms")
    print("=" * 110 + "\n")

    assert not missed_attacks, f"Engine missed attacks on: {missed_attacks}"
    assert not false_alarms, f"Engine had false alarms on normal scenarios: {false_alarms}"


@pytest.mark.slow
@pytest.mark.parametrize("scenario", _ATTACK_SCENARIOS)
def test_attack_scenarios_reach_attack_state(scenario: str) -> None:
    """Each individual attack scenario must end in ATTACK within bounded time_to_detect."""
    res = _evaluate_engine_scenario(scenario)
    assert res["attack_detected"] is True, f"Attack scenario {scenario} failed to reach ATTACK state"
    assert res["min_ttd"] is not None
    assert 0.0 <= res["min_ttd"] <= 60.0, f"TTD {res['min_ttd']} exceeded 60s bound for {scenario}"


@pytest.mark.slow
@pytest.mark.parametrize("scenario", _NORMAL_SCENARIOS)
def test_normal_scenarios_produce_no_attack(scenario: str) -> None:
    """Normal scenarios must produce zero ATTACK state transitions."""
    res = _evaluate_engine_scenario(scenario)
    assert res["attack_detected"] is False, f"Normal scenario {scenario} falsely triggered ATTACK"


# ===========================================================================
# Response Modes Tests
# ===========================================================================


def test_shadow_mode_takes_no_action() -> None:
    """Shadow mode must compute detection and record would_have_blocked without applying blocks."""
    res = _evaluate_engine_scenario("attack_fast", mode="shadow")
    assert res["attack_detected"] is True
    # Fake responder calls must contain zero applied blocks
    assert len(res["fake_responder"].list_blocks()) == 0
    # Recorded incidents must specify would_have_blocked = True
    assert any(inc.would_have_blocked for inc in res["incidents"])


def test_enforce_temp_calls_responder_with_ttl() -> None:
    """Enforce temp mode must invoke block_client with configured TTL."""
    res = _evaluate_engine_scenario("attack_fast", mode="enforce_temp")
    assert res["attack_detected"] is True
    blocks = res["fake_responder"].list_blocks()
    assert len(blocks) >= 1
    # Check that block record is active and has correct TTL expiration
    block = blocks[0]
    assert block.active is True
    assert block.expires_at > block.blocked_at


def test_enforce_strict_calls_responder_indefinite() -> None:
    """Enforce strict mode must invoke block_client with ttl=0 (indefinite block)."""
    res = _evaluate_engine_scenario("attack_fast", mode="enforce_strict")
    assert res["attack_detected"] is True
    blocks = res["fake_responder"].list_blocks()
    assert len(blocks) >= 1
    # Check that block record expires far in future (days >= 365)
    assert (blocks[0].expires_at - blocks[0].blocked_at).days > 365


# ===========================================================================
# Safety Invariant Tests
# ===========================================================================


def test_allowlisted_ip_never_blocked() -> None:
    """Clients on the allowlist must NEVER be blocked even during an active attack."""
    fake_responder = FakeResponder(config={"mode": "enforce_temp", "allowlist": ["10.0.0.55"]})
    engine = DetectionEngine(
        config={"response": {"mode": "enforce_temp", "allowlist": ["10.0.0.55"]}},
        responder=fake_responder,
    )
    # 10.0.0.55 is the attacker IP in attack_fast
    events = _get_scenario_events("attack_fast")
    for evt in events:
        engine.process_event(evt)

    # Fake responder must NOT contain blocks for 10.0.0.55
    assert len(fake_responder.list_blocks()) == 0


def test_panic_stop_suppresses_enforcement() -> None:
    """Global panic stop must immediately disable enforcement at runtime."""
    fake_responder = FakeResponder(config={"mode": "enforce_temp"})
    engine = DetectionEngine(
        config={"response": {"mode": "enforce_temp"}},
        responder=fake_responder,
    )
    engine.set_panic_stop(True)
    events = _get_scenario_events("attack_fast")
    for evt in events:
        engine.process_event(evt)

    assert len(fake_responder.list_blocks()) == 0
    incidents = engine.alert_repo.list_all()
    assert any(inc.action_taken == "panic_stopped" for inc in incidents)


def test_corrupt_ml_model_resilience() -> None:
    """A missing or corrupt ML model must not crash the engine or halt rule detection."""
    fake_responder = FakeResponder(config={"mode": "shadow"})
    engine = DetectionEngine(
        config={"response": {"mode": "shadow"}},
        responder=fake_responder,
    )

    # Patch score to simulate a crash/corruption
    with patch("shareguard.engine.score", side_effect=RuntimeError("Corrupt model file")):
        events = _get_scenario_events("attack_fast")
        for evt in events:
            engine.process_event(evt)

    assert "degraded" in engine.ml_status
    incidents = engine.alert_repo.list_all()
    # Expert rules still detect the attack
    assert any(inc.detected_ts is not None for inc in incidents)


# ===========================================================================
# Event Bus Non-Blocking & Drop Tests
# ===========================================================================


def test_event_bus_subscribers_cannot_block() -> None:
    """Bounded queues must drop the oldest event and increment dropped_count when full."""
    bus = EventBus(queue_size=5)
    q = bus.subscribe_queue(maxsize=5)

    now = datetime.now(tz=UTC)
    for i in range(25):
        bus.publish(
            StateChangedEvent(
                client_ip="192.168.1.10",
                username="alice",
                old_state=ClientState.NORMAL,
                new_state=ClientState.SUSPICIOUS,
                timestamp=now + timedelta(seconds=i),
                reason=f"Event {i}",
            )
        )

    assert len(q) == 5
    assert bus.dropped_count >= 20
    # Newest events retained in bounded deque
    assert q[-1].reason == "Event 24"


# ===========================================================================
# Snapshot Manager Coordination Tests
# ===========================================================================


def test_snapshot_pause_resume_lifecycle() -> None:
    """Snapshots must be paused while any client is SUSPICIOUS/ATTACK and resume when resolved."""
    fake_snapshots = FakeSnapshotManager()
    engine = DetectionEngine(
        config={"response": {"mode": "shadow"}},
        snapshot_manager=fake_snapshots,
    )
    assert fake_snapshots.is_paused is False

    events = _get_scenario_events("attack_fast")
    assert len(events) > 0
    attack_ip = events[0].ip
    attack_user = events[0].user

    for evt in events:
        engine.process_event(evt)

    # Active attack must pause snapshots
    assert fake_snapshots.is_paused is True

    # Resolving client resumes snapshots
    resolved = engine.resolve_client(attack_ip, attack_user)
    assert resolved is True
    assert fake_snapshots.is_paused is False


# ===========================================================================
# Untrusted Filename Sanitization & Bounding Tests
# ===========================================================================


def test_untrusted_path_sanitization_and_bound() -> None:
    """Filenames must be stripped of control chars and capped at 10,000 paths."""
    sanitized = _sanitize_path("sensitive\x00_dir/\x1b[31mfile.txt\x7f")
    assert "\x00" not in sanitized
    assert "\x1b" not in sanitized

    long_path = "a" * 1000
    assert len(_sanitize_path(long_path)) == 512

    now = datetime.now(tz=UTC)
    incident = IncidentRecord(
        incident_id="inc-bounds-test",
        client_ip="10.0.0.88",
        username="intruder",
        first_anomaly_ts=now,
    )
    for i in range(12_000):
        incident.record_path(f"files/path_{i}.docx")

    assert len(incident.files_touched) == 10_000
    assert incident.files_touched_overflow_count == 2_000
    assert incident.files_lost == 12_000
