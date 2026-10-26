"""shareguard.run – Real-time timeline demo CLI.

Usage:
    ./.venv/Scripts/python.exe -m shareguard.run --sim audit_sim.log --speed 10 --mode shadow

Options:
    --sim PATH      Path to audit log file (default: audit_sim.log)
    --speed FLOAT   Playback speed multiplier (default: 10.0)
    --mode MODE     Response mode: shadow | enforce_temp | enforce_strict (default: shadow)
    --no-sleep      Process events immediately without replaying sleep intervals
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from shareguard.engine import (
    ActionTakenEvent,
    AlertOpenedEvent,
    AlertResolvedEvent,
    DetectionEngine,
    EngineEvent,
    EventBus,
    InMemoryAlertRepository,
    StateChangedEvent,
)
from shareguard.parser import replay
from shareguard.responder import FakeResponder
from shareguard.snapshots import FakeSnapshotManager


def _format_timeline_event(event: EngineEvent) -> str | None:
    """Format an engine event into a concise terminal timeline row."""
    if isinstance(event, StateChangedEvent):
        return (
            f"[{event.timestamp.strftime('%H:%M:%S')}] \033[93m[STATE CHANGE]\033[0m "
            f"{event.client_ip} ({event.username}): {event.old_state} -> \033[1m{event.new_state}\033[0m "
            f"| {event.reason}"
        )
    if isinstance(event, AlertOpenedEvent):
        ml_str = f"{event.ml_prob:.2f}" if event.ml_prob is not None else "N/A"
        rules_str = ", ".join(event.triggered_rules) or "none"
        return (
            f"[{event.detected_ts.strftime('%H:%M:%S')}] \033[91m[ATTACK DETECTED]\033[0m "
            f"{event.client_ip} ({event.username}) | TTD: \033[1m{event.time_to_detect:.1f}s\033[0m "
            f"| Rules: [{rules_str}] | ML: {ml_str} | Lost Files: {event.files_touched_count}"
        )
    if isinstance(event, ActionTakenEvent):
        action_color = "\033[96m" if event.would_have_blocked else "\033[91m"
        action_label = "would_have_blocked (shadow)" if event.would_have_blocked else event.action
        return (
            f"[{event.timestamp.strftime('%H:%M:%S')}] {action_color}[ACTION TAKEN]\033[0m "
            f"Mode: {event.mode} -> {action_label} for {event.client_ip} | {event.reason[:80]}"
        )
    if isinstance(event, AlertResolvedEvent):
        return (
            f"[{event.resolved_ts.strftime('%H:%M:%S')}] \033[92m[INCIDENT RESOLVED]\033[0m "
            f"{event.client_ip} ({event.username}) | Reason: {event.reason}"
        )
    return None


def run_pipeline(
    sim_path: Path,
    speed: float = 10.0,
    mode: str = "shadow",
    no_sleep: bool = False,
) -> None:
    """Run simulated audit log through the engine and print readable timeline."""
    if not sim_path.exists():
        print(f"Error: audit log file not found at {sim_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 110)
    print(f"ShareGuard Real-Time Detection Pipeline — Mode: {mode.upper()} | Speed: {speed}x | Source: {sim_path}")
    print("=" * 110)

    # Initialize components
    event_bus = EventBus()
    fake_responder = FakeResponder(config={"mode": mode, "allowlist": ["127.0.0.1", "192.168.1.250"]})
    fake_snapshots = FakeSnapshotManager()
    alert_repo = InMemoryAlertRepository()

    engine_config = {
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
    }

    engine = DetectionEngine(
        config=engine_config,
        responder=fake_responder,
        snapshot_manager=fake_snapshots,
        alert_repository=alert_repo,
        event_bus=event_bus,
    )

    # Subscribe to event bus for real-time printing
    def on_event(evt: EngineEvent) -> None:
        formatted = _format_timeline_event(evt)
        if formatted:
            print(formatted)

    event_bus.subscribe(on_event)

    total_events = 0
    start_wall = time.perf_counter()

    for event, sleep_secs in replay(sim_path, speed=speed):
        total_events += 1
        if not no_sleep and sleep_secs > 0:
            time.sleep(sleep_secs)
        engine.process_event(event)

    duration_wall = time.perf_counter() - start_wall

    # Print summary
    print("\n" + "=" * 110)
    print(f"PIPELINE SUMMARY (Processed {total_events} events in {duration_wall:.2f}s wall time)")
    print("=" * 110)

    incidents = alert_repo.list_all()
    if not incidents:
        print("No anomalous incidents detected. Share status: NORMAL.")
    else:
        print(
            f"{'INCIDENT ID':<14} | {'CLIENT':<22} | {'STATUS':<9} | {'TTD':<7} | {'ML':<5} | {'LOST':<6} | {'ACTION TAKEN':<22}"
        )
        print("-" * 110)
        for inc in incidents:
            client_str = f"{inc.client_ip} ({inc.username})"
            ttd_str = f"{inc.time_to_detect:.1f}s" if inc.time_to_detect is not None else "N/A"
            ml_str = f"{inc.ml_prob:.2f}" if inc.ml_prob is not None else "N/A"
            action_str = "would_block (shadow)" if inc.would_have_blocked else inc.action_taken

            print(
                f"{inc.incident_id:<14} | {client_str:<22} | {inc.status:<9} | {ttd_str:<7} | {ml_str:<5} | {inc.files_lost:<6} | {action_str:<22}"
            )

    print("-" * 110)
    print(f"Snapshot Manager status: {'PAUSED' if fake_snapshots.is_paused else 'ACTIVE'}")
    blocks = fake_responder.list_blocks()
    print(f"Active Blocks in Responder: {len(blocks)} client(s)")
    for b in blocks:
        print(f"  - IP: {b.client_ip} (Expires: {b.expires_at.strftime('%H:%M:%S')}) Reason: {b.reason}")
    print("=" * 110 + "\n")


def main() -> None:
    """CLI entry point for ``python -m shareguard.run``."""
    parser = argparse.ArgumentParser(
        prog="python -m shareguard.run",
        description="ShareGuard real-time detection pipeline replay demo",
    )
    parser.add_argument(
        "--sim",
        type=Path,
        default=Path("audit_sim.log"),
        help="Path to audit log file to replay (default: audit_sim.log)",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=10.0,
        help="Replay speed multiplier (default: 10.0)",
    )
    parser.add_argument(
        "--mode",
        choices=["shadow", "enforce_temp", "enforce_strict"],
        default="shadow",
        help="Response mode (default: shadow)",
    )
    parser.add_argument(
        "--no-sleep",
        action="store_true",
        help="Execute immediately without sleeping between events",
    )
    args = parser.parse_args()
    run_pipeline(
        sim_path=args.sim,
        speed=args.speed,
        mode=args.mode,
        no_sleep=args.no_sleep,
    )


if __name__ == "__main__":
    main()
