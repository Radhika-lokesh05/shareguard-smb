"""
shareguard.tools.replay – Replay audit log and stream rule evaluation results.

Usage::

    ./.venv/Scripts/python.exe -m shareguard.tools.replay audit_sim.log --speed 10

Iterates through log events, maintains per-client sliding windows, computes
behavioural features, and prints rule scores and plain-language reasons
every second of simulated or wall-clock time.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path

from shareguard.features import compute_features
from shareguard.parser import AuditEvent, replay
from shareguard.rules import RuleEngine, RuleResult

__all__ = ["replay_and_evaluate"]


def replay_and_evaluate(
    log_path: Path,
    speed: float = 1.0,
    window_seconds: float = 60.0,
    realtime: bool = True,
) -> None:
    """Replay *log_path* and print rule evaluations per second.

    Args:
        log_path: Path to the vfs_full_audit log file.
        speed: Playback speed multiplier (e.g. 10.0 for 10x speed).
        window_seconds: Duration of sliding window for feature computation.
        realtime: If True, sleep between events according to speed.
    """
    p = Path(log_path)
    if not p.exists():
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    engine = RuleEngine()
    client_events: dict[str, list[AuditEvent]] = defaultdict(list)

    last_reported_second: int | None = None
    total_events = 0

    print(f"[*] Replaying {p} (speed={speed}x, window={window_seconds}s)...")
    print(
        f"{'TIME (UTC)':<20} | {'CLIENT IP':<15} | {'EXPERT':<6} | {'STATUS':<10} | {'BASELINE':<8} | {'REASONS'}"
    )
    print("-" * 95)

    for event, sleep_seconds in replay(p, speed=speed):
        total_events += 1
        if realtime and sleep_seconds > 0:
            time.sleep(sleep_seconds)

        client_key = event.ip
        user = event.user
        events = client_events[client_key]
        events.append(event)

        # Evict events outside the sliding window
        current_ts = event.ts.timestamp()
        cutoff_ts = current_ts - window_seconds
        client_events[client_key] = [e for e in events if e.ts.timestamp() >= cutoff_ts]

        # Report per simulated second
        current_sec = int(current_ts)
        if last_reported_second is None or current_sec != last_reported_second:
            last_reported_second = current_sec

            # Evaluate each active client in this window
            for ip, c_events in list(client_events.items()):
                if not c_events:
                    continue
                features = compute_features(c_events, client_ip=ip, username=user)
                result: RuleResult = engine.evaluate_result(features)
                baseline_fired, _ = engine.evaluate_baseline(features)

                status_tag = "CRITICAL" if result.critical else ("ALERT" if result.score >= 0.5 else "NORMAL")
                baseline_tag = "YES" if baseline_fired else "NO"
                reasons_str = "; ".join(result.reasons) if result.reasons else "Normal behavior"
                ts_str = event.ts.strftime("%Y-%m-%d %H:%M:%S")

                # Print if notable activity or periodically
                if result.score >= 0.5 or baseline_fired or total_events % 10 == 0:
                    print(
                        f"{ts_str:<20} | {ip:<15} | {result.score:<6.2f} | {status_tag:<10} | {baseline_tag:<8} | {reasons_str}"
                    )

    print("-" * 95)
    print(f"[*] Replay complete. Processed {total_events} events.")


def main() -> None:
    """CLI entry point for ``python -m shareguard.tools.replay``."""
    parser = argparse.ArgumentParser(
        prog="python -m shareguard.tools.replay",
        description="Replay an audit log file and display rule scores and reasons per second.",
    )
    parser.add_argument("log_path", type=str, help="Path to audit log file")
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Playback speed multiplier (default: 1.0; 10 = 10x faster)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=60.0,
        help="Sliding window duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--no-sleep",
        action="store_true",
        help="Do not sleep between events (process as fast as possible)",
    )
    args = parser.parse_args()

    replay_and_evaluate(
        log_path=Path(args.log_path),
        speed=args.speed,
        window_seconds=args.window,
        realtime=not args.no_sleep,
    )


if __name__ == "__main__":
    main()
