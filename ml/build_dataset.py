"""
ml/build_dataset.py – Extract windowed features from audit logs and generate datasets.

Reads audit log(s) and matching labels.csv, extracts rolling windows per client,
computes features using shareguard.features.compute_features with SimulatedEntropyProvider,
and assigns binary labels based on overlap with ground-truth attack intervals.
Outputs a Parquet or CSV dataset with metadata columns:
- client_ip
- window_start
- window_end
- scenario
- run_id
- source ('sim' or 'live')
- label (0 = normal, 1 = attack)
+ FEATURE_COLUMNS
"""

from __future__ import annotations

import argparse
import csv
import sys
import warnings
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure workspace root and server packages are importable when script is run directly
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(_WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE_ROOT))
_SERVER_DIR = _WORKSPACE_ROOT / "server"
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

import pandas as pd
from lab.simulate_log import SCENARIO_NAMES, run_simulation

from shareguard.entropy import SimulatedEntropyProvider
from shareguard.features import compute_features
from shareguard.ml import FEATURE_COLUMNS
from shareguard.parser import AuditEvent, parse_line

__all__ = ["build_dataset_from_logs", "extract_features_from_log", "generate_default_dataset"]


def _load_labels(
    labels_path: Path,
    marker_starts: dict[str, float] | None = None,
    marker_ends: dict[str, float] | None = None,
    marker_ips: dict[str, str] | None = None,
    marker_users: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Load attack/normal intervals from labels.csv, deriving timestamps from markers when present."""
    intervals: list[dict[str, Any]] = []
    if not labels_path.exists():
        return intervals

    m_starts = marker_starts or {}
    m_ends = marker_ends or {}
    m_ips = marker_ips or {}
    m_users = marker_users or {}

    with labels_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row.get("run_id", "").strip()
            scenario = row.get("scenario", "unknown")
            label = int(row.get("label", 0))

            if rid and rid in m_starts:
                start_ts = m_starts[rid]
                ip = m_ips.get(rid, row.get("client_ip", row.get("ip", "")))
                user = m_users.get(rid, row.get("user", ""))

                if rid in m_ends:
                    end_ts = m_ends[rid]
                else:
                    warnings.warn(
                        f"Missing end marker for run_id '{rid}'; using fallback end timestamp.",
                        UserWarning,
                        stacklevel=2,
                    )
                    end_str = row.get("end_utc", row.get("end"))
                    if end_str:
                        end_ts = datetime.fromisoformat(end_str).timestamp()
                    else:
                        end_ts = start_ts + 60.0
            else:
                if marker_starts is not None and len(m_starts) > 0:
                    warnings.warn(
                        f"Missing start marker for run_id '{rid}' in audit log; using fallback timestamps from labels.csv.",
                        UserWarning,
                        stacklevel=2,
                    )
                start_str = row.get("start_utc", row.get("start"))
                end_str = row.get("end_utc", row.get("end"))
                if not start_str or not end_str:
                    continue
                start_ts = datetime.fromisoformat(start_str).timestamp()
                end_ts = datetime.fromisoformat(end_str).timestamp()
                ip = row.get("client_ip", row.get("ip", ""))
                user = row.get("user", "")

            intervals.append(
                {
                    "run_id": rid,
                    "start": start_ts,
                    "end": end_ts,
                    "ip": ip,
                    "user": user,
                    "scenario": scenario,
                    "label": label,
                }
            )
    return intervals


def _is_attack_window(
    win_start: float,
    win_end: float,
    ip: str,
    intervals: list[dict[str, Any]],
) -> tuple[int, str]:
    """Check if window overlaps any attack interval for this client IP."""
    matching_scenarios: set[str] = set()
    is_attack = 0

    for inv in intervals:
        # Overlap condition: max(start1, start2) <= min(end1, end2)
        if (not inv.get("ip") or inv.get("ip") == ip) and max(win_start, inv["start"]) <= min(win_end, inv["end"]):
            matching_scenarios.add(inv["scenario"])
            if inv["label"] == 1:
                is_attack = 1

    scenario_name = sorted(matching_scenarios)[0] if matching_scenarios else "unknown"
    return is_attack, scenario_name


def extract_features_from_log(
    log_path: Path,
    labels_path: Path | None,
    run_id: str,
    source: str = "sim",
    window_seconds: float = 60.0,
    slide_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    """Extract rolling window features and labels from one log file."""
    entropy_provider = SimulatedEntropyProvider()

    # Parse all events
    raw_events: list[AuditEvent] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            evt = parse_line(line)
            if evt is not None:
                raw_events.append(evt)

    if not raw_events:
        return []

    # Detect start and end markers to derive server-side ground truth intervals
    marker_starts: dict[str, float] = {}
    marker_ends: dict[str, float] = {}
    marker_ips: dict[str, str] = {}
    marker_users: dict[str, str] = {}

    for evt in raw_events:
        clean_path = evt.path.replace("\\", "/") if evt.path else ""
        filename = Path(clean_path).name
        if filename.startswith("__sg_start_"):
            m_rid = filename[len("__sg_start_"):]
            marker_starts[m_rid] = evt.ts.timestamp()
            marker_ips[m_rid] = evt.ip
            marker_users[m_rid] = evt.user
        elif filename.startswith("__sg_end_"):
            m_rid = filename[len("__sg_end_"):]
            marker_ends[m_rid] = evt.ts.timestamp()

    # Ignore marker events when calculating features
    events: list[AuditEvent] = [
        evt for evt in raw_events
        if not (
            Path(evt.path.replace("\\", "/")).name.startswith("__sg_start_")
            or Path(evt.path.replace("\\", "/")).name.startswith("__sg_end_")
        )
    ]

    if not events:
        return []

    # Sort events by timestamp
    events.sort(key=lambda e: e.ts)
    min_ts = events[0].ts.timestamp()
    max_ts = events[-1].ts.timestamp()

    labels = _load_labels(
        labels_path=labels_path,
        marker_starts=marker_starts,
        marker_ends=marker_ends,
        marker_ips=marker_ips,
        marker_users=marker_users,
    ) if labels_path else []

    from bisect import bisect_left, bisect_right

    # Group events and their timestamps by client IP
    events_by_ip: dict[str, list[AuditEvent]] = defaultdict(list)
    ts_by_ip: dict[str, list[float]] = defaultdict(list)
    for evt in events:
        events_by_ip[evt.ip].append(evt)
        ts_by_ip[evt.ip].append(evt.ts.timestamp())

    rows: list[dict[str, Any]] = []

    # Slide window across entire duration
    cur_start = min_ts
    while cur_start <= max_ts:
        cur_end = cur_start + window_seconds
        for ip, ip_events in events_by_ip.items():
            ip_ts = ts_by_ip[ip]
            idx_start = bisect_left(ip_ts, cur_start)
            idx_end = bisect_right(ip_ts, cur_end)
            if idx_start >= idx_end:
                continue

            win_events = ip_events[idx_start:idx_end]
            username = win_events[0].user
            feats = compute_features(
                win_events,
                client_ip=ip,
                username=username,
                entropy_provider=entropy_provider,
            )

            # Determine label and scenario
            label, scenario = _is_attack_window(cur_start, cur_end, ip, labels)

            row: dict[str, Any] = {
                "client_ip": ip,
                "window_start": cur_start,
                "window_end": cur_end,
                "scenario": scenario,
                "run_id": run_id,
                "source": source,
                "label": label,
            }

            # Add core features
            for col in FEATURE_COLUMNS:
                if hasattr(feats, col):
                    row[col] = float(getattr(feats, col))
                elif col in feats.extra:
                    row[col] = float(feats.extra[col])
                else:
                    row[col] = 0.0

            rows.append(row)

        cur_start += slide_seconds

    return rows


def build_dataset_from_logs(
    log_files: list[tuple[Path, Path | None, str, str]],
    out_path: Path,
    window_seconds: float = 60.0,
    slide_seconds: float = 10.0,
) -> pd.DataFrame:
    """Build dataset from multiple (log_path, labels_path, run_id, source) tuples."""
    all_rows: list[dict[str, Any]] = []

    for idx, (log_path, labels_path, run_id, source) in enumerate(log_files):
        rows = extract_features_from_log(
            log_path=log_path,
            labels_path=labels_path,
            run_id=run_id,
            source=source,
            window_seconds=window_seconds,
            slide_seconds=slide_seconds,
        )
        all_rows.extend(rows)
        if (idx + 1) % 30 == 0 or (idx + 1) == len(log_files):
            print(f"Processed {idx + 1}/{len(log_files)} runs ({len(all_rows)} total windows extracted)...")

    df = pd.DataFrame(all_rows)
    if df.empty:
        # Create empty dataframe with expected columns
        columns = [
            "client_ip",
            "window_start",
            "window_end",
            "scenario",
            "run_id",
            "source",
            "label",
            *FEATURE_COLUMNS,
        ]
        df = pd.DataFrame(columns=columns)

    # Class balance summary
    total = len(df)
    n_attacks = int((df["label"] == 1).sum()) if not df.empty else 0
    n_normal = total - n_attacks
    print(f"Dataset generated with {total} windows:")
    print(f"  Normal (0): {n_normal}")
    print(f"  Attack (1): {n_attacks}")
    if total > 0:
        print(f"  Attack ratio: {n_attacks / total:.2%}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if str(out_path).endswith(".parquet"):
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False)
    print(f"Dataset saved to: {out_path}")
    return df


def generate_default_dataset(
    out_dir: Path = Path("ml/artifacts"),
    runs_per_scenario: int = 30,
    duration: float = 60.0,
) -> Path:
    """Simulate runs for all scenarios across multiple seeds and build dataset.parquet."""
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = out_dir / "sim_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_files: list[tuple[Path, Path | None, str, str]] = []

    print(
        f"Simulating {len(SCENARIO_NAMES)} scenarios x {runs_per_scenario} runs "
        f"(duration={duration}s, speed=100x)..."
    )

    seed_base = 1000
    for scenario in SCENARIO_NAMES:
        for r in range(runs_per_scenario):
            run_id = f"{scenario}_run{r+1}"
            seed = seed_base + r * 17
            log_path = logs_dir / f"{run_id}.log"
            labels_path = logs_dir / f"{run_id}.labels.csv"

            run_simulation(
                scenario_name=scenario,
                out_path=log_path,
                labels_path=labels_path,
                duration=duration,
                speed=100.0,
                seed=seed,
                realtime=False,
            )
            log_files.append((log_path, labels_path, run_id, "sim"))
        seed_base += 100

    dataset_path = out_dir / "dataset.parquet"
    build_dataset_from_logs(log_files, dataset_path)
    return dataset_path


def main() -> None:
    """CLI entry point for dataset builder."""
    parser = argparse.ArgumentParser(description="Build ML dataset from audit logs")
    parser.add_argument(
        "--generate-default",
        action="store_true",
        help="Simulate default scenarios and build ml/artifacts/dataset.parquet",
    )
    parser.add_argument("--logs", "--log", nargs="*", dest="logs", help="List of audit log files")
    parser.add_argument("--labels", "--label", nargs="*", dest="labels", help="Matching labels.csv files")
    parser.add_argument("--source", default=None, choices=["sim", "live"], help="Source type ('live' or 'sim')")
    parser.add_argument("--out", default="ml/artifacts/dataset.parquet", help="Output dataset path")
    parser.add_argument(
        "--runs-per-scenario",
        type=int,
        default=30,
        help="Runs per scenario for default generation",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Duration in seconds per scenario run",
    )
    args = parser.parse_args()

    out_path = Path(args.out)

    if args.generate_default or not args.logs:
        generate_default_dataset(
            out_dir=out_path.parent,
            runs_per_scenario=args.runs_per_scenario,
            duration=args.duration,
        )
    else:
        log_paths = [Path(p) for p in args.logs]
        label_paths = [Path(p) for p in args.labels] if args.labels else []
        log_specs: list[tuple[Path, Path | None, str, str]] = []
        source = args.source or "live"

        for idx, lp in enumerate(log_paths):
            matching_lbl = label_paths[idx] if idx < len(label_paths) else None
            run_id = lp.stem
            log_specs.append((lp, matching_lbl, run_id, source))

        build_dataset_from_logs(log_specs, out_path)


if __name__ == "__main__":
    main()
