"""
lab/collect.py – Scenario orchestrator for ShareGuard data collection.

Runs a sequence of normal-activity and attack scenarios against a Samba share,
restores fake files between attack runs, and records ground-truth labels to
``labels.csv``.

⚠️  LAB ONLY – never import from production code.

SAFETY: The target directory MUST contain ``.shareguard_lab_marker``.
Refuses execution unless:
1. Target contains ``.shareguard_lab_marker`` and ``manifest.json``.
2. Target is a valid isolated subfolder (never a drive or system root).
3. Explicitly inside ``allowed_target_prefix`` from ``lab/config.yaml``.
4. Confirmed with ``--i-understand-this-is-a-lab``.

CLOCK INDEPENDENCE:
Windows client and Ubuntu server clocks can drift. To ensure exact label
alignment, ``collect.py`` drops marker files directly into the share:
- ``__sg_start_<run_id>`` before each step
- ``__sg_end_<run_id>`` after each step
Server-side timestamps in the Samba audit log serve as absolute ground truth.

Output
------
``labels.csv`` columns:
    run_id,scenario,label,parameters,start_utc,end_utc,files_encrypted,client_machine
"""

from __future__ import annotations

import argparse
import csv
import getpass
import importlib
import json
import platform
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lab.safety import (
    MARKER_FILENAME,
    MARKER_LEGACY,
    LabSafetyError,
    check_safety,
    load_lab_config,
    retry_on_windows_busy,
)

__all__: list[str] = ["Step", "run_plan"]

_LABELS_FILE = "labels.csv"
_CSV_COLUMNS = [
    "run_id",
    "scenario",
    "label",
    "parameters",
    "start_utc",
    "end_utc",
    "files_encrypted",
    "client_machine",
]

# ---------------------------------------------------------------------------
# Step dataclass
# ---------------------------------------------------------------------------


@dataclass
class Step:
    """A single step in a collection plan.

    Args:
        kind: ``"attack"`` | ``"normal"`` | ``"restore"``.
        scenario: Human-readable scenario name written to labels.csv.
        label: Ground-truth label (1 = attack, 0 = normal, -1 = internal).
        workload: Workload module name (normal steps only).
        duration: Duration in seconds (normal steps only).
        style: Attack style (attack steps only).
        count: Files to rename (attack steps only).
        ext: Fake extension (attack steps only).
        avoid_canaries: Whether attack skips canary files.
    """

    kind: str                     # "attack" | "normal" | "restore"
    scenario: str = ""
    label: int = 0
    # Normal-step fields
    workload: str = ""
    duration: float = 60.0
    # Attack-step fields
    style: str = "fast"
    count: int = 30
    ext: str = ".locked"
    avoid_canaries: bool = False
    # Runtime-filled
    files_encrypted: int = field(default=0, repr=False)


# ---------------------------------------------------------------------------
# Safety check
# ---------------------------------------------------------------------------


def _check_marker(target: Path) -> None:
    """Exit if neither marker file is present in *target*."""
    has_new = (target / MARKER_FILENAME).exists()
    has_legacy = (target / MARKER_LEGACY).exists()
    if not has_new and not has_legacy:
        print(
            f"[collect] REFUSED: neither '{MARKER_FILENAME}' nor '{MARKER_LEGACY}' "
            f"found in '{target}'.\n"
            "Run: python lab/make_fake_files.py --target <dir>",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Built-in plans
# ---------------------------------------------------------------------------

_ALL_ATTACK_STYLES: list[dict[str, Any]] = [
    {"style": "fast",        "ext": ".locked",   "count": 25, "avoid_canaries": False},
    {"style": "slow",        "ext": ".crypt",    "count": 20, "avoid_canaries": False},
    {"style": "partial",     "ext": ".locked",   "count": 25, "avoid_canaries": False},
    {"style": "rename_only", "ext": ".enc",      "count": 30, "avoid_canaries": False},
    {"style": "copy_delete", "ext": ".deadbeef", "count": 15, "avoid_canaries": False},
    {"style": "fast",        "ext": ".locked",   "count": 25, "avoid_canaries": True},
    {"style": "slow",        "ext": ".crypt",    "count": 20, "avoid_canaries": True},
    {"style": "partial",     "ext": ".locked",   "count": 25, "avoid_canaries": True},
    {"style": "rename_only", "ext": ".enc",      "count": 25, "avoid_canaries": False},
    {"style": "copy_delete", "ext": ".deadbeef", "count": 15, "avoid_canaries": True},
]

_NORMAL_WORKLOADS: list[dict[str, Any]] = [
    {"workload": "office_edit",      "duration": 1800.0},
    {"workload": "bulk_copy",        "duration": 1800.0},
    {"workload": "zip_unzip",        "duration": 1200.0},
    {"workload": "backup_rsync",     "duration": 1200.0},
    {"workload": "many_small_files", "duration": 1200.0},
    {"workload": "photo_import",     "duration": 1800.0},
    {"workload": "mixed",            "duration": 3000.0},
]


def _build_default_plan() -> list[Step]:
    """Build the default plan: 40 attack runs + ~200 min of normal work.

    Returns:
        Ordered list of :class:`Step` objects.
    """
    steps: list[Step] = []
    # 4 cycles of 10 attack styles = 40 total attack runs
    attack_idx = 0
    for cycle in range(4):
        for sub_cycle in range(10):
            style_cfg = _ALL_ATTACK_STYLES[sub_cycle]
            attack_idx += 1
            suffix = "_avoid_canaries" if style_cfg.get("avoid_canaries") else ""
            scen_name = f"attack_{style_cfg['style']}{suffix}"
            steps.append(
                Step(
                    kind="attack",
                    scenario=scen_name,
                    label=1,
                    style=style_cfg["style"],
                    count=style_cfg["count"] + (cycle * 2),
                    ext=style_cfg["ext"],
                    avoid_canaries=style_cfg.get("avoid_canaries", False),
                )
            )

            # After every 4 attack runs or cycle end, interleave a normal workload
            if attack_idx % 4 == 0 or attack_idx == 40:
                wl_cfg = _NORMAL_WORKLOADS[(attack_idx // 4 - 1) % len(_NORMAL_WORKLOADS)]
                steps.append(
                    Step(
                        kind="normal",
                        scenario=f"normal_{wl_cfg['workload']}",
                        label=0,
                        workload=wl_cfg["workload"],
                        duration=wl_cfg["duration"],
                    )
                )

    return steps


def _build_quick_plan() -> list[Step]:
    """Build a short test plan: 6 attack runs + 5 short normal steps (~15 min).

    Returns:
        Ordered list of :class:`Step` objects.
    """
    steps: list[Step] = []
    quick_attacks = [
        {"style": "fast",        "ext": ".locked",   "count": 20, "avoid_canaries": False},
        {"style": "slow",        "ext": ".crypt",    "count": 15, "avoid_canaries": False},
        {"style": "partial",     "ext": ".locked",   "count": 20, "avoid_canaries": False},
        {"style": "rename_only", "ext": ".enc",      "count": 20, "avoid_canaries": False},
        {"style": "copy_delete", "ext": ".deadbeef", "count": 15, "avoid_canaries": False},
        {"style": "fast",        "ext": ".locked",   "count": 20, "avoid_canaries": True},
    ]
    for cfg in quick_attacks:
        suffix = "_avoid_canaries" if cfg["avoid_canaries"] else ""
        steps.append(
            Step(
                kind="attack",
                scenario=f"attack_{cfg['style']}{suffix}",
                label=1,
                style=cfg["style"],
                count=cfg["count"],
                ext=cfg["ext"],
                avoid_canaries=cfg["avoid_canaries"],
            )
        )
    normal_workloads = ["office_edit", "bulk_copy", "zip_unzip", "many_small_files", "photo_import"]
    for name in normal_workloads:
        steps.append(
            Step(
                kind="normal",
                scenario=f"normal_{name}",
                label=0,
                workload=name,
                duration=90.0,
            )
        )
    return steps


# ---------------------------------------------------------------------------
# YAML plan loader
# ---------------------------------------------------------------------------


def _load_plan_from_yaml(path: Path) -> list[Step]:
    """Load a plan from a YAML file.

    Args:
        path: Path to the YAML plan file.

    Returns:
        List of :class:`Step` objects.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        print(
            "[collect] ERROR: PyYAML is required for --plan-file.  "
            "Install it with: pip install pyyaml",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    raw: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    steps: list[Step] = []
    for item in raw:
        kind = item.get("kind", "normal")
        if kind == "attack":
            steps.append(
                Step(
                    kind="attack",
                    scenario=item.get("scenario", f"attack_{item.get('style', 'fast')}"),
                    label=1,
                    style=item.get("style", "fast"),
                    count=int(item.get("count", 30)),
                    ext=item.get("ext", ".locked"),
                    avoid_canaries=bool(item.get("avoid_canaries", False)),
                )
            )
        elif kind == "normal":
            steps.append(
                Step(
                    kind="normal",
                    scenario=item.get("scenario", f"normal_{item.get('workload', 'office_edit')}"),
                    label=0,
                    workload=item.get("workload", "office_edit"),
                    duration=float(item.get("duration", 60.0)),
                )
            )
        elif kind == "restore":
            steps.append(Step(kind="restore", scenario="restore", label=-1))
    return steps


# ---------------------------------------------------------------------------
# Dry-run display
# ---------------------------------------------------------------------------


def _print_plan(steps: list[Step], quick: bool) -> None:
    """Print the plan as a human-readable table.

    Args:
        steps: Ordered list of steps.
        quick: Whether this is the quick plan.
    """
    tag = " [QUICK]" if quick else ""
    print(f"\n{'-' * 76}")
    print(f"  ShareGuard Collection Plan{tag}  -  {len(steps)} steps")
    print(f"{'-' * 76}")
    total_normal_s = 0.0
    attack_count = 0
    print(f"{'#':>4}  {'KIND':<8}  {'SCENARIO':<32}  {'DETAIL'}")
    print(f"{'-' * 76}")
    for i, s in enumerate(steps, 1):
        if s.kind == "attack":
            canary_str = ", avoid_canaries" if s.avoid_canaries else ""
            detail = f"style={s.style}, count={s.count}, ext={s.ext}{canary_str}"
            attack_count += 1
        elif s.kind == "normal":
            detail = f"workload={s.workload}, duration={s.duration:.0f}s"
            total_normal_s += s.duration
        else:
            detail = "(restore fake files)"
        print(f"{i:>4}  {s.kind:<8}  {s.scenario:<32}  {detail}")
    print(f"{'-' * 76}")
    print(f"  Attack steps : {attack_count}")
    print(f"  Normal steps : {total_normal_s / 60:.1f} min total")
    print(f"{'-' * 76}\n")


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------


def _get_client_machine() -> str:
    """Return client machine identifier from lab config or environment."""
    cfg = load_lab_config()
    machine = cfg.get("client_machine_name")
    if machine:
        return str(machine)
    try:
        return platform.node() or "client-pc"
    except Exception:
        return "client-pc"


def _create_marker(target: Path, marker_name: str) -> None:
    """Create an empty marker file on the share to register a server audit timestamp."""
    p = target / marker_name
    retry_on_windows_busy(lambda: p.touch(exist_ok=True))


def _run_attack(step: Step, target: Path) -> int:
    """Run a fake ransomware attack step.

    Args:
        step: The attack step.
        target: The target directory.

    Returns:
        Number of files encrypted.
    """
    from lab.fake_ransomware import simulate_encryption

    return simulate_encryption(
        target,
        count=step.count,
        style=step.style,
        ext=step.ext,
        avoid_canaries=step.avoid_canaries,
        confirmed=True,
    )


def _run_normal(step: Step, target: Path) -> None:
    """Run a normal-activity workload step.

    Args:
        step: The normal step.
        target: The target directory.
    """
    mod = importlib.import_module(f"lab.workloads.{step.workload}")
    mod.run(target, step.duration, confirmed=True)


def _restore(target: Path, count: int = 200) -> None:
    """Restore fake files in *target* after an attack step."""
    from lab.fake_ransomware import restore as fr_restore
    from lab.make_fake_files import restore_files

    try:
        fr_restore(target, confirmed=True)
    except Exception:
        pass
    restore_files(target, count=count, confirmed=True)


def _append_csv(row: dict[str, Any], out_path: Path) -> None:
    """Append one row to the labels CSV, creating headers if the file is new.

    Args:
        row: Mapping of column name → value.
        out_path: Destination CSV path.
    """
    write_header = not out_path.exists() or out_path.stat().st_size == 0
    with out_path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def run_plan(
    target: Path,
    steps: list[Step],
    labels_path: Path,
    fake_file_count: int = 200,
    pause_between_runs: float = 5.0,
) -> None:
    """Execute all steps in *steps* against *target* and write *labels_path*.

    Args:
        target: The target share directory.
        steps: Ordered list of :class:`Step` objects.
        labels_path: Path for the output CSV.
        fake_file_count: Number of fake files to maintain.
        pause_between_runs: Seconds to pause between consecutive runs.
    """
    client_machine = _get_client_machine()

    try:
        for i, step in enumerate(steps, 1):
            run_id = f"run_{i:04d}_{step.scenario}"
            print(f"[collect] Step {i}/{len(steps)}: {step.kind} – {step.scenario} ({run_id})")

            if step.kind == "restore":
                _restore(target, fake_file_count)
                continue

            # Auto-restore before every attack so there are clean files to encrypt.
            if step.kind == "attack":
                print("[collect]   → Restoring fake files …")
                _restore(target, fake_file_count)

            # Drop start marker before starting the workload/attack
            _create_marker(target, f"__sg_start_{run_id}")
            start_utc = datetime.now(UTC).isoformat(timespec="seconds")
            files_encrypted = 0

            try:
                if step.kind == "attack":
                    files_encrypted = _run_attack(step, target)
                else:
                    _run_normal(step, target)
            except Exception as exc:  # noqa: BLE001
                print(f"[collect]   ✗ Step failed: {exc}", file=sys.stderr)

            # Drop end marker immediately after the workload/attack ends
            end_utc = datetime.now(UTC).isoformat(timespec="seconds")
            _create_marker(target, f"__sg_end_{run_id}")

            if step.label >= 0:
                if step.kind == "attack":
                    params = json.dumps({
                        "style": step.style,
                        "count": step.count,
                        "ext": step.ext,
                        "avoid_canaries": step.avoid_canaries,
                    })
                else:
                    params = json.dumps({
                        "workload": step.workload,
                        "duration": step.duration,
                    })

                _append_csv(
                    {
                        "run_id": run_id,
                        "scenario": step.scenario,
                        "label": step.label,
                        "parameters": params,
                        "start_utc": start_utc,
                        "end_utc": end_utc,
                        "files_encrypted": files_encrypted,
                        "client_machine": client_machine,
                    },
                    labels_path,
                )
                print(
                    f"[collect]   ✓ done  (files_encrypted={files_encrypted})"
                    if step.kind == "attack"
                    else "[collect]   ✓ done"
                )

            # Pause between runs to allow background SMB activity to settle
            if pause_between_runs > 0 and i < len(steps):
                time.sleep(pause_between_runs)

        # Final restoration of fake files upon plan completion
        print("\n[collect] Collection finished. Restoring files to clean verified state...")
        _restore(target, fake_file_count)

    except KeyboardInterrupt:
        print("\n[collect] Received interrupt (Ctrl+C). Restoring share safely...", file=sys.stderr)
        _restore(target, fake_file_count)
        print("[collect] ✓ Share restored cleanly. Exiting.", file=sys.stderr)
        sys.exit(130)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="[LAB ONLY] ShareGuard collection orchestrator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target share directory (must have marker)")
    parser.add_argument("--dry-run", action="store_true", help="Print plan and exit without running")
    parser.add_argument("--quick", action="store_true", help="Use the short (~15 min) test plan")
    parser.add_argument("--plan-file", metavar="YAML", help="Load plan from a YAML file")
    parser.add_argument(
        "--labels-out",
        default=_LABELS_FILE,
        help=f"Output CSV path (default: {_LABELS_FILE})",
    )
    parser.add_argument(
        "--fake-file-count",
        type=int,
        default=200,
        help="Number of fake files to maintain in target (default: 200)",
    )
    parser.add_argument(
        "--pause-seconds",
        type=float,
        default=None,
        help="Seconds to pause between runs (default: from lab/config.yaml or 5.0)",
    )
    parser.add_argument(
        "--i-understand-this-is-a-lab",
        action="store_true",
        help="Confirmation flag (required for all operations)",
    )
    args = parser.parse_args()

    raw_target = Path(args.target)

    # Safety check — must happen before any file I/O.
    _check_marker(raw_target)

    # When not dry-run, strictly enforce full safety gates
    if not args.dry_run:
        try:
            check_safety(
                raw_target,
                confirmed=args.i_understand_this_is_a_lab,
                require_marker=True,
                require_manifest=True,
            )
        except LabSafetyError as err:
            print(f"[collect] REFUSED: {err}", file=sys.stderr)
            sys.exit(1)

    target = raw_target.resolve()

    # Select plan.
    if args.plan_file:
        steps = _load_plan_from_yaml(Path(args.plan_file))
        quick = False
    elif args.quick:
        steps = _build_quick_plan()
        quick = True
    else:
        steps = _build_default_plan()
        quick = False

    if args.dry_run:
        _print_plan(steps, quick)
        sys.exit(0)

    cfg = load_lab_config()
    pause_s = args.pause_seconds if args.pause_seconds is not None else float(cfg.get("pause_between_runs_seconds", 5.0))

    labels_path = Path(args.labels_out).resolve()
    print(f"[collect] Target  : {target}")
    print(f"[collect] Labels  : {labels_path}")
    print(f"[collect] Steps   : {len(steps)}")
    print(f"[collect] Pause   : {pause_s:.1f}s between runs")
    _print_plan(steps, quick)

    run_plan(target, steps, labels_path, args.fake_file_count, pause_between_runs=pause_s)
    print(f"\n[collect] ✓ Collection complete.  Labels: {labels_path}")


if __name__ == "__main__":
    main()
