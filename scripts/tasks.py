"""
scripts/tasks.py – ShareGuard task runner.

Usage:
    ./.venv/Scripts/python.exe scripts/tasks.py <command>

Commands:
    setup       Print dependency installation instructions.
    test        Run pytest on server/tests/ (excluding slow tests).
    test-all    Run pytest on server/tests/ (including slow tests).
    lint        Run ruff check on the whole project.
    api         Start the FastAPI server (Uvicorn, port 8000).
    dashboard   Start the Streamlit dashboard (port 8501).
    sim         Run the audit-log simulator (lab/simulate_log.py).
    run-sim       Run real-time detection pipeline on audit log (shareguard.run).
    snapshot-demo Run snapshot, attack, and recovery demo (shareguard.tools.snapshot_demo).
    train         Train the ML model (ml/train.py).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
PYTHON = sys.executable


def _run(args: list[str], env: dict[str, str] | None = None) -> None:
    """Run *args* as a subprocess; exit with the child's return code."""
    result = subprocess.run(args, check=False, env=env)  # noqa: S603  shell=False always
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_setup() -> None:
    """Print dependency installation instructions."""
    print(
        "Install dependencies:\n"
        f"  {PYTHON} -m pip install -r requirements.txt\n"
        f"  {PYTHON} -m pip install -r requirements-dev.txt\n"
    )


def cmd_test() -> None:
    """Run pytest on server/tests/ excluding slow tests."""
    _run([PYTHON, "-m", "pytest", "server/tests/", "-m", "not slow"])


def cmd_test_cov() -> None:
    """Run pytest with pytest-cov across core modules (excluding slow tests)."""
    _run(
        [
            PYTHON,
            "-m",
            "pytest",
            "server/tests/",
            "-m",
            "not slow",
            "--cov=shareguard",
            "--cov-report=term-missing",
        ]
    )


def cmd_test_all() -> None:
    """Run all pytest tests on server/tests/ including slow tests."""
    _run([PYTHON, "-m", "pytest", "server/tests/"])


def cmd_lint() -> None:
    """Run ruff over the whole project."""
    _run([PYTHON, "-m", "ruff", "check", "."])


def cmd_api() -> None:
    """Start the FastAPI server with Uvicorn."""
    import os

    env = os.environ.copy()
    if "--sim" in sys.argv:
        env["SHAREGUARD_SIM"] = "1"
    _run(
        [
            PYTHON,
            "-m",
            "uvicorn",
            "shareguard.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--reload",
        ],
        env=env,
    )


def cmd_dashboard() -> None:
    """Start the Streamlit dashboard bound to 127.0.0.1:8501."""
    _run(
        [
            PYTHON,
            "-m",
            "streamlit",
            "run",
            "dashboard/app.py",
            "--server.address",
            "127.0.0.1",
            "--server.port",
            "8501",
        ]
    )


def cmd_sim() -> None:
    """Start the API server in simulation mode and dashboard together via scripts/dev.py."""
    _run([PYTHON, "scripts/dev.py", "--sim"])


def cmd_build_dataset() -> None:
    """Build the ML dataset from simulated audit logs."""
    _run([PYTHON, "ml/build_dataset.py", "--generate-default"])


def cmd_train() -> None:
    """Train the ML model."""
    _run([PYTHON, "ml/train.py"])


def cmd_evaluate() -> None:
    """Evaluate the ML model and compile docs/ml-report.md."""
    _run([PYTHON, "ml/evaluate.py"])


def cmd_run_sim() -> None:
    """Run real-time detection pipeline on simulated audit log."""
    sim_log = Path("audit_sim.log")
    if not sim_log.exists():
        sim_log = Path("lab/sample_audit.log")
    _run([PYTHON, "-m", "shareguard.run", "--sim", str(sim_log), "--speed", "10"])


def cmd_snapshot_demo() -> None:
    """Run snapshot creation, attack simulation, and recovery demo."""
    _run([PYTHON, "-m", "shareguard.tools.snapshot_demo"])


def cmd_flush_firewall() -> None:
    """Flush ShareGuard firewall rules (emergency undo)."""
    import yaml

    from shareguard.responder import get_responder

    cfg_file = ROOT / "config" / "default.yaml"
    resp_cfg = {}
    if cfg_file.exists():
        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        resp_cfg = data.get("response", {})
    responder = get_responder(resp_cfg)
    count = responder.flush_all()
    print(f"Flushed ShareGuard firewall rules ({count} active blocks removed).")


def cmd_list_blocks() -> None:
    """List active ShareGuard client blocks."""
    import yaml

    from shareguard.responder import get_responder

    cfg_file = ROOT / "config" / "default.yaml"
    resp_cfg = {}
    if cfg_file.exists():
        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        resp_cfg = data.get("response", {})
    responder = get_responder(resp_cfg)
    blocks = responder.list_blocks()
    if not blocks:
        print("No active ShareGuard client blocks.")
        return
    print(f"{'IP Address':<18} {'Expires At (UTC)':<24} {'Backend':<10} {'Reason'}")
    print("-" * 75)
    for b in blocks:
        print(f"{b.client_ip:<18} {b.expires_at.strftime('%Y-%m-%d %H:%M:%S'):<24} {b.backend_type:<10} {b.reason}")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

COMMANDS: dict[str, object] = {
    "setup": cmd_setup,
    "test": cmd_test,
    "test-cov": cmd_test_cov,
    "test-all": cmd_test_all,
    "lint": cmd_lint,
    "api": cmd_api,
    "dashboard": cmd_dashboard,
    "sim": cmd_sim,
    "run-sim": cmd_run_sim,
    "snapshot-demo": cmd_snapshot_demo,
    "flush-firewall": cmd_flush_firewall,
    "list-blocks": cmd_list_blocks,
    "build-dataset": cmd_build_dataset,
    "train": cmd_train,
    "evaluate": cmd_evaluate,
}


def main() -> None:
    """Dispatch to the requested command."""
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        available = ", ".join(COMMANDS)
        print(f"Usage: python scripts/tasks.py <command>\nCommands: {available}")
        sys.exit(1)

    command = sys.argv[1]
    COMMANDS[command]()  # type: ignore[operator]


if __name__ == "__main__":
    main()
