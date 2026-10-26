"""scripts/dev.py – Start the API server and Streamlit dashboard together.

Usage:
    ./.venv/Scripts/python.exe scripts/dev.py [--host 127.0.0.1] [--port 8000] [--sim]

Features:
- Starts FastAPI (Uvicorn) and Streamlit dashboard in managed child processes.
- Waits until the API server responds on /health.
- Configures or generates the simulation login credentials and prints them clearly.
- Stops both processes cleanly on Ctrl+C or if either child process crashes unexpectedly.
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
PYTHON = sys.executable


def _wait_for_api(url: str, timeout: float = 15.0) -> bool:
    """Poll API health endpoint until responsive or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:  # noqa: S310
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def _terminate_process(proc: subprocess.Popen[Any] | None, name: str) -> None:
    """Cleanly terminate child process with graceful fallback to kill."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        print(f"Force-killing {name} process...")
        proc.kill()
        proc.wait()
    except Exception as err:
        print(f"Error terminating {name}: {err}")


def main() -> None:
    """Launch API and dashboard processes with credential output and lifecycle management."""
    parser = argparse.ArgumentParser(description="ShareGuard development server launcher")
    parser.add_argument("--host", default=os.getenv("SHAREGUARD__SERVER__HOST", "127.0.0.1"), help="API bind host")
    parser.add_argument("--port", type=int, default=int(os.getenv("SHAREGUARD__SERVER__PORT", "8000")), help="API port")
    parser.add_argument("--sim", action="store_true", help="Enable background audit simulation loop")
    args = parser.parse_args()

    env = os.environ.copy()
    if args.sim:
        env["SHAREGUARD_SIM"] = "1"

    # Setup simulation credentials
    admin_user = os.getenv("SHAREGUARD_ADMIN_USER", "admin")
    admin_password = os.getenv("SHAREGUARD_ADMIN_PASSWORD")
    generated_pass = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        generated_pass = True

    env["SHAREGUARD_ADMIN_USER"] = admin_user
    env["SHAREGUARD_ADMIN_PASSWORD"] = admin_password

    # 1. Start FastAPI backend process
    api_cmd = [
        PYTHON,
        "-m",
        "uvicorn",
        "shareguard.api:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--reload",
    ]
    api_proc = subprocess.Popen(api_cmd, env=env)  # noqa: S603

    # Wait until API answers
    health_url = f"http://{args.host}:{args.port}/health"
    api_ready = _wait_for_api(health_url, timeout=15.0)

    # 2. Start Streamlit dashboard process
    dashboard_file = ROOT / "dashboard" / "app.py"
    dashboard_proc: subprocess.Popen[bytes] | None = None
    if dashboard_file.exists():
        dashboard_env = env.copy()
        dashboard_env["SHAREGUARD_API_URL"] = f"http://{args.host}:{args.port}/api"
        dashboard_cmd = [
            PYTHON,
            "-m",
            "streamlit",
            "run",
            str(dashboard_file),
            "--server.address",
            "127.0.0.1",
            "--server.port",
            "8501",
        ]
        dashboard_proc = subprocess.Popen(dashboard_cmd, env=dashboard_env)  # noqa: S603

    # Print startup banner and credentials
    print("\n" + "=" * 65)
    print("🛡️  ShareGuard Development Environment Running")
    print("=" * 65)
    print(f"  API Backend:     http://{args.host}:{args.port}")
    print(f"  API Docs:        http://{args.host}:{args.port}/docs")
    print("  Dashboard UI:    http://127.0.0.1:8501")
    print("  Status:          " + ("Connected & Ready" if api_ready else "Starting up..."))
    if args.sim:
        print("  Simulation Loop: Active (replaying attack scenarios)")
    print("-" * 65)
    print("  Dashboard Login Credentials:")
    print(f"    Username:      {admin_user}")
    print(f"    Password:      {admin_password}" + (" (generated for this run)" if generated_pass else ""))
    print("=" * 65)
    print("Press Ctrl+C to cleanly stop both processes.\n")

    try:
        while True:
            # Detect premature child crashes
            if api_proc.poll() is not None:
                print(f"\nAPI process exited unexpectedly (code {api_proc.returncode}). Stopping dashboard...")
                break
            if dashboard_proc and dashboard_proc.poll() is not None:
                print(f"\nDashboard process exited unexpectedly (code {dashboard_proc.returncode}). Stopping API...")
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nReceived Ctrl+C: Shutting down ShareGuard services...")
    finally:
        _terminate_process(dashboard_proc, "Dashboard")
        _terminate_process(api_proc, "API")
        print("All processes stopped successfully.")


if __name__ == "__main__":
    main()
