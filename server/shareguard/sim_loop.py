"""shareguard.sim_loop – Background simulation loop for live dashboard and demo.

Generates realistic SMB audit log events (normal office workloads interleaved
with periodic ransomware attacks) and feeds them into the DetectionEngine.
Updates the database with alerts, client records, and baseline snapshots
so that live dashboard data appears within seconds of startup.
"""

from __future__ import annotations

import logging
import random
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lab.simulate_log import _SCENARIOS

from shareguard.db import AlertModel, ClientModel, get_session, init_db
from shareguard.engine import DetectionEngine
from shareguard.parser import parse_line
from shareguard.responder import FakeResponder
from shareguard.snapshots import PortableSnapshotManager

logger = logging.getLogger(__name__)

_SIM_STOP = threading.Event()
_SIM_THREAD: threading.Thread | None = None


def setup_simulation_environment() -> tuple[Path, Path, PortableSnapshotManager]:
    """Create a temporary simulated share folder with baseline snapshot."""
    sim_base = Path(tempfile.gettempdir()) / "shareguard_sim_env"
    share_root = sim_base / "share"
    snap_dir = sim_base / "snapshots"

    share_root.mkdir(parents=True, exist_ok=True)
    snap_dir.mkdir(parents=True, exist_ok=True)

    # Seed initial legitimate files
    for sub in ["Finance", "Engineering", "HR", "Legal"]:
        sub_dir = share_root / sub
        sub_dir.mkdir(parents=True, exist_ok=True)
        for i in range(1, 6):
            doc = sub_dir / f"document_{i}.docx"
            if not doc.exists():
                doc.write_text(f"Confidential {sub} Report {i}\n", encoding="utf-8")

    mgr = PortableSnapshotManager(snapshot_dir=snap_dir)
    # Ensure at least one clean baseline snapshot exists
    mgr.take_snapshot(share=share_root)
    return share_root, snap_dir, mgr


def run_simulation_loop(
    engine: DetectionEngine,
    stop_event: threading.Event,
    interval_seconds: float = 0.2,
) -> None:
    """Continuously replay scenarios into engine and persist state to DB."""
    scenarios = _SCENARIOS
    normal_names = [s for s in scenarios if s.startswith("normal_")]
    attack_names = [s for s in scenarios if s.startswith("attack_")]

    event_count = 0
    cycle = 0

    while not stop_event.is_set():
        cycle += 1
        # Run periodic attack every 4 cycles (~30-40 events), otherwise normal
        if cycle % 4 == 0 and attack_names:
            scenario_name = random.choice(attack_names)
        else:
            scenario_name = random.choice(normal_names) if normal_names else "normal_office"

        scenario_fn = scenarios[scenario_name]
        start_ts = datetime.now(tz=UTC)
        try:
            lines = list(scenario_fn(start=start_ts, duration=10.0, speed=2.0))
        except Exception as e:
            logger.warning("Error generating scenario %s: %s", scenario_name, e)
            lines = []

        for item in lines:
            if stop_event.is_set():
                break

            line_str = getattr(item, "line", str(item))
            event = parse_line(line_str)
            if not event:
                continue

            event_count += 1
            alert = engine.process_event(event)

            # Update DB with client and alert records
            try:
                with get_session() as session:
                    # Update ClientModel
                    now = datetime.now(tz=UTC)
                    client = session.query(ClientModel).filter_by(client_ip=event.client_ip).first()
                    if not client:
                        client = ClientModel(
                            client_ip=event.client_ip,
                            username=event.username,
                            first_seen=now,
                            last_seen=now,
                            is_blocked=False,
                        )
                        session.add(client)
                    else:
                        client.last_seen = now
                        client.username = event.username

                    # Record alert if triggered
                    if alert is not None:
                        # Check if active alert already exists for this client
                        existing_alert = (
                            session.query(AlertModel)
                            .filter_by(client_ip=alert.client_ip, status="open")
                            .first()
                        )
                        if not existing_alert:
                            reasons = [r for r in alert.details.get("reasons", []) if isinstance(r, str)]
                            rules_str = ",".join(alert.triggered_rules)
                            new_alert = AlertModel(
                                client_ip=alert.client_ip,
                                username=alert.username,
                                severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                                triggered_rules=rules_str,
                                ml_score=alert.details.get("score"),
                                explanation=f"Detected ransomware behavior ({rules_str}): {'; '.join(reasons)}",
                                status="open",
                                first_anomaly_ts=now - timedelta(seconds=15),
                                files_touched="[]",
                                created_at=now,
                            )
                            session.add(new_alert)

                    session.commit()
            except Exception as db_err:
                logger.debug("DB update during simulation: %s", db_err)

            time.sleep(interval_seconds)


def start_simulation(engine: DetectionEngine | None = None) -> threading.Event:
    """Start the simulation worker in a background daemon thread."""
    global _SIM_THREAD, _SIM_STOP
    _SIM_STOP.clear()

    # If engine not supplied, build one configured for simulation
    if engine is None:
        from shareguard.api import get_engine, set_engine

        _share_root, _snap_dir, mgr = setup_simulation_environment()
        sim_engine = get_engine()
        sim_engine.snapshot_manager = mgr
        sim_engine.responder = FakeResponder()
        set_engine(sim_engine)
        engine = sim_engine

    init_db()

    _SIM_THREAD = threading.Thread(
        target=run_simulation_loop,
        args=(engine, _SIM_STOP),
        daemon=True,
        name="ShareGuard-SimWorker",
    )
    _SIM_THREAD.start()
    logger.info("ShareGuard simulation loop started in background.")
    return _SIM_STOP


def stop_simulation() -> None:
    """Signal background simulation worker to stop."""
    global _SIM_STOP, _SIM_THREAD
    _SIM_STOP.set()
    if _SIM_THREAD is not None and _SIM_THREAD.is_alive():
        _SIM_THREAD.join(timeout=2.0)
        _SIM_THREAD = None
