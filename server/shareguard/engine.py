"""shareguard.engine – Real-time detection pipeline and orchestrator.

Pipeline:
audit log follower (or replay in simulation) -> Feature aggregation -> rules + ML score ->
decision state machine per client -> typed event bus / alerts -> responder actions & snapshot coordination.

Decision Logic per client (ip, user):
- NORMAL -> SUSPICIOUS when ml_prob >= suspicious_threshold OR rule score >= 0.5.
- SUSPICIOUS -> ATTACK when (2 of last 3 windows above attack threshold) OR critical rule fires (canary).
- ATTACK -> RESOLVED when unblocked by admin OR no suspicious windows for N minutes.
- SUSPICIOUS -> NORMAL after M quiet windows.

Safety Invariants:
- Allowlists (server IPs, gateway, backup server, admin IPs) are never blocked.
- Untrusted filenames from audit logs are sanitized and bounded.
- Global panic stop disables enforcement at runtime.
- Engine failures catch exceptions per window, continuing without crashing Samba.
- Snapshots are paused while any client is SUSPICIOUS or ATTACK, and resumed when clear.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import uuid
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from shareguard.features import ClientFeatures, compute_features
from shareguard.ml import explain, score
from shareguard.parser import AuditEvent, replay
from shareguard.responder import Responder, get_responder
from shareguard.rules import RuleEngine, RuleResult, RuleThresholds
from shareguard.snapshots import FakeSnapshotManager, SnapshotManager

logger = logging.getLogger(__name__)

__all__ = [
    "ClientState",
    "ResponseMode",
    "IncidentRecord",
    "AlertRepository",
    "InMemoryAlertRepository",
    "WindowScoredEvent",
    "StateChangedEvent",
    "AlertOpenedEvent",
    "ActionTakenEvent",
    "AlertResolvedEvent",
    "EngineEvent",
    "EventBus",
    "DetectionEngine",
    "MAX_TRACKED_PATHS",
]

MAX_TRACKED_PATHS = 10_000


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ClientState(StrEnum):
    """Client lifecycle detection states."""

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"
    RESOLVED = "RESOLVED"


class ResponseMode(StrEnum):
    """Engine response operating modes."""

    SHADOW = "shadow"
    ENFORCE_TEMP = "enforce_temp"
    ENFORCE_STRICT = "enforce_strict"


# ---------------------------------------------------------------------------
# Path Sanitization
# ---------------------------------------------------------------------------


def _sanitize_path(path: str) -> str:
    """Sanitize and truncate untrusted file names from audit logs.

    Args:
        path: Raw path string from log.

    Returns:
        Sanitized path truncated to 512 characters without control chars.
    """
    if not path:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", path).strip()
    return clean[:512]


# ---------------------------------------------------------------------------
# Incident Record & Alert Repository
# ---------------------------------------------------------------------------


@dataclass
class IncidentRecord:
    """Detailed record of a detected anomalous client incident.

    Attributes:
        incident_id: Unique identifier for the incident.
        client_ip: IP address of the client.
        username: Samba username.
        first_anomaly_ts: Timestamp of the first anomalous window in the chain.
        detected_ts: Timestamp when ATTACK state was confirmed.
        time_to_detect: Latency in seconds from first anomaly to detection.
        reasons: Plain-language explanations for triggered rules.
        ml_prob: ML ransomware probability (or None if unavailable).
        top_features: Top explainable features from ML explainer.
        files_touched: Bounded list of file paths touched during the incident.
        files_touched_overflow_count: Count of additional files beyond the bound.
        files_lost: Total count of touched files for restore calculation.
        resolved_at: UTC timestamp when incident was resolved.
        status: Incident status ('active' or 'resolved').
        would_have_blocked: True if block was suppressed due to shadow mode.
        action_taken: String describing action applied (e.g. 'blocked_temp').
    """

    incident_id: str
    client_ip: str
    username: str
    first_anomaly_ts: datetime
    detected_ts: datetime | None = None
    time_to_detect: float | None = None
    reasons: list[str] = field(default_factory=list)
    ml_prob: float | None = None
    top_features: list[dict[str, Any]] = field(default_factory=list)
    files_touched: list[str] = field(default_factory=list)
    files_touched_overflow_count: int = 0
    files_lost: int = 0
    resolved_at: datetime | None = None
    status: str = "active"
    would_have_blocked: bool = False
    action_taken: str = "none"

    def record_path(self, path: str) -> None:
        """Safely record an untrusted touched file path."""
        sanitized = _sanitize_path(path)
        if not sanitized:
            return
        self.files_lost += 1
        if len(self.files_touched) < MAX_TRACKED_PATHS:
            self.files_touched.append(sanitized)
        else:
            self.files_touched_overflow_count += 1


class AlertRepository(ABC):
    """Abstract repository for persisting and querying alert incidents."""

    @abstractmethod
    def add(self, incident: IncidentRecord) -> None:
        """Add a new incident record."""
        ...

    @abstractmethod
    def get(self, incident_id: str) -> IncidentRecord | None:
        """Retrieve an incident by ID."""
        ...

    @abstractmethod
    def list_all(
        self,
        active_only: bool = False,
        client_ip: str | None = None,
    ) -> list[IncidentRecord]:
        """List incidents with optional filtering."""
        ...

    @abstractmethod
    def update(self, incident: IncidentRecord) -> None:
        """Update an existing incident record."""
        ...


class InMemoryAlertRepository(AlertRepository):
    """Thread-safe in-memory alert repository."""

    def __init__(self) -> None:
        self._incidents: dict[str, IncidentRecord] = {}
        self._lock = threading.Lock()

    def add(self, incident: IncidentRecord) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident

    def get(self, incident_id: str) -> IncidentRecord | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def list_all(
        self,
        active_only: bool = False,
        client_ip: str | None = None,
    ) -> list[IncidentRecord]:
        with self._lock:
            res = list(self._incidents.values())
        if active_only:
            res = [inc for inc in res if inc.status == "active"]
        if client_ip:
            res = [inc for inc in res if inc.client_ip == client_ip]
        return res

    def update(self, incident: IncidentRecord) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident


# ---------------------------------------------------------------------------
# Typed Events & Non-blocking Event Bus
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowScoredEvent:
    """Emitted after evaluating a client's sliding window."""

    client_ip: str
    username: str
    window_start: float
    window_end: float
    rule_score: float
    ml_prob: float | None
    triggered_rules: list[str]
    reasons: list[str]
    is_suspicious: bool
    is_attack: bool


@dataclass(frozen=True, slots=True)
class StateChangedEvent:
    """Emitted when a client transitions state."""

    client_ip: str
    username: str
    old_state: ClientState
    new_state: ClientState
    timestamp: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class AlertOpenedEvent:
    """Emitted when an incident is escalated to ATTACK."""

    incident_id: str
    client_ip: str
    username: str
    severity: str
    triggered_rules: list[str]
    ml_prob: float | None
    reasons: list[str]
    detected_ts: datetime
    time_to_detect: float
    top_features: list[dict[str, Any]]
    files_touched_count: int


@dataclass(frozen=True, slots=True)
class ActionTakenEvent:
    """Emitted when a response action is executed or simulated."""

    client_ip: str
    username: str
    action: str
    mode: str
    reason: str
    timestamp: datetime
    would_have_blocked: bool


@dataclass(frozen=True, slots=True)
class AlertResolvedEvent:
    """Emitted when an incident is marked resolved."""

    incident_id: str
    client_ip: str
    username: str
    resolved_ts: datetime
    reason: str


EngineEvent = (
    WindowScoredEvent
    | StateChangedEvent
    | AlertOpenedEvent
    | ActionTakenEvent
    | AlertResolvedEvent
)


class EventBus:
    """In-process event bus with bounded subscriber buffers.

    Invariants:
    - Subscribers cannot block the engine: queues are bounded.
    - When a buffer is full, the oldest event is dropped and a dropped counter is incremented.
    """

    def __init__(self, queue_size: int = 1000) -> None:
        self.queue_size = queue_size
        self._subscribers: list[tuple[Callable[[EngineEvent], None] | None, deque[EngineEvent]]] = []
        self._lock = threading.Lock()
        self.dropped_count: int = 0

    def subscribe_queue(self, maxsize: int | None = None) -> deque[EngineEvent]:
        """Subscribe and receive a bounded event queue."""
        q: deque[EngineEvent] = deque(maxlen=maxsize or self.queue_size)
        with self._lock:
            self._subscribers.append((None, q))
        return q

    def subscribe(
        self,
        callback: Callable[[EngineEvent], None],
        maxsize: int | None = None,
    ) -> deque[EngineEvent]:
        """Subscribe a callable handler backed by a bounded buffer."""
        q: deque[EngineEvent] = deque(maxlen=maxsize or self.queue_size)
        with self._lock:
            self._subscribers.append((callback, q))
        return q

    def publish(self, event: EngineEvent) -> None:
        """Publish an event to all subscribers without blocking."""
        with self._lock:
            for cb, q in self._subscribers:
                if q.maxlen is not None and len(q) == q.maxlen:
                    self.dropped_count += 1
                q.append(event)
                if cb is not None:
                    try:
                        cb(event)
                    except Exception as err:
                        logger.warning("Subscriber callback raised error: %s", err)


# ---------------------------------------------------------------------------
# Per-Client State Tracker
# ---------------------------------------------------------------------------


class _ClientTracker:
    """Maintains sliding event window and state machine history for a single client."""

    def __init__(self, ip: str, user: str) -> None:
        self.ip = ip
        self.user = user
        self.state: ClientState = ClientState.NORMAL
        self.events: deque[AuditEvent] = deque()
        self.window_history: deque[bool] = deque(maxlen=3)  # True if window was >= attack_threshold
        self.quiet_windows: int = 0
        self.last_suspicious_ts: datetime | None = None
        self.first_anomaly_ts: datetime | None = None
        self.current_incident: IncidentRecord | None = None
        self.last_action_ts: datetime | None = None


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------


class DetectionEngine:
    """Real-time detection pipeline and orchestrator.

    Coordinates:
    - Audit log follower / replay
    - Sliding-window feature extraction
    - Rule engine evaluation + ML scoring and explanations
    - Per-client state machine (NORMAL -> SUSPICIOUS -> ATTACK -> RESOLVED)
    - Responder actions (shadow, enforce_temp, enforce_strict)
    - Snapshot manager pause/resume coordination
    - Non-blocking typed event bus
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        responder: Responder | None = None,
        snapshot_manager: SnapshotManager | None = None,
        alert_repository: AlertRepository | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        """Initialise detection engine with configuration and backends."""
        self.config = config or {}

        # Sub-configurations
        det_cfg = self.config.get("detection", {})
        resp_cfg = self.config.get("response", {})
        canary_cfg = self.config.get("canary", {})

        # Detection thresholds
        self.window_seconds: float = float(det_cfg.get("window_seconds", 60))
        self.suspicious_threshold: float = float(det_cfg.get("suspicious_threshold", 0.6))
        self.attack_threshold: float = float(det_cfg.get("attack_threshold", 0.85))
        self.quiet_windows_to_normal: int = int(det_cfg.get("quiet_windows_to_normal", 3))
        self.attack_resolve_minutes: int = int(det_cfg.get("attack_resolve_minutes", 15))

        # Response mode from env SHAREGUARD_MODE or config
        env_mode = os.environ.get("SHAREGUARD_MODE")
        raw_mode = env_mode or resp_cfg.get("mode", "shadow")
        self.mode: ResponseMode = (
            ResponseMode.ENFORCE_TEMP
            if raw_mode in {"enforce_temp", "block"}
            else ResponseMode.ENFORCE_STRICT
            if raw_mode == "enforce_strict"
            else ResponseMode.SHADOW
        )
        self.block_ttl_minutes: int = int(resp_cfg.get("block_ttl_minutes", 15))

        # Allowlist parsing (IPs or CIDRs that must NEVER be blocked)
        raw_allowlist = set(resp_cfg.get("allowlist", ["127.0.0.1", "::1"]))
        raw_allowlist.update(canary_cfg.get("allowlist", ["192.168.1.250"]))
        self.allowlist: set[str] = raw_allowlist

        # Rule thresholds and engine
        rule_thresholds = RuleThresholds(
            ext_change_burst_threshold=int(det_cfg.get("rules", {}).get("ext_change_burst_threshold", 15)),
            write_count_threshold=int(det_cfg.get("rules", {}).get("write_count_threshold", 30)),
            min_distinct_files_threshold=int(det_cfg.get("rules", {}).get("min_distinct_files_threshold", 10)),
            entropy_written_threshold=float(det_cfg.get("rules", {}).get("entropy_written_threshold", 7.0)),
            ransom_note_threshold=int(det_cfg.get("rules", {}).get("ransom_note_threshold", 2)),
            ransom_note_dirs_threshold=int(det_cfg.get("rules", {}).get("ransom_note_dirs_threshold", 2)),
            delete_after_copy_threshold=int(det_cfg.get("rules", {}).get("delete_after_copy_threshold", 10)),
            baseline_files_changed=int(det_cfg.get("rules", {}).get("baseline_files_changed", 10)),
            baseline_ops_per_sec=float(det_cfg.get("rules", {}).get("baseline_ops_per_sec", 15.0)),
            canary_allowlist=list(self.allowlist),
        )
        self.rule_engine = RuleEngine(rule_thresholds)

        # Plug-in components
        self.responder: Responder = responder or get_responder(resp_cfg)
        self.snapshot_manager: SnapshotManager = snapshot_manager or FakeSnapshotManager()
        self.alert_repo: AlertRepository = alert_repository or InMemoryAlertRepository()
        self.event_bus: EventBus = event_bus or EventBus()

        # Engine state
        self._clients: dict[tuple[str, str], _ClientTracker] = {}
        self._lock = threading.Lock()
        self.panic_stop: bool = False
        self.ml_status: str = "ok"

    def set_panic_stop(self, enabled: bool) -> None:
        """Enable or disable global panic stop at runtime.

        When enabled, all enforcement blocking actions are immediately suppressed.
        """
        self.panic_stop = enabled
        logger.warning("Global panic stop set to %s", enabled)

    def is_ip_allowlisted(self, ip_str: str) -> bool:
        """Check if *ip_str* is allowlisted and must never be blocked."""
        try:
            client_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        if client_ip.is_loopback:
            return True

        for item in self.allowlist:
            item_clean = item.strip()
            try:
                if "/" in item_clean:
                    net = ipaddress.ip_network(item_clean, strict=False)
                    if client_ip in net:
                        return True
                else:
                    if client_ip == ipaddress.ip_address(item_clean):
                        return True
            except ValueError:
                continue

        return False

    def _get_tracker(self, ip: str, user: str) -> _ClientTracker:
        """Get or create tracker for client key."""
        key = (ip, user)
        if key not in self._clients:
            self._clients[key] = _ClientTracker(ip, user)
        return self._clients[key]

    def get_client_state(self, ip: str, user: str) -> ClientState:
        """Return the current detection state for client (ip, user)."""
        with self._lock:
            key = (ip, user)
            if key in self._clients:
                return self._clients[key].state
            return ClientState.NORMAL

    def _sync_snapshots(self) -> None:
        """Enforce snapshot coordination invariant:

        While ANY client is SUSPICIOUS or ATTACK, call pause_snapshots();
        resume when all are clear.
        """
        has_suspicious_or_attack = any(
            tracker.state in (ClientState.SUSPICIOUS, ClientState.ATTACK)
            for tracker in self._clients.values()
        )
        if has_suspicious_or_attack:
            self.snapshot_manager.pause_snapshots()
        else:
            self.snapshot_manager.resume_snapshots()

    def process_event(self, event: AuditEvent) -> IncidentRecord | None:
        """Process one audit event through the pipeline.

        Returns:
            The active :class:`IncidentRecord` if in ATTACK/SUSPICIOUS, or None.
        """
        try:
            return self._process_event_unlocked(event)
        except Exception as err:
            logger.error(
                "Engine error processing event for client %s (%s): %s",
                event.ip,
                event.user,
                err,
                exc_info=True,
            )
            return None

    def _process_event_unlocked(self, event: AuditEvent) -> IncidentRecord | None:
        with self._lock:
            tracker = self._get_tracker(event.ip, event.user)

            # 1. Append event to client window and evict old events
            tracker.events.append(event)
            cutoff = event.ts.timestamp() - self.window_seconds
            while tracker.events and tracker.events[0].ts.timestamp() < cutoff:
                tracker.events.popleft()

            # Record untrusted file touched if an incident is in progress
            if tracker.current_incident is not None:
                if event.path:
                    tracker.current_incident.record_path(event.path)
                if event.new_path:
                    tracker.current_incident.record_path(event.new_path)

            # 2. Compute features for window
            window_events = list(tracker.events)
            features: ClientFeatures = compute_features(
                window_events,
                client_ip=tracker.ip,
                username=tracker.user,
            )

            # 3. Rule evaluation
            rule_result: RuleResult = self.rule_engine.evaluate_result(features)

            # 4. ML evaluation (resilient fallback on failure or missing model)
            ml_prob: float | None = None
            try:
                ml_prob = score(features)
            except Exception as ml_err:
                logger.warning("ML model evaluation failed; fallback to rules: %s", ml_err)
                self.ml_status = f"degraded: {ml_err}"

            # Evaluate thresholds
            is_suspicious_window = (
                (ml_prob is not None and ml_prob >= self.suspicious_threshold)
                or (rule_result.score >= 0.5)
            )
            is_attack_window = (
                (ml_prob is not None and ml_prob >= self.attack_threshold)
                or (rule_result.score >= self.attack_threshold)
            )

            tracker.window_history.append(is_attack_window)

            # Publish WindowScoredEvent
            scored_evt = WindowScoredEvent(
                client_ip=tracker.ip,
                username=tracker.user,
                window_start=features.window_start,
                window_end=features.window_end,
                rule_score=rule_result.score,
                ml_prob=ml_prob,
                triggered_rules=rule_result.triggered_rules,
                reasons=rule_result.reasons,
                is_suspicious=is_suspicious_window,
                is_attack=is_attack_window,
            )
            self.event_bus.publish(scored_evt)

            # 5. State Machine Evaluation
            old_state = tracker.state

            if tracker.state == ClientState.NORMAL and (is_suspicious_window or rule_result.critical):
                tracker.state = ClientState.SUSPICIOUS
                tracker.first_anomaly_ts = event.ts
                tracker.last_suspicious_ts = event.ts
                tracker.quiet_windows = 0

                # Start new incident
                inc_id = f"inc-{uuid.uuid4().hex[:10]}"
                incident = IncidentRecord(
                    incident_id=inc_id,
                    client_ip=tracker.ip,
                    username=tracker.user,
                    first_anomaly_ts=event.ts,
                    reasons=list(rule_result.reasons),
                    ml_prob=ml_prob,
                )
                # Add current window paths
                for e in window_events:
                    if e.path:
                        incident.record_path(e.path)
                    if e.new_path:
                        incident.record_path(e.new_path)

                tracker.current_incident = incident
                self.alert_repo.add(incident)

                self.event_bus.publish(
                    StateChangedEvent(
                        client_ip=tracker.ip,
                        username=tracker.user,
                        old_state=old_state,
                        new_state=ClientState.SUSPICIOUS,
                        timestamp=event.ts,
                        reason="; ".join(rule_result.reasons) or "Suspicious activity detected",
                    )
                )
                self._sync_snapshots()

            if tracker.state == ClientState.SUSPICIOUS:
                # Check for escalation to ATTACK:
                # 2 of last 3 windows above attack threshold OR critical rule fired
                attack_windows_count = sum(1 for w in tracker.window_history if w)
                recent_history_len = len(tracker.window_history)
                attack_condition_met = (
                    (recent_history_len >= 2 and attack_windows_count >= 2)
                    or rule_result.critical
                )

                if attack_condition_met:
                    tracker.state = ClientState.ATTACK
                    tracker.last_suspicious_ts = event.ts
                    detected_ts = event.ts
                    first_ts = tracker.first_anomaly_ts or detected_ts
                    ttd = max(0.0, (detected_ts - first_ts).total_seconds())

                    # Explain features if model available
                    top_feats: list[dict[str, Any]] = []
                    try:
                        top_feats = explain(features, top_k=5)
                    except Exception:
                        top_feats = []

                    incident = tracker.current_incident
                    if incident is not None:
                        incident.detected_ts = detected_ts
                        incident.time_to_detect = ttd
                        for r in rule_result.reasons:
                            if r not in incident.reasons:
                                incident.reasons.append(r)
                        incident.ml_prob = ml_prob
                        incident.top_features = top_feats
                        self.alert_repo.update(incident)

                    self.event_bus.publish(
                        StateChangedEvent(
                            client_ip=tracker.ip,
                            username=tracker.user,
                            old_state=ClientState.SUSPICIOUS,
                            new_state=ClientState.ATTACK,
                            timestamp=event.ts,
                            reason="; ".join(rule_result.reasons) or "Attack threshold breached",
                        )
                    )

                    if incident is not None:
                        self.event_bus.publish(
                            AlertOpenedEvent(
                                incident_id=incident.incident_id,
                                client_ip=tracker.ip,
                                username=tracker.user,
                                severity="critical" if rule_result.critical else "high",
                                triggered_rules=rule_result.triggered_rules,
                                ml_prob=ml_prob,
                                reasons=incident.reasons,
                                detected_ts=detected_ts,
                                time_to_detect=ttd,
                                top_features=top_feats,
                                files_touched_count=incident.files_lost,
                            )
                        )

                    # Execute responder action
                    self._execute_response_action(tracker, incident, event.ts)
                    self._sync_snapshots()

                else:
                    # Not escalating to attack yet; check quiet windows
                    if is_suspicious_window:
                        tracker.quiet_windows = 0
                        tracker.last_suspicious_ts = event.ts
                    else:
                        tracker.quiet_windows += 1
                        if tracker.quiet_windows >= self.quiet_windows_to_normal:
                            tracker.state = ClientState.NORMAL
                            self.event_bus.publish(
                                StateChangedEvent(
                                    client_ip=tracker.ip,
                                    username=tracker.user,
                                    old_state=ClientState.SUSPICIOUS,
                                    new_state=ClientState.NORMAL,
                                    timestamp=event.ts,
                                    reason=f"Normalized after {tracker.quiet_windows} quiet windows",
                                )
                            )
                            tracker.current_incident = None
                            self._sync_snapshots()

            elif tracker.state == ClientState.ATTACK:
                if is_suspicious_window:
                    tracker.last_suspicious_ts = event.ts
                else:
                    # Check auto-resolution after N minutes of quiet
                    if (
                        tracker.last_suspicious_ts is not None
                        and (event.ts - tracker.last_suspicious_ts).total_seconds() >= self.attack_resolve_minutes * 60
                    ):
                        self._resolve_client_internal(
                            tracker,
                            event.ts,
                            reason=f"Auto-resolved after {self.attack_resolve_minutes}m quiet",
                        )

            return tracker.current_incident

    def _execute_response_action(
        self,
        tracker: _ClientTracker,
        incident: IncidentRecord | None,
        now: datetime,
    ) -> None:
        """Apply response action according to configured mode and safety guards."""
        ip = tracker.ip
        reasons_str = "; ".join(incident.reasons) if incident else "Ransomware detection"

        # Safety Check 1: Allowlist
        if self.is_ip_allowlisted(ip):
            logger.info("IP %s is allowlisted; suppression of all block actions.", ip)
            if incident:
                incident.action_taken = "allowlisted_skipped"
                incident.would_have_blocked = False
            self.event_bus.publish(
                ActionTakenEvent(
                    client_ip=ip,
                    username=tracker.user,
                    action="allowlisted_skipped",
                    mode=self.mode.value,
                    reason="Client IP is in allowlist",
                    timestamp=now,
                    would_have_blocked=False,
                )
            )
            return

        # Safety Check 2: Panic stop
        if self.panic_stop:
            logger.warning("Global panic stop active: suppressing block action for %s", ip)
            if incident:
                incident.action_taken = "panic_stopped"
                incident.would_have_blocked = True
            self.event_bus.publish(
                ActionTakenEvent(
                    client_ip=ip,
                    username=tracker.user,
                    action="panic_stopped",
                    mode=self.mode.value,
                    reason="Global panic stop enabled",
                    timestamp=now,
                    would_have_blocked=True,
                )
            )
            return

        # Safety Check 3: Cooldown
        if tracker.last_action_ts is not None and (now - tracker.last_action_ts).total_seconds() < 60:
            logger.debug("Client %s action cooldown active; skipping duplicate.", ip)
            return

        tracker.last_action_ts = now

        # Response Mode Handling
        if self.mode == ResponseMode.SHADOW:
            if incident:
                incident.would_have_blocked = True
                incident.action_taken = "would_have_blocked"
            self.event_bus.publish(
                ActionTakenEvent(
                    client_ip=ip,
                    username=tracker.user,
                    action="would_have_blocked",
                    mode="shadow",
                    reason=reasons_str,
                    timestamp=now,
                    would_have_blocked=True,
                )
            )

        elif self.mode == ResponseMode.ENFORCE_TEMP:
            record = self.responder.block_client(
                ip=ip,
                ttl=self.block_ttl_minutes,
                reason=reasons_str,
                username=tracker.user,
            )
            action_desc = "blocked_temp" if record else "block_failed"
            if incident:
                incident.action_taken = action_desc
                incident.would_have_blocked = False
            self.event_bus.publish(
                ActionTakenEvent(
                    client_ip=ip,
                    username=tracker.user,
                    action=action_desc,
                    mode="enforce_temp",
                    reason=reasons_str,
                    timestamp=now,
                    would_have_blocked=False,
                )
            )

        elif self.mode == ResponseMode.ENFORCE_STRICT:
            record = self.responder.block_client(
                ip=ip,
                ttl=0,  # Indefinite until admin unblocks
                reason=reasons_str,
                username=tracker.user,
            )
            action_desc = "blocked_strict" if record else "block_failed"
            if incident:
                incident.action_taken = action_desc
                incident.would_have_blocked = False
            self.event_bus.publish(
                ActionTakenEvent(
                    client_ip=ip,
                    username=tracker.user,
                    action=action_desc,
                    mode="enforce_strict",
                    reason=reasons_str,
                    timestamp=now,
                    would_have_blocked=False,
                )
            )

    def resolve_client(
        self,
        ip: str,
        user: str,
        reason: str = "Admin unblock",
    ) -> bool:
        """Resolve a client's incident, unblock them, and resume snapshots if clear."""
        with self._lock:
            key = (ip, user)
            if key not in self._clients:
                return False
            tracker = self._clients[key]
            return self._resolve_client_internal(tracker, datetime.now(tz=UTC), reason=reason)

    def _resolve_client_internal(
        self,
        tracker: _ClientTracker,
        now: datetime,
        reason: str,
    ) -> bool:
        """Internal resolution handler."""
        old_state = tracker.state
        tracker.state = ClientState.RESOLVED
        incident = tracker.current_incident
        if incident is not None:
            incident.status = "resolved"
            incident.resolved_at = now
            self.alert_repo.update(incident)

        # Unblock via responder
        self.responder.unblock_client(tracker.ip)

        self.event_bus.publish(
            StateChangedEvent(
                client_ip=tracker.ip,
                username=tracker.user,
                old_state=old_state,
                new_state=ClientState.RESOLVED,
                timestamp=now,
                reason=reason,
            )
        )

        if incident is not None:
            self.event_bus.publish(
                AlertResolvedEvent(
                    incident_id=incident.incident_id,
                    client_ip=tracker.ip,
                    username=tracker.user,
                    resolved_ts=now,
                    reason=reason,
                )
            )

        self._sync_snapshots()
        return True

    def process_batch(self, events: list[AuditEvent]) -> list[IncidentRecord]:
        """Process an ordered list of audit events."""
        for evt in events:
            self.process_event(evt)
        return self.alert_repo.list_all()

    def run_sim(
        self,
        log_path: Path,
        speed: float = 1.0,
        stop_event: threading.Event | None = None,
    ) -> list[IncidentRecord]:
        """Replay simulated audit log file through detection engine with speed multiplier.

        Args:
            log_path: Path to audit log file.
            speed: Speed multiplier for replay generator.
            stop_event: Optional event to terminate playback early.

        Returns:
            List of detected incidents.
        """
        for event, _sleep_secs in replay(log_path, speed=speed):
            if stop_event is not None and stop_event.is_set():
                break
            self.process_event(event)
        return self.alert_repo.list_all()
