"""
shareguard.rules – Rule-based ransomware detector.

Evaluates aggregated :class:`~shareguard.features.ClientFeatures` against
expert detection rules:
- R1: Canary file touched by non-allowlisted client -> critical alert.
- R2: Extension change burst (rapid renaming to new/suspicious extensions).
- R3: High write count combined with high entropy written (mass encryption).
- R4: Ransom-note-like file creation across multiple directories.
- R5: Delete-after-copy pattern (encrypted writes followed by original unlinks).
- BaselineV1Rule: Legacy activity-rate proxy (files changed > 10 and high ops/sec).

Returns typed :class:`RuleResult` objects explaining detections in plain language.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from shareguard.canary import is_client_allowlisted

if TYPE_CHECKING:
    from shareguard.features import ClientFeatures

__all__ = [
    "AlertSeverity",
    "Alert",
    "RuleResult",
    "RuleThresholds",
    "RuleEngine",
    "BaselineV1Rule",
    "evaluate_rules",
    "load_rule_thresholds",
]


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class RuleResult:
    """The result of evaluating detection rules against a client's features.

    Attributes:
        score: Anomaly score between 0.0 and 1.0.
        reasons: Plain-language explanations for triggered rules.
        critical: True if an immediate critical response is warranted.
        triggered_rules: List of rule identifiers that fired (e.g. ["R1", "R2"]).
    """

    score: float
    reasons: list[str]
    critical: bool
    triggered_rules: list[str] = field(default_factory=list)


@dataclass
class Alert:
    """An alert produced by the rule engine or the ML model.

    Attributes:
        client_ip: IP address of the suspected client.
        username: Samba username of the suspected client.
        severity: Alert severity level.
        triggered_rules: Names of the rules that fired.
        details: Key→value map of rule scores / feature values.
        created_at: UTC timestamp of alert creation.
        ml_score: Probability from the ML model (0–1), if available.
    """

    client_ip: str
    username: str
    severity: AlertSeverity
    triggered_rules: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ml_score: float | None = None


@dataclass
class RuleThresholds:
    """Configurable thresholds for detection rules with validation."""

    ext_change_burst_threshold: int = 15
    write_count_threshold: int = 30
    min_distinct_files_threshold: int = 10
    entropy_written_threshold: float = 7.0
    ransom_note_threshold: int = 2
    ransom_note_dirs_threshold: int = 2
    delete_after_copy_threshold: int = 10
    baseline_files_changed: int = 10
    baseline_ops_per_sec: float = 15.0
    canary_allowlist: list[str] = field(default_factory=lambda: ["192.168.1.250"])

    def __post_init__(self) -> None:
        """Validate threshold ranges."""
        if self.ext_change_burst_threshold <= 0:
            raise ValueError("ext_change_burst_threshold must be positive")
        if self.write_count_threshold <= 0:
            raise ValueError("write_count_threshold must be positive")
        if self.min_distinct_files_threshold <= 0:
            raise ValueError("min_distinct_files_threshold must be positive")
        if not (0.0 <= self.entropy_written_threshold <= 8.0):
            raise ValueError("entropy_written_threshold must be between 0.0 and 8.0")
        if self.ransom_note_threshold <= 0:
            raise ValueError("ransom_note_threshold must be positive")
        if self.ransom_note_dirs_threshold <= 0:
            raise ValueError("ransom_note_dirs_threshold must be positive")
        if self.delete_after_copy_threshold <= 0:
            raise ValueError("delete_after_copy_threshold must be positive")
        if self.baseline_files_changed <= 0:
            raise ValueError("baseline_files_changed must be positive")
        if self.baseline_ops_per_sec <= 0.0:
            raise ValueError("baseline_ops_per_sec must be positive")


def load_rule_thresholds(config_path: Path | None = None) -> RuleThresholds:
    """Load and validate rule thresholds from YAML configuration.

    Args:
        config_path: Path to configuration file. If None, resolves config/default.yaml.

    Returns:
        A validated :class:`RuleThresholds` instance.
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"

    if not config_path.exists():
        return RuleThresholds()

    try:
        content = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        detection_cfg = content.get("detection", {})
        rules_cfg = detection_cfg.get("rules", {})
        canary_cfg = content.get("canary", {})
        allowlist = canary_cfg.get("allowlist", ["192.168.1.250"])

        return RuleThresholds(
            ext_change_burst_threshold=int(rules_cfg.get("ext_change_burst_threshold", 15)),
            write_count_threshold=int(rules_cfg.get("write_count_threshold", 30)),
            min_distinct_files_threshold=int(rules_cfg.get("min_distinct_files_threshold", 10)),
            entropy_written_threshold=float(rules_cfg.get("entropy_written_threshold", 7.0)),
            ransom_note_threshold=int(rules_cfg.get("ransom_note_threshold", 2)),
            ransom_note_dirs_threshold=int(rules_cfg.get("ransom_note_dirs_threshold", 2)),
            delete_after_copy_threshold=int(rules_cfg.get("delete_after_copy_threshold", 10)),
            baseline_files_changed=int(rules_cfg.get("baseline_files_changed", 10)),
            baseline_ops_per_sec=float(rules_cfg.get("baseline_ops_per_sec", 15.0)),
            canary_allowlist=list(allowlist),
        )
    except Exception:
        return RuleThresholds()


class BaselineV1Rule:
    """Legacy baseline rule: files changed > threshold and high ops_per_sec."""

    def __init__(self, files_threshold: int = 10, ops_threshold: float = 15.0) -> None:
        self.files_threshold = files_threshold
        self.ops_threshold = ops_threshold

    def evaluate(self, features: ClientFeatures) -> tuple[bool, str]:
        """Evaluate baseline rule.

        Returns (fired, reason_text).
        """
        files_changed = features.extra.get(
            "files_changed",
            float(features.rename_count + features.write_count + features.delete_count),
        )
        ops_per_sec = features.extra.get("ops_per_sec", 0.0)

        if files_changed > self.files_threshold and ops_per_sec > self.ops_threshold:
            return (
                True,
                f"Baseline V1 activity proxy triggered: {files_changed:.0f} files changed at {ops_per_sec:.1f} ops/sec",
            )
        return False, ""


class RuleEngine:
    """Stateless rule evaluator configured from thresholds.

    Evaluates R1 through R5 and BaselineV1.
    """

    def __init__(self, thresholds: RuleThresholds | dict[str, Any] | None = None) -> None:
        if isinstance(thresholds, RuleThresholds):
            self.thresholds = thresholds
        elif isinstance(thresholds, dict):
            # Parse dict into RuleThresholds
            self.thresholds = RuleThresholds(
                ext_change_burst_threshold=int(thresholds.get("ext_change_burst_threshold", 15)),
                write_count_threshold=int(thresholds.get("write_count_threshold", 30)),
                min_distinct_files_threshold=int(thresholds.get("min_distinct_files_threshold", 10)),
                entropy_written_threshold=float(thresholds.get("entropy_written_threshold", 7.0)),
                ransom_note_threshold=int(thresholds.get("ransom_note_threshold", 2)),
                ransom_note_dirs_threshold=int(thresholds.get("ransom_note_dirs_threshold", 2)),
                delete_after_copy_threshold=int(thresholds.get("delete_after_copy_threshold", 10)),
                baseline_files_changed=int(thresholds.get("baseline_files_changed", 10)),
                baseline_ops_per_sec=float(thresholds.get("baseline_ops_per_sec", 15.0)),
                canary_allowlist=list(thresholds.get("canary_allowlist", ["192.168.1.250"])),
            )
        else:
            self.thresholds = load_rule_thresholds()

        self.baseline_rule = BaselineV1Rule(
            files_threshold=self.thresholds.baseline_files_changed,
            ops_threshold=self.thresholds.baseline_ops_per_sec,
        )

    def evaluate_result(self, features: ClientFeatures) -> RuleResult:
        """Evaluate features against all detection rules and return a RuleResult."""
        triggered: list[str] = []
        reasons: list[str] = []
        is_critical = False
        rule_scores: list[float] = []

        extra = features.extra

        # R1: Canary file touched by non-allowlisted client
        canary_touches = extra.get("canary_touch_count", 0.0)
        if canary_touches > 0.0 and not is_client_allowlisted(
            features.client_ip, self.thresholds.canary_allowlist
        ):
            triggered.append("R1")
            reasons.append(
                f"Canary decoy file accessed by unauthorized client {features.client_ip}"
            )
            is_critical = True
            rule_scores.append(1.0)

        # R2: Extension change burst
        ext_changes = extra.get("ext_change_count", float(features.rename_count))
        if ext_changes >= self.thresholds.ext_change_burst_threshold:
            triggered.append("R2")
            reasons.append(
                f"Burst of {int(ext_changes)} file renames changing extension (threshold: {self.thresholds.ext_change_burst_threshold})"
            )
            rule_scores.append(0.85)

        # R3: High open_write_count with high mean_entropy_written across distinct files
        write_count = features.write_count
        entropy_written = extra.get("mean_entropy_written", 0.0)
        distinct_files = extra.get("distinct_high_entropy_files", 0.0)
        if (
            write_count >= self.thresholds.write_count_threshold
            and entropy_written >= self.thresholds.entropy_written_threshold
            and distinct_files >= self.thresholds.min_distinct_files_threshold
        ):
            triggered.append("R3")
            reasons.append(
                f"High write volume ({write_count} writes across {int(distinct_files)} distinct files) with high entropy content ({entropy_written:.2f} bits)"
            )
            rule_scores.append(0.85)

        # R4: Ransom-note-like file creation across many directories
        notes_created = extra.get("ransom_note_count", 0.0)
        note_dirs = extra.get("ransom_note_dirs", 0.0)
        if (
            notes_created >= self.thresholds.ransom_note_threshold
            and note_dirs >= self.thresholds.ransom_note_dirs_threshold
        ):
            triggered.append("R4")
            reasons.append(
                f"Ransom note file creation detected ({int(notes_created)} notes across {int(note_dirs)} directories)"
            )
            rule_scores.append(0.90)

        # R5: Delete-after-copy pattern
        delete_after_copy = extra.get("delete_after_copy_count", 0.0)
        if delete_after_copy >= self.thresholds.delete_after_copy_threshold:
            triggered.append("R5")
            reasons.append(
                f"Delete-after-copy ransomware pattern ({int(delete_after_copy)} pre-existing files deleted after encrypted copies were written)"
            )
            rule_scores.append(0.85)

        if not rule_scores:
            return RuleResult(score=0.0, reasons=[], critical=False, triggered_rules=[])

        # Aggregate score: critical rules force 1.0, otherwise combine scores
        if is_critical:
            final_score = 1.0
        else:
            final_score = min(1.0, max(rule_scores) + 0.05 * (len(rule_scores) - 1))

        return RuleResult(
            score=round(final_score, 3),
            reasons=reasons,
            critical=is_critical,
            triggered_rules=triggered,
        )

    def evaluate_baseline(self, features: ClientFeatures) -> tuple[bool, str]:
        """Evaluate baseline legacy proxy rule independently."""
        return self.baseline_rule.evaluate(features)

    def evaluate(self, features: ClientFeatures) -> Alert | None:
        """Evaluate *features* against all rules and return an Alert if score >= 0.5."""
        result = self.evaluate_result(features)
        if result.score < 0.5:
            return None

        severity = AlertSeverity.CRITICAL if result.critical else AlertSeverity.HIGH
        return Alert(
            client_ip=features.client_ip,
            username=features.username,
            severity=severity,
            triggered_rules=result.triggered_rules,
            details={
                "score": result.score,
                "reasons": result.reasons,
                "critical": result.critical,
            },
        )


def evaluate_rules(
    features: ClientFeatures,
    thresholds: RuleThresholds | dict[str, Any] | None = None,
) -> Alert | None:
    """Convenience wrapper: instantiate RuleEngine and evaluate once."""
    engine = RuleEngine(thresholds)
    return engine.evaluate(features)
