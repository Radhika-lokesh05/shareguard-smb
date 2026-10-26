"""
server/tests/test_rules.py – Unit tests for detection rules and threshold validation.

Tests:
- R1: Canary touched by non-allowlisted client triggers critical alert.
- R1: Canary touched by allowlisted backup daemon does not trigger.
- R2: Extension change burst triggers.
- R3: High write count with high entropy written triggers.
- R4: Ransom note creation across multiple directories triggers.
- R5: Delete-after-copy triggers.
- BaselineV1Rule: Activity rate proxy triggers on high files changed and high ops/sec.
- Threshold validation rejects invalid values.
- Configuration loading from YAML.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shareguard.features import ClientFeatures
from shareguard.rules import (
    AlertSeverity,
    BaselineV1Rule,
    RuleEngine,
    RuleThresholds,
    load_rule_thresholds,
)


def _base_features(
    client_ip: str = "192.168.1.10",
    username: str = "alice",
    **kwargs,
) -> ClientFeatures:
    """Helper to instantiate ClientFeatures with default zero values."""
    extra = kwargs.pop("extra", {})
    return ClientFeatures(
        client_ip=client_ip,
        username=username,
        window_start=1000.0,
        window_end=1060.0,
        extra=extra,
        **kwargs,
    )


def test_rule_r1_canary_touch_unauthorized() -> None:
    """R1 fires with critical=True when an unauthorized client touches a canary."""
    thresholds = RuleThresholds(canary_allowlist=["192.168.1.250"])
    engine = RuleEngine(thresholds)

    # Attacker touches canary
    features = _base_features(
        client_ip="10.0.0.55",
        extra={"canary_touch_count": 1.0},
    )
    result = engine.evaluate_result(features)
    assert result.critical is True
    assert result.score == 1.0
    assert "R1" in result.triggered_rules
    assert any("Canary decoy file" in r for r in result.reasons)

    # Alert conversion has CRITICAL severity
    alert = engine.evaluate(features)
    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL


def test_rule_r1_canary_touch_allowlisted() -> None:
    """R1 does not fire when an allowlisted backup software touches a canary."""
    thresholds = RuleThresholds(canary_allowlist=["192.168.1.250"])
    engine = RuleEngine(thresholds)

    features = _base_features(
        client_ip="192.168.1.250",
        extra={"canary_touch_count": 1.0},
    )
    result = engine.evaluate_result(features)
    assert "R1" not in result.triggered_rules
    assert result.critical is False


def test_rule_r2_ext_change_burst() -> None:
    """R2 fires when renames changing extensions exceed the threshold."""
    thresholds = RuleThresholds(ext_change_burst_threshold=15)
    engine = RuleEngine(thresholds)

    # Below threshold
    res_low = engine.evaluate_result(_base_features(extra={"ext_change_count": 5.0}))
    assert "R2" not in res_low.triggered_rules

    # Above threshold
    res_high = engine.evaluate_result(_base_features(extra={"ext_change_count": 20.0}))
    assert "R2" in res_high.triggered_rules
    assert res_high.score >= 0.85
    assert any("Burst of 20 file renames" in r for r in res_high.reasons)


def test_rule_r3_high_write_high_entropy() -> None:
    """R3 fires when high write count coincides with high entropy across distinct files."""
    thresholds = RuleThresholds(
        write_count_threshold=30,
        entropy_written_threshold=7.0,
        min_distinct_files_threshold=10,
    )
    engine = RuleEngine(thresholds)

    # High write, low entropy -> benign
    res_normal = engine.evaluate_result(
        _base_features(
            write_count=50,
            extra={"mean_entropy_written": 4.5, "distinct_high_entropy_files": 20.0},
        )
    )
    assert "R3" not in res_normal.triggered_rules

    # Low write, high entropy -> benign
    res_low_write = engine.evaluate_result(
        _base_features(
            write_count=5,
            extra={"mean_entropy_written": 7.9, "distinct_high_entropy_files": 5.0},
        )
    )
    assert "R3" not in res_low_write.triggered_rules

    # Zip-like: Many writes to a single output archive -> must NOT fire R3
    res_zip = engine.evaluate_result(
        _base_features(
            write_count=100,
            extra={"mean_entropy_written": 7.9, "distinct_high_entropy_files": 1.0},
        )
    )
    assert "R3" not in res_zip.triggered_rules

    # Ransomware: High write, high entropy across 25 distinct files -> attack
    res_attack = engine.evaluate_result(
        _base_features(
            write_count=45,
            extra={"mean_entropy_written": 7.8, "distinct_high_entropy_files": 25.0},
        )
    )
    assert "R3" in res_attack.triggered_rules
    assert res_attack.score >= 0.85


def test_dev_like_temp_file_cleanup_does_not_fire_r5() -> None:
    """A developer creating and deleting their own temp files must NOT fire R5."""
    thresholds = RuleThresholds(delete_after_copy_threshold=10)
    engine = RuleEngine(thresholds)

    # Developer deleted 20 of its own files -> delete_after_copy_count is 0
    res_dev = engine.evaluate_result(
        _base_features(
            delete_count=20,
            extra={"files_created_by_client": 20.0, "delete_after_copy_count": 0.0},
        )
    )
    assert "R5" not in res_dev.triggered_rules


def test_ransomware_copy_delete_fires_r5() -> None:
    """Ransomware deleting pre-existing originals after writing encrypted copies fires R5."""
    thresholds = RuleThresholds(delete_after_copy_threshold=10)
    engine = RuleEngine(thresholds)

    res_attack = engine.evaluate_result(
        _base_features(
            delete_count=15,
            extra={
                "preexisting_files_deleted": 15.0,
                "delete_after_copy_count": 15.0,
            },
        )
    )
    assert "R5" in res_attack.triggered_rules
    assert res_attack.score >= 0.85
    assert any("Delete-after-copy" in r for r in res_attack.reasons)


def test_rule_r4_ransom_note_spray() -> None:
    """R4 fires when ransom notes are created across multiple directories."""
    thresholds = RuleThresholds(ransom_note_threshold=2, ransom_note_dirs_threshold=2)
    engine = RuleEngine(thresholds)

    # Note created in only 1 directory -> not enough
    res_one_dir = engine.evaluate_result(
        _base_features(extra={"ransom_note_count": 3.0, "ransom_note_dirs": 1.0})
    )
    assert "R4" not in res_one_dir.triggered_rules

    # Notes spread across 3 directories -> attack
    res_spray = engine.evaluate_result(
        _base_features(extra={"ransom_note_count": 3.0, "ransom_note_dirs": 3.0})
    )
    assert "R4" in res_spray.triggered_rules
    assert any("Ransom note file creation" in r for r in res_spray.reasons)


def test_rule_r5_delete_after_copy() -> None:
    """R5 fires when delete-after-copy count exceeds threshold."""
    thresholds = RuleThresholds(delete_after_copy_threshold=10)
    engine = RuleEngine(thresholds)

    res_below = engine.evaluate_result(_base_features(extra={"delete_after_copy_count": 5.0}))
    assert "R5" not in res_below.triggered_rules

    res_above = engine.evaluate_result(_base_features(extra={"delete_after_copy_count": 15.0}))
    assert "R5" in res_above.triggered_rules
    assert any("Delete-after-copy" in r for r in res_above.reasons)


def test_baseline_v1_rule() -> None:
    """Baseline V1 activity proxy fires when files changed > 10 and ops_per_sec > threshold."""
    rule = BaselineV1Rule(files_threshold=10, ops_threshold=15.0)

    # High files, low ops/sec
    fired, _ = rule.evaluate(
        _base_features(extra={"files_changed": 50.0, "ops_per_sec": 5.0})
    )
    assert not fired

    # Low files, high ops/sec
    fired, _ = rule.evaluate(
        _base_features(extra={"files_changed": 5.0, "ops_per_sec": 30.0})
    )
    assert not fired

    # Both high -> fired
    fired, reason = rule.evaluate(
        _base_features(extra={"files_changed": 25.0, "ops_per_sec": 20.0})
    )
    assert fired
    assert "Baseline V1" in reason

    # RuleEngine evaluate_result must NOT include BASELINE_V1
    engine = RuleEngine()
    result = engine.evaluate_result(
        _base_features(extra={"files_changed": 25.0, "ops_per_sec": 20.0})
    )
    assert "BASELINE_V1" not in result.triggered_rules
    assert not any("Baseline V1" in r for r in result.reasons)
    # But evaluate_baseline must return True
    b_fired, b_reason = engine.evaluate_baseline(
        _base_features(extra={"files_changed": 25.0, "ops_per_sec": 20.0})
    )
    assert b_fired is True
    assert "Baseline V1" in b_reason


def test_rule_thresholds_validation() -> None:
    """Threshold validation rejects zero or negative thresholds."""
    with pytest.raises(ValueError, match="ext_change_burst_threshold"):
        RuleThresholds(ext_change_burst_threshold=0)

    with pytest.raises(ValueError, match="entropy_written_threshold"):
        RuleThresholds(entropy_written_threshold=9.5)

    with pytest.raises(ValueError, match="baseline_ops_per_sec"):
        RuleThresholds(baseline_ops_per_sec=-1.0)


def test_load_rule_thresholds_from_config() -> None:
    """load_rule_thresholds successfully reads config/default.yaml."""
    thresholds = load_rule_thresholds()
    assert thresholds.ext_change_burst_threshold > 0
    assert thresholds.write_count_threshold > 0
    assert 0.0 <= thresholds.entropy_written_threshold <= 8.0
    assert "192.168.1.250" in thresholds.canary_allowlist


def test_rule_thresholds_all_validations() -> None:
    """Validate all individual bounds checks in RuleThresholds."""
    with pytest.raises(ValueError, match="write_count_threshold"):
        RuleThresholds(write_count_threshold=0)
    with pytest.raises(ValueError, match="min_distinct_files_threshold"):
        RuleThresholds(min_distinct_files_threshold=0)
    with pytest.raises(ValueError, match="ransom_note_threshold"):
        RuleThresholds(ransom_note_threshold=0)
    with pytest.raises(ValueError, match="ransom_note_dirs_threshold"):
        RuleThresholds(ransom_note_dirs_threshold=0)
    with pytest.raises(ValueError, match="delete_after_copy_threshold"):
        RuleThresholds(delete_after_copy_threshold=0)
    with pytest.raises(ValueError, match="baseline_files_changed"):
        RuleThresholds(baseline_files_changed=0)


def test_load_rule_thresholds_nonexistent_path(tmp_path: Path) -> None:
    """load_rule_thresholds returns default thresholds when file does not exist."""
    missing_file = tmp_path / "does_not_exist.yaml"
    thresholds = load_rule_thresholds(missing_file)
    assert thresholds.ext_change_burst_threshold == 15


def test_rule_engine_dict_init_and_convenience_evaluate() -> None:
    """RuleEngine initializes from a plain dictionary and evaluate_rules works."""
    from shareguard.rules import evaluate_rules

    dict_cfg = {
        "ext_change_burst_threshold": 10,
        "write_count_threshold": 20,
    }
    engine = RuleEngine(dict_cfg)
    assert engine.thresholds.ext_change_burst_threshold == 10

    # Low score returns None
    feat_low = _base_features()
    assert evaluate_rules(feat_low) is None

    # High score returns Alert
    feat_high = _base_features(extra={"canary_touch_count": 1.0})
    alert = evaluate_rules(feat_high)
    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
