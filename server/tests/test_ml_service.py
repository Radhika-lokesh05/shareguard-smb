"""
server/tests/test_ml_service.py – Fast unit tests for ShareGuard ML inference & explanation service.

Covers:
1. Scoring on loaded pipeline.
2. Missing model file returns None gracefully without error.
3. Corrupt model file returns None gracefully without crashing.
4. Feature order mismatch raises clear descriptive ValueError.
5. explain() returns at most 5 structured dictionary items with valid directions and values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from shareguard.ml import (
    FEATURE_COLUMNS,
    MLModel,
    explain,
    score,
)


@pytest.fixture
def tiny_trained_model(tmp_path: Path) -> Path:
    """Create and serialize a tiny working RandomForest pipeline."""
    model_path = tmp_path / "model.joblib"
    np.random.seed(42)

    X = np.random.uniform(0.0, 10.0, size=(20, len(FEATURE_COLUMNS)))
    y = np.array([0] * 10 + [1] * 10)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=5, random_state=42)
    clf.fit(X_scaled, y)

    pipeline = {
        "scaler": scaler,
        "model": clf,
        "feature_columns": FEATURE_COLUMNS,
        "threshold": 0.5,
        "model_type": "rf",
    }
    joblib.dump(pipeline, model_path)
    return model_path


def test_score_normal_and_attack(tiny_trained_model: Path) -> None:
    """Model scores valid ClientFeatures or dict accurately within [0.0, 1.0]."""
    feat_dict = dict.fromkeys(FEATURE_COLUMNS, 1.0)
    prob = score(feat_dict, model_path=tiny_trained_model)

    assert prob is not None
    assert 0.0 <= prob <= 1.0

    # Test via MLModel wrapper
    wrapper = MLModel(model_path=tiny_trained_model)
    prob_wrap = wrapper.predict(feat_dict)
    assert 0.0 <= prob_wrap <= 1.0


def test_missing_model_returns_none(tmp_path: Path) -> None:
    """Missing model returns None and never raises an exception."""
    non_existent = tmp_path / "does_not_exist.joblib"
    prob = score(dict.fromkeys(FEATURE_COLUMNS, 1.0), model_path=non_existent)
    assert prob is None

    explanations = explain(dict.fromkeys(FEATURE_COLUMNS, 1.0), model_path=non_existent)
    assert explanations == []


def test_corrupt_model_safe_fallback(tmp_path: Path) -> None:
    """Corrupt model file returns None and logs warning without crashing."""
    corrupt_file = tmp_path / "corrupt_model.joblib"
    corrupt_file.write_bytes(b"NOT_A_VALID_JOBLIB_DATA_GARBAGE")

    prob = score(dict.fromkeys(FEATURE_COLUMNS, 1.0), model_path=corrupt_file)
    assert prob is None


def test_feature_order_mismatch_raises(tiny_trained_model: Path) -> None:
    """Mismatched vector length or missing dictionary keys raises ValueError."""
    # Too short vector
    short_vec = np.array([1.0, 2.0, 3.0])
    with pytest.raises(ValueError, match="Feature vector length mismatch"):
        score(short_vec, model_path=tiny_trained_model)

    # Missing expected column in dictionary
    incomplete_dict: dict[str, Any] = {"rename_count": 5.0}
    with pytest.raises(ValueError, match="Feature order mismatch: missing expected feature"):
        score(incomplete_dict, model_path=tiny_trained_model)


def test_explain_structure_and_cap(tiny_trained_model: Path) -> None:
    """explain() returns at most 5 items with plain data types and valid directions."""
    feat_dict = dict.fromkeys(FEATURE_COLUMNS, 2.5)
    items = explain(feat_dict, model_path=tiny_trained_model, top_k=5)

    assert isinstance(items, list)
    assert 0 < len(items) <= 5

    for item in items:
        assert "feature" in item
        assert "label" in item
        assert "value" in item
        assert "importance" in item
        assert "direction" in item
        assert item["direction"] in {"attack", "normal"}
        assert isinstance(item["value"], float)
        assert isinstance(item["importance"], float)
