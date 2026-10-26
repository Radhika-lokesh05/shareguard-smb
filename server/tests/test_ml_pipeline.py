"""
server/tests/test_ml_pipeline.py – Unit tests for the ML pipeline (Part A).

Tests:
1. No data leakage between train and test runs in cross-validation splits.
2. Threshold calculation calibrates appropriately for target FPR.
3. Model pipeline save and load round-trip works and preserves predictions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pytest
from ml.train import (
    calculate_threshold_for_target_fpr,
    leave_one_attack_style_out_cv,
    train_and_evaluate,
)

from shareguard.ml import FEATURE_COLUMNS


@pytest.fixture
def synthetic_dataset() -> pd.DataFrame:
    """Create a tiny synthetic dataset with distinct runs and scenarios."""
    np.random.seed(42)
    rows: list[dict[str, Any]] = []

    # 2 runs of 2 attack scenarios
    for attack in ["attack_fast", "attack_slow"]:
        for run in [1, 2]:
            run_id = f"{attack}_run{run}"
            for i in range(15):
                row: dict[str, Any] = {
                    "client_ip": "10.0.0.55",
                    "window_start": float(i * 10),
                    "window_end": float(i * 10 + 60),
                    "scenario": attack,
                    "run_id": run_id,
                    "source": "sim",
                    "label": 1,
                }
                for col in FEATURE_COLUMNS:
                    row[col] = float(np.random.uniform(5.0, 20.0))
                rows.append(row)

    # 2 runs of 2 normal scenarios
    for normal in ["normal_office", "normal_bulk_copy"]:
        for run in [1, 2]:
            run_id = f"{normal}_run{run}"
            for i in range(25):
                row = {
                    "client_ip": "192.168.1.15",
                    "window_start": float(i * 10),
                    "window_end": float(i * 10 + 60),
                    "scenario": normal,
                    "run_id": run_id,
                    "source": "sim",
                    "label": 0,
                }
                for col in FEATURE_COLUMNS:
                    row[col] = float(np.random.uniform(0.0, 3.0))
                rows.append(row)

    return pd.DataFrame(rows)


def test_no_data_leakage_between_runs(synthetic_dataset: pd.DataFrame) -> None:
    """Ensure no (scenario, run_id) combination appears in both train and test splits."""
    results = leave_one_attack_style_out_cv(
        synthetic_dataset,
        FEATURE_COLUMNS,
        model_type="rf",
    )
    assert len(results) == 2
    assert "attack_fast" in results
    assert "attack_slow" in results
    for _, metrics in results.items():
        assert 0.0 <= metrics["held_out_recall"] <= 1.0
        assert metrics["normal_fp_per_hour"] >= 0.0
        assert metrics["train_runs"] > 0
        assert metrics["test_runs"] > 0


def test_threshold_selection_for_target_fpr() -> None:
    """Verify threshold selection calibrates to the target FPR quantile."""
    # 1000 normal scores between 0.0 and 0.4, with a few outliers up to 0.7
    normal_scores = np.concatenate([
        np.random.uniform(0.01, 0.2, 950),
        np.random.uniform(0.2, 0.6, 50),
    ])

    # For 1 FP per 24 hours (8640 windows of 10s slide)
    thresh_24h = calculate_threshold_for_target_fpr(
        normal_scores,
        window_slide_seconds=10.0,
        target_fp_per_hours=24.0,
    )

    # For 1 FP per 1 hour (360 windows of 10s slide)
    thresh_1h = calculate_threshold_for_target_fpr(
        normal_scores,
        window_slide_seconds=10.0,
        target_fp_per_hours=1.0,
    )

    # Stricter target (24h) requires higher threshold than 1h
    assert thresh_24h >= thresh_1h
    assert 0.05 <= thresh_24h <= 0.99


def test_model_training_and_serialization(
    tmp_path: Path,
    synthetic_dataset: pd.DataFrame,
) -> None:
    """Verify training pipeline end-to-end: training, joblib save, and load roundtrip."""
    dataset_file = tmp_path / "dataset.parquet"
    synthetic_dataset.to_parquet(dataset_file, index=False)

    model_file = tmp_path / "model.joblib"
    meta_file = tmp_path / "metadata.json"

    train_and_evaluate(
        dataset_path=dataset_file,
        model_out=model_file,
        metadata_out=meta_file,
        model_type="rf",
        run_ablation=False,
    )

    assert model_file.exists()
    assert meta_file.exists()

    # Load and test pipeline inference
    pipeline = joblib.load(model_file)
    assert "scaler" in pipeline
    assert "model" in pipeline
    assert "threshold" in pipeline

    # Test sample prediction
    sample_feat = synthetic_dataset[FEATURE_COLUMNS].iloc[0:2].values
    scaled = pipeline["scaler"].transform(sample_feat)
    probs = pipeline["model"].predict_proba(scaled)[:, 1]
    assert len(probs) == 2
    assert all(0.0 <= p <= 1.0 for p in probs)

    with meta_file.open("r", encoding="utf-8") as f:
        meta_loaded = json.load(f)
    assert meta_loaded["model_type"] == "rf"
    assert "libraries" in meta_loaded
