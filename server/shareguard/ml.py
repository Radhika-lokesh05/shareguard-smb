"""
shareguard.ml – Machine-learning model wrapper and explanation service.

Provides:
- load_model(model_path): cached loading of joblib pipeline and metadata.
- score(features): predict ransomware probability (0.0 to 1.0). Returns None
  if model is missing or corrupt, allowing graceful fallback to rules.
- explain(features): top 5 features with impact direction, values, and plain labels.
- MLModel: wrapper class providing the object-oriented interface.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib
import numpy as np

if TYPE_CHECKING:
    from shareguard.features import ClientFeatures

logger = logging.getLogger(__name__)

__all__ = [
    "FEATURE_COLUMNS",
    "BEHAVIORAL_FEATURE_COLUMNS",
    "MLModel",
    "load_model",
    "score",
    "explain",
    "FEATURE_LABELS",
]

# Full feature columns (including canary and ransom note detections)
FEATURE_COLUMNS: list[str] = [
    "rename_count",
    "delete_count",
    "write_count",
    "read_count",
    "unique_extensions",
    "mean_entropy",
    "total_events",
    "ops_per_sec",
    "ext_change_count",
    "delete_after_copy_count",
    "distinct_high_entropy_files",
    "mean_entropy_written",
    "canary_touch_count",
    "ransom_note_count",
    "ransom_note_dirs",
]

# Behavioral-only features (excludes giveaway canary & ransom note signals)
BEHAVIORAL_FEATURE_COLUMNS: list[str] = [
    "rename_count",
    "delete_count",
    "write_count",
    "read_count",
    "unique_extensions",
    "mean_entropy",
    "total_events",
    "ops_per_sec",
    "ext_change_count",
    "delete_after_copy_count",
    "distinct_high_entropy_files",
    "mean_entropy_written",
]

FEATURE_LABELS: dict[str, str] = {
    "rename_count": "File Renames",
    "delete_count": "File Deletions",
    "write_count": "File Writes",
    "read_count": "File Reads",
    "unique_extensions": "Unique Extensions",
    "mean_entropy": "Extension Entropy",
    "total_events": "Total Operations",
    "ops_per_sec": "Activity Rate (Ops/s)",
    "ext_change_count": "Extension Changes",
    "delete_after_copy_count": "Delete-After-Copy Operations",
    "distinct_high_entropy_files": "High-Entropy Files Written",
    "mean_entropy_written": "Mean Written Entropy",
    "canary_touch_count": "Canary Decoy Touches",
    "ransom_note_count": "Ransom Notes Written",
    "ransom_note_dirs": "Directories with Ransom Notes",
}

# Module-level cache for singleton loaded model
_CACHED_PIPELINE: dict[str, Any] | None = None
_CACHED_EXPLAINER: Any = None
_CACHED_MODEL_PATH: Path | None = None
_CACHED_META: dict[str, Any] | None = None


def _extract_feature_vector(
    features: ClientFeatures | dict[str, Any] | np.ndarray,
    expected_columns: list[str],
) -> np.ndarray:
    """Extract and validate 1D feature array matching expected column order."""
    if isinstance(features, np.ndarray):
        vec = features.flatten()
        if len(vec) != len(expected_columns):
            raise ValueError(
                f"Feature vector length mismatch: expected {len(expected_columns)} ({expected_columns}), got {len(vec)}"
            )
        return vec.astype(float)

    if isinstance(features, dict):
        # Dict mapping feature name to value
        values: list[float] = []
        for col in expected_columns:
            if col not in features:
                raise ValueError(f"Feature order mismatch: missing expected feature '{col}'")
            values.append(float(features[col]))
        return np.array(values, dtype=float)

    # ClientFeatures dataclass instance
    values = []
    for col in expected_columns:
        if hasattr(features, col):
            values.append(float(getattr(features, col)))
        elif col in features.extra:
            values.append(float(features.extra[col]))
        else:
            values.append(0.0)
    return np.array(values, dtype=float)


def load_model(model_path: Path | str | None = None) -> dict[str, Any] | None:
    """Load model pipeline and metadata with caching.

    Returns:
        Loaded pipeline dict or None if model file does not exist or is corrupt.
    """
    global _CACHED_PIPELINE, _CACHED_EXPLAINER, _CACHED_MODEL_PATH, _CACHED_META

    model_path = Path("ml/artifacts/model.joblib") if model_path is None else Path(model_path)

    if _CACHED_PIPELINE is not None and model_path == _CACHED_MODEL_PATH:
        return _CACHED_PIPELINE

    if not model_path.exists():
        logger.debug("ML model path not found at %s", model_path)
        return None

    try:
        pipeline = joblib.load(model_path)
        if not isinstance(pipeline, dict) or "model" not in pipeline:
            logger.warning("Invalid model pipeline object in %s", model_path)
            return None

        _CACHED_PIPELINE = pipeline
        _CACHED_MODEL_PATH = model_path

        # Try to load companion metadata.json
        meta_path = model_path.with_name("metadata.json")
        if meta_path.exists():
            try:
                _CACHED_META = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Failed to parse metadata.json at %s: %s", meta_path, e)
                _CACHED_META = None
        else:
            _CACHED_META = None

        # Build SHAP explainer lazily
        _CACHED_EXPLAINER = None
        try:
            import shap

            estimator = pipeline["model"]
            if hasattr(estimator, "predict_proba"):
                _CACHED_EXPLAINER = shap.TreeExplainer(estimator)
        except Exception as e:
            logger.debug("SHAP TreeExplainer initialization skipped: %s", e)
            _CACHED_EXPLAINER = None

        return _CACHED_PIPELINE

    except Exception as e:
        logger.warning("Failed to load ML model from %s: %s", model_path, e)
        return None


def score(
    features: ClientFeatures | dict[str, Any] | np.ndarray,
    model_path: Path | str | None = None,
) -> float | None:
    """Predict ransomware probability score (0.0 to 1.0) for a client window.

    Returns:
        Probability float, or None if no model is loaded/valid.
    """
    pipeline = load_model(model_path)
    if pipeline is None:
        return None

    expected_cols = pipeline.get("feature_columns", FEATURE_COLUMNS)
    vec = _extract_feature_vector(features, expected_cols)
    X = vec.reshape(1, -1)

    try:
        scaler = pipeline.get("scaler")
        if scaler is not None:
            X = scaler.transform(X)

        estimator = pipeline["model"]
        if hasattr(estimator, "predict_proba"):
            probs = estimator.predict_proba(X)
            return float(probs[0, 1])
        elif hasattr(estimator, "score_samples"):
            # Anomaly detector (Isolation Forest)
            raw = float(-estimator.score_samples(X)[0])
            return float(np.clip(raw, 0.0, 1.0))
        return None

    except Exception as e:
        logger.warning("Error during ML scoring: %s", e)
        return None


def explain(
    features: ClientFeatures | dict[str, Any] | np.ndarray,
    model_path: Path | str | None = None,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Explain model score with top-k contributing features.

    Returns:
        List of dicts:
        [
            {
                "feature": "ext_change_count",
                "label": "Extension Changes",
                "value": 15.0,
                "importance": 0.42,
                "direction": "attack" | "normal",
            },
            ...
        ]
    """
    pipeline = load_model(model_path)
    if pipeline is None:
        return []

    expected_cols = pipeline.get("feature_columns", FEATURE_COLUMNS)
    vec = _extract_feature_vector(features, expected_cols)
    X = vec.reshape(1, -1)

    try:
        scaler = pipeline.get("scaler")
        X_scaled = scaler.transform(X) if scaler is not None else X
        estimator = pipeline["model"]

        # Attempt SHAP explanation
        shap_values: np.ndarray | None = None
        global _CACHED_EXPLAINER
        if _CACHED_EXPLAINER is not None:
            try:
                sv = _CACHED_EXPLAINER.shap_values(X_scaled)
                # Binary classification returns list of [neg, pos] or 2D array
                if isinstance(sv, list) and len(sv) == 2:
                    shap_values = np.array(sv[1]).flatten()
                elif isinstance(sv, np.ndarray):
                    if sv.ndim == 3:
                        shap_values = sv[0, :, 1]
                    elif sv.ndim == 2:
                        shap_values = sv[0]
                    else:
                        shap_values = sv.flatten()
            except Exception:
                shap_values = None

        # Fallback to feature importance weighting if SHAP is unavailable
        if shap_values is None or len(shap_values) != len(expected_cols):
            importances = getattr(estimator, "feature_importances_", None)
            if importances is not None and len(importances) == len(expected_cols):
                mean_baseline = scaler.mean_ if scaler is not None else np.zeros_like(vec)
                diff = vec - mean_baseline
                shap_values = importances * diff
            else:
                shap_values = np.zeros(len(expected_cols))

        # Build feature impact items
        items: list[dict[str, Any]] = []
        for i, col in enumerate(expected_cols):
            imp = float(shap_values[i])
            val = float(vec[i])
            direction = "attack" if imp > 0 else "normal"
            label = FEATURE_LABELS.get(col, col.replace("_", " ").title())
            items.append(
                {
                    "feature": col,
                    "label": label,
                    "value": val,
                    "importance": round(imp, 4),
                    "abs_importance": abs(imp),
                    "direction": direction,
                }
            )

        # Sort descending by absolute impact and cap at top_k
        items.sort(key=lambda x: x["abs_importance"], reverse=True)
        result = [
            {
                "feature": it["feature"],
                "label": it["label"],
                "value": it["value"],
                "importance": it["importance"],
                "direction": it["direction"],
            }
            for it in items[:top_k]
        ]
        return result

    except Exception as e:
        logger.warning("Error generating ML explanation: %s", e)
        return []


class MLModel:
    """Stateful ML model wrapper."""

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else Path("ml/artifacts/model.joblib")

    def load(self) -> None:
        """Load model pipeline into memory."""
        load_model(self.model_path)

    def predict(self, features: ClientFeatures | dict[str, Any] | np.ndarray) -> float:
        """Return ransomware probability score."""
        val = score(features, self.model_path)
        return val if val is not None else 0.0

    def explain(
        self,
        features: ClientFeatures | dict[str, Any] | np.ndarray,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Return top contributing features."""
        return explain(features, self.model_path, top_k=top_k)
