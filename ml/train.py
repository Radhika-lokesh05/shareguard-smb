"""
ml/train.py – Comprehensive ML evaluation & training for ShareGuard.

Features:
1. Strict Leave-One-Attack-Style-Out & Rotated Normal Run CV (no test leakage).
2. Report False Positives Per Hour of normal activity (not raw window FPR).
3. 95% Confidence Intervals via run-level bootstrapping.
4. Time-to-detect (TTD) tracking per attack run in seconds.
5. Multi-model comparison: RandomForest, XGBoost, Isolation Forest.
6. Feature ablation: Full features vs. Behavioral-only features (without giveaway canaries/notes).
7. Transparent evaluation summary banner with simulation disclaimer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

# Ensure workspace root and server packages are importable when script is run directly
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(_WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE_ROOT))
_SERVER_DIR = _WORKSPACE_ROOT / "server"
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from shareguard.ml import BEHAVIORAL_FEATURE_COLUMNS, FEATURE_COLUMNS

__all__ = [
    "train_and_evaluate",
    "calculate_threshold_for_target_fpr",
    "leave_one_attack_style_out_cv",
    "run_multi_model_comparison",
]

_DEFAULT_DATASET = Path("ml/artifacts/dataset.parquet")
_DEFAULT_MODEL_OUT = Path("ml/artifacts/model.joblib")
_DEFAULT_META_OUT = Path("ml/artifacts/metadata.json")


def calculate_threshold_for_target_fpr(
    y_scores_normal: np.ndarray,
    window_slide_seconds: float = 10.0,
    target_fp_per_hours: float = 24.0,
) -> float:
    """Calculate the score threshold yielding <= 1 false alarm per target normal hours.

    Args:
        y_scores_normal: Predicted probability scores on normal validation data.
        window_slide_seconds: Slide step size in seconds.
        target_fp_per_hours: Desired max false alarm interval in hours (default 24h).
    """
    if len(y_scores_normal) == 0:
        return 0.5

    windows_per_hour = 3600.0 / max(1.0, window_slide_seconds)
    total_target_windows = windows_per_hour * max(0.1, target_fp_per_hours)
    target_fpr_per_window = 1.0 / total_target_windows

    desired_quantile = max(0.5, 1.0 - target_fpr_per_window)
    threshold = float(np.quantile(y_scores_normal, desired_quantile))
    return float(np.clip(threshold, 0.05, 0.99))


def _compute_run_bootstrap_ci(
    run_records: list[dict[str, Any]],
    metric_key: str,
    n_bootstraps: int = 500,
) -> tuple[float, float, float]:
    """Compute mean and 95% confidence interval via run-level bootstrapping."""
    if not run_records:
        return 0.0, 0.0, 0.0

    values = [r[metric_key] for r in run_records if metric_key in r]
    if not values:
        return 0.0, 0.0, 0.0

    mean_val = float(np.mean(values))
    if len(values) == 1:
        return mean_val, mean_val, mean_val

    rng = np.random.default_rng(42)
    boot_means: list[float] = []
    n = len(values)
    for _ in range(n_bootstraps):
        sample = rng.choice(values, size=n, replace=True)
        boot_means.append(float(np.mean(sample)))

    ci_lower = float(np.percentile(boot_means, 2.5))
    ci_upper = float(np.percentile(boot_means, 97.5))
    return mean_val, ci_lower, ci_upper


def leave_one_attack_style_out_cv(
    df: pd.DataFrame,
    feature_cols: list[str],
    model_type: str = "rf",
    target_fp_per_hours: float = 24.0,
    window_slide_seconds: float = 10.0,
) -> dict[str, Any]:
    """Perform Leave-One-Attack-Style-Out CV with rotatable normal run splits."""
    attack_scenarios = sorted(
        [s for s in df["scenario"].dropna().unique() if str(s).startswith("attack_")]
    )
    normal_scenarios = sorted(
        [s for s in df["scenario"].dropna().unique() if str(s).startswith("normal_")]
    )

    if not attack_scenarios:
        raise ValueError("Dataset does not contain attack scenarios starting with 'attack_'")

    # Map each attack scenario index to a distinct slice of normal runs
    cv_results: dict[str, Any] = {}
    windows_per_hour = 3600.0 / max(1.0, window_slide_seconds)

    # Collect normal runs per scenario
    normal_runs_by_scen: dict[str, list[str]] = {
        scen: sorted(df[df["scenario"] == scen]["run_id"].unique())
        for scen in normal_scenarios
    }

    n_folds = len(attack_scenarios)

    for fold_idx, held_out_attack in enumerate(attack_scenarios):
        # 1. Determine test attack runs (all runs of held_out_attack)
        test_attack_mask = df["scenario"] == held_out_attack

        # 2. Assign a distinct non-overlapping slice of normal runs for this fold
        test_normal_mask = pd.Series(False, index=df.index)
        for scen, runs in normal_runs_by_scen.items():
            if len(runs) >= n_folds:
                fold_slice_size = max(1, len(runs) // n_folds)
                start_i = fold_idx * fold_slice_size
                end_i = start_i + fold_slice_size if fold_idx < n_folds - 1 else len(runs)
                fold_test_runs = runs[start_i:end_i]
            else:
                # If very few runs, use deterministic modulo assignment
                fold_test_runs = [runs[fold_idx % len(runs)]]

            test_normal_mask |= (df["scenario"] == scen) & (df["run_id"].isin(fold_test_runs))

        test_mask = test_attack_mask | test_normal_mask
        train_df = df[~test_mask].copy()
        test_df = df[test_mask].copy()

        # Sanity check: zero leakage between train and test runs
        train_groups = set(zip(train_df["scenario"], train_df["run_id"], strict=False))
        test_groups = set(zip(test_df["scenario"], test_df["run_id"], strict=False))
        assert train_groups.isdisjoint(test_groups), "Leakage detected: overlapping runs between train and test!"

        # Reserve a 20% validation split from normal train runs for threshold calibration
        train_norm_runs = sorted(train_df[train_df["label"] == 0]["run_id"].unique())
        val_norm_count = max(1, len(train_norm_runs) // 5)
        val_norm_runs = set(train_norm_runs[-val_norm_count:])

        fit_mask = ~train_df["run_id"].isin(val_norm_runs)
        fit_df = train_df[fit_mask]
        calib_df = train_df[train_df["run_id"].isin(val_norm_runs) & (train_df["label"] == 0)]

        X_fit = fit_df[feature_cols].values
        y_fit = fit_df["label"].values.astype(int)

        X_calib = calib_df[feature_cols].values
        X_test = test_df[feature_cols].values

        scaler = StandardScaler()
        X_fit_scaled = scaler.fit_transform(X_fit)
        X_calib_scaled = scaler.transform(X_calib) if len(X_calib) > 0 else X_fit_scaled
        X_test_scaled = scaler.transform(X_test)

        # Train model
        if model_type == "rf":
            model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
            model.fit(X_fit_scaled, y_fit)
            calib_scores = model.predict_proba(X_calib_scaled)[:, 1]
            test_scores = model.predict_proba(X_test_scaled)[:, 1]
        elif model_type == "xgb":
            pos_weight = max(1.0, float((y_fit == 0).sum()) / max(1.0, float((y_fit == 1).sum())))
            model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.1,
                scale_pos_weight=pos_weight,
                random_state=42,
                eval_metric="logloss",
            )
            model.fit(X_fit_scaled, y_fit)
            calib_scores = model.predict_proba(X_calib_scaled)[:, 1]
            test_scores = model.predict_proba(X_test_scaled)[:, 1]
        elif model_type == "isolation_forest":
            norm_mask = y_fit == 0
            model = IsolationForest(contamination=0.01, random_state=42)
            model.fit(X_fit_scaled[norm_mask])
            fit_raw = -model.score_samples(X_fit_scaled[norm_mask])
            p_min, p_max = fit_raw.min(), fit_raw.max()
            calib_raw = -model.score_samples(X_calib_scaled)
            calib_scores = np.clip((calib_raw - p_min) / max(1e-5, p_max - p_min), 0.0, 1.0)
            test_raw = -model.score_samples(X_test_scaled)
            test_scores = np.clip((test_raw - p_min) / max(1e-5, p_max - p_min), 0.0, 1.0)
        else:
            raise ValueError(f"Unknown model_type: {model_type}")

        # Threshold calibration on calibration normal scores
        threshold = calculate_threshold_for_target_fpr(
            calib_scores,
            window_slide_seconds=window_slide_seconds,
            target_fp_per_hours=target_fp_per_hours,
        )

        test_preds = (test_scores >= threshold).astype(int)
        test_df["score"] = test_scores
        test_df["pred"] = test_preds

        # Evaluation on held-out attack runs
        attack_test_df = test_df[test_df["scenario"] == held_out_attack]
        attack_runs = sorted(attack_test_df["run_id"].unique())
        run_recalls: list[float] = []
        ttd_seconds_list: list[float] = []

        attack_run_records: list[dict[str, Any]] = []

        for arid in attack_runs:
            rdf = attack_test_df[attack_test_df["run_id"] == arid]
            atk_windows = rdf[rdf["label"] == 1]
            if not atk_windows.empty:
                r_recall = float((atk_windows["pred"] == 1).sum() / len(atk_windows))
                run_recalls.append(r_recall)
                attack_run_records.append({"run_id": arid, "recall": r_recall})

                # Compute Time-To-Detect (TTD)
                first_atk_time = atk_windows["window_start"].min()
                detected_windows = atk_windows[atk_windows["pred"] == 1]
                if not detected_windows.empty:
                    first_detect_time = detected_windows["window_start"].min()
                    ttd = max(0.0, first_detect_time - first_atk_time)
                    ttd_seconds_list.append(ttd)

        # Evaluation on held-out normal runs
        norm_test_df = test_df[test_df["label"] == 0]
        normal_runs = sorted(norm_test_df["run_id"].unique())
        norm_run_records: list[dict[str, Any]] = []

        for nrid in normal_runs:
            ndf = norm_test_df[norm_test_df["run_id"] == nrid]
            n_fp = int((ndf["pred"] == 1).sum())
            fp_per_hour = (n_fp / max(1, len(ndf))) * windows_per_hour
            norm_run_records.append({"run_id": nrid, "fp_per_hour": fp_per_hour})

        # Bootstrap 95% Confidence Intervals
        recall_mean, recall_ci_low, recall_ci_high = _compute_run_bootstrap_ci(
            attack_run_records, "recall"
        )
        fph_mean, fph_ci_low, fph_ci_high = _compute_run_bootstrap_ci(
            norm_run_records, "fp_per_hour"
        )

        median_ttd = float(np.median(ttd_seconds_list)) if ttd_seconds_list else 0.0

        cv_results[held_out_attack] = {
            "held_out_recall": recall_mean,
            "recall_ci": (recall_ci_low, recall_ci_high),
            "normal_fp_per_hour": fph_mean,
            "fp_per_hour_ci": (fph_ci_low, fph_ci_high),
            "median_ttd_seconds": median_ttd,
            "threshold": threshold,
            "train_runs": len(train_groups),
            "test_runs": len(test_groups),
            "train_windows": len(train_df),
            "test_windows": len(test_df),
        }

    return cv_results


def run_multi_model_comparison(
    df: pd.DataFrame,
    target_fp_per_hours: float = 24.0,
) -> dict[str, Any]:
    """Run cross-validation comparison across RF, XGBoost, and Isolation Forest.

    Evaluates both Full features and Behavioral-only features (ablation).
    """
    models = ["rf", "xgb", "isolation_forest"]
    regimes = [
        ("Full Features", FEATURE_COLUMNS),
        ("Behavior-Only (No Canaries/Notes)", BEHAVIORAL_FEATURE_COLUMNS),
    ]

    all_comparison_results: dict[str, Any] = {}

    print("\n" + "=" * 115)
    print(" " * 32 + "MULTI-MODEL & ABLATION COMPARISON (CROSS-VALIDATED)")
    print("=" * 115)
    print(
        f"{'Model & Regime':<35} | {'Held-Out Attack':<20} | {'Recall (95% CI)':<18} | {'FP / Hour (95% CI)':<22} | {'Median TTD':<10}"
    )
    print("-" * 115)

    for regime_name, feat_cols in regimes:
        for model_name in models:
            key = f"{model_name.upper()} [{regime_name}]"
            cv_res = leave_one_attack_style_out_cv(
                df,
                feat_cols,
                model_type=model_name,
                target_fp_per_hours=target_fp_per_hours,
            )
            all_comparison_results[key] = cv_res

            for scen, metrics in cv_res.items():
                r_ci = f"{metrics['held_out_recall']:.1%} [{metrics['recall_ci'][0]:.1%}-{metrics['recall_ci'][1]:.1%}]"
                fp_ci = f"{metrics['normal_fp_per_hour']:.3f} [{metrics['fp_per_hour_ci'][0]:.2f}-{metrics['fp_per_hour_ci'][1]:.2f}]"
                ttd_str = f"{metrics['median_ttd_seconds']:.1f}s"
                print(
                    f"{key:<35} | {scen:<20} | {r_ci:<18} | {fp_ci:<22} | {ttd_str:<10}"
                )
            print("-" * 115)

    print("=" * 115 + "\n")
    return all_comparison_results


def train_and_evaluate(
    dataset_path: Path,
    model_out: Path,
    metadata_out: Path,
    model_type: str = "rf",
    target_fp_per_hours: float = 24.0,
    run_ablation: bool = True,
) -> dict[str, Any]:
    """Train production model, evaluate models and feature ablations, and save artifacts."""
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    df = pd.read_parquet(dataset_path) if str(dataset_path).endswith(".parquet") else pd.read_csv(dataset_path)

    # Validate feature columns exist in dataset
    missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset missing required feature columns: {missing_cols}")

    with dataset_path.open("rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()

    comparison_results: dict[str, Any] = {}
    if run_ablation:
        comparison_results = run_multi_model_comparison(
            df, target_fp_per_hours=target_fp_per_hours
        )

    # Train production model on entire dataset using behavioral features
    # (or full features based on preference; we use FEATURE_COLUMNS for final artifact)
    X = df[FEATURE_COLUMNS].values
    y = df["label"].values.astype(int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    if model_type == "rf":
        final_model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
        final_model.fit(X_scaled, y)
        probs = final_model.predict_proba(X_scaled)[:, 1]
    elif model_type == "xgb":
        pos_weight = max(1.0, float((y == 0).sum()) / max(1.0, float((y == 1).sum())))
        final_model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            scale_pos_weight=pos_weight,
            random_state=42,
            eval_metric="logloss",
        )
        final_model.fit(X_scaled, y)
        probs = final_model.predict_proba(X_scaled)[:, 1]
    elif model_type == "isolation_forest":
        final_model = IsolationForest(contamination=0.01, random_state=42)
        final_model.fit(X_scaled[y == 0])
        raw_scores = -final_model.score_samples(X_scaled)
        norm_scores = raw_scores[y == 0]
        p_min, p_max = norm_scores.min(), norm_scores.max()
        probs = np.clip((raw_scores - p_min) / max(1e-5, p_max - p_min), 0.0, 1.0)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    normal_scores = probs[y == 0]
    final_threshold = calculate_threshold_for_target_fpr(
        normal_scores,
        window_slide_seconds=10.0,
        target_fp_per_hours=target_fp_per_hours,
    )

    pipeline = {
        "scaler": scaler,
        "model": final_model,
        "feature_columns": FEATURE_COLUMNS,
        "threshold": final_threshold,
        "model_type": model_type,
    }

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_out)
    print(f"Model pipeline saved to: {model_out}")

    metadata = {
        "model_type": model_type,
        "feature_columns": FEATURE_COLUMNS,
        "behavioral_feature_columns": BEHAVIORAL_FEATURE_COLUMNS,
        "threshold": final_threshold,
        "target_fp_per_hours": target_fp_per_hours,
        "dataset_hash": data_hash,
        "dataset_rows": len(df),
        "comparison_results": comparison_results,
        "libraries": {
            "scikit-learn": sklearn.__version__,
            "xgboost": xgb.__version__,
            "pandas": pd.__version__,
            "joblib": joblib.__version__,
            "python": platform.python_version(),
        },
        "disclaimer": "SIMULATED DATA ONLY: NOT VALID FOR REAL-WORLD PERFORMANCE CLAIMS.",
    }

    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    with metadata_out.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_out}")

    # Honest summary banner
    print("\n" + "=" * 80)
    print(" HONEST SUMMARY & DISCLAIMER")
    print("=" * 80)
    print(" * Results evaluated strictly on synthetic lab logs with simulated user workloads.")
    print(" * Attackers intentionally made stealthier and normal traffic made noisier.")
    print(" * SIMULATED DATA ONLY: NOT VALID FOR REAL-WORLD PERFORMANCE CLAIMS.")
    print("=" * 80 + "\n")

    return metadata


def main() -> None:
    """CLI entry point for model training."""
    parser = argparse.ArgumentParser(description="Train ShareGuard ML detection model")
    parser.add_argument("--dataset", default=str(_DEFAULT_DATASET), help="Input dataset path")
    parser.add_argument("--out", default=str(_DEFAULT_MODEL_OUT), help="Output model.joblib path")
    parser.add_argument("--meta", default=str(_DEFAULT_META_OUT), help="Output metadata.json path")
    parser.add_argument(
        "--model",
        choices=["rf", "xgb", "isolation_forest"],
        default="rf",
        help="Model algorithm to train",
    )
    parser.add_argument(
        "--target-fp-hours",
        type=float,
        default=24.0,
        help="Target maximum false positive rate per hours of normal activity (default: 24h)",
    )
    parser.add_argument(
        "--no-ablation",
        action="store_true",
        help="Skip full multi-model ablation comparison",
    )
    args = parser.parse_args()

    train_and_evaluate(
        dataset_path=Path(args.dataset),
        model_out=Path(args.out),
        metadata_out=Path(args.meta),
        model_type=args.model,
        target_fp_per_hours=args.target_fp_hours,
        run_ablation=not args.no_ablation,
    )


if __name__ == "__main__":
    main()
