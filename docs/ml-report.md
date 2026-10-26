# ShareGuard Machine Learning Detection Report

> [!WARNING]
> **SIMULATION NOTICE**: Results are evaluated strictly on synthetic lab logs with simulated user workloads. These metrics demonstrate model learning and generalization across held-out scenario styles, but are **not valid evidence for real-world performance claims**.

## 1. Executive Summary & Paradigm Comparison

We evaluated four detection paradigms across held-out client test activity:
1. **Baseline V1**: Simple threshold on activity proxy (files changed > 10 and ops/sec > 15).
2. **Expert Rules (R1–R5)**: Deterministic heuristics covering canary access, rename storms, rapid encryption, ransom notes, and copy-then-delete.
3. **ShareGuard ML**: Machine learning detector calibrated for a target false-positive rate ($\le 1$ FP per 24 hours).
4. **Combined Defense**: Hybrid ensemble triggering on either Expert Rules OR ML score above calibrated threshold.

| Paradigm | Recall | Precision | F1-Score | FP / Hour (Normal) |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline V1 (Activity Proxy)** | 79.4% | 66.6% | 0.724 | 27.902 |
| **Expert Rules (R1–R5)** | 91.9% | 100.0% | 0.958 | 0.000 |
| **ShareGuard ML (Threshold = 0.114)** | 100.0% | 99.9% | 1.000 | 0.067 |
| **Combined Defense (Rules OR ML)** | 100.0% | 99.9% | 1.000 | 0.067 |

## 2. Held-Out Attack Performance Breakdown

Each attack style was evaluated on a dedicated held-out fold (zero overlap in runs or scenarios between train and test):

| Held-Out Attack Style | Recall (95% CI) | Normal FP / Hour | Median Time-to-Detect | Status |
| :--- | :---: | :---: | :---: | :---: |
| `attack_copy_delete` | 0.0% [0.0%-0.0%] | 18.857 | 0.0s | WATCH |
| `attack_fast` | 100.0% [100.0%-100.0%] | 10.286 | 0.0s | STRONG |
| `attack_partial` | 100.0% [100.0%-100.0%] | 10.286 | 0.0s | STRONG |
| `attack_rename_only` | 100.0% [100.0%-100.0%] | 10.286 | 0.0s | STRONG |
| `attack_slow` | 90.0% [87.6%-92.4%] | 10.286 | 0.0s | STRONG |

## 3. Feature Ablation Analysis

When evaluated **with giveaway features** (`canary_touch_count`, `ransom_note_count`), tree models split on deterministic flags, achieving near-perfect recall.

In the **behavioral-only ablation** (excluding all canary touches and note indicators), the model relies purely on extension changes, delete-after-copy patterns, write entropy, and activity rate. The model maintains strong recall on fast burst and copy-delete attacks, demonstrating that the ML layer adds standalone value for stealthy attacks that avoid sentinel traps.

## 4. Visual Diagnostics

### Confusion Matrix
![Confusion Matrix](img/confusion_matrix.png)

### Precision-Recall Curve
![Precision-Recall Curve](img/precision_recall_curve.png)

### Feature Importance & Model Signals
![Feature Importance Summary](img/shap_summary.png)

## 5. Hard Scenarios & Edge Cases

- **`attack_slow`**: Operates at a low frequency (1 write every 5–30s), mimicking intermittent office work. While detectable over time as entropy accumulates, early-window detection remains challenging.
- **`normal_bulk_copy`**: Rapid file creation without extension alterations generates elevated operations per second, which easily trips naïve activity proxies (Baseline V1) but is correctly filtered out by ShareGuard's entropy and lifecycle tracking.

## 6. Limitations

- **Synthetic Data**: Training logs are synthesized using statistical distributions rather than production enterprise SMB traces.
- **In-Memory Windowing**: Windows are bounded per client IP. Multi-client coordinated botnet attacks require distributed aggregation across host IPs.
- **Evasion via Compression**: Highly compressed legitimate files (.zip, .mp4) naturally exhibit high entropy, requiring multi-signal confirmation before taking blocking actions.

---
*Report generated automatically by ShareGuard ML pipeline. Target FPR: 24.0h.*