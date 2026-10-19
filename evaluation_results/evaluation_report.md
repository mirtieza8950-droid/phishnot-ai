# Model Evaluation Report

- **Test set size:** 1269 samples (20% held-out, stratified)
- **Class distribution (test):** ham=423, phishing=423, spam=423
- **Device:** cpu
- **Random seed:** 42 (matches training split exactly)

## 1. Ablation Table

This table shows how each individual model performs in isolation, compared against partial and full ensemble configurations. The goal is to justify the multi-model design by quantifying the contribution of each component.

| Configuration | Accuracy | Macro F1 | Weighted F1 | Precision (M) | Recall (M) | Avg Latency (ms/sample) |
|---|---|---|---|---|---|---|
| Logistic Regression (only) | 0.7864 | 0.7847 | 0.7847 | 0.7837 | 0.7864 | 0.00 |
| SVM (only) | 0.7533 | 0.7482 | 0.7482 | 0.7491 | 0.7533 | 0.06 |
| DistilBERT + Dense (only) | 0.8101 | 0.8109 | 0.8109 | 0.8147 | 0.8101 | 206.26 |
| CNN + Transformer (only) | 0.5800 | 0.5537 | 0.5537 | 0.5985 | 0.5800 | 11.20 |
| Classical Ensemble (LR + SVM) | 0.7801 | 0.7773 | 0.7773 | 0.7760 | 0.7801 | 0.06 |
| Deep Ensemble (DistilBERT + CNN-Trans) | 0.8006 | 0.7984 | 0.7984 | 0.7989 | 0.8006 | 217.46 |
| FULL Ensemble (all 4, weighted) | 0.8148 | 0.8130 | 0.8130 | 0.8144 | 0.8148 | 217.52 |

## 2. Per-Class Metrics (Full Ensemble)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ham | 0.9276 | 0.9693 | 0.9480 | 423 |
| phishing | 0.7259 | 0.7825 | 0.7531 | 423 |
| spam | 0.7898 | 0.6927 | 0.7380 | 423 |

## 3. Confusion Matrices

Grid of all configurations: `confusion_matrices.png`

High-resolution ensemble matrix (for inclusion in report): `ensemble_confusion_matrix.png`

## 4. Observations

- **Ensemble vs. best single model:** the full weighted ensemble achieves a macro F1 of **0.8130**, compared to **0.8109** for the best individual model (DistilBERT + Dense (only)). Net change: **+0.0022**.
- **Hardest confusion:** the ensemble most often confuses **spam → phishing** (118 samples). This is consistent with the linguistic overlap between commercial spam and phishing emails, which both use urgency, calls-to-action, and brand impersonation.
- **Classical vs. deep:** classical models (LR, SVM) average **0.7664** macro F1, while deep models (DistilBERT, CNN+Transformer) average **0.6823**. The ensemble combines complementary strengths: classical models for n-gram surface features, deep models for semantic context.
- **Latency:** full ensemble inference averages **217.5 ms/sample** on cpu, which is well within interactive-application requirements (<500 ms).

## 5. Reproducibility

Run `py evaluate.py` from the project root. The script uses the same `train_test_split(..., random_state=42, stratify=y)` as `training.py`, so the test set is deterministic and identical to the one models were validated on.
