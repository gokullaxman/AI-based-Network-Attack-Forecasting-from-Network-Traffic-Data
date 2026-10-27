"""
Phase 7B.1 Audit Experiment: Leakage-Free Feature-Deduplicated Baseline.
Implements a defensible alternative experiment where deduplication is performed
directly on the 66 behavioral features before splitting, guaranteeing 0 feature-vector
overlap between Train, Validation, and Test partitions.

Artifacts are preserved in models/benchmark_audit/ without modifying Phase 7B models.
"""

import os
import json
import pickle
import time
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score
)

from pipeline.benchmark_dataset import (
    BenchmarkDatasetPipeline,
    LABEL_MAPPING,
    CONSTANT_COLUMNS,
    REDUNDANT_COLUMNS,
    METADATA_EXCLUDED_COLUMNS
)

AUDIT_ARTIFACTS_DIR = os.path.join("models", "benchmark_audit")
RANDOM_SEED = 42

def run_audit_experiment():
    print("=" * 70)
    print("PHASE 7B.1: AUDIT ALTERNATIVE EXPERIMENT (ZERO-LEAKAGE DEDUPLICATION)")
    print("=" * 70)

    os.makedirs(AUDIT_ARTIFACTS_DIR, exist_ok=True)
    pipe = BenchmarkDatasetPipeline()

    # Step 1: Load raw without 79-column deduplication
    print("\n[Step 1/5] Loading authentic benchmark dataset...")
    raw_df = pipe.load_and_clean_raw(deduplicate=False)
    features = pipe.select_feature_columns(raw_df, exclude_port=True)
    print(f"Total raw records: {len(raw_df):,}")

    # Step 2: Feature-level deduplication (on 66 behavioral features)
    print("\n[Step 2/5] Performing feature-level deduplication on the 66 behavioral features...")
    dedup_df = raw_df.drop_duplicates(subset=features).reset_index(drop=True)
    print(f"Total unique 66-feature records: {len(dedup_df):,}")
    print(f"Class breakdown:\n{dedup_df['Label'].value_counts().to_string()}")

    # Step 3: Row-order Train / Val / Test Partitioning
    print("\n[Step 3/5] Partitioning into Train (70%), Val (15%), Held-out Test (15%)...")
    n = len(dedup_df)
    n_train = int(n * 0.70)
    n_val = int(n * 0.15)
    train_df = dedup_df.iloc[:n_train].reset_index(drop=True)
    val_df = dedup_df.iloc[n_train:n_train + n_val].reset_index(drop=True)
    test_df = dedup_df.iloc[n_train + n_val:].reset_index(drop=True)

    split_meta = {
        "train": {
            "total": len(train_df),
            "classes": {k: int(v) for k, v in train_df["Label"].value_counts().items()}
        },
        "validation": {
            "total": len(val_df),
            "classes": {k: int(v) for k, v in val_df["Label"].value_counts().items()}
        },
        "test": {
            "total": len(test_df),
            "classes": {k: int(v) for k, v in test_df["Label"].value_counts().items()}
        },
        "random_seed": RANDOM_SEED,
        "split_method": "row_order_feature_deduplicated_zero_overlap",
        "deduplicated_on": "66_behavioral_features"
    }

    # Verify 0 feature overlap
    train_tuples = set(map(tuple, train_df[features].values))
    test_tuples = set(map(tuple, test_df[features].values))
    overlap = len(train_tuples.intersection(test_tuples))
    assert overlap == 0, f"Unexpected feature overlap: {overlap}"
    print(f"Train/Test feature-vector overlap: {overlap} (Strict zero-leakage verified)")

    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_split_metadata.json"), "w") as f:
        json.dump(split_meta, f, indent=2)

    # Step 4: Fit preprocessing EXCLUSIVELY on Train
    print("\n[Step 4/5] Fitting preprocessing strictly on Train partition only...")
    imputation_medians = {}
    imputation_max_finite = {}
    X_train_clean = pd.DataFrame(index=train_df.index)

    for col in features:
        s = pd.to_numeric(train_df[col], errors="coerce")
        finite = np.isfinite(s)
        med = float(s[finite].median()) if finite.any() else 0.0
        mxf = float(s[finite].max()) if finite.any() else 0.0
        imputation_medians[col] = med
        imputation_max_finite[col] = mxf
        clean = s.replace([np.inf, -np.inf], mxf).fillna(med)
        X_train_clean[col] = clean

    scaler = StandardScaler()
    scaler.fit(X_train_clean.values)

    def transform(df_sub):
        X = pd.DataFrame(index=df_sub.index)
        for col in features:
            s = pd.to_numeric(df_sub[col], errors="coerce")
            clean = s.replace([np.inf, -np.inf], imputation_max_finite[col]).fillna(imputation_medians[col])
            X[col] = clean
        return scaler.transform(X.values)

    # Save preprocessing config and scaler
    audit_config = {
        "feature_columns": features,
        "feature_count": len(features),
        "label_mapping": LABEL_MAPPING,
        "imputation_medians": imputation_medians,
        "imputation_max_finite": imputation_max_finite,
        "constant_columns_excluded": CONSTANT_COLUMNS,
        "redundant_columns_excluded": REDUNDANT_COLUMNS,
        "metadata_excluded": METADATA_EXCLUDED_COLUMNS,
        "scaler_type": "StandardScaler"
    }
    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_preprocessing_config.json"), "w") as f:
        json.dump(audit_config, f, indent=2)
    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)

    X_train = scaler.transform(X_train_clean.values)
    y_train = train_df["Label"].map(LABEL_MAPPING).values.astype(int)

    X_val = transform(val_df)
    y_val = val_df["Label"].map(LABEL_MAPPING).values.astype(int)

    X_test = transform(test_df)
    y_test = test_df["Label"].map(LABEL_MAPPING).values.astype(int)

    # Step 5: Train & Evaluate Models
    print("\n[Step 5/5] Training and evaluating baseline models on untouched audit test partition...")

    # Logistic Regression
    lr = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
    t0 = time.time()
    lr.fit(X_train, y_train)
    lr_train_time = time.time() - t0

    # Random Forest
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=15, min_samples_split=10, n_jobs=-1, random_state=RANDOM_SEED
    )
    t0 = time.time()
    rf.fit(X_train, y_train)
    rf_train_time = time.time() - t0

    models = {
        "Logistic Regression (Audit Baseline)": (lr, lr_train_time),
        "Random Forest (Audit Baseline)": (rf, rf_train_time)
    }

    eval_results = {
        "experiment": "Phase 7B.1 Zero-Leakage Alternative",
        "partitions": split_meta,
        "models": {}
    }

    for model_name, (model, train_duration) in models.items():
        t0 = time.time()
        preds = model.predict(X_test)
        infer_duration = time.time() - t0
        latency_us = (infer_duration / len(X_test)) * 1_000_000

        probs = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
        cm = confusion_matrix(y_test, preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        acc = accuracy_score(y_test, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average=None, labels=[0, 1])
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(y_test, preds, average="macro")
        auc = roc_auc_score(y_test, probs) if probs is not None else None

        res = {
            "training_time_seconds": round(train_duration, 2),
            "inference_latency_microseconds": round(latency_us, 2),
            "accuracy": float(acc),
            "macro_f1": float(macro_f1),
            "macro_precision": float(macro_prec),
            "macro_recall": float(macro_rec),
            "roc_auc": float(auc) if auc is not None else None,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "false_positive_rate_benign": float(fpr),
            "false_negative_rate_attack": float(fnr),
            "class_0_benign": {
                "precision": float(prec[0]),
                "recall": float(rec[0]),
                "f1_score": float(f1[0]),
                "support": int((y_test == 0).sum())
            },
            "class_1_attack": {
                "precision": float(prec[1]),
                "recall": float(rec[1]),
                "f1_score": float(f1[1]),
                "support": int((y_test == 1).sum())
            }
        }
        eval_results["models"][model_name] = res

        print(f"\nResults for {model_name}:")
        print(f"  Accuracy:                      {acc:.4f} ({acc*100:.2f}%)")
        print(f"  Macro F1-Score:                {macro_f1:.4f}")
        print(f"  ROC-AUC:                       {auc:.4f}" if auc else "  ROC-AUC: N/A")
        print(f"  Confusion Matrix:              TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
        print(f"  False Positive Rate (Benign):  {fpr:.6f} ({fpr*100:.4f}%)")
        print(f"  False Negative Rate (Attack):  {fnr:.6f} ({fnr*100:.4f}%)")
        print(f"  Class 0 (Benign)   - Prec: {prec[0]:.4f}, Rec: {rec[0]:.4f}, F1: {f1[0]:.4f}")
        print(f"  Class 1 (PortScan) - Prec: {prec[1]:.4f}, Rec: {rec[1]:.4f}, F1: {f1[1]:.4f}")

    # Save models and results
    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_lr.pkl"), "wb") as f:
        pickle.dump(lr, f)
    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_rf.pkl"), "wb") as f:
        pickle.dump(rf, f)
    with open(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_evaluation_results.json"), "w") as f:
        json.dump(eval_results, f, indent=2)

    print(f"\nAll audit artifacts successfully saved to: {AUDIT_ARTIFACTS_DIR}")
    print("=" * 70)

if __name__ == "__main__":
    run_audit_experiment()
