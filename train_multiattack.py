"""
Train baseline intrusion detection models (Multiclass Logistic Regression and Random Forest)
on authentic CICIDS2017 multi-attack benchmark data across 6 canonical classes:
  0: BENIGN
  1: PortScan
  2: DoS_DDoS
  3: BruteForce
  4: WebAttacks
  5: Botnet

Leakage-control guarantees:
- Feature extraction excludes metadata, timestamps, IPs, Destination Port, and 10 constant columns.
- Duplicate-group-aware partitioning: Evaluates on unique 66-feature behavioral profiles.
- Conflicting feature profiles (identical features with contradictory labels) quarantined and removed.
- Zero feature-vector overlap between Train, Validation, and Test partitions.
- All imputation and feature scaling strictly fitted on Train partition only.
- Validation tuning only; Test partition remains completely untouched until independent evaluation.
- All artifacts saved to models/benchmark_multiattack/.
"""

import os
import sys
import time
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from pipeline.benchmark_multiattack import (
    MultiAttackDatasetPipeline,
    BENCHMARK_MULTIATTACK_DIR,
    CLASS_MAPPING,
    CLASS_NAMES,
    CONSTANT_COLUMNS,
    REDUNDANT_COLUMNS,
    METADATA_EXCLUDED_COLUMNS
)

RANDOM_SEED = 42


def train_multiattack_baselines():
    print("=" * 75)
    print("PHASE 8B: MULTI-ATTACK BENCHMARK BASELINE MODEL TRAINING")
    print("=" * 75)

    os.makedirs(BENCHMARK_MULTIATTACK_DIR, exist_ok=True)
    pipe = MultiAttackDatasetPipeline()

    # Step 1: Load authentic benchmark dataset
    print("\n[Step 1/6] Loading authentic CICIDS2017 multi-attack dataset...")
    t0 = time.time()
    raw_df = pipe.load_all_raw_data()
    load_time = time.time() - t0
    print(f"Loaded {len(raw_df):,} raw flow records in {load_time:.2f}s.")

    raw_counts = raw_df["NormLabel"].value_counts().to_dict()
    print("Raw flow record distribution:")
    for cname in CLASS_NAMES:
        print(f"  {cname:12s}: {raw_counts.get(cname, 0):,}")

    # Step 2: Feature selection
    print("\n[Step 2/6] Selecting behavioral flow features...")
    feature_cols = pipe.select_feature_columns(raw_df)
    print(f"Selected {len(feature_cols)} behavioral flow features.")
    print("Explicitly excluded:")
    print(f"  - Metadata / Shortcut: {METADATA_EXCLUDED_COLUMNS}")
    print(f"  - Constant features:   {CONSTANT_COLUMNS}")
    print(f"  - Redundant features:  {REDUNDANT_COLUMNS}")
    print("  - Target label:        ['Label', 'NormLabel']")

    # Step 3: Deduplication and Conflict Audit
    print("\n[Step 3/6] Auditing identical feature profiles and conflicting labels...")
    t_dedup = time.time()
    clean_dedup_df, n_conflicts = pipe.deduplicate_and_audit(raw_df, feature_cols)
    dedup_time = time.time() - t_dedup
    print(f"Deduplication complete in {dedup_time:.2f}s:")
    print(f"  Original flow records:         {len(raw_df):,}")
    print(f"  Conflicting feature profiles:  {n_conflicts:,} (removed to prevent contradictory ground truth)")
    print(f"  Clean unique feature profiles: {len(clean_dedup_df):,}")

    dedup_counts = clean_dedup_df["NormLabel"].value_counts().to_dict()
    print("Clean unique profile distribution:")
    for cname in CLASS_NAMES:
        print(f"  {cname:12s}: {dedup_counts.get(cname, 0):,}")

    # Step 4: Stratified Zero-Leakage Split (70/15/15)
    print("\n[Step 4/6] Partitioning profiles into Train (70%), Val (15%), Test (15%)...")
    train_df, val_df, test_df = pipe.stratified_zero_leakage_split(
        clean_dedup_df,
        feature_cols,
        train_ratio=0.70,
        val_ratio=0.15,
        random_seed=RANDOM_SEED
    )

    split_info = {
        "random_seed": RANDOM_SEED,
        "split_method": "stratified_zero_leakage_unique_profiles",
        "original_raw_flows": {
            "total": len(raw_df),
            "distribution": {cname: int(raw_counts.get(cname, 0)) for cname in CLASS_NAMES}
        },
        "conflicting_profiles_removed": n_conflicts,
        "clean_unique_profiles_total": len(clean_dedup_df),
        "partitions": {
            "train": {
                "total": len(train_df),
                "classes": {cname: int((train_df["NormLabel"] == cname).sum()) for cname in CLASS_NAMES}
            },
            "validation": {
                "total": len(val_df),
                "classes": {cname: int((val_df["NormLabel"] == cname).sum()) for cname in CLASS_NAMES}
            },
            "test": {
                "total": len(test_df),
                "classes": {cname: int((test_df["NormLabel"] == cname).sum()) for cname in CLASS_NAMES}
            }
        }
    }

    split_meta_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "split_metadata.json")
    with open(split_meta_path, "w") as f:
        json.dump(split_info, f, indent=2)
    print(f"Saved split metadata to {split_meta_path}")

    # Save test partition index / features for independent untouched evaluation
    test_cache_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "held_out_test_profiles.parquet")
    test_df.to_parquet(test_cache_path, index=False)
    print(f"Cached held-out test partition to {test_cache_path} ({len(test_df):,} profiles)")

    # Step 5: Fit Preprocessing Strictly on Train Partition ONLY
    print("\n[Step 5/6] Fitting preprocessing transformations strictly on Train partition...")
    pipe.fit_preprocessing(train_df, feature_cols)
    pipe.save_artifacts(BENCHMARK_MULTIATTACK_DIR)
    print(f"Saved preprocessor config and scaler to {BENCHMARK_MULTIATTACK_DIR}")

    X_train = pipe.transform_features(train_df)
    y_train = pipe.extract_labels(train_df)
    X_val = pipe.transform_features(val_df)
    y_val = pipe.extract_labels(val_df)

    # Step 6: Train Baseline Classifiers
    print("\n[Step 6/6] Training baseline classifiers...")

    # Model 1: Multiclass Logistic Regression
    print("\n--- Model 1: Multiclass Logistic Regression (balanced, lbfgs, max_iter=1000) ---")
    lr_start = time.time()
    lr_model = LogisticRegression(
        penalty="l2",
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
        random_state=RANDOM_SEED
    )
    lr_model.fit(X_train, y_train)
    lr_time = time.time() - lr_start
    print(f"Logistic Regression trained in {lr_time:.2f}s.")

    # Validation evaluation for LR
    lr_val_preds = lr_model.predict(X_val)
    lr_val_acc = accuracy_score(y_val, lr_val_preds)
    _, _, lr_val_f1_macro, _ = precision_recall_fscore_support(y_val, lr_val_preds, average="macro", zero_division=0)
    _, _, lr_val_f1_weighted, _ = precision_recall_fscore_support(y_val, lr_val_preds, average="weighted", zero_division=0)
    print(f"LR Validation: Accuracy={lr_val_acc:.4f}, Macro-F1={lr_val_f1_macro:.4f}, Weighted-F1={lr_val_f1_weighted:.4f}")

    lr_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "baseline_multiattack_lr.pkl")
    with open(lr_path, "wb") as f:
        pickle.dump(lr_model, f)
    print(f"Saved Logistic Regression model to {lr_path}")

    # Model 2: Multiclass Random Forest
    print("\n--- Model 2: Multiclass Random Forest (n_estimators=100, max_depth=15, balanced) ---")
    rf_start = time.time()
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=10,
        max_samples=50000,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_SEED
    )
    rf_model.fit(X_train, y_train)
    rf_time = time.time() - rf_start
    print(f"Random Forest trained in {rf_time:.2f}s.")

    # Validation evaluation for RF
    rf_val_preds = rf_model.predict(X_val)
    rf_val_acc = accuracy_score(y_val, rf_val_preds)
    _, _, rf_val_f1_macro, _ = precision_recall_fscore_support(y_val, rf_val_preds, average="macro", zero_division=0)
    _, _, rf_val_f1_weighted, _ = precision_recall_fscore_support(y_val, rf_val_preds, average="weighted", zero_division=0)
    print(f"RF Validation: Accuracy={rf_val_acc:.4f}, Macro-F1={rf_val_f1_macro:.4f}, Weighted-F1={rf_val_f1_weighted:.4f}")

    # Top 10 feature importances for RF
    importances = rf_model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:10]
    print("\nTop 10 Feature Importances (Random Forest):")
    for rank, idx in enumerate(top_indices, 1):
        print(f"  {rank:2d}. {feature_cols[idx]}: {importances[idx]:.4f}")

    rf_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "baseline_multiattack_rf.pkl")
    with open(rf_path, "wb") as f:
        pickle.dump(rf_model, f)
    print(f"\nSaved Random Forest model to {rf_path}")

    # Save training summary
    summary = {
        "status": "COMPLETED",
        "training_time_seconds": {
            "logistic_regression": round(lr_time, 2),
            "random_forest": round(rf_time, 2)
        },
        "validation_metrics": {
            "logistic_regression": {
                "accuracy": float(lr_val_acc),
                "macro_f1": float(lr_val_f1_macro),
                "weighted_f1": float(lr_val_f1_weighted)
            },
            "random_forest": {
                "accuracy": float(rf_val_acc),
                "macro_f1": float(rf_val_f1_macro),
                "weighted_f1": float(rf_val_f1_weighted)
            }
        },
        "top_features_rf": [
            {"rank": rank, "feature": feature_cols[idx], "importance": float(importances[idx])}
            for rank, idx in enumerate(top_indices, 1)
        ]
    }
    summary_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved training summary to {summary_path}")
    print("\nPhase 8B baseline training finished successfully.")


if __name__ == "__main__":
    train_multiattack_baselines()
