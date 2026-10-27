"""
Train baseline intrusion detection models (Logistic Regression and Random Forest)
on authentic CICIDS2017 PortScan benchmark data.
Follows strict data leakage prevention:
- All preprocessing fitted exclusively on training data.
- Evaluates on validation data during training.
- Saves new artifacts to models/benchmark/ without overwriting production models.
"""

import os
import time
import json
import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

from pipeline.benchmark_dataset import (
    BenchmarkDatasetPipeline,
    BENCHMARK_ARTIFACTS_DIR
)

RANDOM_SEED = 42

def train_baselines():
    print("=" * 60)
    print("PHASE 7B: BENCHMARK BASELINE MODEL TRAINING")
    print("=" * 60)

    os.makedirs(BENCHMARK_ARTIFACTS_DIR, exist_ok=True)
    pipe = BenchmarkDatasetPipeline()

    # Step 1: Load authentic benchmark data
    print("\n[Step 1/5] Loading authentic benchmark dataset...")
    df = pipe.load_and_clean_raw(deduplicate=True)
    print(f"Total deduplicated flow records: {len(df):,}")
    print(f"Class distribution:\n{df['Label'].value_counts().to_string()}")

    # Step 2: Feature selection
    print("\n[Step 2/5] Selecting behavioral flow features...")
    feature_cols = pipe.select_feature_columns(df, exclude_port=True)
    print(f"Selected {len(feature_cols)} behavioral flow features.")
    print("Excluded: Destination Port, 10 zero-variance columns, 1 duplicate column, target Label.")

    # Step 3: Chronological Train / Val / Test Partitioning
    print("\n[Step 3/5] Partitioning into Train (70%), Val (15%), Held-out Test (15%)...")
    train_df, val_df, test_df = pipe.chronological_split(df, train_ratio=0.70, val_ratio=0.15)
    
    split_info = {
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
        "split_method": "chronological_sequence_without_overlap",
        "deduplicated": True
    }
    print(f"Train set: {len(train_df):,} records | {split_info['train']['classes']}")
    print(f"Val set:   {len(val_df):,} records | {split_info['validation']['classes']}")
    print(f"Test set:  {len(test_df):,} records | {split_info['test']['classes']}")

    # Save split metadata
    with open(os.path.join(BENCHMARK_ARTIFACTS_DIR, "split_metadata.json"), "w") as f:
        json.dump(split_info, f, indent=2)

    # Step 4: Preprocessing (Fit strictly on Train ONLY)
    print("\n[Step 4/5] Fitting preprocessing transformations on Train partition only...")
    pipe.fit_preprocessing(train_df, feature_cols)
    
    # Save preprocessing artifacts
    scaler_out = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_scaler.pkl")
    config_out = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_preprocessing_config.json")
    pipe.save_artifacts(config_path=config_out, scaler_path=scaler_out)
    print(f"Saved preprocessing config to {config_out}")
    print(f"Saved fitted scaler to {scaler_out}")

    # Transform Train and Validation
    X_train = pipe.transform_features(train_df)
    y_train = pipe.extract_labels(train_df)
    X_val = pipe.transform_features(val_df)
    y_val = pipe.extract_labels(val_df)

    # Step 5: Train Models
    print("\n[Step 5/5] Training baseline classifiers...")

    # Model 1: Logistic Regression
    print("\n--- Training Model 1: Logistic Regression (L2, max_iter=1000) ---")
    lr_start = time.time()
    lr_model = LogisticRegression(
        penalty="l2",
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        random_state=RANDOM_SEED
    )
    lr_model.fit(X_train, y_train)
    lr_duration = time.time() - lr_start
    print(f"Logistic Regression trained in {lr_duration:.2f}s.")

    # Validation evaluation for LR
    lr_val_preds = lr_model.predict(X_val)
    lr_val_probs = lr_model.predict_proba(X_val)[:, 1]
    lr_val_acc = accuracy_score(y_val, lr_val_preds)
    lr_prec, lr_rec, lr_f1, _ = precision_recall_fscore_support(y_val, lr_val_preds, average="binary")
    lr_val_auc = roc_auc_score(y_val, lr_val_probs)
    print(f"LR Validation: Accuracy={lr_val_acc:.4f}, Precision={lr_prec:.4f}, Recall={lr_rec:.4f}, F1={lr_f1:.4f}, ROC-AUC={lr_val_auc:.4f}")

    lr_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_lr.pkl")
    with open(lr_path, "wb") as f:
        pickle.dump(lr_model, f)
    print(f"Saved Logistic Regression model to {lr_path}")

    # Model 2: Random Forest
    print("\n--- Training Model 2: Random Forest (n_estimators=100, max_depth=15) ---")
    rf_start = time.time()
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=10,
        n_jobs=-1,
        random_state=RANDOM_SEED
    )
    rf_model.fit(X_train, y_train)
    rf_duration = time.time() - rf_start
    print(f"Random Forest trained in {rf_duration:.2f}s.")

    # Validation evaluation for RF
    rf_val_preds = rf_model.predict(X_val)
    rf_val_probs = rf_model.predict_proba(X_val)[:, 1]
    rf_val_acc = accuracy_score(y_val, rf_val_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_val, rf_val_preds, average="binary")
    rf_val_auc = roc_auc_score(y_val, rf_val_probs)
    print(f"RF Validation: Accuracy={rf_val_acc:.4f}, Precision={rf_prec:.4f}, Recall={rf_rec:.4f}, F1={rf_f1:.4f}, ROC-AUC={rf_val_auc:.4f}")

    # Top 10 feature importances for RF
    importances = rf_model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:10]
    print("\nTop 10 Feature Importances (Random Forest):")
    for rank, idx in enumerate(top_indices, 1):
        print(f"  {rank}. {feature_cols[idx]}: {importances[idx]:.4f}")

    rf_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_rf.pkl")
    with open(rf_path, "wb") as f:
        pickle.dump(rf_model, f)
    print(f"\nSaved Random Forest model to {rf_path}")

    # Training summary log
    train_summary = {
        "dataset": "CICIDS2017 Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "split_sizes": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df)
        },
        "features": {
            "count": len(feature_cols),
            "list": feature_cols
        },
        "logistic_regression": {
            "training_time_seconds": round(lr_duration, 2),
            "val_accuracy": float(lr_val_acc),
            "val_f1": float(lr_f1),
            "val_roc_auc": float(lr_val_auc)
        },
        "random_forest": {
            "training_time_seconds": round(rf_duration, 2),
            "val_accuracy": float(rf_val_acc),
            "val_f1": float(rf_f1),
            "val_roc_auc": float(rf_val_auc),
            "top_10_features": [
                {"feature": feature_cols[idx], "importance": float(importances[idx])}
                for idx in top_indices
            ]
        }
    }
    summary_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump(train_summary, f, indent=2)
    print(f"Saved training summary to {summary_path}")
    print("\nBaseline training completed successfully.")

if __name__ == "__main__":
    train_baselines()
