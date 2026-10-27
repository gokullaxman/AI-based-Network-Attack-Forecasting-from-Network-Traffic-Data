"""
Independent evaluation script for Phase 8B multi-attack baseline models
on the untouched held-out test partition.

Computes comprehensive, scientifically defensible performance metrics across 6 classes:
  0: BENIGN
  1: PortScan
  2: DoS_DDoS
  3: BruteForce
  4: WebAttacks
  5: Botnet

Required Evaluation:
- Accuracy, Macro F1, Weighted F1
- Per-class Precision, Recall, F1, and Support
- Benign False Positive Rate (FPR) with explicit formula and denominator
- Full 6x6 Confusion Matrix
- Inference Latency (total and per-profile microseconds)
- Dual distribution reporting: Original Flow Records vs Deduplicated Unique Profiles
- Saves complete results to models/benchmark_multiattack/multiattack_evaluation_results.json
"""

import os
import sys
import time
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support
)

from pipeline.benchmark_multiattack import (
    MultiAttackDatasetPipeline,
    BENCHMARK_MULTIATTACK_DIR,
    CLASS_MAPPING,
    CLASS_NAMES
)


def evaluate_multiattack_test_set():
    print("=" * 80)
    print("PHASE 8B: MULTI-ATTACK BENCHMARK HELD-OUT TEST EVALUATION")
    print("=" * 80)

    # 1. Load Preprocessor and Metadata
    config_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_preprocessing_config.json")
    scaler_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_scaler.pkl")
    split_meta_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "split_metadata.json")
    test_parquet_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "held_out_test_profiles.parquet")

    if not os.path.exists(config_path) or not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Preprocessing artifacts not found in {BENCHMARK_MULTIATTACK_DIR}. Run train_multiattack.py first.")

    with open(split_meta_path, "r") as f:
        split_meta = json.load(f)

    pipe = MultiAttackDatasetPipeline()
    pipe.load_artifacts(config_path=config_path, scaler_path=scaler_path)

    # 2. Load Untouched Held-Out Test Partition
    print("\n[Step 1/3] Loading held-out test partition...")
    if os.path.exists(test_parquet_path):
        test_df = pd.read_parquet(test_parquet_path)
    else:
        # Fallback to reconstructing from raw data if parquet missing
        raw_df = pipe.load_all_raw_data()
        feature_cols = pipe.select_feature_columns(raw_df)
        clean_df, _ = pipe.deduplicate_and_audit(raw_df, feature_cols)
        _, _, test_df = pipe.stratified_zero_leakage_split(clean_df, feature_cols)

    y_test = pipe.extract_labels(test_df)
    X_test = pipe.transform_features(test_df)

    n_test = len(y_test)
    print(f"Test Partition Size: {n_test:,} unique behavioral profiles")
    test_counts = {cname: int((y_test == cid).sum()) for cid, cname in enumerate(CLASS_NAMES)}
    for cname in CLASS_NAMES:
        cnt = test_counts[cname]
        pct = (cnt / n_test) * 100
        print(f"  Class {CLASS_MAPPING[cname]} ({cname:12s}): {cnt:8,d} ({pct:6.2f}%)")

    # 3. Load Trained Baseline Models
    print("\n[Step 2/3] Loading trained baseline models...")
    lr_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "baseline_multiattack_lr.pkl")
    rf_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "baseline_multiattack_rf.pkl")

    if not os.path.exists(lr_path) or not os.path.exists(rf_path):
        raise FileNotFoundError("Model artifacts missing. Run train_multiattack.py first.")

    with open(lr_path, "rb") as f:
        lr_model = pickle.load(f)
    with open(rf_path, "rb") as f:
        rf_model = pickle.load(f)

    models = {
        "Multiclass Logistic Regression (Linear Baseline)": lr_model,
        "Multiclass Random Forest (Ensemble Baseline)": rf_model
    }

    # Structure Results Document
    results = {
        "benchmark_phase": "Phase 8B Multi-Attack Classification Benchmark",
        "dataset_provenance": {
            "source": "Authentic CICIDS2017 Benchmark Flow Data (ISCX CSVs)",
            "classes": CLASS_NAMES,
            "feature_count": len(pipe.feature_columns),
            "excluded_labels": {
                "Heartbleed": "11 instances in raw dataset; excluded due to extreme rarity (<50 flows)",
                "Infiltration": "36 instances in raw dataset; excluded due to extreme rarity (<50 flows)"
            }
        },
        "population_audit": {
            "original_flow_records": split_meta["original_raw_flows"],
            "conflicting_profiles_removed": split_meta["conflicting_profiles_removed"],
            "clean_unique_profiles_total": split_meta["clean_unique_profiles_total"],
            "split_partition_sizes": split_meta["partitions"]
        },
        "evaluation_domain": {
            "metric_type": "Deduplicated Unique Feature Profiles (Novel Profile Generalization)",
            "warning": "Metrics evaluate observed flow classification on unique feature profiles, not operational raw flow-level error rates or live stream forecasting."
        },
        "models": {}
    }

    print("\n[Step 3/3] Evaluating models on held-out test partition...")

    for model_name, model in models.items():
        print(f"\n========================================================")
        print(f"Evaluating: {model_name}")
        print(f"========================================================")

        t_infer_start = time.time()
        y_pred = model.predict(X_test)
        infer_duration = time.time() - t_infer_start
        latency_us = (infer_duration / n_test) * 1_000_000

        # Overall Metrics
        acc = accuracy_score(y_test, y_pred)
        prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
            y_test, y_pred, average="macro", zero_division=0
        )
        prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted", zero_division=0
        )

        # Per-Class Metrics
        prec_per_class, rec_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
            y_test, y_pred, average=None, labels=list(range(len(CLASS_NAMES))), zero_division=0
        )

        # 6x6 Confusion Matrix
        cm = confusion_matrix(y_test, y_pred, labels=list(range(len(CLASS_NAMES))))

        # Benign False Positive Rate:
        # True Benign: rows where y_test == 0
        # False Positives: rows where y_test == 0 but y_pred != 0 (falsely classified as any attack)
        # True Negatives: rows where y_test == 0 and y_pred == 0
        benign_mask = (y_test == 0)
        total_benign = int(benign_mask.sum())
        benign_fp = int((benign_mask & (y_pred != 0)).sum())
        benign_tn = int((benign_mask & (y_pred == 0)).sum())
        benign_fpr = benign_fp / total_benign if total_benign > 0 else 0.0

        model_eval = {
            "overall_metrics": {
                "accuracy": float(acc),
                "macro_f1": float(f1_macro),
                "macro_precision": float(prec_macro),
                "macro_recall": float(rec_macro),
                "weighted_f1": float(f1_weighted),
                "weighted_precision": float(prec_weighted),
                "weighted_recall": float(rec_weighted)
            },
            "benign_false_positive_rate": {
                "fpr": float(benign_fpr),
                "false_positives_count": benign_fp,
                "true_benign_denominator": total_benign,
                "formula": "benign_fp / total_true_benign (where y_true == 0 and y_pred != 0)"
            },
            "per_class_metrics": {},
            "confusion_matrix": {
                "classes": CLASS_NAMES,
                "matrix_rows_are_true_cols_are_pred": cm.tolist()
            },
            "inference_latency": {
                "total_seconds": round(infer_duration, 4),
                "microseconds_per_profile": round(latency_us, 2)
            }
        }

        print(f"Accuracy:         {acc:.4f} ({acc*100:.2f}%)")
        print(f"Macro F1-Score:   {f1_macro:.4f}")
        print(f"Weighted F1:      {f1_weighted:.4f}")
        print(f"Benign FPR:       {benign_fpr:.4f} ({benign_fp:,} / {total_benign:,})")
        print(f"Inference Latency: {latency_us:.2f} us/profile")

        print("\nPer-Class Performance:")
        print(f"{'Class':14s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s} | {'Support':8s}")
        print("-" * 62)
        for cid, cname in enumerate(CLASS_NAMES):
            p = float(prec_per_class[cid])
            r = float(rec_per_class[cid])
            f = float(f1_per_class[cid])
            s = int(support_per_class[cid])
            model_eval["per_class_metrics"][cname] = {
                "class_id": cid,
                "precision": p,
                "recall": r,
                "f1_score": f,
                "support": s
            }
            print(f"{cname:14s} | {p:10.4f} | {r:10.4f} | {f:10.4f} | {s:8,d}")

        print("\n6x6 Confusion Matrix (Rows: True, Columns: Predicted):")
        header = f"{'True \\ Pred':12s}" + "".join([f"{cname[:8]:>10s}" for cname in CLASS_NAMES])
        print(header)
        print("-" * len(header))
        for cid, cname in enumerate(CLASS_NAMES):
            row_str = f"{cname[:12]:12s}" + "".join([f"{cm[cid, j]:10d}" for j in range(len(CLASS_NAMES))])
            print(row_str)

        results["models"][model_name] = model_eval

    # Save complete evaluation output
    out_results_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_evaluation_results.json")
    with open(out_results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n========================================================")
    print(f"Evaluation complete. Full results saved to:\n  {out_results_path}")
    print(f"========================================================")


if __name__ == "__main__":
    evaluate_multiattack_test_set()
