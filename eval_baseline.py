"""
Independent evaluation script for baseline models on the untouched held-out test set.
Computes comprehensive, scientifically defensible performance metrics:
- Confusion Matrix (TN, FP, FN, TP)
- Accuracy & Macro F1
- Per-class Precision, Recall, F1
- False Positive Rate on Benign traffic
- False Negative Rate on Attack traffic
- Model inference latency
Saves complete results to models/benchmark/test_evaluation_results.json.
"""

import os
import json
import pickle
import time
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score
)

from pipeline.benchmark_dataset import (
    BenchmarkDatasetPipeline,
    BENCHMARK_ARTIFACTS_DIR
)

def evaluate_test_set():
    print("=" * 70)
    print("PHASE 7B: INDEPENDENT HELD-OUT TEST EVALUATION")
    print("=" * 70)

    # 1. Load Preprocessor and Metadata
    config_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_preprocessing_config.json")
    scaler_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_scaler.pkl")
    split_meta_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "split_metadata.json")

    if not os.path.exists(config_path) or not os.path.exists(scaler_path):
        raise FileNotFoundError("Baseline artifacts not found. Run train_baseline.py first.")

    with open(split_meta_path, "r") as f:
        split_meta = json.load(f)

    pipe = BenchmarkDatasetPipeline()
    pipe.load_artifacts(config_path=config_path, scaler_path=scaler_path)

    # 2. Load Raw Benchmark Dataset and Extract Held-out Test Split
    print("\n[Step 1/3] Loading held-out test partition...")
    df = pipe.load_and_clean_raw(deduplicate=True)
    _, _, test_df = pipe.chronological_split(df, train_ratio=0.70, val_ratio=0.15)
    
    y_test = pipe.extract_labels(test_df)
    X_test = pipe.transform_features(test_df)

    n_test = len(y_test)
    n_benign = int((y_test == 0).sum())
    n_attack = int((y_test == 1).sum())

    print(f"Test Partition Size: {n_test:,} records")
    print(f"  Class 0 (Benign):   {n_benign:,} ({n_benign / n_test * 100:.2f}%)")
    print(f"  Class 1 (PortScan): {n_attack:,} ({n_attack / n_test * 100:.2f}%)")

    # 3. Load Models
    lr_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_lr.pkl")
    rf_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_rf.pkl")

    with open(lr_path, "rb") as f:
        lr_model = pickle.load(f)
    with open(rf_path, "rb") as f:
        rf_model = pickle.load(f)

    models = {
        "Logistic Regression (Linear Baseline)": lr_model,
        "Random Forest (Ensemble Baseline)": rf_model
    }

    results = {
        "dataset": "CICIDS2017 Friday-WorkingHours-Afternoon-PortScan",
        "partitions": split_meta,
        "test_partition": {
            "total_records": n_test,
            "benign_records": n_benign,
            "attack_records": n_attack,
            "benign_prevalence": round(n_benign / n_test, 4),
            "attack_prevalence": round(n_attack / n_test, 4)
        },
        "models": {}
    }

    print("\n[Step 2/3] Evaluating models on held-out test set...")

    for model_name, model in models.items():
        print(f"\nEvaluating: {model_name}")
        t0 = time.time()
        y_pred = model.predict(X_test)
        inference_time = time.time() - t0
        latency_us_per_flow = (inference_time / n_test) * 1_000_000

        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # Rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec_per_class, rec_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
            y_test, y_pred, average=None, labels=[0, 1]
        )
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average="macro"
        )
        auc = roc_auc_score(y_test, y_prob) if y_prob is not None else None

        model_results = {
            "accuracy": float(acc),
            "macro_f1": float(macro_f1),
            "macro_precision": float(macro_prec),
            "macro_recall": float(macro_rec),
            "roc_auc": float(auc) if auc is not None else None,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            },
            "error_rates": {
                "false_positive_rate_benign": float(fpr),
                "false_negative_rate_attack": float(fnr)
            },
            "class_0_benign": {
                "precision": float(prec_per_class[0]),
                "recall": float(rec_per_class[0]),
                "f1_score": float(f1_per_class[0]),
                "support": int(support_per_class[0])
            },
            "class_1_attack": {
                "precision": float(prec_per_class[1]),
                "recall": float(rec_per_class[1]),
                "f1_score": float(f1_per_class[1]),
                "support": int(support_per_class[1])
            },
            "inference_latency": {
                "total_seconds": round(inference_time, 4),
                "microseconds_per_flow": round(latency_us_per_flow, 2)
            }
        }
        results["models"][model_name] = model_results

        print("-" * 50)
        print(f"  Accuracy:                      {acc:.4f} ({acc*100:.2f}%)")
        print(f"  Macro F1-Score:                {macro_f1:.4f}")
        print(f"  ROC-AUC:                       {auc:.4f}" if auc else "  ROC-AUC: N/A")
        print(f"  Confusion Matrix:              TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
        print(f"  False Positive Rate (Benign):  {fpr:.6f} ({fpr*100:.4f}%)")
        print(f"  False Negative Rate (Attack):  {fnr:.6f} ({fnr*100:.4f}%)")
        print(f"  Class 0 (Benign)   - Prec: {prec_per_class[0]:.4f}, Rec: {rec_per_class[0]:.4f}, F1: {f1_per_class[0]:.4f}")
        print(f"  Class 1 (PortScan) - Prec: {prec_per_class[1]:.4f}, Rec: {rec_per_class[1]:.4f}, F1: {f1_per_class[1]:.4f}")
        print(f"  Inference Latency:             {latency_us_per_flow:.2f} µs/flow")

    # Save results
    out_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "test_evaluation_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[Step 3/3] Complete evaluation results saved to: {out_path}")
    print("=" * 70)

if __name__ == "__main__":
    evaluate_test_set()
