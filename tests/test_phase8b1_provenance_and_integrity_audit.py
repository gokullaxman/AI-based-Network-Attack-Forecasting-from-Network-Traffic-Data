"""
Test suite for Phase 8B.1: Dataset Provenance and Evaluation Integrity Audit.
Audits:
1. Dataset Provenance and Column Verification (79 columns, absence of Timestamp/IPs).
2. Label Normalization, Unknown-Label Rejection, and Rare-Class Exclusion.
3. Conflict Identification and Removal Integrity.
4. Duplicate-Group Partition Isolation (Zero Feature Leakage).
5. Mathematical Consistency between Confusion Matrices and Reported Metrics.
6. Production and Benchmark Artifact Path & Checksum Preservation.
"""

import os
import json
import hashlib
import pytest
import numpy as np
import pandas as pd

from pipeline.benchmark_multiattack import (
    MultiAttackDatasetPipeline,
    BENCHMARK_MULTIATTACK_DIR,
    CLASS_MAPPING,
    CLASS_NAMES,
    normalize_raw_label
)


PROD_WEIGHTS_SHA256 = "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
PROD_SCALER_SHA256 = "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"


def test_provenance_csv_headers_and_lack_of_timestamps():
    """Audits that local benchmark files originate from the 79-column MachineLearningCVE distribution without timestamps."""
    raw_dir = os.path.join("data", "benchmark", "raw")
    csv_files = [f for f in os.listdir(raw_dir) if f.endswith(".csv")]
    assert len(csv_files) >= 6, "Expected at least 6 multi-attack benchmark CSVs"

    for fname in csv_files:
        fpath = os.path.join(raw_dir, fname)
        df_head = pd.read_csv(fpath, nrows=5, encoding="latin1")
        cols = [c.strip() for c in df_head.columns]

        # MachineLearningCVE format has exactly 79 columns
        assert len(cols) == 79, f"{fname} has {len(cols)} columns, expected 79"

        # Explicitly verify lack of temporal shortcuts and IP metadata
        assert not any("timestamp" in c.lower() or "date" in c.lower() for c in cols), (
            f"Unexpected timestamp column found in {fname}"
        )
        assert not any("source ip" in c.lower() or "destination ip" in c.lower() for c in cols), (
            f"Unexpected IP address column found in {fname}"
        )
        assert not any("flow id" in c.lower() for c in cols), (
            f"Unexpected Flow ID column found in {fname}"
        )


def test_label_normalization_and_unknown_rejection():
    """Verifies that approved labels map to 0..5, rare attacks map to EXCLUDED, and unknown labels return None."""
    # 1. Six approved classes
    assert normalize_raw_label("BENIGN") == "BENIGN"
    assert normalize_raw_label("PortScan") == "PortScan"
    assert normalize_raw_label("DoS Hulk") == "DoS_DDoS"
    assert normalize_raw_label("DDoS") == "DoS_DDoS"
    assert normalize_raw_label("FTP-Patator") == "BruteForce"
    assert normalize_raw_label("SSH-Patator") == "BruteForce"
    assert normalize_raw_label("Web Attack \ufffd XSS") == "WebAttacks"
    assert normalize_raw_label("Bot") == "Botnet"

    # 2. Excluded rare classes
    assert normalize_raw_label("Heartbleed") == "EXCLUDED"
    assert normalize_raw_label("Infiltration") == "EXCLUDED"

    # 3. Unknown labels must NOT silently map to BENIGN or EXCLUDED
    unknown_samples = [
        "ZeroDay_Exploit",
        "Ransomware.WannaCry",
        "SYN_Flood_Custom",
        "UNKNOWN_ATTACK",
        "",
        None,
        np.nan
    ]
    for unk in unknown_samples:
        assert normalize_raw_label(unk) is None, f"Unknown label {unk} was not rejected!"


def test_conflict_detection_and_removal_audit():
    """Verifies that identical feature profiles with differing ground-truth labels are detected and quarantined."""
    pipe = MultiAttackDatasetPipeline()
    feature_cols = ["f1", "f2"]

    # Profile (1.0, 10.0) has both BENIGN and DoS_DDoS (conflict)
    # Profile (2.0, 20.0) has only BENIGN across multiple rows (not a conflict)
    # Profile (3.0, 30.0) has only Botnet (not a conflict)
    df = pd.DataFrame({
        "f1": [1.0, 1.0, 2.0, 2.0, 3.0],
        "f2": [10.0, 10.0, 20.0, 20.0, 30.0],
        "NormLabel": ["BENIGN", "DoS_DDoS", "BENIGN", "BENIGN", "Botnet"]
    })

    clean_df, n_conflicts = pipe.deduplicate_and_audit(df, feature_cols)

    assert n_conflicts == 1, f"Expected 1 conflicting profile, got {n_conflicts}"
    assert len(clean_df) == 2, f"Expected 2 clean unique profiles, got {len(clean_df)}"
    assert set(clean_df["NormLabel"]) == {"BENIGN", "Botnet"}


def test_zero_feature_leakage_in_test_partition():
    """Verifies that the saved held-out test partition has strictly 0 duplicate profiles internally and against metadata."""
    test_parquet_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "held_out_test_profiles.parquet")
    split_meta_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "split_metadata.json")

    assert os.path.exists(test_parquet_path), "Held-out test partition parquet missing"
    assert os.path.exists(split_meta_path), "Split metadata missing"

    with open(split_meta_path, "r") as f:
        meta = json.load(f)

    test_df = pd.read_parquet(test_parquet_path)
    assert len(test_df) == meta["partitions"]["test"]["total"]

    # Verify no duplicate feature profiles exist in the held-out test set
    feature_cols = [c for c in test_df.columns if c not in ["Label", "NormLabel", "Destination Port"]]
    assert not test_df.duplicated(subset=feature_cols).any(), (
        "Internal duplicate profiles found inside held-out test set!"
    )


def test_confusion_matrix_and_metric_mathematical_consistency():
    """Verifies exact mathematical consistency between confusion matrix and reported metrics in evaluation results."""
    eval_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_evaluation_results.json")
    assert os.path.exists(eval_path), "Multiattack evaluation results missing"

    with open(eval_path, "r") as f:
        eval_data = json.load(f)

    for model_name, m_data in eval_data["models"].items():
        cm = np.array(m_data["confusion_matrix"]["matrix_rows_are_true_cols_are_pred"])
        n_classes = len(CLASS_NAMES)
        assert cm.shape == (n_classes, n_classes), f"Expected {n_classes}x{n_classes} confusion matrix"

        total_samples = cm.sum()
        total_correct = np.diag(cm).sum()
        computed_acc = total_correct / total_samples

        reported_acc = m_data["overall_metrics"]["accuracy"]
        assert pytest.approx(reported_acc, rel=1e-5) == computed_acc, (
            f"Accuracy mismatch for {model_name}: reported {reported_acc}, computed {computed_acc}"
        )

        # Benign FPR verification
        benign_fp = cm[0, 1:].sum()
        total_benign = cm[0, :].sum()
        computed_benign_fpr = benign_fp / total_benign if total_benign > 0 else 0.0

        reported_fpr = m_data["benign_false_positive_rate"]["fpr"]
        assert pytest.approx(reported_fpr, rel=1e-5) == computed_benign_fpr, (
            f"Benign FPR mismatch for {model_name}: reported {reported_fpr}, computed {computed_benign_fpr}"
        )
        assert m_data["benign_false_positive_rate"]["false_positives_count"] == int(benign_fp)
        assert m_data["benign_false_positive_rate"]["true_benign_denominator"] == int(total_benign)

        # Per-class precision, recall, and support verification
        for cid, cname in enumerate(CLASS_NAMES):
            true_support = cm[cid, :].sum()
            pred_support = cm[:, cid].sum()
            tp = cm[cid, cid]

            comp_rec = tp / true_support if true_support > 0 else 0.0
            comp_prec = tp / pred_support if pred_support > 0 else 0.0

            rep_rec = m_data["per_class_metrics"][cname]["recall"]
            rep_prec = m_data["per_class_metrics"][cname]["precision"]
            rep_supp = m_data["per_class_metrics"][cname]["support"]

            assert int(rep_supp) == int(true_support), f"Support mismatch for {cname}"
            assert pytest.approx(rep_rec, rel=1e-4) == comp_rec, f"Recall mismatch for {cname}"
            assert pytest.approx(rep_prec, rel=1e-4) == comp_prec, f"Precision mismatch for {cname}"


def test_production_artifact_preservation():
    """Audits that production model weights and scalers have not been altered."""
    prod_weights_path = os.path.join("models", "bilstm_weights.pt")
    prod_scaler_path = os.path.join("pipeline", "scaler.pkl")

    assert os.path.exists(prod_weights_path), "Production BiLSTM weights missing!"
    assert os.path.exists(prod_scaler_path), "Production scaler missing!"

    with open(prod_weights_path, "rb") as f:
        weights_sha = hashlib.sha256(f.read()).hexdigest()
    with open(prod_scaler_path, "rb") as f:
        scaler_sha = hashlib.sha256(f.read()).hexdigest()

    assert weights_sha == PROD_WEIGHTS_SHA256, "Production BiLSTM weights were modified!"
    assert scaler_sha == PROD_SCALER_SHA256, "Production scaler was modified!"
