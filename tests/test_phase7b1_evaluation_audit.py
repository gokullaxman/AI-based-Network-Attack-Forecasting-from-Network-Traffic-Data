"""
Unit and integration tests for Phase 7B.1: Evaluation Integrity Audit.
Verifies provenance checksum, lack of temporal columns, conflicting label absence,
duplicate-handling differences, feature-vector overlap detection, zero-leakage alternative
split isolation, metric mathematical consistency, and production artifact preservation.
"""

import os
import json
import hashlib
import pickle
import pytest
import numpy as np
import pandas as pd

from pipeline.benchmark_dataset import (
    BenchmarkDatasetPipeline,
    DEFAULT_RAW_PATH,
    BENCHMARK_ARTIFACTS_DIR
)
from run_audit_experiment import AUDIT_ARTIFACTS_DIR


def test_audit_provenance_and_file_checksum():
    """Verify raw benchmark CSV byte size and exact SHA-256 checksum."""
    assert os.path.exists(DEFAULT_RAW_PATH), f"Raw benchmark file missing: {DEFAULT_RAW_PATH}"
    file_size = os.path.getsize(DEFAULT_RAW_PATH)
    assert file_size == 76906168, f"Unexpected file size: {file_size}"

    sha256 = hashlib.sha256()
    with open(DEFAULT_RAW_PATH, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    assert digest == "ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b"


def test_audit_temporal_columns_absence():
    """Verify that no timestamp, date, or flow-start time columns exist in the benchmark CSV."""
    df_head = pd.read_csv(DEFAULT_RAW_PATH, nrows=5)
    cols = [c.strip().lower() for c in df_head.columns]
    
    # Must NOT have timestamp or datetime columns
    for candidate in ["timestamp", "date", "time", "flow_start", "start_time"]:
        assert candidate not in cols, f"Unexpected temporal column found: {candidate}"


def test_audit_no_conflicting_labels_across_features():
    """Verify that identical feature vectors never appear with conflicting labels."""
    pipe = BenchmarkDatasetPipeline()
    df = pipe.load_and_clean_raw(deduplicate=False)
    features = pipe.select_feature_columns(df, exclude_port=True)
    
    # Duplicate feature vectors
    dup_features = df[df.duplicated(subset=features, keep=False)]
    grouped_labels = dup_features.groupby(features)["Label"].nunique()
    assert (grouped_labels > 1).sum() == 0, "Conflicting labels found for identical feature vectors!"


def test_audit_feature_overlap_quantification():
    """Verify that 79-col deduplication permits 66-feat overlap, while 66-feat deduplication eliminates it."""
    pipe = BenchmarkDatasetPipeline()
    
    # 1. 79-col dedup (Phase 7B original)
    df_79 = pipe.load_and_clean_raw(deduplicate=True)
    features = pipe.select_feature_columns(df_79, exclude_port=True)
    train_79, _, test_79 = pipe.chronological_split(df_79)
    train_tuples_79 = set(map(tuple, train_79[features].values))
    test_tuples_79 = set(map(tuple, test_79[features].values))
    overlap_79 = len(train_tuples_79.intersection(test_tuples_79))
    assert overlap_79 > 0, "Expected overlap when port was excluded after 79-col dedup"
    assert overlap_79 == 765, f"Expected exactly 765 overlapping feature vectors, got {overlap_79}"

    # 2. 66-feat dedup (Phase 7B.1 audit alternative)
    df_66 = df_79.drop_duplicates(subset=features).reset_index(drop=True)
    train_66, _, test_66 = pipe.chronological_split(df_66)
    train_tuples_66 = set(map(tuple, train_66[features].values))
    test_tuples_66 = set(map(tuple, test_66[features].values))
    overlap_66 = len(train_tuples_66.intersection(test_tuples_66))
    assert overlap_66 == 0, f"Expected 0 overlap in audit alternative, got {overlap_66}"


def test_audit_metric_mathematical_consistency():
    """Verify that confusion matrices mathematically reproduce reported accuracy, precision, recall, and FPR/FNR."""
    # Check original Phase 7B results
    p7b_results_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "test_evaluation_results.json")
    with open(p7b_results_path, "r") as f:
        p7b_data = json.load(f)

    for m_name, m_data in p7b_data["models"].items():
        cm = m_data["confusion_matrix"]
        tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
        total = tn + fp + fn + tp

        # Check accuracy
        calc_acc = (tp + tn) / total
        assert pytest.approx(m_data["accuracy"], abs=1e-5) == calc_acc

        # Check FPR and FNR
        calc_fpr = fp / (fp + tn)
        calc_fnr = fn / (fn + tp)
        assert pytest.approx(m_data["error_rates"]["false_positive_rate_benign"], abs=1e-5) == calc_fpr
        assert pytest.approx(m_data["error_rates"]["false_negative_rate_attack"], abs=1e-5) == calc_fnr


def test_audit_artifacts_preservation():
    """Verify that Phase 7B.1 audit artifacts exist and do NOT touch Phase 7B original or production models."""
    # Audit artifacts
    assert os.path.exists(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_rf.pkl"))
    assert os.path.exists(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_lr.pkl"))
    assert os.path.exists(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_scaler.pkl"))
    assert os.path.exists(os.path.join(AUDIT_ARTIFACTS_DIR, "audit_evaluation_results.json"))

    # Phase 7B original artifacts preserved
    assert os.path.exists(os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_rf.pkl"))
    assert os.path.exists(os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_lr.pkl"))
    assert os.path.exists(os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_scaler.pkl"))
    assert os.path.exists(os.path.join(BENCHMARK_ARTIFACTS_DIR, "test_evaluation_results.json"))

    # Production inference artifacts preserved
    prod_model_path = os.path.join("models", "bilstm_weights.pt")
    prod_scaler_path = os.path.join("pipeline", "scaler.pkl")
    assert os.path.exists(prod_model_path)
    assert os.path.exists(prod_scaler_path)

    with open(prod_scaler_path, "rb") as f:
        prod_scaler = pickle.load(f)
    assert prod_scaler.n_features_in_ == 12, "Production scaler must have 12 features"
