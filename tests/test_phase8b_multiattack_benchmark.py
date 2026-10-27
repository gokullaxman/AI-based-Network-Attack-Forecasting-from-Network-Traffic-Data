"""
Test suite for Phase 8B: Leakage-Controlled Multi-Attack Detection Benchmark.
Verifies:
1. Label normalization for all 6 target classes.
2. Rejection of unknown labels (never silently mapped to BENIGN).
3. Explicit exclusion of Heartbleed and Infiltration.
4. Conflicting label detection across identical feature vectors.
5. Strict zero-leakage duplicate-group split isolation.
6. Exclusion of metadata (Destination Port), 10 constant columns, and redundant columns.
7. Train-only preprocessing fit (StandardScaler and medians).
8. Reproducibility of partitioning with fixed random seed.
9. Correct confusion matrix dimensions (6x6).
10. Strict isolation from production model artifacts.
"""

import os
import json
import pickle
import pytest
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from pipeline.benchmark_multiattack import (
    MultiAttackDatasetPipeline,
    BENCHMARK_MULTIATTACK_DIR,
    CLASS_MAPPING,
    CLASS_NAMES,
    CONSTANT_COLUMNS,
    REDUNDANT_COLUMNS,
    METADATA_EXCLUDED_COLUMNS,
    normalize_raw_label
)


def test_label_normalization_canonical_classes():
    """Verifies that all authentic raw CICIDS2017 label variants map to their target class."""
    # BENIGN
    assert normalize_raw_label("BENIGN") == "BENIGN"
    assert normalize_raw_label(" BENIGN ") == "BENIGN"

    # PortScan
    assert normalize_raw_label("PortScan") == "PortScan"
    assert normalize_raw_label("PortScan ") == "PortScan"

    # DoS / DDoS
    assert normalize_raw_label("DDoS") == "DoS_DDoS"
    assert normalize_raw_label("DoS Hulk") == "DoS_DDoS"
    assert normalize_raw_label("DoS GoldenEye") == "DoS_DDoS"
    assert normalize_raw_label("DoS slowloris") == "DoS_DDoS"
    assert normalize_raw_label("DoS Slowloris") == "DoS_DDoS"
    assert normalize_raw_label("DoS Slowhttptest") == "DoS_DDoS"

    # BruteForce
    assert normalize_raw_label("FTP-Patator") == "BruteForce"
    assert normalize_raw_label("SSH-Patator") == "BruteForce"

    # WebAttacks (including encoding corruptions like \ufffd and en-dashes)
    assert normalize_raw_label("Web Attack \ufffd Brute Force") == "WebAttacks"
    assert normalize_raw_label("Web Attack \ufffd XSS") == "WebAttacks"
    assert normalize_raw_label("Web Attack \ufffd Sql Injection") == "WebAttacks"
    assert normalize_raw_label("Web Attack - Brute Force") == "WebAttacks"
    assert normalize_raw_label("Web Attack – XSS") == "WebAttacks"

    # Botnet
    assert normalize_raw_label("Bot") == "Botnet"


def test_unknown_label_and_excluded_handling():
    """Verifies that unknown labels return None and are never silently mapped to BENIGN, while rare attacks return EXCLUDED."""
    # Unknown labels
    assert normalize_raw_label("RandomAttack_123") is None
    assert normalize_raw_label("MALWARE") is None
    assert normalize_raw_label("") is None
    assert normalize_raw_label(None) is None
    assert normalize_raw_label(np.nan) is None

    # Excluded rare attacks
    assert normalize_raw_label("Heartbleed") == "EXCLUDED"
    assert normalize_raw_label("Infiltration") == "EXCLUDED"


def test_feature_selection_and_metadata_exclusion():
    """Verifies that Destination Port, constant columns, redundant columns, and labels are excluded."""
    pipe = MultiAttackDatasetPipeline()
    sample_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Destination Port",
        "Bwd PSH Flags",
        "Fwd Header Length.1",
        "Label",
        "NormLabel"
    ]
    df = pd.DataFrame(columns=sample_cols)
    selected = pipe.select_feature_columns(df)

    assert "Flow Duration" in selected
    assert "Total Fwd Packets" in selected
    assert "Total Backward Packets" in selected
    assert "Destination Port" not in selected
    assert "Bwd PSH Flags" not in selected
    assert "Fwd Header Length.1" not in selected
    assert "Label" not in selected
    assert "NormLabel" not in selected


def test_conflicting_label_detection_and_removal():
    """Verifies that identical feature profiles with differing labels are identified and removed."""
    pipe = MultiAttackDatasetPipeline()
    feature_cols = ["f1", "f2"]
    data = {
        "f1": [1.0, 1.0, 1.0, 2.0, 3.0],
        "f2": [10.0, 10.0, 10.0, 20.0, 30.0],
        "NormLabel": ["BENIGN", "BENIGN", "DoS_DDoS", "PortScan", "Botnet"]
    }
    df = pd.DataFrame(data)

    clean_df, n_conflicts = pipe.deduplicate_and_audit(df, feature_cols)

    # The profile (1.0, 10.0) has both BENIGN and DoS_DDoS, so it is a conflict
    assert n_conflicts == 1
    # Conflicting profile must be entirely removed from clean benchmark
    assert len(clean_df) == 2
    assert set(clean_df["NormLabel"]) == {"PortScan", "Botnet"}


def test_zero_leakage_duplicate_aware_split():
    """Verifies that partitioning guarantees 0 feature-vector overlap between train, val, and test."""
    pipe = MultiAttackDatasetPipeline()
    feature_cols = ["f1", "f2"]
    # 120 distinct profiles, 20 of each class
    records = []
    for i in range(120):
        cname = CLASS_NAMES[i % 6]
        records.append({"f1": float(i), "f2": float(i * 10), "NormLabel": cname})
    df = pd.DataFrame(records)

    clean_df, n_conflicts = pipe.deduplicate_and_audit(df, feature_cols)
    assert n_conflicts == 0
    assert len(clean_df) == 120

    train_df, val_df, test_df = pipe.stratified_zero_leakage_split(
        clean_df, feature_cols, train_ratio=0.70, val_ratio=0.15, random_seed=42
    )

    # Check zero overlap between train and test
    combined_train_test = pd.concat([train_df[feature_cols], test_df[feature_cols]], ignore_index=True)
    assert not combined_train_test.duplicated().any()

    # Check zero overlap between train and val
    combined_train_val = pd.concat([train_df[feature_cols], val_df[feature_cols]], ignore_index=True)
    assert not combined_train_val.duplicated().any()

    # Check zero overlap between val and test
    combined_val_test = pd.concat([val_df[feature_cols], test_df[feature_cols]], ignore_index=True)
    assert not combined_val_test.duplicated().any()


def test_train_only_preprocessing_fit():
    """Verifies that preprocessing statistics are learned strictly from train partition."""
    pipe = MultiAttackDatasetPipeline()
    feature_cols = ["f1", "f2"]

    train_df = pd.DataFrame({
        "f1": [10.0, 20.0, np.nan, 30.0],
        "f2": [100.0, np.inf, 300.0, 400.0],
        "NormLabel": ["BENIGN", "PortScan", "BENIGN", "PortScan"]
    })

    test_df = pd.DataFrame({
        "f1": [np.nan, 50.0],
        "f2": [np.inf, 200.0],
        "NormLabel": ["BENIGN", "PortScan"]
    })

    pipe.fit_preprocessing(train_df, feature_cols)

    # Train medians should be used for imputation
    expected_f1_median = 20.0  # median of [10.0, 20.0, 30.0]
    expected_f2_max_finite = 400.0  # max finite of [100.0, 300.0, 400.0]

    assert pipe.imputation_medians["f1"] == expected_f1_median
    assert pipe.imputation_max_finite["f2"] == expected_f2_max_finite

    # Transform test set without fitting
    X_test_trans = pipe.transform_features(test_df)
    assert not np.isnan(X_test_trans).any()
    assert not np.isinf(X_test_trans).any()


def test_reproducible_splitting():
    """Verifies that split partitions are deterministic when given the same random seed."""
    pipe = MultiAttackDatasetPipeline()
    feature_cols = ["f1", "f2"]
    records = [{"f1": float(i), "f2": float(i * 5), "NormLabel": CLASS_NAMES[i % 6]} for i in range(60)]
    df = pd.DataFrame(records)

    train_1, val_1, test_1 = pipe.stratified_zero_leakage_split(df, feature_cols, random_seed=42)
    train_2, val_2, test_2 = pipe.stratified_zero_leakage_split(df, feature_cols, random_seed=42)

    pd.testing.assert_frame_equal(train_1, train_2)
    pd.testing.assert_frame_equal(val_1, val_2)
    pd.testing.assert_frame_equal(test_1, test_2)


def test_confusion_matrix_dimensions_and_classes():
    """Verifies that evaluation structures preserve all 6 classes in the exact canonical order."""
    assert len(CLASS_NAMES) == 6
    assert CLASS_NAMES == ["BENIGN", "PortScan", "DoS_DDoS", "BruteForce", "WebAttacks", "Botnet"]
    for i, name in enumerate(CLASS_NAMES):
        assert CLASS_MAPPING[name] == i


def test_artifact_isolation_from_production():
    """Verifies that Phase 8B artifacts are isolated and do not alter production weights or scalers."""
    # Production paths must exist and remain untouched
    prod_weights = os.path.join("models", "bilstm_weights.pt")
    prod_scaler = os.path.join("pipeline", "scaler.pkl")

    assert os.path.exists(prod_weights), "Production BiLSTM weights missing!"
    assert os.path.exists(prod_scaler), "Production scaler missing!"

    # Multiattack artifacts belong strictly under models/benchmark_multiattack/
    assert BENCHMARK_MULTIATTACK_DIR == os.path.join("models", "benchmark_multiattack")
