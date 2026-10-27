"""
Unit and integration tests for Phase 7B: Real-Data Intrusion Detection Baseline.
Verifies data loading, label mapping, feature selection, train-only preprocessing isolation,
leakage-free chronological splitting, baseline model inference, safe failure modes,
and preservation of existing production artifacts.
"""

import os
import json
import pickle
import pytest
import numpy as np
import pandas as pd

from pipeline.benchmark_dataset import (
    BenchmarkDatasetPipeline,
    LABEL_MAPPING,
    CONSTANT_COLUMNS,
    REDUNDANT_COLUMNS,
    METADATA_EXCLUDED_COLUMNS,
    BENCHMARK_ARTIFACTS_DIR
)


def test_label_mapping_integrity():
    """Verify that class mapping is strictly binary: 0 for Benign, 1 for Attack."""
    assert LABEL_MAPPING["BENIGN"] == 0
    assert LABEL_MAPPING["PortScan"] == 1
    assert len(LABEL_MAPPING) == 2


def test_benchmark_data_loading_and_deduplication():
    """Verify loading raw benchmark CSV, header stripping, and deduplication."""
    pipe = BenchmarkDatasetPipeline()
    assert os.path.exists(pipe.raw_csv_path), f"Raw benchmark file missing: {pipe.raw_csv_path}"
    
    df = pipe.load_and_clean_raw(deduplicate=True)
    assert len(df) > 0
    assert "Label" in df.columns
    # Ensure no leading/trailing whitespace in columns
    for col in df.columns:
        assert col == col.strip()
    
    # Verify label values
    labels = set(df["Label"].unique())
    assert labels == {"BENIGN", "PortScan"}


def test_feature_selection_excludes_shortcuts():
    """Verify that host identifiers, zero-variance columns, and redundant columns are excluded."""
    pipe = BenchmarkDatasetPipeline()
    df = pipe.load_and_clean_raw(deduplicate=True)
    features = pipe.select_feature_columns(df, exclude_port=True)

    assert "Label" not in features
    assert "Destination Port" not in features
    for col in CONSTANT_COLUMNS:
        assert col not in features
    for col in REDUNDANT_COLUMNS:
        assert col not in features
    
    # 79 total columns - 1 Label - 1 Destination Port - 10 Constant - 1 Redundant = 66
    assert len(features) == 66


def test_chronological_split_isolation():
    """Verify train/val/test chronological partition sizes and zero feature overlap."""
    pipe = BenchmarkDatasetPipeline()
    df = pipe.load_and_clean_raw(deduplicate=True)
    train_df, val_df, test_df = pipe.chronological_split(df, train_ratio=0.70, val_ratio=0.15)

    assert len(train_df) + len(val_df) + len(test_df) == len(df)
    assert len(train_df) > 0
    assert len(val_df) > 0
    assert len(test_df) > 0

    # Verify both classes exist in all partitions
    for part, name in [(train_df, "Train"), (val_df, "Val"), (test_df, "Test")]:
        part_labels = set(part["Label"].unique())
        assert 0 in [LABEL_MAPPING[lbl] for lbl in part_labels], f"Benign missing in {name}"
        assert 1 in [LABEL_MAPPING[lbl] for lbl in part_labels], f"Attack missing in {name}"


def test_preprocessing_fitted_exclusively_on_train():
    """Verify that scaler and imputation values are computed strictly from training data."""
    pipe = BenchmarkDatasetPipeline()
    
    # Create small synthetic dataframe to verify strictly train-only calculation
    train_mock = pd.DataFrame({
        "feat1": [10.0, 20.0, np.nan, np.inf],
        "feat2": [100.0, 200.0, 300.0, 400.0],
        "Label": ["BENIGN", "PortScan", "BENIGN", "PortScan"]
    })
    test_mock = pd.DataFrame({
        "feat1": [np.nan, 999.0],
        "feat2": [500.0, 600.0],
        "Label": ["BENIGN", "PortScan"]
    })

    pipe.fit_preprocessing(train_mock, feature_cols=["feat1", "feat2"])
    
    # Expected median on train for feat1: median of [10.0, 20.0] = 15.0
    # Expected max finite on train for feat1: 20.0
    assert pipe.imputation_medians["feat1"] == 15.0
    assert pipe.imputation_max_finite["feat1"] == 20.0

    # Transform test set using train stats
    X_test_trans = pipe.transform_features(test_mock)
    assert not np.isnan(X_test_trans).any()
    assert not np.isinf(X_test_trans).any()


def test_safe_failure_on_missing_file_or_invalid_labels():
    """Verify that pipeline raises clear errors and does not fabricate data on bad input."""
    pipe_bad = BenchmarkDatasetPipeline(raw_csv_path="non_existent_file.csv")
    with pytest.raises(FileNotFoundError):
        pipe_bad.load_and_clean_raw()

    # Pipeline with corrupted labels
    pipe_valid = BenchmarkDatasetPipeline()
    corrupt_df = pd.DataFrame({
        "feat1": [1.0, 2.0],
        "Label": ["UNKNOWN_ATTACK", "FABRICATED_LABEL"]
    })
    # Writing to a temp CSV to test load_and_clean_raw validation
    tmp_path = os.path.join("data", "benchmark", "temp_corrupt.csv")
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    corrupt_df.to_csv(tmp_path, index=False)
    
    try:
        pipe_corrupt = BenchmarkDatasetPipeline(raw_csv_path=tmp_path)
        with pytest.raises(ValueError, match="Unexpected labels encountered"):
            pipe_corrupt.load_and_clean_raw()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_baseline_models_and_artifacts_saved_separately():
    """Verify that new benchmark baseline artifacts exist and did NOT overwrite production models."""
    rf_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_rf.pkl")
    lr_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_lr.pkl")
    scaler_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_scaler.pkl")
    config_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_preprocessing_config.json")
    results_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "test_evaluation_results.json")

    assert os.path.exists(rf_path), "Baseline Random Forest model missing"
    assert os.path.exists(lr_path), "Baseline Logistic Regression model missing"
    assert os.path.exists(scaler_path), "Baseline scaler missing"
    assert os.path.exists(config_path), "Baseline config missing"
    assert os.path.exists(results_path), "Evaluation results missing"

    # CRITICAL: Verify production models and scalers were NOT overwritten
    prod_model_path = os.path.join("models", "bilstm_weights.pt")
    prod_scaler_path = os.path.join("pipeline", "scaler.pkl")
    assert os.path.exists(prod_model_path), "Production BiLSTM weights were removed!"
    assert os.path.exists(prod_scaler_path), "Production scaler was removed!"
    
    # Check that production scaler is separate from benchmark scaler
    with open(prod_scaler_path, "rb") as f:
        prod_scaler = pickle.load(f)
    with open(scaler_path, "rb") as f:
        bench_scaler = pickle.load(f)
    
    # Production scaler has 12 features; benchmark scaler has 66 features
    assert prod_scaler.n_features_in_ == 12, "Production scaler was corrupted!"
    assert bench_scaler.n_features_in_ == 66, "Benchmark scaler should have 66 features"


def test_baseline_models_predict_valid_classes():
    """Verify that baseline models output valid binary class predictions (0 or 1)."""
    rf_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_rf.pkl")
    lr_path = os.path.join(BENCHMARK_ARTIFACTS_DIR, "baseline_lr.pkl")

    with open(rf_path, "rb") as f:
        rf_model = pickle.load(f)
    with open(lr_path, "rb") as f:
        lr_model = pickle.load(f)

    # Synthetic sample of 66 features
    dummy_X = np.zeros((5, 66))
    
    lr_preds = lr_model.predict(dummy_X)
    rf_preds = rf_model.predict(dummy_X)

    assert len(lr_preds) == 5
    assert len(rf_preds) == 5
    for p in list(lr_preds) + list(rf_preds):
        assert p in [0, 1]
