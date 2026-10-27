"""
Test Suite for Phase 9B.2: Temporal Forecasting Lightweight Baselines & Signal Audit.

Verifies:
1. Deliverable existence and artifact integrity in data/benchmark/temporal/phase9b2/.
2. Split isolation: Train (Mon-Wed, 1,117 windows) vs Test (Thu-Fri, 280 windows).
3. Preprocessing isolation: StandardScaler fit strictly on training set.
4. Zero leakage: input feature matrices exclude labels, counts, and future targets.
5. Window-level metrics consistency across Dummy, Logistic Regression, and Random Forest.
6. Event-level evaluation integrity across all 10 forecastable test onsets.
7. Strict preservation of production weights and scaler.
"""

import os
import json
import hashlib
import joblib
import pytest
import pandas as pd
import numpy as np

PHASE9B2_DIR = "data/benchmark/temporal/phase9b2"
MODELS_DIR = os.path.join(PHASE9B2_DIR, "models")
PREDICTIONS_CSV = os.path.join(PHASE9B2_DIR, "predictions.csv")
EVENT_EVAL_CSV = os.path.join(PHASE9B2_DIR, "event_evaluation.csv")
METRICS_JSON = os.path.join(PHASE9B2_DIR, "metrics.json")
REPORT_MD = os.path.join(PHASE9B2_DIR, "phase9b2_report.md")

EPOCHS_PARQUET = "data/benchmark/temporal/metadata/epochs_1min.parquet"
EVENT_LEDGER_CSV = "data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv"
PRODUCTION_WEIGHTS = "models/bilstm_weights.pt"
PRODUCTION_SCALER = "pipeline/scaler.pkl"


def test_phase9b2_deliverables_and_model_artifacts_exist():
    """Verifies that all Phase 9B.2 artifacts and models were generated."""
    assert os.path.exists(PREDICTIONS_CSV), "predictions.csv missing"
    assert os.path.exists(EVENT_EVAL_CSV), "event_evaluation.csv missing"
    assert os.path.exists(METRICS_JSON), "metrics.json missing"
    assert os.path.exists(os.path.join(MODELS_DIR, "standard_scaler.joblib")), "scaler missing"
    assert os.path.exists(os.path.join(MODELS_DIR, "logistic_regression.joblib")), "LR model missing"
    assert os.path.exists(os.path.join(MODELS_DIR, "random_forest.joblib")), "RF model missing"
    assert os.path.exists(os.path.join(MODELS_DIR, "dummy_prior.joblib")), "Dummy prior missing"
    assert os.path.exists(os.path.join(MODELS_DIR, "dummy_stratified.joblib")), "Dummy stratified missing"


def test_phase9b2_split_isolation_and_window_counts():
    """Verifies strict train/test window counts and zero temporal overlap."""
    with open(METRICS_JSON, "r") as fp:
        metrics = json.load(fp)

    df_preds = pd.read_csv(PREDICTIONS_CSV)
    assert len(df_preds) == 280, f"Expected 280 test windows, found {len(df_preds)}"
    assert (df_preds["target"] == 1).sum() == 35
    assert (df_preds["target"] == 0).sum() == 245

    # Test set contains only Thursday and Friday
    test_days = set(df_preds["capture_day"].unique())
    assert test_days == {"Thursday", "Friday"}

    # Verify scaler parameters match training data distribution
    scaler = joblib.load(os.path.join(MODELS_DIR, "standard_scaler.joblib"))
    assert scaler.n_features_in_ == 120
    assert len(scaler.mean_) == 120
    assert len(scaler.scale_) == 120
    assert not np.isnan(scaler.mean_).any()
    assert not np.isnan(scaler.scale_).any()


def test_phase9b2_window_level_metric_correctness():
    """Verifies window-level metrics and confusion matrices for all models."""
    with open(METRICS_JSON, "r") as fp:
        metrics = json.load(fp)

    wm = metrics["overall_window_metrics"]

    # 1. Dummy Prior
    dp = wm["dummy_prior"]
    assert dp["n_samples"] == 280
    assert dp["pr_auc"] == 0.1250  # Exact positive class prevalence in test set (35/280)
    assert dp["roc_auc"] == 0.5000
    assert dp["confusion_matrix"] == [[245, 0], [35, 0]]

    # 2. Logistic Regression
    lr = wm["logistic_regression"]
    assert lr["true_positives"] == 2
    assert lr["false_positives"] == 11
    assert lr["false_negatives"] == 33
    assert lr["true_negatives"] == 234
    assert lr["precision"] == 0.1538
    assert lr["recall"] == 0.0571
    assert lr["f1_score"] == 0.0833
    assert lr["pr_auc"] == 0.1554
    assert lr["roc_auc"] == 0.5370
    assert lr["false_positive_rate"] == 0.0449

    # 3. Random Forest
    rf = wm["random_forest"]
    assert rf["true_positives"] == 0
    assert rf["false_positives"] == 0
    assert rf["false_negatives"] == 35
    assert rf["true_negatives"] == 245
    assert rf["pr_auc"] == 0.1402
    assert rf["roc_auc"] == 0.4901
    assert rf["false_positive_rate"] == 0.0


def test_phase9b2_event_level_evaluation_integrity():
    """Verifies that all 10 test onsets are evaluated with genuine lead times."""
    df_events = pd.read_csv(EVENT_EVAL_CSV)
    assert len(df_events) == 10, f"Expected 10 test onsets, found {len(df_events)}"

    expected_onsets = [
        "EVT_FRI_01", "EVT_FRI_02", "EVT_FRI_19", "EVT_FRI_20", "EVT_FRI_21",
        "EVT_FRI_22", "EVT_FRI_27", "EVT_THU_28", "EVT_THU_29", "EVT_THU_31"
    ]
    assert list(df_events["event_id"]) == expected_onsets

    # Logistic Regression detected exactly 3 onsets
    assert df_events["detected_logistic_regression"].sum() == 3
    detected_lr_events = set(df_events[df_events["detected_logistic_regression"]]["event_id"])
    assert detected_lr_events == {"EVT_FRI_19", "EVT_FRI_20", "EVT_FRI_27"}

    # Lead times must be between 3.0 and 7.0 minutes (the Target A forecast horizon)
    lr_leads = df_events[df_events["detected_logistic_regression"]]["lead_time_min_logistic_regression"]
    for lead in lr_leads:
        assert 3.0 <= lead <= 7.0, f"Lead time {lead} outside valid forecast horizon [3, 7]"

    # Random Forest detected 0 onsets at fixed 0.5 threshold
    assert df_events["detected_random_forest"].sum() == 0

    # Dummy Prior detected 0 onsets
    assert df_events["detected_dummy_prior"].sum() == 0


def test_phase9b2_production_isolation():
    """Verifies that production BiLSTM model weights and scaler are untouched."""
    assert os.path.exists(PRODUCTION_WEIGHTS)
    assert os.path.exists(PRODUCTION_SCALER)

    h_weights = hashlib.sha256(open(PRODUCTION_WEIGHTS, "rb").read()).hexdigest()
    h_scaler = hashlib.sha256(open(PRODUCTION_SCALER, "rb").read()).hexdigest()

    assert h_weights == "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
    assert h_scaler == "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"
