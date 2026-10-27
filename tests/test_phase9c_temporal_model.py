"""
Tests for Phase 9C: Real-Data Attack Forecasting Model.

Validates:
1. Model save/load and artifact integrity
2. Feature schema validation and ordering
3. Missing and invalid features (NaNs, wrong dimensions, packet schema rejection)
4. Training-only preprocessing verification
5. Prediction output format and calibration notice
6. Target leakage prevention
7. Reproducible evaluation metrics
8. Strict separation between experimental model and production BiLSTM
9. API experimental endpoints
"""

import os
import json
import hashlib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from models.temporal_forecasting import TemporalAttackForecaster
from models.temporal_forecasting.forecaster import (
    EXPECTED_FLOW_FEATURES, INCOMPATIBLE_PACKET_SIGNATURES
)
from pipeline.train_temporal_forecaster import (
    PREDICTOR_COLUMNS, EXCLUDED_LABEL_COLUMNS
)
from dashboard.server import app

client = TestClient(app)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "temporal_forecasting")
METRICS_PATH = os.path.join(PROJECT_ROOT, "data", "benchmark", "temporal", "phase9c", "metrics.json")
PRODUCTION_WEIGHTS = os.path.join(PROJECT_ROOT, "models", "bilstm_weights.pt")
PRODUCTION_SCALER = os.path.join(PROJECT_ROOT, "pipeline", "scaler.pkl")


def compute_sha256(fpath: str) -> str:
    h = hashlib.sha256()
    with open(fpath, "rb") as fp:
        while chunk := fp.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def test_model_save_and_load():
    """Verify that TemporalAttackForecaster loads model, preprocessor, and metadata cleanly."""
    forecaster = TemporalAttackForecaster()
    assert forecaster.model is not None
    assert forecaster.scaler is not None
    assert forecaster.metadata is not None
    assert forecaster.expected_feature_count == 120
    assert len(forecaster.expected_columns) == 120
    assert forecaster.metadata["model_name"] == "Target_A_Temporal_Attack_Forecaster"


def test_feature_schema_validation():
    """Verify feature schema ordering: 12 base flow features x 10 lag minutes."""
    forecaster = TemporalAttackForecaster()
    expected_order = [f"{col}_lag_{9-step}" for step in range(10) for col in EXPECTED_FLOW_FEATURES]
    assert forecaster.expected_columns == expected_order

    # Valid array of 120 features
    valid_arr = np.zeros((1, 120), dtype=float)
    validated = forecaster.validate_features(valid_arr)
    assert validated.shape == (1, 120)

    # Valid DataFrame with exact columns
    valid_df = pd.DataFrame([np.zeros(120)], columns=expected_order)
    validated_df = forecaster.validate_features(valid_df)
    assert validated_df.shape == (1, 120)


def test_missing_and_invalid_features():
    """Verify that invalid inputs, NaNs, incorrect dimensions, and packet features are rejected."""
    forecaster = TemporalAttackForecaster()

    # Rejection of None
    with pytest.raises(ValueError, match="cannot be None"):
        forecaster.validate_features(None)

    # Rejection of NaNs
    nan_arr = np.full((1, 120), np.nan)
    with pytest.raises(ValueError, match="contain NaN"):
        forecaster.validate_features(nan_arr)

    # Rejection of Infs
    inf_arr = np.full((1, 120), np.inf)
    with pytest.raises(ValueError, match="contain infinite"):
        forecaster.validate_features(inf_arr)

    # Rejection of incorrect dimension
    wrong_dim = np.zeros((1, 50))
    with pytest.raises(ValueError, match="Invalid feature dimensions"):
        forecaster.validate_features(wrong_dim)

    # Rejection of packet-layer feature schemas from live capture
    packet_df = pd.DataFrame([{
        "mean_frame_length": 500.0,
        "std_frame_length": 100.0,
        "tcp_packet_ratio": 0.8
    }])
    with pytest.raises(ValueError, match="Detected incompatible packet-layer feature"):
        forecaster.validate_features(packet_df)


def test_training_only_preprocessing():
    """Verify that preprocessor was fit strictly on training split (1,117 samples)."""
    forecaster = TemporalAttackForecaster()
    # Scikit-learn StandardScaler records n_samples_seen_
    assert forecaster.scaler.n_samples_seen_ == 1117, (
        f"Expected scaler to be fit on exactly 1,117 training samples, saw {forecaster.scaler.n_samples_seen_}"
    )


def test_prediction_output_and_calibration():
    """Verify prediction output structure, bounds, and uncalibrated notice."""
    forecaster = TemporalAttackForecaster()
    sample = np.zeros((1, 120), dtype=float)

    # Probability prediction
    res_prob = forecaster.predict_proba(sample)
    assert res_prob["status"] == "EXPERIMENTAL_RESEARCH_MODEL"
    assert res_prob["is_calibrated"] is False
    assert "Uncalibrated" in res_prob["calibration_note"]
    assert 0.0 <= res_prob["forecast_probability"] <= 1.0

    # Binary prediction
    res_bin = forecaster.predict(sample, threshold=0.5)
    assert "forecast_onset_positive" in res_bin
    assert isinstance(res_bin["forecast_onset_positive"], bool)
    assert res_bin["decision_threshold"] == 0.5


def test_target_leakage_prevention():
    """Verify that predictor columns strictly exclude all labels and target-derived fields."""
    for label_col in EXCLUDED_LABEL_COLUMNS:
        assert label_col not in PREDICTOR_COLUMNS, f"Label {label_col} illegally found in predictor columns!"

    forecaster = TemporalAttackForecaster()
    for col in forecaster.expected_columns:
        for label_col in EXCLUDED_LABEL_COLUMNS:
            assert label_col not in col, f"Label component {label_col} found in feature {col}!"


def test_reproducible_evaluation_metrics():
    """Verify that exported metrics match verified benchmark results."""
    assert os.path.exists(METRICS_PATH), f"Metrics file missing at {METRICS_PATH}"
    with open(METRICS_PATH, "r") as fp:
        metrics = json.load(fp)

    wm = metrics["evaluation_metrics"]["window_level"]
    # Logistic Regression metrics
    lr = wm["logistic_regression"]
    assert lr["pr_auc"] == 0.1554
    assert lr["roc_auc"] == 0.5370
    assert lr["true_positives"] == 2
    assert lr["false_positives"] == 11
    assert lr["false_alarms_per_hour"] == 2.69

    # Dummy Prior comparison
    dummy = wm["dummy_prior"]
    assert dummy["pr_auc"] == 0.1250
    assert dummy["roc_auc"] == 0.5000

    # Event level recall
    em = metrics["evaluation_metrics"]["event_level"]
    assert em["logistic_regression"]["rule1_multi_credit_detected"] == 3
    assert em["logistic_regression"]["rule2_strict_earliest_detected"] == 2
    assert em["logistic_regression"]["rule2_recall"] == 0.2000
    assert len(em["logistic_regression"]["lead_times_minutes"]) == 3


def test_separation_between_experimental_and_production_models():
    """Verify that original production BiLSTM weights and scaler were NOT modified."""
    # Production BiLSTM weights must match exact reference
    assert os.path.exists(PRODUCTION_WEIGHTS)
    assert os.path.getsize(PRODUCTION_WEIGHTS) == 634157
    assert compute_sha256(PRODUCTION_WEIGHTS).startswith("35807897ae6c")

    # Production scaler must match exact reference
    assert os.path.exists(PRODUCTION_SCALER)
    assert os.path.getsize(PRODUCTION_SCALER) == 704
    assert compute_sha256(PRODUCTION_SCALER).startswith("7ffea55f48ad")


def test_api_experimental_endpoints():
    """Test the FastAPI experimental research endpoints."""
    # 1. Metadata endpoint
    res_meta = client.get("/api/forecast/temporal-experimental/metadata")
    assert res_meta.status_code == 200
    meta_json = res_meta.json()
    assert meta_json["model_name"] == "Target_A_Temporal_Attack_Forecaster"

    # 2. Prediction endpoint with valid 120-dim input
    sample_features = [0.0] * 120
    res_pred = client.post(
        "/api/forecast/temporal-experimental",
        json={"features": sample_features, "threshold": 0.5}
    )
    assert res_pred.status_code == 200
    pred_json = res_pred.json()
    assert pred_json["status"] == "EXPERIMENTAL_RESEARCH_MODEL"
    assert "forecast_probability" in pred_json
    assert "forecast_onset_positive" in pred_json

    # 3. Prediction endpoint rejecting packet features
    res_bad = client.post(
        "/api/forecast/temporal-experimental",
        json={"features": [{"mean_frame_length": 500.0, "tcp_packet_ratio": 0.8}]}
    )
    assert res_bad.status_code == 422
    assert "incompatible packet-layer feature" in res_bad.json()["error"]


def test_sample_windows_endpoint():
    """Verify sample windows endpoint returns curated benchmark test windows."""
    res = client.get("/api/forecast/temporal-experimental/sample-windows")
    assert res.status_code == 200
    data = res.json()
    assert "samples" in data
    assert len(data["samples"]) > 0
    sample = data["samples"][0]
    assert "sample_id" in sample
    assert "features" in sample
    assert len(sample["features"]) == 120
    assert "horizon_start" in sample
    assert "horizon_end" in sample
    assert "ground_truth_target" in sample


def test_dashboard_html_contains_phase9c_panel_and_tab():
    """Verify that index.html contains the Phase 9C navigation tab, panel, and rejection notice."""
    html_path = os.path.join(PROJECT_ROOT, "dashboard", "static", "index.html")
    assert os.path.exists(html_path)
    with open(html_path, "r", encoding="utf-8") as fp:
        html = fp.read()

    # Tab
    assert 'id="tabTemporalExperimental"' in html
    assert 'data-view="temporalExperimentalView"' in html

    # View container
    assert 'id="temporalExperimentalView"' in html

    # Live packet incompatibility notice
    assert 'id="temporalLiveAlertBox"' in html
    assert 'Live Packet Stream Incompatible with Flow Model' in html
    assert 'FORECASTING MODEL NOT VALIDATED FOR THIS DATA' in html

    # Interactive evaluation elements
    assert 'id="temporalSampleSelect"' in html
    assert 'id="btnRunTemporalForecast"' in html
    assert 'id="btnTestPacketRejection"' in html
    assert 'id="temporalScoreCircle"' in html
    assert 'EXPERIMENTAL SCORE: NOT CALIBRATED PROBABILITY' in html

    # Target A Horizon Tracker
    assert 'TARGET A FORECAST HORIZON ARCHITECTURE' in html
    assert '10 Minutes [t-9m ... t]' in html
    assert '2 Minutes [t+1m, t+2m]' in html
    assert '5 Minutes [t+3m ... t+7m]' in html


def test_live_capture_status_indicates_gated_model():
    """Verify that live capture endpoints return explicit unvalidated status."""
    res = client.get("/api/capture/temporal-windows")
    assert res.status_code == 200
    data = res.json()
    assert data["model_readiness"] == "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"

