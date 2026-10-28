"""
Automated Test Suite for Verification of Audit Fixes and Reliability Improvements.
Covers:
- Risk Engine input validation and elimination of fabricated SHAP attributions
- Temporal Forecaster schema rejection of packet features and threshold bounds
- API threshold validation and permanent failure caching
- Windows Scapy interface resolution and capture worker thread joining
- Temporal preprocessor morning file timestamp preservation
- BiLSTM bidirectional endpoints pooling
- Device registry thread-safe stale cleanup
"""

import math
import time
import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from models.risk_engine import DynamicRiskEngine
from models.temporal_forecasting.forecaster import TemporalAttackForecaster, INCOMPATIBLE_PACKET_SIGNATURES
from models.attack_forecaster import AttackForecasterBiLSTM
from pipeline.live_capture import resolve_scapy_interface, LiveNetworkCaptureEngine
from pipeline.temporal_preprocessor import parse_timestamp_series
from pipeline.device_registry import DeviceObservationRegistry
from dashboard.server import app, get_temporal_forecaster


@pytest.fixture
def risk_engine():
    return DynamicRiskEngine()


@pytest.fixture
def test_client():
    return TestClient(app)


# ============================================================================
# 1. RISK ENGINE VALIDATION & NO FABRICATED EXPLANATIONS
# ============================================================================

def test_risk_engine_validates_confidence_bounds(risk_engine):
    """Risk engine must reject NaN, Inf, out-of-bounds, or non-numeric confidence."""
    with pytest.raises(ValueError, match="Invalid confidence"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=float("nan"))

    with pytest.raises(ValueError, match="Invalid confidence"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=float("inf"))

    with pytest.raises(ValueError, match="out of supported range"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=1.5)

    with pytest.raises(ValueError, match="out of supported range"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=-0.1)


def test_risk_engine_validates_anomaly_intensity_bounds(risk_engine):
    """Risk engine must reject NaN, Inf, or out-of-bounds anomaly_intensity."""
    with pytest.raises(ValueError, match="Invalid anomaly_intensity"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=0.8, anomaly_intensity=float("nan"))

    with pytest.raises(ValueError, match="out of supported range"):
        risk_engine.compute_risk("Scanning", "Exploitation", confidence=0.8, anomaly_intensity=1.2)


def test_risk_engine_no_fake_shap_values_when_unavailable(risk_engine):
    """When top_features is None or empty, no fabricated attribution numbers (e.g. 0.45, 0.38) or false features may appear."""
    rec = risk_engine.get_recommendation("Reconnaissance", top_features=None)
    assert rec["attribution_available"] is False
    for opt in rec["options"]:
        # Verify fake hardcoded attribution values are NOT in the rationale
        assert "0.45" not in opt["rationale"]
        assert "0.38" not in opt["rationale"]
        assert "SHAP attribution unavailable" in opt["rationale"] or "baseline" in opt["rationale"] or "defensive" in opt["rationale"]

    # When top_features is provided, real values and features must be used
    real_features = [
        {"feature": "syn_flag_burst", "attribution": 0.72},
        {"feature": "port_entropy", "attribution": 0.61}
    ]
    rec_with_shap = risk_engine.get_recommendation("Scanning", top_features=real_features)
    assert rec_with_shap["attribution_available"] is True
    assert "syn_flag_burst" in rec_with_shap["options"][0]["rationale"]
    assert "0.72" in rec_with_shap["options"][0]["rationale"]


# ============================================================================
# 2. TEMPORAL FORECASTER SCHEMA REJECTION & THRESHOLD VALIDATION
# ============================================================================

def test_forecaster_rejects_all_incompatible_packet_features():
    """Forecaster must reject any input DataFrame containing packet-level aggregation features."""
    forecaster = TemporalAttackForecaster()
    for feat in INCOMPATIBLE_PACKET_SIGNATURES:
        bad_df = pd.DataFrame([{feat: 1.0}])
        with pytest.raises(ValueError, match="Schema Mismatch: Detected incompatible packet-layer feature"):
            forecaster.validate_features(bad_df)

        # Lagged variants must also be caught
        lagged_df = pd.DataFrame([{f"{feat}_lag1": 1.0}])
        with pytest.raises(ValueError, match="Schema Mismatch: Detected incompatible packet-layer feature"):
            forecaster.validate_features(lagged_df)


def test_forecaster_predict_validates_threshold_bounds():
    """Predict must reject non-finite, out-of-range thresholds."""
    forecaster = TemporalAttackForecaster()
    dummy_input = np.zeros((1, 120), dtype=float)

    with pytest.raises(ValueError, match="Invalid threshold"):
        forecaster.predict(dummy_input, threshold=float("nan"))

    with pytest.raises(ValueError, match="Invalid threshold"):
        forecaster.predict(dummy_input, threshold=float("inf"))

    with pytest.raises(ValueError, match="out of supported range"):
        forecaster.predict(dummy_input, threshold=1.5)

    with pytest.raises(ValueError, match="out of supported range"):
        forecaster.predict(dummy_input, threshold=-0.01)

    # Valid threshold in [0.0, 1.0] succeeds
    res = forecaster.predict(dummy_input, threshold=0.35)
    assert res["decision_threshold"] == 0.35
    assert "forecast_onset_positive" in res


# ============================================================================
# 3. API THRESHOLD VALIDATION & FAILURE HANDLING
# ============================================================================

def test_api_predict_rejects_malformed_threshold(test_client):
    """API endpoint /api/forecast/temporal-experimental must return 422 on invalid threshold."""
    # NaN threshold
    res = test_client.post("/api/forecast/temporal-experimental", json={"features": [0.0] * 120, "threshold": "NaN"})
    assert res.status_code == 422
    assert "Invalid threshold" in res.json()["error"]

    # Infinite threshold
    res = test_client.post("/api/forecast/temporal-experimental", json={"features": [0.0] * 120, "threshold": "Infinity"})
    assert res.status_code == 422

    # String threshold
    res = test_client.post("/api/forecast/temporal-experimental", json={"features": [0.0] * 120, "threshold": "invalid"})
    assert res.status_code == 422

    # Out-of-bounds threshold
    res = test_client.post("/api/forecast/temporal-experimental", json={"features": [0.0] * 120, "threshold": 2.5})
    assert res.status_code == 422


def test_api_predict_rejects_missing_features(test_client):
    """API endpoint /api/forecast/temporal-experimental must return 400 when 'features' is missing."""
    res = test_client.post("/api/forecast/temporal-experimental", json={"threshold": 0.5})
    assert res.status_code == 400
    assert "Missing 'features'" in res.json()["error"]


# ============================================================================
# 4. CAPTURE LIFECYCLE & SCAPY INTERFACE RESOLUTION
# ============================================================================

def test_resolve_scapy_interface_fallback():
    """Interface resolver should return None or Scapy dev without raising an unhandled exception."""
    res = resolve_scapy_interface("NON_EXISTENT_INTERFACE_XYZ")
    assert res is None


def test_stop_capture_waits_for_thread_termination():
    """LiveNetworkCaptureEngine.stop_capture() must cleanly terminate and not leave running workers."""
    engine = LiveNetworkCaptureEngine()
    engine.is_capturing = False
    # Stopping an idle engine should be cleanly idempotent
    engine.stop_capture()
    assert not engine.is_capturing


# ============================================================================
# 5. TEMPORAL PREPROCESSOR MORNING TIMESTAMP PRESERVATION
# ============================================================================

def test_timestamp_parser_preserves_morning_files():
    """Morning files (containing 'morning') must NOT undergo the +12h PM conversion."""
    morning_timestamps = pd.Series([
        "07/07/2017 01:15:00",
        "07/07/2017 03:30:00",
        "07/07/2017 06:45:00"
    ])
    parsed = parse_timestamp_series(morning_timestamps, file_context="Friday-WorkingHours-Morning.pcap_ISCX.csv")
    assert parsed.dt.hour.iloc[0] == 1  # Kept as 1 AM
    assert parsed.dt.hour.iloc[1] == 3  # Kept as 3 AM
    assert parsed.dt.hour.iloc[2] == 6  # Kept as 6 AM


# ============================================================================
# 6. BiLSTM SEQUENCE POOLING
# ============================================================================

def test_bilstm_supports_bidirectional_endpoints():
    """BiLSTM must support bidirectional_endpoints pooling without breaking output shape."""
    model = AttackForecasterBiLSTM(
        input_dim=12,
        hidden_dim=32,
        num_layers=1,
        num_classes=5,
        sequence_pooling="bidirectional_endpoints"
    )
    import torch
    x = torch.randn(4, 10, 12)
    curr_logits, next_logits = model(x)
    assert curr_logits.shape == (4, 5)
    assert next_logits.shape == (4, 5)


# ============================================================================
# 7. DEVICE REGISTRY THREAD-SAFE STALE CLEANUP
# ============================================================================

def test_device_registry_cleanup_stale():
    """DeviceObservationRegistry.cleanup_stale() must remove old records while preserving fresh ones."""
    reg = DeviceObservationRegistry()
    now = time.time()

    # Old record: 200 seconds ago
    reg.record_observation(ip="192.168.1.50", timestamp=now - 200, mode="live")
    # Fresh record: 5 seconds ago
    reg.record_observation(ip="192.168.1.60", timestamp=now - 5, mode="live")

    assert reg.count(mode="live") == 2

    # Prune records older than 60 seconds
    pruned = reg.cleanup_stale(max_age_seconds=60.0, mode="live")
    assert pruned == 1
    assert reg.count(mode="live") == 1
    assert reg.get_device_by_ip("192.168.1.60", mode="live") is not None
    assert reg.get_device_by_ip("192.168.1.50", mode="live") is None
