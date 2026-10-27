"""
Unit Tests for Model Readiness and Forecasting Gates
Tests:
- Capture readiness does not imply model readiness
- Unvalidated models cannot issue genuine forecasts on real network traffic
- System returns: FORECASTING MODEL NOT VALIDATED FOR THIS DATA
- Unknown labels remain unknown (no default BENIGN assumptions)
- API endpoints report truthful empty states and error messages
"""

import pytest
import numpy as np
from fastapi.testclient import TestClient

from dashboard.server import app, process_sequence, capture_engine


@pytest.fixture
def client():
    return TestClient(app)


def test_real_data_gating_reports_unvalidated_model():
    """Verify that passing authentic real network data to process_sequence triggers strict Phase G gating."""
    # Create valid 10x12 matrix from real observations
    real_seq = np.ones((10, 12), dtype=np.float32)

    # When is_real_data is True, inference must be gated
    res = process_sequence(real_seq, is_real_data=True)

    assert res["prediction_available"] is False
    assert res["status"] == "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"
    assert res["model_readiness"] == "NOT_VALIDATED_FOR_REAL_DATA"
    assert "not validated" in res["reason"].lower()
    assert res["formatted_output"] == "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"
    assert res["risk_level"] == "UNAVAILABLE"
    assert res["confidence"] is None
    assert res["current_stage_idx"] is None
    assert res["candidate_forecasts"] == []


def test_capture_readiness_does_not_imply_model_readiness(client):
    """
    Verify that an active packet capture does NOT automatically enable model forecasting.
    Capture may be operational while forecasting remains gated.
    """
    res = client.get("/api/soc/overview")
    assert res.status_code == 200
    data = res.json()

    # Model readiness must be UNAVAILABLE or MODEL NOT VALIDATED
    threat = data["threat_stats"]
    assert threat["prediction_available"] is False
    assert threat["risk_level"] == "UNAVAILABLE"
    assert "insufficient" in threat["reason"].lower() or "not validated" in threat["reason"].lower()


def test_temporal_windows_endpoint_reports_model_unvalidated(client):
    """Verify /api/capture/temporal-windows reports schema, aggregation health, and unvalidated model status."""
    res = client.get("/api/capture/temporal-windows")
    assert res.status_code == 200
    data = res.json()

    assert "feature_schema" in data
    assert len(data["feature_schema"]) == 13
    assert data["aggregation_interval_seconds"] == 60.0
    assert data["model_readiness"] == "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"
    assert "missing_value_policy" in data


def test_captures_manifest_endpoint(client):
    """Verify /api/captures/manifest returns registered capture history."""
    res = client.get("/api/captures/manifest")
    assert res.status_code == 200
    data = res.json()
    assert "total_captures" in data
    assert "captures" in data
    assert isinstance(data["captures"], list)
