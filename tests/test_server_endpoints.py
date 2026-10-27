"""
Unit Tests for Phase 4: Server API Endpoints & Model Inference Gating
Tests:
1. Live mode is default.
2. Missing Npcap produces explicit capture error.
3. Insufficient flow steps prevent inference (prediction_available: False).
4. Incorrect feature dimensions prevent inference.
5. NaN and infinite values are rejected.
6. Valid input reaches inference only when model and preprocessing are available.
7. Invalid or unsupported mode selection is rejected.
8. PCAP data cannot enter live registry.
9. Simulation cannot contaminate live telemetry.
10. Device endpoint returns empty list when no devices are observed.
11. Capture health never claims packets were captured when count is zero.
12. Existing SOC endpoint contracts remain compatible.
"""

import os
import time
import pytest
import numpy as np
from fastapi.testclient import TestClient

from dashboard.server import app, process_sequence, capture_engine, soc_manager
from pipeline.live_capture import CapturedPacket


@pytest.fixture
def client():
    # Stop background sniffing and clear buffers before test runs
    capture_engine.stop_capture()
    capture_engine.clear_buffer()
    if capture_engine.device_registry:
        capture_engine.device_registry.clear()
    soc_manager.clear()
    return TestClient(app)


def test_live_mode_is_default(client):
    """Test 1: Live mode is default operating mode on server."""
    res = client.get("/api/capture/health")
    assert res.status_code == 200
    data = res.json()
    assert data["capture_mode"] == "live"


def test_missing_npcap_produces_explicit_error(client):
    """Test 2: Missing Npcap produces explicit error status and recovery instruction."""
    res = client.get("/api/capture/health")
    assert res.status_code == 200
    data = res.json()
    diag = data["npcap_diagnostics"]
    assert "installed" in diag
    if not diag["installed"]:
        assert data["capture_status"] in ("INITIALIZING", "CAPTURE ERROR", "STOPPED", "MONITOR NOT DETECTED")
        assert diag["status"] == "NOT_INSTALLED"
        assert "recovery_instruction" in diag
        assert diag["recovery_instruction"] is not None
    else:
        assert data["capture_status"] in ("INITIALIZING", "CAPTURE ERROR", "STOPPED", "MONITOR NOT DETECTED", "NO PACKETS OBSERVED", "CAPTURING REAL PACKETS")
        assert diag["status"] == "READY"


def test_insufficient_flow_steps_prevents_inference():
    """Test 3: Insufficient flow steps (< 10) prevents inference and returns prediction_available=False."""
    # Test with None
    res_none = process_sequence(None)
    assert not res_none["prediction_available"]
    assert "insufficient validated real traffic data" in res_none["reason"].lower()
    assert res_none["risk_score"] is None
    assert res_none["confidence"] is None

    # Test with 5 steps
    five_steps = np.ones((5, 12), dtype=np.float32)
    res_five = process_sequence(five_steps)
    assert not res_five["prediction_available"]
    assert "5/10" in res_five["reason"]
    assert res_five["risk_score"] is None
    assert res_five["confidence"] is None


def test_incorrect_feature_dimensions_prevent_inference():
    """Test 4: Incorrect feature dimensions (e.g. 10 features instead of 12) prevents inference."""
    wrong_dim = np.ones((10, 8), dtype=np.float32)
    res = process_sequence(wrong_dim)
    assert not res["prediction_available"]
    assert res["status"] == "INVALID_SCHEMA"
    assert "Expected 12" in res["reason"]


def test_nan_and_infinite_values_rejected():
    """Test 5: NaN and Infinite values in feature sequence are rejected safely."""
    nan_seq = np.ones((10, 12), dtype=np.float32)
    nan_seq[3, 2] = np.nan
    res_nan = process_sequence(nan_seq)
    assert not res_nan["prediction_available"]
    assert res_nan["status"] == "INVALID_VALUES"

    inf_seq = np.ones((10, 12), dtype=np.float32)
    inf_seq[7, 5] = np.inf
    res_inf = process_sequence(inf_seq)
    assert not res_inf["prediction_available"]
    assert res_inf["status"] == "INVALID_VALUES"


def test_valid_input_reaches_inference():
    """Test 6: Valid 10-step, 12-feature input executes inference and returns structured predictions."""
    valid_seq = np.array([
        [2.5, 25.0, 3.0, 0.25, 4.0, 0.85, 0.15, 0.05, 0.40, 15.0, 0.20, 2.1]
        for _ in range(10)
    ], dtype=np.float32)

    res = process_sequence(valid_seq)
    assert res["prediction_available"]
    assert res["status"] == "VALID"
    assert "current_stage" in res
    assert "predicted_next_stage" in res
    assert res["confidence"] is not None
    assert 0 <= res["confidence"] <= 100
    assert res["risk_score"] is not None
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert len(res["candidate_forecasts"]) == 5


def test_invalid_mode_selection_rejected(client):
    """Test 7: Unsupported mode selection is rejected with HTTP 400."""
    res = client.post("/api/mode/select", json={"mode": "unsupported_magic_mode"})
    assert res.status_code == 400
    assert "Unsupported mode" in res.json()["detail"]


def test_pcap_data_cannot_enter_live_registry(client):
    """Test 8: PCAP observations are isolated in pcap mode and do not contaminate live registry."""
    # Record packet under pcap mode
    pcap_pkt = CapturedPacket(
        pkt_id=1,
        timestamp=time.time(),
        src_ip="172.16.50.2",
        dst_ip="172.16.50.1",
        sport=1234,
        dport=80,
        proto="TCP",
        length=60,
        observation_source="Offline PCAP File (Historical)"
    )
    capture_engine.device_registry.record_packet(pcap_pkt, mode="pcap")

    # Query live devices endpoint
    res_live = client.get("/api/soc/devices?mode=live")
    assert res_live.status_code == 200
    assert res_live.json()["count"] == 0

    # Query pcap devices endpoint
    res_pcap = client.get("/api/soc/devices?mode=pcap")
    assert res_pcap.status_code == 200
    assert res_pcap.json()["count"] == 2


def test_simulation_cannot_contaminate_live_telemetry(client):
    """Test 9: Simulation data cannot contaminate live overview or topology."""
    sim_pkt = CapturedPacket(
        pkt_id=99,
        timestamp=time.time(),
        src_ip="192.168.1.185",
        dst_ip="10.0.0.45",
        sport=55555,
        dport=80,
        proto="TCP",
        length=64,
        observation_source="Simulation Engine (Test Only)"
    )
    capture_engine.device_registry.record_packet(sim_pkt, mode="simulation")

    res_topo = client.get("/api/soc/topology")
    assert res_topo.status_code == 200
    assert res_topo.json()["node_count"] == 0


def test_device_endpoint_empty_when_no_devices(client):
    """Test 10: Device endpoint returns an empty list when no devices are observed."""
    res = client.get("/api/soc/devices")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 0
    assert data["devices"] == []


def test_capture_health_never_claims_fake_packets(client):
    """Test 11: Capture health reports actual_packets_captured=0 when no packets have arrived."""
    res = client.get("/api/capture/health")
    assert res.status_code == 200
    data = res.json()
    assert data["actual_packets_captured"] == 0
    assert data["last_packet_timestamp"] is None


def test_existing_soc_endpoint_contracts_compatible(client):
    """Test 12: Existing SOC overview and threat logs API contracts remain preserved."""
    # 1. Overview
    res_ov = client.get("/api/soc/overview")
    assert res_ov.status_code == 200
    ov = res_ov.json()
    assert "traffic_counts" in ov
    assert "network_stats" in ov
    assert "threat_stats" in ov
    assert "severity_breakdown" in ov
    assert "time_series" in ov
    assert "active_alert" in ov

    # 2. Threat logs
    res_logs = client.get("/api/soc/threat-logs")
    assert res_logs.status_code == 200
    assert "count" in res_logs.json()
    assert "logs" in res_logs.json()

    # 3. Interfaces
    res_if = client.get("/api/capture/interfaces")
    assert res_if.status_code == 200
    assert "interfaces" in res_if.json()
    assert len(res_if.json()["interfaces"]) > 0
