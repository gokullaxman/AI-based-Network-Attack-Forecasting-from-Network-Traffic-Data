"""
Automated Tests for Real Network Data Traffic Capture & Working Model Engine
Tests:
- LiveNetworkCaptureEngine (Socket capture, PCAP dissection, attack replay)
- Sliding window 12-feature calculation and BiLSTM working model inference
- Live capture FastAPI endpoints (/api/capture/status, start, stop, feed, upload-pcap, load-sample-pcap)
"""

import os
import time
import pytest
import numpy as np
from fastapi.testclient import TestClient

from pipeline.live_capture import LiveNetworkCaptureEngine, generate_sample_attack_pcap, CapturedPacket
from dashboard.server import app, process_sequence


@pytest.fixture
def client():
    return TestClient(app)


def test_live_capture_engine_initialization():
    """Verify capture engine initialization and baseline sequence."""
    engine = LiveNetworkCaptureEngine(max_packet_buffer=200, sequence_length=10)
    assert not engine.is_capturing
    status = engine.get_status()
    assert status["packet_counter"] == 0
    assert status["buffer_size"] == 0
    
    # Under strict gating, empty engine has no sequence yet
    window = engine.get_sliding_window()
    assert window is None


def test_live_capture_simulation_mode():
    """Verify testing simulation trace generation and quarantined feature updates."""
    engine = LiveNetworkCaptureEngine(max_packet_buffer=100, sequence_length=10)
    start_res = engine.start_capture("simulation")
    assert start_res["status"] == "started"
    assert engine.is_capturing
    
    time.sleep(1.2)
    
    status = engine.get_status()
    assert status["packet_counter"] > 0
    recent = engine.get_recent_packets(count=10)
    assert len(recent) > 0
    assert "src_ip" in recent[0]
    assert "dst_ip" in recent[0]
    assert "proto" in recent[0]
    
    stop_res = engine.stop_capture()
    assert stop_res["status"] == "stopped"
    assert not engine.is_capturing


def test_live_capture_connection_metadata_mode():
    """Verify host network connection / socket monitoring via connection_metadata mode."""
    engine = LiveNetworkCaptureEngine(max_packet_buffer=100, sequence_length=10)
    start_res = engine.start_capture("connection_metadata")
    assert start_res["status"] == "started"
    
    time.sleep(1.2)
    
    status = engine.get_status()
    assert status["is_capturing"]
    engine.stop_capture()


def test_pcap_parsing_and_working_model():
    """Verify parsing binary PCAP packets and feeding extracted features to BiLSTM working model."""
    sample_pcap = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_network_attack.pcap")
    if not os.path.exists(sample_pcap):
        generate_sample_attack_pcap(sample_pcap)
        
    engine = LiveNetworkCaptureEngine(sequence_length=10)
    with open(sample_pcap, "rb") as f:
        pcap_bytes = f.read()
        
    parsed = engine.parse_pcap_bytes(pcap_bytes)
    assert len(parsed) > 0
    assert isinstance(parsed[0], CapturedPacket)
    
    # Get window and evaluate through working BiLSTM model
    window = engine.get_sliding_window()
    assert window.shape == (10, 12)
    
    pred = process_sequence(window)
    assert "current_stage" in pred
    assert "predicted_next_stage" in pred
    assert "confidence" in pred
    assert "risk_score" in pred
    assert "risk_level" in pred
    assert 0 <= pred["confidence"] <= 100
    assert 0 <= pred["risk_score"] <= 100
    assert pred["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert len(pred["candidate_forecasts"]) == 5


def test_api_capture_endpoints(client):
    """Integration test for all capture API endpoints."""
    # 1. Status
    res = client.get("/api/capture/status")
    assert res.status_code == 200
    assert "is_capturing" in res.json()

    # 2. Interfaces
    res_if = client.get("/api/capture/interfaces")
    assert res_if.status_code == 200
    assert "interfaces" in res_if.json()

    # 3. Start capture
    res_start = client.post("/api/capture/start", json={"mode": "simulation"})
    assert res_start.status_code == 200
    assert res_start.json()["status"] in ("started", "already_running")

    time.sleep(1.2)

    # 4. Live Feed
    res_feed = client.get("/api/capture/feed?packet_count=20")
    assert res_feed.status_code == 200
    feed_data = res_feed.json()
    assert "telemetry" in feed_data
    assert "recent_packets" in feed_data
    assert "latest_features" in feed_data
    assert "prediction" in feed_data

    # 5. Stop capture
    res_stop = client.post("/api/capture/stop")
    assert res_stop.status_code == 200

    # 6. Load sample PCAP
    res_pcap = client.post("/api/capture/load-sample-pcap")
    assert res_pcap.status_code == 200
    pcap_data = res_pcap.json()
    assert pcap_data["filename"] == "sample_network_attack.pcap"

    # 7. Feed after PCAP load should now have 12 features and valid prediction
    res_feed_pcap = client.get("/api/capture/feed?packet_count=20")
    assert res_feed_pcap.status_code == 200
    pcap_feed = res_feed_pcap.json()
    assert pcap_feed["latest_features"] is not None
    assert len(pcap_feed["latest_features"]) == 12
    pred = pcap_feed["prediction"]
    # Phase G: Model readiness is independent of capture readiness.
    # The production BiLSTM is not validated on authentic packet data, so prediction is gated.
    assert pred["prediction_available"] is False
    assert pred["status"] == "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"
    assert "current_stage" in pred
    assert "predicted_next_stage" in pred
    assert "formatted_output" in pred
    assert "recommendation" in pred
    assert pcap_data["packets_parsed"] > 0
    assert "prediction" in pcap_data
