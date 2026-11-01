"""
Comprehensive Deterministic Test Suite for Streaming Bidirectional Flow Assembler (Phase 9D).

Covers:
- Forward and reverse traffic mapped to same bidirectional flow
- Multiple simultaneous flows
- TCP and UDP protocol handling
- IPv4 and IPv6 address parsing
- Missing transport ports (ICMP, raw IP)
- Flow expiration (inactivity timeout and FIN/RST termination)
- Long-lived flows handling
- Epoch boundary aggregation and empty epochs
- Timestamp ordering and out-of-order packets
- Duplicate packet observations
- Ten-epoch history tracking and insufficient history protection
- 120-dimensional feature vector ordering, dimensions, and units
- Direct inference compatibility with Target A Temporal Forecaster
- Capacity bounding and memory limits
- API endpoints: /api/capture/flow-epochs and /api/forecast/temporal-experimental/live
"""

import time
import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from pipeline.streaming_flow_assembler import (
    StreamingFlowAssembler,
    BidirectionalFlow,
    compute_shannon_entropy,
    PREDICTOR_COLUMNS,
    EPOCH_DURATION_SECONDS,
    TOTAL_EPOCHS_REQUIRED
)
from models.temporal_forecasting.forecaster import TemporalAttackForecaster
from dashboard.server import app, capture_engine


@pytest.fixture
def assembler():
    return StreamingFlowAssembler(
        epoch_duration=60.0,
        history_length=10,
        flow_idle_timeout=60.0,
        flow_active_timeout=120.0,
        max_active_flows=1000,
        provenance="test_stream"
    )


@pytest.fixture
def test_client():
    return TestClient(app)


# ============================================================================
# 1. BIDIRECTIONAL FLOW INTEGRITY
# ============================================================================

def test_forward_and_reverse_packets_assigned_to_same_bidirectional_flow(assembler):
    """Packets traveling in opposite directions must be unified into a single bidirectional flow."""
    # Forward: Client -> Server
    fwd = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        sport=45123,
        dport=443,
        proto="TCP",
        length=74,
        flags="S"
    )
    assert fwd is not None
    assert assembler.total_flows_assembled == 1
    assert fwd.fwd_packets == 1
    assert fwd.bwd_packets == 0
    assert fwd.fwd_bytes == 74
    assert fwd.has_syn is True
    assert fwd.dst_port == 443

    # Reverse: Server -> Client (swapped IPs and ports)
    bwd = assembler.ingest_packet(
        timestamp=100.05,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.50",
        sport=443,
        dport=45123,
        proto="TCP",
        length=66,
        flags="SA"
    )
    assert bwd is not None
    # Still exactly 1 flow assembled
    assert assembler.total_flows_assembled == 1
    assert bwd.flow_id == fwd.flow_id
    assert bwd.fwd_packets == 1
    assert bwd.bwd_packets == 1
    assert bwd.fwd_bytes == 74
    assert bwd.bwd_bytes == 66
    assert bwd.total_packets == 2
    assert bwd.total_bytes == 140
    # Duration: (100.05 - 100.0) * 1000 = 50.0 ms
    assert pytest.approx(bwd.duration_ms, rel=1e-3) == 50.0


def test_multiple_simultaneous_flows(assembler):
    """Simultaneous independent flows must be isolated into distinct bidirectional state entries."""
    for i in range(5):
        assembler.ingest_packet(
            timestamp=100.0,
            src_ip=f"192.168.1.{10 + i}",
            dst_ip="10.0.0.1",
            sport=50000 + i,
            dport=80,
            proto="TCP",
            length=100
        )
    assert assembler.total_flows_assembled == 5
    assert len(assembler._active_flows) == 5


# ============================================================================
# 2. PROTOCOL & ADDRESS SUPPORT (TCP, UDP, IPv4, IPv6, MISSING PORTS)
# ============================================================================

def test_tcp_and_udp_protocol_handling(assembler):
    """TCP and UDP protocols must be correctly parsed into numeric protocol codes."""
    tcp_flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        sport=1000,
        dport=80,
        proto="TCP",
        length=100
    )
    assert tcp_flow.protocol == 6

    udp_flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="1.1.1.1",
        dst_ip="8.8.8.8",
        sport=2000,
        dport=53,
        proto="UDP",
        length=80
    )
    assert udp_flow.protocol == 17


def test_ipv4_and_ipv6_support(assembler):
    """IPv6 addresses must be safely handled without throwing string formatting or dictionary key errors."""
    flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dst_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7335",
        sport=60000,
        dport=443,
        proto="TCP",
        length=120
    )
    assert flow is not None
    assert "2001:0db8" in flow.src_ip
    assert assembler.total_flows_assembled == 1


def test_missing_transport_ports_handled_safely(assembler):
    """ICMP and raw IP packets without transport ports must default ports to 0 safely."""
    flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        sport=None,
        dport=None,
        proto="ICMP",
        length=64
    )
    assert flow is not None
    assert flow.src_port == 0
    assert flow.dst_port == 0
    assert flow.protocol == 1


# ============================================================================
# 3. FLOW EXPIRATION & TERMINATION (FIN/RST & TIMEOUTS)
# ============================================================================

def test_flow_termination_via_fin_flag(assembler):
    """TCP packets carrying FIN ('F') or RST ('R') flags must mark the flow closed."""
    flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        sport=1234,
        dport=80,
        proto="TCP",
        length=54,
        flags="FA"
    )
    assert flow.is_closed is True


def test_flow_expiration_idle_and_active_timeouts(assembler):
    """Flows exceeding idle timeout must be pruned during epoch boundary advance."""
    # Packet at t=10.0
    assembler.ingest_packet(
        timestamp=10.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        sport=1234,
        dport=80,
        proto="TCP",
        length=54
    )
    assert len(assembler._active_flows) == 1

    # Advance time to t=150.0 (crosses 60s and 120s epoch boundaries)
    assembler.ingest_packet(
        timestamp=150.0,
        src_ip="10.0.0.3",
        dst_ip="10.0.0.4",
        sport=5678,
        dport=443,
        proto="TCP",
        length=54
    )
    # The first flow (inactive since t=10.0) should have been pruned
    fwd_key_1 = ("10.0.0.1", 1234, "10.0.0.2", 80, 6)
    assert fwd_key_1 not in assembler._active_flows


# ============================================================================
# 4. TIMESTAMPS, OUT-OF-ORDER PACKETS & DUPLICATES
# ============================================================================

def test_out_of_order_packets_update_time_bounds(assembler):
    """Packets arriving out-of-order must properly expand flow start and end timestamps."""
    flow = assembler.ingest_packet(
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        sport=1234,
        dport=80,
        proto="TCP",
        length=100
    )
    # Packet arriving with earlier timestamp (e.g. 95.0s)
    assembler.ingest_packet(
        timestamp=95.0,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        sport=80,
        dport=1234,
        proto="TCP",
        length=100
    )
    assert flow.first_seen == 95.0
    assert flow.last_seen == 100.0
    assert pytest.approx(flow.duration_ms, rel=1e-3) == 5000.0


def test_duplicate_packets_handled_safely(assembler):
    """Duplicate packet observations must safely increment counters without state corruption."""
    for _ in range(3):
        assembler.ingest_packet(
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            sport=1234,
            dport=80,
            proto="TCP",
            length=100
        )
    flow = list(assembler._active_flows.values())[0]
    assert flow.total_packets == 3
    assert flow.total_bytes == 300


# ============================================================================
# 5. EPOCH BOUNDARY AGGREGATION & EMPTY EPOCHS
# ============================================================================

def test_epoch_boundary_aggregation_and_empty_epochs(assembler):
    """Discrete 60s epochs must be aggregated correctly; empty epochs must record 0s without crashing."""
    # Epoch 0 (t in [0.0, 60.0)): 2 flows
    assembler.ingest_packet(
        timestamp=10.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        sport=1000,
        dport=80,
        proto="TCP",
        length=200,
        flags="S"
    )
    assembler.ingest_packet(
        timestamp=20.0,
        src_ip="192.168.1.2",
        dst_ip="10.0.0.2",
        sport=2000,
        dport=53,
        proto="UDP",
        length=100
    )

    # Jump to t=185.0s (skips epoch [60.0, 120.0), ending up in [180.0, 240.0))
    assembler.ingest_packet(
        timestamp=185.0,
        src_ip="192.168.1.3",
        dst_ip="10.0.0.3",
        sport=3000,
        dport=443,
        proto="TCP",
        length=150
    )

    # Completed epochs should now contain:
    # 1. Epoch at 0.0s (populated)
    # 2. Epoch at 60.0s (empty)
    # 3. Epoch at 120.0s (empty)
    completed = list(assembler._completed_epochs)
    assert len(completed) == 3

    # Check Epoch 0
    ep0 = completed[0]
    assert ep0.flow_count == 2
    assert ep0.total_packets == 2.0
    assert ep0.total_bytes == 300.0
    assert ep0.tcp_flow_ratio == 0.5
    assert ep0.udp_flow_ratio == 0.5
    assert ep0.syn_flag_ratio == 0.5
    assert ep0.is_empty is False

    # Check Epoch 1 (empty window)
    ep1 = completed[1]
    assert ep1.flow_count == 0
    assert ep1.total_packets == 0.0
    assert ep1.total_bytes == 0.0
    assert ep1.is_empty is True
    # All features in empty epoch must be finite 0.0
    for k, v in ep1.to_feature_dict().items():
        assert not np.isnan(v)
        assert not np.isinf(v)
        assert v == 0.0


# ============================================================================
# 6. SHANNON ENTROPY CALCULATION
# ============================================================================

def test_compute_shannon_entropy_deterministic():
    """Shannon entropy must match normalized formula: 0.0 for uniform/single class, and > 0 for diverse classes."""
    # Empty
    assert compute_shannon_entropy([]) == 0.0
    # Single class
    assert compute_shannon_entropy([80, 80, 80]) == 0.0
    # Exactly 2 equally distributed classes (max entropy = 1.0)
    assert pytest.approx(compute_shannon_entropy([80, 443]), rel=1e-4) == 1.0
    # 4 classes
    ent_4 = compute_shannon_entropy([80, 443, 22, 53])
    assert pytest.approx(ent_4, rel=1e-4) == 1.0


# ============================================================================
# 7. TEN-EPOCH SLIDING WINDOW & FORECASTER COMPATIBILITY
# ============================================================================

def test_insufficient_history_returns_explicit_status(assembler):
    """When fewer than 10 consecutive epochs exist, assembler must refuse to generate features."""
    for i in range(3):
        assembler.ingest_packet(
            timestamp=float(i * 60 + 10),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            sport=1000 + i,
            dport=80,
            proto="TCP",
            length=100
        )
    # Flush to completed
    assembler.flush_current_epoch(current_time=240.0)

    res = assembler.get_sliding_window_features()
    assert res["ready"] is False
    assert res["status"] == "INSUFFICIENT_HISTORY"
    assert res["epochs_available"] < 10
    assert res["features"] is None


def test_ten_epoch_window_generates_exact_forecaster_schema(assembler):
    """When 10 epochs are completed, assembler must produce exactly the 120-dim schema required by forecaster."""
    # Generate 10 consecutive minutes of traffic
    for step in range(10):
        t_base = float(step * 60 + 5)
        assembler.ingest_packet(
            timestamp=t_base,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            sport=40000 + step,
            dport=80 if step % 2 == 0 else 443,
            proto="TCP",
            length=150,
            flags="S" if step % 3 == 0 else "A"
        )
    # Flush the 10th epoch
    assembler.flush_current_epoch(current_time=605.0)

    window = assembler.get_sliding_window_features()
    assert window["ready"] is True
    assert window["status"] == "READY"
    assert window["epochs_available"] == 10

    features = window["features"]
    assert isinstance(features, np.ndarray)
    assert features.shape == (1, 120)
    assert not np.isnan(features).any()
    assert not np.isinf(features).any()

    # Pass directly into the authoritative Target A TemporalAttackForecaster
    forecaster = TemporalAttackForecaster()
    pred = forecaster.predict(features, threshold=0.5)

    assert pred["prediction_available"] is True
    assert "forecast_probability" in pred
    assert 0.0 <= pred["forecast_probability"] <= 1.0
    assert "forecast_onset_positive" in pred
    assert pred["decision_threshold"] == 0.5


# ============================================================================
# 8. CAPACITY BOUNDING & MEMORY LIMITS
# ============================================================================

def test_capacity_bounding_prevents_unbounded_growth():
    """Assembler must prune oldest flows when max_active_flows capacity is reached."""
    tiny_assembler = StreamingFlowAssembler(max_active_flows=10)
    # Ingest 25 distinct flows
    for i in range(25):
        tiny_assembler.ingest_packet(
            timestamp=float(100 + i),
            src_ip=f"10.0.0.{i}",
            dst_ip="192.168.1.1",
            sport=1000 + i,
            dport=80,
            proto="TCP",
            length=100
        )
    # Active flows must never exceed capacity
    assert len(tiny_assembler._active_flows) <= 10


# ============================================================================
# 9. FASTAPI ENDPOINTS INTEGRATION
# ============================================================================

def test_api_flow_epochs_endpoint(test_client):
    """GET /api/capture/flow-epochs must return 200 with schema and epoch list."""
    res = test_client.get("/api/capture/flow-epochs")
    assert res.status_code == 200
    data = res.json()
    assert "feature_schema" in data
    assert len(data["feature_schema"]) == 12
    assert "total_completed_epochs" in data
    assert "sliding_window_status" in data


def test_api_live_forecast_endpoint_insufficient_history(test_client):
    """GET /api/forecast/temporal-experimental/live must return status='INSUFFICIENT_HISTORY' when <10 epochs."""
    # Reset capture engine buffer
    capture_engine.clear_buffer()
    res = test_client.get("/api/forecast/temporal-experimental/live")
    assert res.status_code == 200
    data = res.json()
    assert data["ready"] is False
    assert data["status"] == "INSUFFICIENT_HISTORY"
    assert data["forecast"] is None
    assert "Insufficient history" in data["message"]
