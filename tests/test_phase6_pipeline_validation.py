"""
Phase 6: End-to-End Data Pipeline and AI Inference Validation Test Suite
Tests are separated into three strict categories:
- Category A: Unit tests (parsing, feature math, gating, scaling, output interpretation)
- Category B: Offline trace tests (sample PCAP parsing, timestamp preservation, provenance)
- Category C: Model compatibility tests (weights, scaler, forward pass, SHAP)
"""

import os
import io
import time
import math
import pytest
import numpy as np
import torch
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw

from pipeline.feature_extractor import FEATURE_NAMES, FlowFeatureExtractor
from pipeline.live_capture import (
    LiveNetworkCaptureEngine,
    CapturedPacket,
    generate_sample_attack_pcap
)
from pipeline.device_registry import DeviceObservationRegistry
from models.attack_forecaster import AttackForecasterBiLSTM
from models.risk_engine import DynamicRiskEngine
from models.shap_explainer import AttackForecasterSHAPExplainer
from dashboard.server import process_sequence, model, scaler, background_data, shap_explainer


# ==============================================================================
# CATEGORY A: Unit Tests
# Controlled, explicitly labelled test fixtures verifying parsing, math, gating
# ==============================================================================

def test_unit_feature_names_and_ordering():
    """Verify the exact 12-feature schema, naming, and position."""
    expected_12_features = [
        "conn_frequency",
        "packet_rate",
        "dst_ip_fanout",
        "src_dst_entropy",
        "port_diversity",
        "well_known_port_ratio",
        "host_sweep_rate",
        "icmp_arp_ratio",
        "service_probe_rate",
        "targeted_query_volume",
        "iat_jitter",
        "burstiness_index"
    ]
    assert len(FEATURE_NAMES) == 12
    assert FEATURE_NAMES == expected_12_features


def test_unit_packet_parsing_multiproto():
    """Verify Scapy packet parsing across IPv4, IPv6, TCP, UDP, ICMP, and ARP."""
    engine = LiveNetworkCaptureEngine(sequence_length=10)

    # 1. TCP IPv4 packet with SYN
    sc_tcp = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
             IP(src="192.168.1.10", dst="192.168.1.20") / \
             TCP(sport=54321, dport=80, flags="S") / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    sc_tcp.time = 1000.0

    engine._process_genuine_packet(sc_tcp)
    assert len(engine.packets_buffer) == 1
    pkt = engine.packets_buffer[-1]
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "192.168.1.20"
    assert pkt.sport == 54321
    assert pkt.dport == 80
    assert pkt.proto == "TCP"
    assert "S" in pkt.flags
    assert pkt.payload_len == len(b"GET / HTTP/1.1\r\n\r\n")

    # 2. UDP IPv4 packet
    sc_udp = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=40000, dport=53)
    sc_udp.time = 1000.1
    engine._process_genuine_packet(sc_udp)
    pkt_udp = engine.packets_buffer[-1]
    assert pkt_udp.proto == "UDP"
    assert pkt_udp.dport == 53

    # 3. ICMP packet
    sc_icmp = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8, code=0)
    sc_icmp.time = 1000.2
    engine._process_genuine_packet(sc_icmp)
    pkt_icmp = engine.packets_buffer[-1]
    assert pkt_icmp.proto == "ICMP"

    # 4. ARP packet
    sc_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01", hwdst="ff:ff:ff:ff:ff:ff")
    sc_arp.time = 1000.3
    engine._process_genuine_packet(sc_arp)
    pkt_arp = engine.packets_buffer[-1]
    assert pkt_arp.proto == "ARP"
    assert pkt_arp.src_ip == "192.168.1.10"

    # 5. IPv6 packet
    sc_ipv6 = Ether(src="aa:bb:cc:dd:ee:01", dst="33:33:00:00:00:02") / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=5000, dport=443)
    sc_ipv6.time = 1000.4
    engine._process_genuine_packet(sc_ipv6)
    pkt_ipv6 = engine.packets_buffer[-1]
    assert pkt_ipv6.src_ip == "fe80::1"
    assert pkt_ipv6.dst_ip == "fe80::2"
    assert pkt_ipv6.dport == 443


def test_unit_feature_aggregation_numerical_stability():
    """Verify that _aggregate_and_step_features is free of zero division, NaN, and Inf."""
    engine = LiveNetworkCaptureEngine(sequence_length=10)

    # Edge Case 1: 5 identical packets at identical timestamp (t_span = 0)
    packets_zero_span = [
        CapturedPacket(
            pkt_id=i, timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            sport=1000, dport=80, proto="TCP", length=64, flags="S"
        )
        for i in range(5)
    ]
    engine._aggregate_and_step_features(packets_zero_span)
    assert len(engine.flow_sequence) == 1
    feat1 = engine.flow_sequence[-1]
    assert np.all(np.isfinite(feat1)), "Features must be finite even when timestamps are identical"
    assert np.all(feat1 >= 0), "Features must be non-negative"
    assert feat1.dtype == np.float32

    # Edge Case 2: Diverse packets with ICMP, high ports, multiple targets
    packets_diverse = [
        CapturedPacket(pkt_id=1, timestamp=101.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1000, dport=80, proto="TCP", length=100),
        CapturedPacket(pkt_id=2, timestamp=101.1, src_ip="10.0.0.1", dst_ip="10.0.0.3", sport=1001, dport=443, proto="TCP", length=200),
        CapturedPacket(pkt_id=3, timestamp=101.3, src_ip="10.0.0.1", dst_ip="10.0.0.4", sport=0, dport=0, proto="ICMP", length=64),
        CapturedPacket(pkt_id=4, timestamp=101.6, src_ip="10.0.0.1", dst_ip="10.0.0.5", sport=0, dport=0, proto="ARP", length=42),
        CapturedPacket(pkt_id=5, timestamp=102.0, src_ip="10.0.0.1", dst_ip="10.0.0.6", sport=50000, dport=8080, proto="TCP", length=500, flags="SYN")
    ]
    engine._aggregate_and_step_features(packets_diverse)
    assert len(engine.flow_sequence) == 2
    feat2 = engine.flow_sequence[-1]
    assert np.all(np.isfinite(feat2))
    assert feat2[2] == 5.0, "dst_ip_fanout should be 5 distinct destinations"
    assert feat2[7] == 0.4, "icmp_arp_ratio should be 2/5 = 0.4"
    assert feat2[8] > 0.0, "service_probe_rate should reflect the SYN packet"


def test_unit_sequence_fifo_ordering():
    """Verify that flow_sequence adheres to strict chronological FIFO sliding window of length 10."""
    engine = LiveNetworkCaptureEngine(sequence_length=10)
    assert engine.get_sliding_window() is None, "Window must be None when < 10 flow steps exist"

    # Add 12 distinct steps
    for step in range(12):
        fake_pkts = [
            CapturedPacket(
                pkt_id=step * 5 + i,
                timestamp=1000.0 + step + (i * 0.1),
                src_ip="192.168.1.1",
                dst_ip=f"10.0.0.{step + 1}",
                sport=10000 + step,
                dport=80,
                proto="TCP",
                length=64 + step
            )
            for i in range(5)
        ]
        engine._aggregate_and_step_features(fake_pkts)

    window = engine.get_sliding_window()
    assert window is not None
    assert window.shape == (10, 12)
    # The oldest 2 steps (steps 0 and 1) should have been evicted
    # Window steps should correspond to steps 2 through 11
    assert len(engine.flow_sequence) == 10


def test_unit_inference_gating_comprehensive():
    """Verify that process_sequence strictly gates model inference on invalid or insufficient input."""
    # 1. None input
    res_none = process_sequence(None)
    assert not res_none["prediction_available"]
    assert res_none["status"] == "UNAVAILABLE"

    # 2. Insufficient sequence steps (e.g. 5 steps < 10)
    res_short = process_sequence(np.zeros((5, 12), dtype=np.float32))
    assert not res_short["prediction_available"]
    assert res_short["status"] == "INSUFFICIENT_DATA"

    # 3. Invalid feature count (e.g. 10 steps of 8 features)
    res_wrong_feat = process_sequence(np.zeros((10, 8), dtype=np.float32))
    assert not res_wrong_feat["prediction_available"]
    assert res_wrong_feat["status"] == "INVALID_SCHEMA"

    # 4. Non-finite values (NaN)
    nan_arr = np.ones((10, 12), dtype=np.float32)
    nan_arr[3, 4] = np.nan
    res_nan = process_sequence(nan_arr)
    assert not res_nan["prediction_available"]
    assert res_nan["status"] == "INVALID_VALUES"

    # 5. Non-finite values (Inf)
    inf_arr = np.ones((10, 12), dtype=np.float32)
    inf_arr[2, 1] = np.inf
    res_inf = process_sequence(inf_arr)
    assert not res_inf["prediction_available"]
    assert res_inf["status"] == "INVALID_VALUES"


def test_unit_risk_engine_scoring_and_recommendations():
    """Verify that DynamicRiskEngine produces bounded scores and defensive options for all stages."""
    risk_eng = DynamicRiskEngine()

    stages = ["Reconnaissance", "Scanning", "Enumeration", "Exploitation", "Intrusion"]
    for curr in stages:
        for nxt in stages:
            score, level = risk_eng.compute_risk(
                current_stage=curr,
                predicted_next_stage=nxt,
                confidence=0.85,
                anomaly_intensity=0.6
            )
            assert 5 <= score <= 100, f"Risk score {score} out of bounds for {curr} -> {nxt}"
            assert level in ("LOW", "MEDIUM", "HIGH")

            rec = risk_eng.get_recommendation(nxt, top_features=[{"feature": "conn_frequency", "attribution": 0.4}])
            assert "title" in rec
            assert "options" in rec
            assert len(rec["options"]) >= 2
            for opt in rec["options"]:
                assert "priority" in opt
                assert "action" in opt
                assert "rationale" in opt


# ==============================================================================
# CATEGORY B: Offline Trace Tests
# Verifying PCAP parsing, timestamp preservation, and provenance labeling
# ==============================================================================

def test_offline_pcap_trace_provenance_and_timestamps():
    """
    DISSECTION OF OFFLINE PCAP TRACE: data/sample_network_attack.pcap
    Provenance: Synthetic test fixture generated via Scapy packet crafting (generate_sample_attack_pcap).
    """
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "sample_network_attack.pcap"
    )
    if not os.path.exists(pcap_path):
        generate_sample_attack_pcap(pcap_path)

    engine = LiveNetworkCaptureEngine(sequence_length=10)
    with open(pcap_path, "rb") as f:
        pcap_bytes = f.read()

    parsed = engine.parse_pcap_bytes(pcap_bytes)
    assert len(parsed) == 37, "Expected exactly 37 crafted packets in sample_network_attack.pcap"

    # Check that provenance is strictly labeled as Historical PCAP
    for pkt in parsed:
        assert pkt.observation_source == "Offline PCAP File (Historical)"
        assert pkt.attack_hint == "Historical PCAP Record"

    # Verify timestamps are preserved and monotonically non-decreasing
    timestamps = [p.timestamp for p in parsed]
    for i in range(1, len(timestamps)):
        assert timestamps[i] >= timestamps[i - 1], "PCAP packet timestamps must be monotonic"


def test_offline_pcap_device_attribution():
    """Verify that offline PCAP parsing records all observed endpoints into the device registry."""
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "sample_network_attack.pcap"
    )
    registry = DeviceObservationRegistry()
    engine = LiveNetworkCaptureEngine(sequence_length=10)
    engine.set_device_registry(registry)

    with open(pcap_path, "rb") as f:
        pcap_bytes = f.read()

    engine.parse_pcap_bytes(pcap_bytes)

    # In sample_network_attack.pcap: attacker is 192.168.1.185, target is 10.0.0.45, plus sweeps on 10.0.0.1-11
    attacker_obs = registry.get_device_by_ip("192.168.1.185", mode="pcap")
    assert attacker_obs is not None
    assert attacker_obs["ip_address"] == "192.168.1.185"
    assert "Historical PCAP File" in attacker_obs["observation_source"]

    target_obs = registry.get_device_by_ip("10.0.0.45", mode="pcap")
    assert target_obs is not None
    assert target_obs["ip_address"] == "10.0.0.45"


# ==============================================================================
# CATEGORY C: Model Compatibility Tests
# Verifying expected input dimensions, scaler parameters, model forward pass, and SHAP
# ==============================================================================

def test_model_architecture_and_weights_compatibility():
    """Verify PyTorch model structure, weights loading, and dual-head output dimensions."""
    assert isinstance(model, AttackForecasterBiLSTM)
    assert model.input_dim == 12
    assert model.hidden_dim == 64
    assert model.num_classes == 5

    # Test single-batch forward pass with shape [1, 10, 12]
    dummy_input = torch.zeros((1, 10, 12), dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        curr_logits, next_logits = model(dummy_input)

    assert curr_logits.shape == (1, 5)
    assert next_logits.shape == (1, 5)

    curr_probs, next_probs = model.predict_probabilities(dummy_input)
    assert torch.allclose(curr_probs.sum(dim=-1), torch.tensor([1.0]), atol=1e-5)
    assert torch.allclose(next_probs.sum(dim=-1), torch.tensor([1.0]), atol=1e-5)


def test_scaler_parameters_and_compatibility():
    """Verify that scaler.pkl matches the 12-feature schema and inspect fitted parameters."""
    assert scaler is not None
    assert hasattr(scaler, "mean_")
    assert hasattr(scaler, "scale_")
    assert len(scaler.mean_) == 12
    assert len(scaler.scale_) == 12
    assert getattr(scaler, "n_features_in_", 12) == 12

    # Verify scaling produces finite output on sample flow
    sample_raw = np.array([[10.0, 50.0, 3.0, 0.4, 5.0, 0.8, 1.0, 0.05, 1.0, 40.0, 0.5, 2.0]] * 10, dtype=np.float32)
    scaled = scaler.transform(sample_raw)
    assert scaled.shape == (10, 12)
    assert np.all(np.isfinite(scaled))


def test_shap_explainer_execution():
    """Verify SHAP GradientExplainer runs deterministically and produces 12 feature attributions."""
    assert shap_explainer is not None
    sample_raw = np.array([[10.0, 50.0, 3.0, 0.4, 5.0, 0.8, 1.0, 0.05, 1.0, 40.0, 0.5, 2.0]] * 10, dtype=np.float32)
    scaled = scaler.transform(sample_raw)

    explanation = shap_explainer.explain(
        input_sequence=scaled,
        predicted_next_stage_idx=1,
        predicted_prob=0.75
    )

    assert "feature_ranking" in explanation
    assert len(explanation["feature_ranking"]) == 12
    assert "force_plot" in explanation
    assert len(explanation["force_plot"]["contributions"]) == 12
    assert "base_value" in explanation["force_plot"]


def test_end_to_end_pipeline_execution():
    """
    Full end-to-end forward test:
    Valid 10-step sequence -> process_sequence -> scaled tensor -> BiLSTM forward -> Risk score -> SHAP -> Dashboard API structure.
    """
    valid_seq = np.array([
        [5.0, 25.0, 2.0, 0.3, 4.0, 0.9, 0.5, 0.05, 0.8, 55.0, 0.4, 1.8]
        for _ in range(10)
    ], dtype=np.float32)

    result = process_sequence(valid_seq)
    assert result["prediction_available"] is True
    assert result["status"] == "VALID"
    assert result["current_stage"] in ["Reconnaissance", "Scanning", "Enumeration", "Exploitation", "Intrusion"]
    assert result["predicted_next_stage"] in ["Reconnaissance", "Scanning", "Enumeration", "Exploitation", "Intrusion"]
    assert isinstance(result["confidence"], int)
    assert isinstance(result["risk_score"], int)
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert len(result["candidate_forecasts"]) == 5
    assert len(result["shap"]["feature_ranking"]) == 12
    assert "options" in result["recommendation"]
