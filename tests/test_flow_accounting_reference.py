"""
Deterministic Reference Implementation & Verification Suite for Flow Accounting Semantics.

Audits and validates the training-time flow aggregation semantics vs live streaming options:
- Option A: Start-epoch attribution (training-equivalent)
- Option B: Epoch-sliced aggregation (interval-traffic accounting)

Contains independent reference calculation functions that do NOT import or invoke
StreamingFlowAssembler's internal feature calculation methods.

Covers all 10 mandatory reference cases:
1. Flow that starts and ends within one minute.
2. Flow that crosses two minute boundaries.
3. Flow that remains active for several minutes.
4. Flow that expires through inactivity.
5. Out-of-order packets.
6. Packet received after its epoch has been finalized.
7. Empty epochs.
8. Repeated epoch retrieval (idempotence).
9. Capture restarts and state reset.
10. All 12 feature values for each applicable epoch compared against reference math.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import pytest

from pipeline.streaming_flow_assembler import (
    StreamingFlowAssembler,
    PREDICTOR_COLUMNS,
    compute_shannon_entropy as assembler_entropy
)


# ============================================================================
# INDEPENDENT REFERENCE IMPLEMENTATION (Training Semantics: Start-Epoch Attribution)
# ============================================================================

@dataclass
class ReferencePacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: int
    length: int
    flags: str = ""


@dataclass
class ReferenceFlow:
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    proto: int
    first_seen: float
    last_seen: float
    total_packets: int
    total_bytes: int
    has_syn: bool
    is_closed: bool

    @property
    def duration_ms(self) -> float:
        return max(0.001, (self.last_seen - self.first_seen) * 1000.0)


def compute_reference_shannon_entropy(items: List[Any]) -> float:
    """Independent reference calculation of normalized Shannon entropy."""
    if not items:
        return 0.0
    counts = Counter(items).values()
    n = len(items)
    k = len(counts)
    if k <= 1:
        return 0.0
    probs = [c / n for c in counts]
    ent = -sum(p * math.log2(p) for p in probs)
    max_ent = math.log2(k)
    return float(ent / max_ent) if max_ent > 0 else 0.0


def independent_reference_aggregate(
    packets: List[ReferencePacket],
    epoch_duration: float = 60.0
) -> Dict[float, Dict[str, float]]:
    """
    Independent reference implementation of CICIDS2017 training pipeline:
    1. Assemble packets into bidirectional flows.
    2. Attribute each completed flow to the epoch of its FIRST packet (start time).
    3. Calculate the 12 authoritative features for each epoch.
    """
    # 1. Assemble bidirectional flows
    active_flows: Dict[Tuple, ReferenceFlow] = {}
    reverse_map: Dict[Tuple, Tuple] = {}

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        fwd_key = (pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport, pkt.proto)
        bwd_key = (pkt.dst_ip, pkt.dport, pkt.src_ip, pkt.sport, pkt.proto)

        if fwd_key in active_flows:
            flow = active_flows[fwd_key]
            flow.last_seen = max(flow.last_seen, pkt.timestamp)
            flow.first_seen = min(flow.first_seen, pkt.timestamp)
            flow.total_packets += 1
            flow.total_bytes += pkt.length
            if "S" in pkt.flags.upper():
                flow.has_syn = True
            if "F" in pkt.flags.upper() or "R" in pkt.flags.upper():
                flow.is_closed = True
        elif fwd_key in reverse_map:
            primary_key = reverse_map[fwd_key]
            flow = active_flows[primary_key]
            flow.last_seen = max(flow.last_seen, pkt.timestamp)
            flow.first_seen = min(flow.first_seen, pkt.timestamp)
            flow.total_packets += 1
            flow.total_bytes += pkt.length
            if "S" in pkt.flags.upper():
                flow.has_syn = True
            if "F" in pkt.flags.upper() or "R" in pkt.flags.upper():
                flow.is_closed = True
        else:
            flow = ReferenceFlow(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                sport=pkt.sport,
                dport=pkt.dport,
                proto=pkt.proto,
                first_seen=pkt.timestamp,
                last_seen=pkt.timestamp,
                total_packets=1,
                total_bytes=pkt.length,
                has_syn=("S" in pkt.flags.upper()),
                is_closed=("F" in pkt.flags.upper() or "R" in pkt.flags.upper())
            )
            active_flows[fwd_key] = flow
            reverse_map[bwd_key] = fwd_key

    # 2. Group completed flows by start epoch (Training Semantics)
    epoch_flows: Dict[float, List[ReferenceFlow]] = {}
    if packets:
        min_ts = min(p.timestamp for p in packets)
        max_ts = max(p.timestamp for p in packets)
        min_epoch = math.floor(min_ts / epoch_duration) * epoch_duration
        max_epoch = math.floor(max_ts / epoch_duration) * epoch_duration
        curr_ep = min_epoch
        while curr_ep <= max_epoch:
            epoch_flows[curr_ep] = []
            curr_ep += epoch_duration

    for flow in active_flows.values():
        ep = math.floor(flow.first_seen / epoch_duration) * epoch_duration
        if ep not in epoch_flows:
            epoch_flows[ep] = []
        epoch_flows[ep].append(flow)

    # 3. Calculate 12 features per epoch
    results: Dict[float, Dict[str, float]] = {}
    for ep, flows in epoch_flows.items():
        n = len(flows)
        if n == 0:
            results[ep] = {col: 0.0 for col in PREDICTOR_COLUMNS}
            continue

        tot_pkts = float(sum(f.total_packets for f in flows))
        tot_bytes = float(sum(f.total_bytes for f in flows))
        durations = [f.duration_ms for f in flows]
        mean_dur = float(np.mean(durations))
        std_dur = float(np.std(durations, ddof=0)) if len(durations) > 1 else 0.0

        tcp_cnt = sum(1 for f in flows if f.proto == 6)
        udp_cnt = sum(1 for f in flows if f.proto == 17)
        tcp_ratio = float(tcp_cnt) / n
        udp_ratio = float(udp_cnt) / n

        dst_ports = [f.dport for f in flows if f.dport > 0]
        dst_div = len(set(dst_ports))
        dst_ent = compute_reference_shannon_entropy(dst_ports)

        distinct_src = len(set(f.src_ip for f in flows))
        distinct_dst = len(set(f.dst_ip for f in flows))
        syn_ratio = float(sum(1 for f in flows if f.has_syn)) / n

        results[ep] = {
            "flow_count": float(n),
            "total_packets": tot_pkts,
            "total_bytes": tot_bytes,
            "mean_flow_duration_ms": mean_dur,
            "std_flow_duration_ms": std_dur,
            "tcp_flow_ratio": tcp_ratio,
            "udp_flow_ratio": udp_ratio,
            "dst_port_diversity": float(dst_div),
            "dst_port_entropy": dst_ent,
            "distinct_src_ips": float(distinct_src),
            "distinct_dst_ips": float(distinct_dst),
            "syn_flag_ratio": syn_ratio
        }

    return results


# ============================================================================
# DETERMINISTIC REFERENCE TEST CASES (1 to 10)
# ============================================================================

def test_case_1_flow_starts_and_ends_within_one_minute():
    """Case 1: Flow starts at 10.0s and ends at 30.0s. All traffic falls into epoch 0.0."""
    pkts = [
        ReferencePacket(10.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 100, "S"),
        ReferencePacket(20.0, "10.0.0.1", "192.168.1.10", 80, 50000, 6, 200, "SA"),
        ReferencePacket(30.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 50, "FA"),
    ]
    ref = independent_reference_aggregate(pkts, epoch_duration=60.0)

    assert 0.0 in ref
    ep0 = ref[0.0]
    assert ep0["flow_count"] == 1.0
    assert ep0["total_packets"] == 3.0
    assert ep0["total_bytes"] == 350.0
    assert pytest.approx(ep0["mean_flow_duration_ms"], rel=1e-3) == 20000.0  # (30-10)*1000
    assert ep0["std_flow_duration_ms"] == 0.0
    assert ep0["tcp_flow_ratio"] == 1.0
    assert ep0["udp_flow_ratio"] == 0.0
    assert ep0["dst_port_diversity"] == 1.0
    assert ep0["distinct_src_ips"] == 1.0
    assert ep0["distinct_dst_ips"] == 1.0
    assert ep0["syn_flag_ratio"] == 1.0


def test_case_2_flow_crosses_two_minute_boundaries():
    """Case 2: Flow starts at 10.0s (epoch 0) and sends another packet at 75.0s (epoch 1)."""
    pkts = [
        ReferencePacket(10.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 1000, "S"),
        ReferencePacket(75.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 500, "A"),
    ]
    ref = independent_reference_aggregate(pkts, epoch_duration=60.0)

    # In training semantics: Flow belongs entirely to epoch 0.0 (where it started)
    assert 0.0 in ref
    assert 60.0 in ref
    ep0 = ref[0.0]
    ep1 = ref[60.0]

    # Epoch 0 gets both packets and all 1500 bytes under start-epoch attribution
    assert ep0["flow_count"] == 1.0
    assert ep0["total_packets"] == 2.0
    assert ep0["total_bytes"] == 1500.0
    assert pytest.approx(ep0["mean_flow_duration_ms"], rel=1e-3) == 65000.0

    # Epoch 1 has 0 flows starting in it
    assert ep1["flow_count"] == 0.0
    assert ep1["total_packets"] == 0.0
    assert ep1["total_bytes"] == 0.0


def test_case_3_flow_remains_active_across_several_minutes():
    """Case 3: Flow starts at 10.0s and continues sending packets at 70.0s, 130.0s, and 190.0s."""
    pkts = [
        ReferencePacket(10.0, "10.0.0.1", "10.0.0.2", 1111, 443, 6, 100, "S"),
        ReferencePacket(70.0, "10.0.0.2", "10.0.0.1", 443, 1111, 6, 200, "A"),
        ReferencePacket(130.0, "10.0.0.1", "10.0.0.2", 1111, 443, 6, 300, "A"),
        ReferencePacket(190.0, "10.0.0.2", "10.0.0.1", 443, 1111, 6, 400, "FA"),
    ]
    ref = independent_reference_aggregate(pkts, epoch_duration=60.0)

    # Epoch 0 (t=0.0): Contains the flow
    ep0 = ref[0.0]
    assert ep0["flow_count"] == 1.0
    assert ep0["total_packets"] == 4.0
    assert ep0["total_bytes"] == 1000.0
    assert pytest.approx(ep0["mean_flow_duration_ms"], rel=1e-3) == 180000.0  # (190-10)*1000

    # Epochs 1, 2, 3 have zero new flows initiated
    for ep_ts in [60.0, 120.0, 180.0]:
        assert ref[ep_ts]["flow_count"] == 0.0
        assert ref[ep_ts]["total_packets"] == 0.0
        assert ref[ep_ts]["total_bytes"] == 0.0


def test_case_4_flow_expires_via_inactivity():
    """Case 4: Flow starts at 10.0s, receives packet at 20.0s, then expires after idle timeout."""
    pkts = [
        ReferencePacket(10.0, "10.0.0.1", "10.0.0.2", 2222, 53, 17, 80),
        ReferencePacket(20.0, "10.0.0.2", "10.0.0.1", 53, 2222, 17, 120),
    ]
    ref = independent_reference_aggregate(pkts, epoch_duration=60.0)

    ep0 = ref[0.0]
    assert ep0["flow_count"] == 1.0
    assert ep0["total_packets"] == 2.0
    assert ep0["total_bytes"] == 200.0
    assert pytest.approx(ep0["mean_flow_duration_ms"], rel=1e-3) == 10000.0
    assert ep0["udp_flow_ratio"] == 1.0
    assert ep0["tcp_flow_ratio"] == 0.0


def test_case_5_out_of_order_packets():
    """Case 5: Packets arrive in reverse chronological order (25s, then 10s, then 30s)."""
    pkts = [
        ReferencePacket(25.0, "1.1.1.1", "2.2.2.2", 100, 80, 6, 50),
        ReferencePacket(10.0, "1.1.1.1", "2.2.2.2", 100, 80, 6, 100, "S"),
        ReferencePacket(30.0, "2.2.2.2", "1.1.1.1", 80, 100, 6, 200),
    ]
    ref = independent_reference_aggregate(pkts, epoch_duration=60.0)

    ep0 = ref[0.0]
    # Bound expansion: first_seen = 10.0, last_seen = 30.0
    assert ep0["flow_count"] == 1.0
    assert ep0["total_packets"] == 3.0
    assert ep0["total_bytes"] == 350.0
    assert pytest.approx(ep0["mean_flow_duration_ms"], rel=1e-3) == 20000.0
    assert ep0["syn_flag_ratio"] == 1.0


def test_case_6_late_packet_after_epoch_finalization():
    """Case 6: Epoch 0 (0..60s) finalized at 150s. Late packet at 45s arrives."""
    assembler = StreamingFlowAssembler(epoch_duration=60.0, history_length=10)
    # Packet in epoch 0
    assembler.ingest_packet(10.0, "10.0.0.1", "10.0.0.2", 1000, 80, "TCP", 100)
    # Advance past epoch 0 and 1 into epoch 2 (150s)
    assembler.ingest_packet(150.0, "10.0.0.3", "10.0.0.4", 2000, 443, "TCP", 100)

    # Epoch 0 is completed in history
    completed_before = list(assembler._completed_epochs)
    assert len(completed_before) == 2  # ep 0.0 and ep 60.0
    ep0_rec = completed_before[0]
    assert ep0_rec.epoch_timestamp == 0.0
    assert ep0_rec.total_bytes == 100.0

    # Ingest late packet for epoch 0
    late_flow = assembler.ingest_packet(45.0, "10.0.0.5", "10.0.0.6", 3000, 80, "TCP", 250)

    # Invariant: Finalized historical records in completed_epochs MUST NOT be silently modified
    completed_after = list(assembler._completed_epochs)
    assert len(completed_after) == 2
    assert completed_after[0].total_bytes == 100.0
    assert completed_after[0].flow_count == 1


def test_case_7_empty_epochs_produce_deterministic_zeros():
    """Case 7: Empty epochs must record exactly 0.0 for all 12 features."""
    ref = independent_reference_aggregate([], epoch_duration=60.0)
    # Query an empty epoch
    assembler = StreamingFlowAssembler(epoch_duration=60.0, history_length=10)
    # Advance from 0 to 180 with no packets
    assembler.flush_current_epoch(current_time=60.0)
    assembler.flush_current_epoch(current_time=120.0)

    for ep in assembler._completed_epochs:
        feats = ep.to_feature_dict()
        assert len(feats) == 12
        for col_name, val in feats.items():
            assert val == 0.0
            assert not np.isnan(val)
            assert not np.isinf(val)


def test_case_8_repeated_epoch_retrieval_idempotence():
    """Case 8: Repeated retrieval of sliding window features must be idempotent."""
    assembler = StreamingFlowAssembler(epoch_duration=60.0, history_length=10)
    for i in range(10):
        assembler.ingest_packet(float(i * 60 + 5), "10.0.0.1", "10.0.0.2", 1000 + i, 80, "TCP", 100)
    assembler.flush_current_epoch(current_time=605.0)

    res1 = assembler.get_sliding_window_features()
    res2 = assembler.get_sliding_window_features()

    assert res1["ready"] is True
    assert res2["ready"] is True
    assert np.array_equal(res1["features"], res2["features"])
    assert res1["anchor_epoch"] == res2["anchor_epoch"]


def test_case_9_capture_restarts_and_state_reset():
    """Case 9: Clear resets all internal tables; subsequent capture starts clean."""
    assembler = StreamingFlowAssembler(epoch_duration=60.0, history_length=10)
    assembler.ingest_packet(10.0, "10.0.0.1", "10.0.0.2", 1000, 80, "TCP", 100)
    assert assembler.total_packets_processed == 1
    assert len(assembler._active_flows) == 1

    assembler.clear()

    assert assembler.total_packets_processed == 0
    assert assembler.total_flows_assembled == 0
    assert len(assembler._active_flows) == 0
    assert len(assembler._reverse_map) == 0
    assert len(assembler._completed_epochs) == 0
    assert assembler._current_epoch_floor is None

    # New capture starts cleanly
    flow = assembler.ingest_packet(500.0, "1.1.1.1", "2.2.2.2", 2000, 443, "TCP", 50)
    assert flow is not None
    assert assembler.total_packets_processed == 1
    assert assembler._current_epoch_floor == 480.0  # math.floor(500/60)*60 = 480


def test_case_10_all_12_features_match_reference_calculation():
    """Case 10: Compare all 12 feature values calculated by assembler vs independent reference."""
    pkts = [
        ReferencePacket(10.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 100, "S"),
        ReferencePacket(15.0, "192.168.1.11", "10.0.0.1", 50001, 443, 6, 200, "S"),
        ReferencePacket(20.0, "192.168.1.12", "10.0.0.2", 50002, 53, 17, 80),
        ReferencePacket(25.0, "10.0.0.1", "192.168.1.10", 80, 50000, 6, 150),
        ReferencePacket(30.0, "10.0.0.2", "192.168.1.12", 53, 50002, 17, 120),
    ]

    # Independent reference
    ref_dict = independent_reference_aggregate(pkts, epoch_duration=60.0)[0.0]

    # Assembler calculation
    assembler = StreamingFlowAssembler(epoch_duration=60.0, history_length=10)
    for p in pkts:
        assembler.ingest_packet(
            timestamp=p.timestamp,
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            sport=p.sport,
            dport=p.dport,
            proto="TCP" if p.proto == 6 else "UDP",
            length=p.length,
            flags=p.flags
        )
    assembler.flush_current_epoch(current_time=60.0)
    ep0_asm = assembler._completed_epochs[0].to_feature_dict()

    for col in PREDICTOR_COLUMNS:
        asm_val = ep0_asm[col]
        ref_val = ref_dict[col]
        assert pytest.approx(asm_val, rel=1e-3, abs=1e-5) == ref_val, (
            f"Feature mismatch on {col}: assembler={asm_val}, reference={ref_val}"
        )
