"""
Unit Tests for Temporal Feature Aggregation Component
Tests:
- 1-minute discrete window boundaries
- Correct packet, byte, and length calculations
- Protocol ratios and boundedness [0.0, 1.0]
- SYN flag ratio calculation
- Inter-arrival time statistics (IAT)
- Handling of empty intervals (is_empty=True, no synthetic packets)
- Zero future-data leakage
"""

import pytest
import numpy as np

from pipeline.packet_record import PacketMetadata
from pipeline.temporal_aggregator import (
    TemporalAggregator,
    TemporalWindow,
    AGGREGATION_FEATURE_NAMES
)


def make_test_packet(
    pkt_id: int,
    ts: float,
    length: int = 100,
    proto: str = "TCP",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    dport: int = 80,
    flags: str = ""
) -> PacketMetadata:
    """Creates a deterministic PacketMetadata fixture."""
    return PacketMetadata(
        pkt_id=pkt_id,
        timestamp=ts,
        captured_len=length,
        wire_len=length,
        network_protocol="IPv4",
        transport_protocol=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000 + pkt_id,
        dst_port=dport,
        tcp_flags=flags,
        parse_status="OK",
        observation_source="Unit Test"
    )


def test_empty_window_aggregation():
    """Verify aggregation of an empty list of packets produces is_empty=True without fabrication."""
    agg = TemporalAggregator(window_size_seconds=60.0)
    w = agg.aggregate_packet_batch(
        packets=[],
        window_start=1700000000.0,
        window_end=1700000060.0,
        window_index=0
    )
    assert isinstance(w, TemporalWindow)
    assert w.is_empty is True
    assert w.packet_count == 0
    assert w.total_captured_bytes == 0
    assert w.mean_frame_length == 0.0
    assert w.tcp_packet_ratio == 0.0
    assert w.syn_flag_ratio == 0.0
    assert w.iat_mean == 0.0

    vec = w.to_feature_vector()
    assert vec.shape == (13,)
    assert np.all(vec == 0.0)


def test_packet_and_byte_calculations():
    """Verify exact count, sum, mean, and std of frame lengths."""
    agg = TemporalAggregator(window_size_seconds=60.0)
    packets = [
        make_test_packet(1, 1700000010.0, length=50),
        make_test_packet(2, 1700000020.0, length=150),
        make_test_packet(3, 1700000030.0, length=100)
    ]
    w = agg.aggregate_packet_batch(
        packets=packets,
        window_start=1700000000.0,
        window_end=1700000060.0,
        window_index=1
    )
    assert w.packet_count == 3
    assert w.total_captured_bytes == 300
    assert w.mean_frame_length == 100.0
    # Population std of [50, 150, 100] is sqrt(((50^2 + 50^2 + 0)/3)) = sqrt(5000/3) = ~40.82
    assert abs(w.std_frame_length - 40.82) < 0.1
    assert w.is_empty is False


def test_protocol_and_syn_ratios():
    """Verify TCP, UDP, other protocol ratios and SYN flag ratio."""
    agg = TemporalAggregator(window_size_seconds=60.0)
    packets = [
        make_test_packet(1, 1700000005.0, proto="TCP", flags="S"),
        make_test_packet(2, 1700000015.0, proto="TCP", flags="A"),
        make_test_packet(3, 1700000025.0, proto="UDP"),
        make_test_packet(4, 1700000035.0, proto="ICMP")
    ]
    w = agg.aggregate_packet_batch(
        packets=packets,
        window_start=1700000000.0,
        window_end=1700000060.0
    )
    assert w.packet_count == 4
    assert w.tcp_packet_ratio == 0.5  # 2 TCP out of 4
    assert w.udp_packet_ratio == 0.25 # 1 UDP out of 4
    assert w.other_protocol_ratio == 0.25 # 1 ICMP out of 4
    assert round(w.tcp_packet_ratio + w.udp_packet_ratio + w.other_protocol_ratio, 4) == 1.0

    # 1 SYN packet out of 2 TCP packets = 0.5
    assert w.syn_flag_ratio == 0.5


def test_inter_arrival_time_statistics():
    """Verify mean and standard deviation of packet inter-arrival times."""
    agg = TemporalAggregator(window_size_seconds=60.0)
    # Timestamps at 0s, 2s, 6s: IATs are 2.0s and 4.0s. Mean = 3.0s, std = 1.0s
    packets = [
        make_test_packet(1, 1700000000.0),
        make_test_packet(2, 1700000002.0),
        make_test_packet(3, 1700000006.0)
    ]
    w = agg.aggregate_packet_batch(
        packets=packets,
        window_start=1700000000.0,
        window_end=1700000060.0
    )
    assert w.iat_mean == 3.0
    assert w.iat_std == 1.0


def test_chronological_stream_partitioning():
    """Verify that aggregate_chronological_stream correctly partitions packets into 1-minute windows."""
    agg = TemporalAggregator(window_size_seconds=60.0)
    t0 = 1700000040.0 # Exact minute boundary (divisible by 60)
    t1 = t0 + 70.0    # Next minute
    t2 = t0 + 130.0   # Following minute

    packets = [
        make_test_packet(1, t0 + 10.0),
        make_test_packet(2, t0 + 20.0),
        make_test_packet(3, t1),
        make_test_packet(4, t2)
    ]

    windows = agg.aggregate_chronological_stream(packets, align_to_minute_boundaries=True)
    assert len(windows) == 3

    assert windows[0].packet_count == 2
    assert windows[1].packet_count == 1
    assert windows[2].packet_count == 1

    # Verify no future leakage: window 0 only contains packets from t0 to t0+60
    assert windows[0].window_start == t0
    assert windows[0].window_end == t0 + 60.0
