"""
Temporal Feature Aggregation Component
Aggregates authentic PacketMetadata records into discrete 1-minute (60.0s) observation epochs.
Implements leak-free, mathematically verified feature extraction with full provenance and missing-interval policies.

Feature Definitions & Mathematical Specifications:
1. packet_count: Total observed packets in window [count, integer, >= 0]
2. total_captured_bytes: Sum of captured frame lengths in window [bytes, integer, >= 0]
3. mean_frame_length: Mean captured frame length [bytes/packet, float, >= 0.0]
4. std_frame_length: Standard deviation of frame lengths [bytes, float, >= 0.0]
5. tcp_packet_ratio: TCP packets / total packets [fraction, [0.0, 1.0], 0.0 if empty]
6. udp_packet_ratio: UDP packets / total packets [fraction, [0.0, 1.0], 0.0 if empty]
7. other_protocol_ratio: Non-(TCP/UDP) packets / total packets [fraction, [0.0, 1.0]]
8. distinct_src_ips: Count of distinct observed source IP addresses [count, integer, >= 0]
9. distinct_dst_ips: Count of distinct observed destination IP addresses [count, integer, >= 0]
10. distinct_dst_ports: Count of distinct destination ports [count, integer, >= 0]
11. syn_flag_ratio: TCP SYN packets / total TCP packets [fraction, [0.0, 1.0], 0.0 if no TCP]
12. iat_mean: Mean packet inter-arrival time in seconds [seconds, float, >= 0.0; 0.0 if count < 2]
13. iat_std: Standard deviation of packet inter-arrival times [seconds, float, >= 0.0; 0.0 if count < 2]
"""

import math
from typing import List, Dict, Any, Optional, Iterator
from dataclasses import dataclass, asdict
import numpy as np

from .packet_record import PacketMetadata


AGGREGATION_FEATURE_NAMES = [
    "packet_count",
    "total_captured_bytes",
    "mean_frame_length",
    "std_frame_length",
    "tcp_packet_ratio",
    "udp_packet_ratio",
    "other_protocol_ratio",
    "distinct_src_ips",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "syn_flag_ratio",
    "iat_mean",
    "iat_std"
]


@dataclass
class TemporalWindow:
    """Represents a discrete 1-minute observation window with health metadata."""
    window_index: int
    window_start: float
    window_end: float
    packet_count: int
    total_captured_bytes: int
    mean_frame_length: float
    std_frame_length: float
    tcp_packet_ratio: float
    udp_packet_ratio: float
    other_protocol_ratio: float
    distinct_src_ips: int
    distinct_dst_ips: int
    distinct_dst_ports: int
    syn_flag_ratio: float
    iat_mean: float
    iat_std: float
    is_empty: bool
    parsing_errors: int
    provenance: str

    def to_feature_vector(self) -> np.ndarray:
        """Returns standard NumPy float32 vector of the 13 observable temporal features."""
        return np.array([
            float(self.packet_count),
            float(self.total_captured_bytes),
            float(self.mean_frame_length),
            float(self.std_frame_length),
            float(self.tcp_packet_ratio),
            float(self.udp_packet_ratio),
            float(self.other_protocol_ratio),
            float(self.distinct_src_ips),
            float(self.distinct_dst_ips),
            float(self.distinct_dst_ports),
            float(self.syn_flag_ratio),
            float(self.iat_mean),
            float(self.iat_std)
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TemporalAggregator:
    """
    Constructs discrete 1-minute time windows from genuine packet streams.
    Prevents future data leakage by strictly partitioning packets by timestamp.
    """

    def __init__(self, window_size_seconds: float = 60.0):
        self.window_size_seconds = float(window_size_seconds)

    def aggregate_packet_batch(
        self,
        packets: List[PacketMetadata],
        window_start: float,
        window_end: float,
        window_index: int = 0,
        provenance: str = "Real Observation"
    ) -> TemporalWindow:
        """
        Calculates all 13 temporal features for a single explicit time window.
        """
        valid_packets = [p for p in packets if p.parse_status == "OK"]
        errors = sum(1 for p in packets if p.parse_status != "OK")
        count = len(valid_packets)

        if count == 0:
            return TemporalWindow(
                window_index=window_index,
                window_start=window_start,
                window_end=window_end,
                packet_count=0,
                total_captured_bytes=0,
                mean_frame_length=0.0,
                std_frame_length=0.0,
                tcp_packet_ratio=0.0,
                udp_packet_ratio=0.0,
                other_protocol_ratio=0.0,
                distinct_src_ips=0,
                distinct_dst_ips=0,
                distinct_dst_ports=0,
                syn_flag_ratio=0.0,
                iat_mean=0.0,
                iat_std=0.0,
                is_empty=True,
                parsing_errors=errors,
                provenance=provenance
            )

        # 1. Byte and frame length statistics
        lengths = [p.captured_len for p in valid_packets]
        total_bytes = sum(lengths)
        mean_len = float(np.mean(lengths))
        std_len = float(np.std(lengths)) if count > 1 else 0.0

        # 2. Protocol ratios
        tcp_count = sum(1 for p in valid_packets if p.transport_protocol == "TCP")
        udp_count = sum(1 for p in valid_packets if p.transport_protocol == "UDP")
        other_count = count - (tcp_count + udp_count)

        tcp_ratio = float(tcp_count / count)
        udp_ratio = float(udp_count / count)
        other_ratio = float(other_count / count)

        # 3. IP and port diversity
        src_ips = set(p.src_ip for p in valid_packets if p.src_ip)
        dst_ips = set(p.dst_ip for p in valid_packets if p.dst_ip)
        dst_ports = set(p.dst_port for p in valid_packets if p.dst_port is not None and p.dst_port > 0)

        # 4. SYN flag ratio (fraction of TCP packets with SYN)
        if tcp_count > 0:
            syn_count = sum(1 for p in valid_packets if p.transport_protocol == "TCP" and p.tcp_flags and "S" in p.tcp_flags)
            syn_ratio = float(syn_count / tcp_count)
        else:
            syn_ratio = 0.0

        # 5. Inter-arrival time statistics (IAT)
        timestamps = sorted([p.timestamp for p in valid_packets])
        if count >= 2:
            iats = [timestamps[i] - timestamps[i - 1] for i in range(1, count)]
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0

        return TemporalWindow(
            window_index=window_index,
            window_start=window_start,
            window_end=window_end,
            packet_count=count,
            total_captured_bytes=total_bytes,
            mean_frame_length=round(mean_len, 2),
            std_frame_length=round(std_len, 2),
            tcp_packet_ratio=round(tcp_ratio, 4),
            udp_packet_ratio=round(udp_ratio, 4),
            other_protocol_ratio=round(other_ratio, 4),
            distinct_src_ips=len(src_ips),
            distinct_dst_ips=len(dst_ips),
            distinct_dst_ports=len(dst_ports),
            syn_flag_ratio=round(syn_ratio, 4),
            iat_mean=round(iat_mean, 6),
            iat_std=round(iat_std, 6),
            is_empty=False,
            parsing_errors=errors,
            provenance=provenance
        )

    def aggregate_chronological_stream(
        self,
        packets: List[PacketMetadata],
        align_to_minute_boundaries: bool = True,
        provenance: str = "Real Observation"
    ) -> List[TemporalWindow]:
        """
        Groups chronological packet sequence into consecutive 1-minute discrete windows.
        Handles observed empty intervals without fabricating data during capture outages.
        """
        if not packets:
            return []

        valid_ts = [p.timestamp for p in packets if p.timestamp > 0]
        if not valid_ts:
            return []

        t_min = min(valid_ts)
        t_max = max(valid_ts)

        if align_to_minute_boundaries:
            # Align window_start to integer minute boundary (e.g. 12:00:00)
            start_epoch = math.floor(t_min / self.window_size_seconds) * self.window_size_seconds
        else:
            start_epoch = t_min

        windows: List[TemporalWindow] = []
        curr_start = start_epoch
        idx = 0

        # Sort packets chronologically
        sorted_pkts = sorted(packets, key=lambda p: p.timestamp)
        pkt_iter = iter(sorted_pkts)
        curr_pkt = next(pkt_iter, None)

        while curr_start <= t_max:
            curr_end = curr_start + self.window_size_seconds
            window_pkts: List[PacketMetadata] = []

            while curr_pkt is not None and curr_pkt.timestamp < curr_end:
                if curr_pkt.timestamp >= curr_start:
                    window_pkts.append(curr_pkt)
                curr_pkt = next(pkt_iter, None)

            tw = self.aggregate_packet_batch(
                packets=window_pkts,
                window_start=curr_start,
                window_end=curr_end,
                window_index=idx,
                provenance=provenance
            )
            windows.append(tw)
            curr_start = curr_end
            idx += 1

        return windows
