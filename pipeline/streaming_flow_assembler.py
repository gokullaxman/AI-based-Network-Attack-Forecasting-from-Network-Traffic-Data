"""
Streaming Bidirectional Network-Flow Assembler (Phase 9D).

Converts live network packets (or historical PCAP traces) into authentic bidirectional
flow records and discrete 60-second temporal epochs. Generates the exact 12-feature
schema and 120-dimensional lagged sequence required by the Target A Temporal Forecaster.

Mathematically and structurally verified against:
- CICIDS2017 flow definitions
- pipeline/temporal_preprocessor.py
- models/temporal_forecasting/metadata.json
"""

import math
import time
import threading
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set, Union
import numpy as np
import pandas as pd
        

PREDICTOR_COLUMNS = [
    "flow_count",
    "total_packets",
    "total_bytes",
    "mean_flow_duration_ms",
    "std_flow_duration_ms",
    "tcp_flow_ratio",
    "udp_flow_ratio",
    "dst_port_diversity",
    "dst_port_entropy",
    "distinct_src_ips",
    "distinct_dst_ips",
    "syn_flag_ratio"
]

TOTAL_EPOCHS_REQUIRED = 10
EPOCH_DURATION_SECONDS = 60.0


def compute_shannon_entropy(items: List[Any]) -> float:
    """
    Computes normalized Shannon entropy of a categorical sequence.
    Normalized to range [0.0, 1.0]. Returns 0.0 if empty or uniform single category.
    Matches compute_shannon_entropy() in pipeline/temporal_preprocessor.py.
    """
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


def get_protocol_code(proto_str_or_int: Any) -> int:
    """Maps protocol name or number to standard IP protocol number."""
    if isinstance(proto_str_or_int, int):
        return proto_str_or_int
    p_str = str(proto_str_or_int).strip().upper()
    if p_str == "TCP":
        return 6
    if p_str == "UDP":
        return 17
    if p_str == "ICMP":
        return 1
    if p_str in ("IPV6", "IPV6-ICMP", "ICMPV6"):
        return 58
    try:
        return int(p_str)
    except ValueError:
        return 0


@dataclass
class BidirectionalFlow:
    """
    Represents an authentic bidirectional network flow bounded by 5-tuple:
    (source_ip, source_port, destination_ip, destination_port, protocol).
    Forward direction is defined by the initial observation packet.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    proto_name: str
    first_seen: float
    last_seen: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    has_syn: bool = False
    is_closed: bool = False
    provenance: str = "live_capture"

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration_ms(self) -> float:
        """Flow duration in milliseconds, clamped to minimum 0.001 ms."""
        raw_ms = (self.last_seen - self.first_seen) * 1000.0
        return max(0.001, raw_ms)

    def add_packet(self, pkt_ts: float, pkt_len: int, is_forward: bool, flags: str = ""):
        """Updates flow state with an incoming packet observation."""
        if pkt_ts < self.first_seen:
            self.first_seen = pkt_ts
        if pkt_ts > self.last_seen:
            self.last_seen = pkt_ts

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len

        # Check for SYN flag (TCP)
        if "S" in flags.upper():
            self.has_syn = True

        # Check for connection termination flags (FIN / RST)
        flags_up = flags.upper()
        if "F" in flags_up or "R" in flags_up:
            self.is_closed = True


@dataclass
class FlowEpochRecord:
    """Represents a discrete 1-minute temporal observation epoch."""
    epoch_timestamp: float
    epoch_iso: str
    flow_count: int
    total_packets: float
    total_bytes: float
    mean_flow_duration_ms: float
    std_flow_duration_ms: float
    tcp_flow_ratio: float
    udp_flow_ratio: float
    dst_port_diversity: int
    dst_port_entropy: float
    distinct_src_ips: int
    distinct_dst_ips: int
    syn_flag_ratio: float
    is_empty: bool = False
    provenance: str = "live_capture"

    def to_feature_dict(self) -> Dict[str, float]:
        """Returns the 12 base features for this epoch."""
        return {
            "flow_count": float(self.flow_count),
            "total_packets": float(self.total_packets),
            "total_bytes": float(self.total_bytes),
            "mean_flow_duration_ms": float(self.mean_flow_duration_ms),
            "std_flow_duration_ms": float(self.std_flow_duration_ms),
            "tcp_flow_ratio": float(self.tcp_flow_ratio),
            "udp_flow_ratio": float(self.udp_flow_ratio),
            "dst_port_diversity": float(self.dst_port_diversity),
            "dst_port_entropy": float(self.dst_port_entropy),
            "distinct_src_ips": float(self.distinct_src_ips),
            "distinct_dst_ips": float(self.distinct_dst_ips),
            "syn_flag_ratio": float(self.syn_flag_ratio)
        }


class StreamingFlowAssembler:
    """
    Real-time streaming bidirectional flow assembler and 10-epoch sliding window generator.
    Converts individual packet observations into verified flow statistics without synthetic padding.
    """

    def __init__(
        self,
        epoch_duration: float = EPOCH_DURATION_SECONDS,
        history_length: int = TOTAL_EPOCHS_REQUIRED,
        flow_idle_timeout: float = 60.0,
        flow_active_timeout: float = 120.0,
        max_active_flows: int = 50_000,
        provenance: str = "live_capture"
    ):
        self.epoch_duration = float(epoch_duration)
        self.history_length = int(history_length)
        self.flow_idle_timeout = float(flow_idle_timeout)
        self.flow_active_timeout = float(flow_active_timeout)
        self.max_active_flows = int(max_active_flows)
        self.provenance = provenance

        self._lock = threading.RLock()

        # Active flow tables: forward_tuple -> BidirectionalFlow, reverse_tuple -> BidirectionalFlow
        self._active_flows: Dict[Tuple, BidirectionalFlow] = {}
        self._reverse_map: Dict[Tuple, Tuple] = {}  # reverse_tuple -> forward_tuple

        # Current working epoch
        self._current_epoch_floor: Optional[float] = None
        self._current_epoch_flows: List[BidirectionalFlow] = []

        # History of completed 1-minute epochs (sliding window of max 10)
        self._completed_epochs: deque[FlowEpochRecord] = deque(maxlen=self.history_length)

        # Telemetry counters
        self.total_packets_processed: int = 0
        self.total_flows_assembled: int = 0
        self.dropped_malformed_packets: int = 0
        self.last_packet_timestamp: Optional[float] = None

    def _canonicalize_ports_and_ips(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        sport: Optional[int],
        dport: Optional[int]
    ) -> Tuple[str, str, int, int]:
        """Normalizes and safely sanitizes IP addresses and transport ports."""
        s_ip = (src_ip or "0.0.0.0").strip("[] ")
        d_ip = (dst_ip or "0.0.0.0").strip("[] ")
        s_port = max(0, min(65535, int(sport or 0)))
        d_port = max(0, min(65535, int(dport or 0)))
        return s_ip, d_ip, s_port, d_port

    def ingest_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: Union[str, int],
        length: int,
        flags: str = "",
        provenance: Optional[str] = None
    ) -> Optional[BidirectionalFlow]:
        """
        Thread-safely ingests an authentic CapturedPacket into bidirectional flow state.
        Flushes completed epochs when packet timestamp crosses 60-second boundaries.
        """
        if timestamp is None or math.isnan(timestamp) or math.isinf(timestamp):
            self.dropped_malformed_packets += 1
            return None

        if length is None or length < 0:
            length = 0

        prov = provenance or self.provenance
        s_ip, d_ip, s_port, d_port = self._canonicalize_ports_and_ips(src_ip, dst_ip, sport, dport)
        p_code = get_protocol_code(proto)
        p_name = "TCP" if p_code == 6 else ("UDP" if p_code == 17 else ("ICMP" if p_code == 1 else str(proto)))

        fwd_tuple = (s_ip, s_port, d_ip, d_port, p_code)
        bwd_tuple = (d_ip, d_port, s_ip, s_port, p_code)

        with self._lock:
            self.total_packets_processed += 1
            self.last_packet_timestamp = timestamp

            # Advance epoch tracking if timestamp has crossed boundary
            self._advance_epochs_to_timestamp(timestamp)

            flow: Optional[BidirectionalFlow] = None

            # Case 1: Packet belongs to forward direction of existing flow
            if fwd_tuple in self._active_flows:
                flow = self._active_flows[fwd_tuple]
                flow.add_packet(timestamp, length, is_forward=True, flags=flags)

            # Case 2: Packet belongs to reverse direction of existing flow
            elif fwd_tuple in self._reverse_map:
                primary_tuple = self._reverse_map[fwd_tuple]
                if primary_tuple in self._active_flows:
                    flow = self._active_flows[primary_tuple]
                    flow.add_packet(timestamp, length, is_forward=False, flags=flags)

            # Case 3: New bidirectional flow starting with this packet
            if flow is None:
                # Capacity guard: prune oldest inactive flow if at capacity
                if len(self._active_flows) >= self.max_active_flows:
                    self._prune_oldest_flow()

                flow_id = f"flow_{self.total_flows_assembled + 1}_{fwd_tuple[0]}_{fwd_tuple[1]}"
                flow = BidirectionalFlow(
                    flow_id=flow_id,
                    src_ip=s_ip,
                    dst_ip=d_ip,
                    src_port=s_port,
                    dst_port=d_port,
                    protocol=p_code,
                    proto_name=p_name,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    fwd_packets=1,
                    bwd_packets=0,
                    fwd_bytes=length,
                    bwd_bytes=0,
                    has_syn=("S" in str(flags).upper()),
                    is_closed=("F" in str(flags).upper() or "R" in str(flags).upper()),
                    provenance=prov
                )
                self.total_flows_assembled += 1
                self._active_flows[fwd_tuple] = flow
                self._reverse_map[bwd_tuple] = fwd_tuple
                self._current_epoch_flows.append(flow)

            # If flow has terminated (FIN/RST), schedule for cleanup
            if flow.is_closed:
                # Flow recorded; keep in epoch flows for statistics but unregister from active table
                pass

            return flow

    def _advance_epochs_to_timestamp(self, current_ts: float):
        """
        Flushes finished epochs when time advances past 60-second boundaries.
        Emits explicit empty epochs if network traffic was completely absent during an epoch.
        """
        epoch_floor = math.floor(current_ts / self.epoch_duration) * self.epoch_duration

        if self._current_epoch_floor is None:
            self._current_epoch_floor = epoch_floor
            return

        # While there are completed epochs between _current_epoch_floor and current_ts
        while (self._current_epoch_floor + self.epoch_duration) <= current_ts:
            finished_epoch_floor = self._current_epoch_floor
            flows_in_epoch = list(self._current_epoch_flows)

            # Aggregate and store completed epoch
            epoch_record = self._calculate_epoch_features(finished_epoch_floor, flows_in_epoch)
            self._completed_epochs.append(epoch_record)

            # Prune closed or expired active flows
            self._prune_expired_flows(finished_epoch_floor + self.epoch_duration)

            # Move to next consecutive epoch
            self._current_epoch_floor += self.epoch_duration
            self._current_epoch_flows = []

    def _calculate_epoch_features(self, epoch_ts: float, flows: List[BidirectionalFlow]) -> FlowEpochRecord:
        """
        Calculates the authoritative 12 flow-level features for a discrete 60s epoch.
        Matches pipeline/temporal_preprocessor.py and models/temporal_forecasting/metadata.json.
        """
        from datetime import datetime
        iso_str = datetime.fromtimestamp(epoch_ts).strftime("%Y-%m-%d %H:%M:%S")

        tot_flows = len(flows)
        if tot_flows == 0:
            return FlowEpochRecord(
                epoch_timestamp=epoch_ts,
                epoch_iso=iso_str,
                flow_count=0,
                total_packets=0.0,
                total_bytes=0.0,
                mean_flow_duration_ms=0.0,
                std_flow_duration_ms=0.0,
                tcp_flow_ratio=0.0,
                udp_flow_ratio=0.0,
                dst_port_diversity=0,
                dst_port_entropy=0.0,
                distinct_src_ips=0,
                distinct_dst_ips=0,
                syn_flag_ratio=0.0,
                is_empty=True,
                provenance=self.provenance
            )

        # 1. flow_count
        flow_count = tot_flows

        # 2. total_packets
        tot_pkts = float(sum(f.total_packets for f in flows))

        # 3. total_bytes
        tot_bytes = float(sum(f.total_bytes for f in flows))

        # 4 & 5. Flow durations (in ms)
        durations = [f.duration_ms for f in flows]
        mean_dur = float(np.mean(durations))
        std_dur = float(np.std(durations, ddof=0)) if len(durations) > 1 else 0.0

        # 6 & 7. Protocol ratios
        tcp_count = sum(1 for f in flows if f.protocol == 6)
        udp_count = sum(1 for f in flows if f.protocol == 17)
        tcp_ratio = float(tcp_count) / tot_flows
        udp_ratio = float(udp_count) / tot_flows

        # 8 & 9. Destination Port Diversity & Shannon Entropy
        dst_ports = [f.dst_port for f in flows if f.dst_port > 0]
        dst_port_div = len(set(dst_ports))
        dst_port_ent = compute_shannon_entropy(dst_ports)

        # 10 & 11. Distinct IPs
        src_ips = set(f.src_ip for f in flows)
        dst_ips = set(f.dst_ip for f in flows)
        distinct_src = len(src_ips)
        distinct_dst = len(dst_ips)

        # 12. SYN Flag Ratio
        syn_count = sum(1 for f in flows if f.has_syn)
        syn_ratio = float(syn_count) / tot_flows

        return FlowEpochRecord(
            epoch_timestamp=epoch_ts,
            epoch_iso=iso_str,
            flow_count=flow_count,
            total_packets=tot_pkts,
            total_bytes=tot_bytes,
            mean_flow_duration_ms=mean_dur,
            std_flow_duration_ms=std_dur,
            tcp_flow_ratio=tcp_ratio,
            udp_flow_ratio=udp_ratio,
            dst_port_diversity=dst_port_div,
            dst_port_entropy=dst_port_ent,
            distinct_src_ips=distinct_src,
            distinct_dst_ips=distinct_dst,
            syn_flag_ratio=syn_ratio,
            is_empty=False,
            provenance=self.provenance
        )

    def _prune_expired_flows(self, current_time: float):
        """Removes flows that are closed or have exceeded idle/active timeout."""
        keys_to_del = []
        for key, flow in self._active_flows.items():
            is_idle = (current_time - flow.last_seen) > self.flow_idle_timeout
            is_over_max = (current_time - flow.first_seen) > self.flow_active_timeout
            if flow.is_closed or is_idle or is_over_max:
                keys_to_del.append(key)

        for key in keys_to_del:
            flow = self._active_flows.pop(key, None)
            # Remove associated reverse mapping
            bwd_tuple = (key[2], key[3], key[0], key[1], key[4])
            self._reverse_map.pop(bwd_tuple, None)

    def _prune_oldest_flow(self):
        """Evicts oldest flow to enforce memory bounding."""
        if not self._active_flows:
            return
        oldest_key = min(self._active_flows.keys(), key=lambda k: self._active_flows[k].last_seen)
        self._active_flows.pop(oldest_key, None)
        bwd_tuple = (oldest_key[2], oldest_key[3], oldest_key[0], oldest_key[1], oldest_key[4])
        self._reverse_map.pop(bwd_tuple, None)

    def flush_current_epoch(self, current_time: Optional[float] = None) -> Optional[FlowEpochRecord]:
        """
        Manually flushes the current epoch if populated, advancing historical context.
        Useful at stream completion (e.g. PCAP upload or test batch).
        """
        with self._lock:
            now = current_time if current_time is not None else (self.last_packet_timestamp or time.time())
            if self._current_epoch_floor is None:
                self._current_epoch_floor = math.floor(now / self.epoch_duration) * self.epoch_duration

            epoch_rec = self._calculate_epoch_features(self._current_epoch_floor, self._current_epoch_flows)
            self._completed_epochs.append(epoch_rec)

            self._current_epoch_floor += self.epoch_duration
            self._current_epoch_flows = []
            return epoch_rec

    def get_sliding_window_features(self) -> Dict[str, Any]:
        """
        Extracts the 120-dimensional flattened feature vector for Target A temporal forecasting.
        Requires exactly 10 consecutive 1-minute epochs: lag_9 (oldest) to lag_0 (newest).
        
        Returns:
            Dict containing:
            - "ready": bool (True only when 10 full epochs exist)
            - "status": str ("READY", "INSUFFICIENT_HISTORY", etc.)
            - "epochs_available": int
            - "epochs_required": int (10)
            - "features": np.ndarray shape (1, 120) or None
            - "feature_names": List[str] matching lag_order from metadata.json
        """
        with self._lock:
            n_epochs = len(self._completed_epochs)
            expected_names = [
                f"{col}_lag_{9-step}"
                for step in range(self.history_length)
                for col in PREDICTOR_COLUMNS
            ]

            if n_epochs < self.history_length:
                return {
                    "ready": False,
                    "status": "INSUFFICIENT_HISTORY",
                    "epochs_available": n_epochs,
                    "epochs_required": self.history_length,
                    "features": None,
                    "feature_names": expected_names,
                    "diagnostic": f"Need {self.history_length} consecutive 1-minute epochs. Currently have {n_epochs}."
                }

            # Stack exactly the 10 completed epochs in chronological order
            epochs_list = list(self._completed_epochs)[-self.history_length:]

            # Matrix shape: (10, 12)
            mat = np.zeros((self.history_length, len(PREDICTOR_COLUMNS)), dtype=np.float64)
            for step_idx, epoch in enumerate(epochs_list):
                feat_dict = epoch.to_feature_dict()
                for col_idx, col_name in enumerate(PREDICTOR_COLUMNS):
                    mat[step_idx, col_idx] = feat_dict[col_name]

            # Flatten to 1D vector (120,) then reshape to 2D (1, 120)
            flat_features = mat.flatten().reshape(1, -1)

            # Metadata timestamps
            anchor_epoch_iso = epochs_list[-1].epoch_iso
            oldest_epoch_iso = epochs_list[0].epoch_iso

            return {
                "ready": True,
                "status": "READY",
                "epochs_available": n_epochs,
                "epochs_required": self.history_length,
                "features": flat_features,
                "feature_names": expected_names,
                "anchor_epoch": anchor_epoch_iso,
                "oldest_epoch": oldest_epoch_iso,
                "target_horizon": "Onset within [anchor+3min, anchor+7min] after 2min clean gap"
            }

    def clear(self):
        """Resets all active flows and epoch buffers."""
        with self._lock:
            self._active_flows.clear()
            self._reverse_map.clear()
            self._current_epoch_floor = None
            self._current_epoch_flows.clear()
            self._completed_epochs.clear()
            self.total_packets_processed = 0
            self.total_flows_assembled = 0
            self.dropped_malformed_packets = 0
            self.last_packet_timestamp = None
