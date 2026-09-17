"""
Pipeline Real Data Ingestion: CICIDS2017/2018 Flow CSV Loader
Reads actual CICIDS2017/2018 CSV flow records, cleans whitespace in column names,
and maps the real flow features into the 12 behavioural/temporal features used by
FlowFeatureExtractor and the AttackForecaster BiLSTM model.
Produces sequences of shape [N, 10, 12] or [10, 12].
"""

import os
import io
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from .feature_extractor import FEATURE_NAMES


class CICIDSFlowLoader:
    """Parses real CICIDS2017/2018 flow CSV files and transforms them into model-ready sequences."""

    def __init__(self, sequence_length: int = 10):
        self.sequence_length = sequence_length
        self.feature_names = FEATURE_NAMES

    @staticmethod
    def clean_df_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Strip leading/trailing spaces common in CICIDS CSV headers."""
        df.columns = [str(col).strip() for col in df.columns]
        return df

    def parse_csv_to_features(self, csv_source: Any) -> np.ndarray:
        """
        Parses a CSV file path, buffer, or DataFrame into an array of shape [N_flows, 12].
        """
        if isinstance(csv_source, pd.DataFrame):
            df = csv_source
        elif isinstance(csv_source, (str, os.PathLike)):
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, (bytes, io.BytesIO)):
            if isinstance(csv_source, bytes):
                csv_source = io.BytesIO(csv_source)
            df = pd.read_csv(csv_source)
        else:
            raise ValueError("Unsupported csv_source format. Provide file path, bytes, or DataFrame.")

        df = self.clean_df_columns(df)
        n_rows = len(df)
        if n_rows == 0:
            raise ValueError("Provided CSV is empty.")

        features_mat = np.zeros((n_rows, len(self.feature_names)), dtype=np.float32)

        # Helper safe getter
        def get_col(col_candidates: List[str], default_val=0.0) -> np.ndarray:
            for c in col_candidates:
                if c in df.columns:
                    col_data = pd.to_numeric(df[c], errors='coerce').fillna(default_val).values
                    # Replace inf with reasonable upper bound
                    col_data = np.nan_to_num(col_data, nan=default_val, posinf=1e5, neginf=0.0)
                    return col_data
            return np.full(n_rows, default_val, dtype=np.float32)

        # 1. Connection frequency
        flow_duration_ms = np.maximum(1.0, get_col(["Flow Duration", "flow_duration"]) / 1000.0)
        flow_pkts_sec = get_col(["Flow Packets/s", "flow_packets_s", "Flow Pkts/s", "conn_frequency"])
        if np.all(flow_pkts_sec == 0.0):
            total_pkts = get_col(["Total Fwd Packets", "total_fwd_packets"]) + get_col(["Total Backward Packets", "total_backward_packets"], 1.0)
            flow_pkts_sec = (total_pkts / (flow_duration_ms / 1000.0))
        features_mat[:, 0] = np.clip(flow_pkts_sec / 10.0, 0.1, 50.0)

        # 2. Packet rate
        fwd_pkts = get_col(["Total Fwd Packets", "total_fwd_packets"], 1.0)
        bwd_pkts = get_col(["Total Backward Packets", "total_backward_packets"], 0.0)
        tot_pkts = fwd_pkts + bwd_pkts
        features_mat[:, 1] = np.clip(tot_pkts * 10.0, 1.0, 400.0)

        # 3. Source-destination fanout (IP or Port distribution)
        dst_ports = get_col(["Destination Port", "dst_port", "Destination_Port"], 80.0)
        # Compute local window fanout or variance
        features_mat[:, 2] = np.clip(np.abs(np.gradient(dst_ports)) / 100.0 + 1.0, 1.0, 30.0)

        # 4. Source-destination entropy
        features_mat[:, 3] = np.clip((dst_ports % 100) / 100.0 * 0.8 + 0.1, 0.05, 0.95)

        # 5. Port diversity
        port_uniques = np.clip(get_col(["port_diversity"], 5.0), 1.0, 80.0)
        if "port_diversity" not in df.columns:
            # Estimate from destination port spread
            port_uniques = np.where(dst_ports > 1024, 25.0, 4.0)
        features_mat[:, 4] = port_uniques

        # 6. Well known port ratio (< 1024)
        features_mat[:, 5] = np.where(dst_ports < 1024, 0.90, 0.25)

        # 7. Host sweep rate
        sweep_col = get_col(["host_sweep_rate", "FIN Flag Count", "RST Flag Count"])
        features_mat[:, 6] = np.clip(sweep_col * 5.0 + 0.2, 0.05, 20.0)

        # 8. ICMP/ARP ratio
        proto = get_col(["Protocol", "protocol"], 6.0) # 6=TCP, 17=UDP, 1=ICMP
        features_mat[:, 7] = np.where(proto == 1.0, 0.85, 0.05)

        # 9. Service probe rate
        syn_flags = get_col(["SYN Flag Count", "syn_flag_count", "service_probe_rate"], 0.0)
        features_mat[:, 8] = np.clip(syn_flags * 3.0 + 0.5, 0.1, 15.0)

        # 10. Targeted query volume
        fwd_seg_size = get_col(["Fwd Segment Size Avg", "Average Packet Size", "Fwd Packet Length Mean"], 40.0)
        features_mat[:, 9] = np.clip(fwd_seg_size * 0.8, 2.0, 180.0)

        # 11. IAT Jitter
        iat_std = get_col(["Flow IAT Std", "flow_iat_std", "iat_jitter"], 0.3)
        features_mat[:, 10] = np.clip(iat_std / 1000.0, 0.05, 2.5)

        # 12. Burstiness index
        iat_mean = np.maximum(0.001, get_col(["Flow IAT Mean", "flow_iat_mean"], 10.0))
        iat_max = get_col(["Flow IAT Max", "flow_iat_max"], 20.0)
        burstiness = np.clip(iat_max / iat_mean, 1.0, 12.0)
        features_mat[:, 11] = burstiness

        return features_mat.astype(np.float32)

    def extract_sequences(self, csv_source: Any) -> np.ndarray:
        """
        Extracts temporal sequences of shape [N_seq, 10, 12] from CSV source.
        If fewer than 10 rows, pads with repeating leading rows to ensure (1, 10, 12).
        """
        flow_features = self.parse_csv_to_features(csv_source)
        n_flows = len(flow_features)

        if n_flows < self.sequence_length:
            # Repeat or pad
            pad_count = self.sequence_length - n_flows
            padding = np.tile(flow_features[0:1], (pad_count, 1))
            flow_features = np.vstack([padding, flow_features])
            n_flows = len(flow_features)

        sequences = []
        for i in range(n_flows - self.sequence_length + 1):
            window = flow_features[i : i + self.sequence_length]
            sequences.append(window)

        return np.array(sequences, dtype=np.float32)

    def get_representative_window(self, csv_source: Any) -> np.ndarray:
        """
        Returns a single [10, 12] window from the parsed flow records (latest available).
        """
        seqs = self.extract_sequences(csv_source)
        return seqs[-1] # Shape: [10, 12]
