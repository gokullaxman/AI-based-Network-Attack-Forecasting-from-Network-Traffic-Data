"""
Phase 9B.1: Temporal Dataset Preprocessing and Target Validation Engine.
Processes authentic CICIDS2017 GeneratedLabelledFlows CSV files incrementally into
1-minute discrete network epochs, deriving dataset-native behavioral features,
and validates the candidate attack-onset forecasting target.
"""

import os
import glob
import json
import math
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional

TEMPORAL_RAW_DIR = os.path.join("data", "benchmark", "temporal", "raw")
TEMPORAL_META_DIR = os.path.join("data", "benchmark", "temporal", "metadata")


def parse_timestamp_series(series: pd.Series, apply_afternoon_correction: bool = True) -> pd.Series:
    """
    Parses CICIDS2017 timestamp strings handling both Monday (%d/%m/%Y %H:%M:%S)
    and Tue-Fri (%d/%m/%Y %H:%M) formats, truncating to 1-minute epoch boundaries.
    If apply_afternoon_correction is True, corrects the documented CICIDS2017 12-hour format omission
    for afternoon working hours (hours 1..7 -> 13..19) while strictly preserving morning hours (8..12).
    """
    s1 = pd.to_datetime(series, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    s2 = pd.to_datetime(series, format="%d/%m/%Y %H:%M", errors="coerce")
    combined = s1.fillna(s2)
    if apply_afternoon_correction:
        hours = combined.dt.hour
        is_pm = hours.isin([1, 2, 3, 4, 5, 6, 7])
        combined.loc[is_pm] = combined.loc[is_pm] + pd.Timedelta(hours=12)
    return combined.dt.floor("min")


def compute_shannon_entropy(series: pd.Series) -> float:
    """Computes normalized Shannon entropy of a categorical series."""
    if len(series) == 0:
        return 0.0
    counts = series.value_counts().values
    n = len(series)
    k = len(counts)
    if k <= 1:
        return 0.0
    probs = counts / n
    ent = -np.sum(probs * np.log2(probs))
    max_ent = math.log2(k)
    return float(ent / max_ent) if max_ent > 0 else 0.0


class TemporalEpochAggregator:
    """
    Incrementally aggregates flow records from GeneratedLabelledFlows CSVs into
    discrete 1-minute network traffic epochs with documented statistical features.
    """

    def __init__(self, raw_dir: str = TEMPORAL_RAW_DIR):
        self.raw_dir = raw_dir

    def process_file_to_epochs(self, fpath: str, chunk_size: int = 50_000) -> pd.DataFrame:
        """
        Processes a single CSV in streaming chunks, aggregating by 1-minute epochs.
        Avoids loading entire 300MB uncompressed CSVs into RAM simultaneously.
        """
        fname = os.path.basename(fpath)
        day_tag = fname.split("-")[0]

        # Read header to get exact column names from CSV
        header0 = list(pd.read_csv(fpath, nrows=0, encoding="latin1").columns)
        target_keys = {
            "timestamp": "Timestamp",
            "label": "Label",
            "flow id": "Flow ID",
            "source ip": "Source IP",
            "destination ip": "Destination IP",
            "destination port": "Destination Port",
            "protocol": "Protocol",
            "flow duration": "Flow Duration",
            "total fwd packets": "Total Fwd Packets",
            "total backward packets": "Total Backward Packets",
            "total length of fwd packets": "Total Length of Fwd Packets",
            "total length of bwd packets": "Total Length of Bwd Packets",
            "syn flag count": "SYN Flag Count"
        }

        actual_cols = []
        col_rename = {}
        for c in header0:
            c_clean = c.strip().lower()
            if c_clean in target_keys:
                actual_cols.append(c)
                col_rename[c] = target_keys[c_clean]

        epoch_groups = []

        for chunk in pd.read_csv(fpath, usecols=actual_cols, chunksize=chunk_size, encoding="latin1", low_memory=False):
            chunk = chunk.rename(columns=col_rename)

            # Parse and truncate timestamp to 1-minute epoch
            chunk["Epoch"] = parse_timestamp_series(chunk["Timestamp"])
            chunk = chunk[chunk["Epoch"].notnull()].copy()

            if len(chunk) == 0:
                continue

            # Standardize numeric columns
            chunk["TotalPackets"] = pd.to_numeric(chunk["Total Fwd Packets"], errors="coerce").fillna(1) + \
                                   pd.to_numeric(chunk["Total Backward Packets"], errors="coerce").fillna(0)
            chunk["TotalBytes"] = pd.to_numeric(chunk["Total Length of Fwd Packets"], errors="coerce").fillna(0) + \
                                 pd.to_numeric(chunk["Total Length of Bwd Packets"], errors="coerce").fillna(0)
            chunk["DurationMs"] = np.maximum(0.001, pd.to_numeric(chunk["Flow Duration"], errors="coerce").fillna(0) / 1000.0)

            # Attack vs Benign flow indicator
            is_attack = chunk["Label"].astype(str).str.strip().str.upper() != "BENIGN"
            chunk["IsAttack"] = is_attack

            has_syn = "SYN Flag Count" in chunk.columns

            # Group by 1-minute epoch within chunk
            for epoch_ts, grp in chunk.groupby("Epoch"):
                proto_counts = grp["Protocol"].value_counts()
                tot_flows = len(grp)
                tcp_ratio = float(proto_counts.get(6, 0)) / tot_flows
                udp_ratio = float(proto_counts.get(17, 0)) / tot_flows

                ports = grp["Destination Port"].dropna()
                syn_ratio = float(grp["SYN Flag Count"].sum()) / tot_flows if has_syn else 0.0

                attack_flows = int(grp["IsAttack"].sum())
                attack_classes = grp.loc[grp["IsAttack"], "Label"].unique().tolist()

                epoch_groups.append({
                    "epoch_timestamp": epoch_ts,
                    "capture_day": day_tag,
                    "capture_file": fname,
                    "flow_count": tot_flows,
                    "total_packets": float(grp["TotalPackets"].sum()),
                    "total_bytes": float(grp["TotalBytes"].sum()),
                    "mean_flow_duration_ms": float(grp["DurationMs"].mean()),
                    "std_flow_duration_ms": float(grp["DurationMs"].std(ddof=0)),
                    "tcp_flow_ratio": tcp_ratio,
                    "udp_flow_ratio": udp_ratio,
                    "dst_port_diversity": int(ports.nunique()),
                    "dst_port_entropy": compute_shannon_entropy(ports),
                    "distinct_src_ips": int(grp["Source IP"].nunique()),
                    "distinct_dst_ips": int(grp["Destination IP"].nunique()),
                    "syn_flag_ratio": syn_ratio,
                    "attack_flow_count": attack_flows,
                    "benign_flow_count": tot_flows - attack_flows,
                    "is_attack_active": attack_flows > 0,
                    "attack_classes": attack_classes
                })

        if not epoch_groups:
            return pd.DataFrame()

        # Combine across chunks for the file (aggregating any epoch spanning multiple chunks)
        raw_epochs_df = pd.DataFrame(epoch_groups)

        # Merge epochs that had rows in separate chunks
        agg_rules = {
            "capture_day": "first",
            "capture_file": "first",
            "flow_count": "sum",
            "total_packets": "sum",
            "total_bytes": "sum",
            "mean_flow_duration_ms": "mean",
            "std_flow_duration_ms": "mean",
            "tcp_flow_ratio": "mean",
            "udp_flow_ratio": "mean",
            "dst_port_diversity": "max",
            "dst_port_entropy": "mean",
            "distinct_src_ips": "max",
            "distinct_dst_ips": "max",
            "syn_flag_ratio": "mean",
            "attack_flow_count": "sum",
            "benign_flow_count": "sum",
            "is_attack_active": "max"
        }

        # Handle list aggregation for attack classes
        file_epochs = raw_epochs_df.groupby("epoch_timestamp", as_index=False).agg(agg_rules)
        file_epochs["is_attack_active"] = file_epochs["attack_flow_count"] > 0
        file_epochs = file_epochs.sort_values("epoch_timestamp").reset_index(drop=True)

        return file_epochs

    def process_all_files(self) -> pd.DataFrame:
        """Processes all 7 extracted temporal CSVs into an aggregated chronological epoch table."""
        csv_files = sorted(glob.glob(os.path.join(self.raw_dir, "*.csv")))
        if not csv_files:
            raise FileNotFoundError(f"No temporal CSV files found in {self.raw_dir}")

        all_day_dfs = []
        for fpath in csv_files:
            print(f"Aggregating epochs for: {os.path.basename(fpath)}...")
            df_epoch = self.process_file_to_epochs(fpath)
            all_day_dfs.append(df_epoch)

        combined = pd.concat(all_day_dfs, ignore_index=True)
        # Sort chronologically by epoch timestamp
        combined = combined.sort_values("epoch_timestamp").reset_index(drop=True)
        return combined


class ForecastingTargetValidator:
    """
    Validates the candidate forecasting target:
    - History: 10 consecutive 1-minute epochs ([t-9, ..., t])
    - Lead time: 2 minutes ([t+1, t+2])
    - Horizon: 5 minutes ([t+3, ..., t+7])
    - Pre-onset condition: History [t-9, ..., t] must be 100% attack-free.
    """

    def __init__(
        self,
        history_len: int = 10,
        lead_time_gap: int = 2,
        horizon_len: int = 5,
        target_type: str = "onset"
    ):
        self.history_len = history_len
        self.lead_time_gap = lead_time_gap
        self.horizon_len = horizon_len
        self.target_type = target_type
        self.total_window_span = history_len + lead_time_gap + horizon_len  # 17 minutes

    def audit_target_on_epochs(self, epochs_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Audits candidate forecasting windows across the epoch sequence.
        Identifies positive onset windows, negative benign windows, ineligible ongoing attack windows,
        and capture gap exclusions.
        """
        valid_epochs_count = len(epochs_df)
        eligible_windows = 0
        positive_windows = 0
        negative_windows = 0
        ineligible_active_attack_in_history = 0
        ineligible_active_attack_in_gap = 0
        excluded_boundary_or_gap = 0

        # Group by capture day to prevent overnight window stitching
        onset_events = []

        for day_name, day_df in epochs_df.groupby("capture_day"):
            day_df = day_df.sort_values("epoch_timestamp").reset_index(drop=True)
            n_epochs = len(day_df)

            # Detect continuous blocks (epochs separated by exactly 1 minute)
            time_diffs = (day_df["epoch_timestamp"].diff().dt.total_seconds() / 60.0).fillna(1.0)
            is_continuous = (time_diffs == 1.0)

            for i in range(n_epochs):
                # Ensure we have enough history (i - 9 >= 0) and enough horizon (i + 7 < n_epochs)
                if i < (self.history_len - 1) or (i + self.lead_time_gap + self.horizon_len) >= n_epochs:
                    excluded_boundary_or_gap += 1
                    continue

                hist_indices = range(i - self.history_len + 1, i + 1)
                lead_indices = range(i + 1, i + 1 + self.lead_time_gap)
                horizon_indices = range(i + 1 + self.lead_time_gap, i + 1 + self.lead_time_gap + self.horizon_len)

                # Check continuity across the full window span
                all_indices = list(range(i - self.history_len + 1, i + 1 + self.lead_time_gap + self.horizon_len))
                if not is_continuous.iloc[all_indices[1:]].all():
                    excluded_boundary_or_gap += 1
                    continue

                hist_slice = day_df.iloc[hist_indices]
                gap_slice = day_df.iloc[lead_indices]
                horizon_slice = day_df.iloc[horizon_indices]

                # Eligibility Condition 1: History must be completely attack-free (pre-onset condition)
                has_attack_in_hist = (hist_slice["attack_flow_count"] > 0).any()
                if has_attack_in_hist:
                    ineligible_active_attack_in_history += 1
                    continue

                # Eligibility Condition 2 (Target A onset forecasting): Gap must also be completely attack-free
                has_attack_in_gap = (gap_slice["attack_flow_count"] > 0).any()
                if self.target_type == "onset" and has_attack_in_gap:
                    ineligible_active_attack_in_gap += 1
                    continue

                eligible_windows += 1

                # Target calculation: Attack flow appears in horizon
                attack_in_horizon = (horizon_slice["attack_flow_count"] > 0).any()
                if attack_in_horizon:
                    positive_windows += 1
                    onset_events.append({
                        "capture_day": day_name,
                        "current_epoch": str(day_df.iloc[i]["epoch_timestamp"]),
                        "horizon_start": str(horizon_slice.iloc[0]["epoch_timestamp"]),
                        "horizon_end": str(horizon_slice.iloc[-1]["epoch_timestamp"]),
                        "attack_flows_in_horizon": int(horizon_slice["attack_flow_count"].sum())
                    })
                else:
                    negative_windows += 1

        # Count independent onset events (clusters of positive windows leading up to the same attack start)
        clusters = []
        curr_cluster = []
        for ev in onset_events:
            if not curr_cluster:
                curr_cluster.append(ev)
            else:
                prev_ev = curr_cluster[-1]
                t_prev = pd.to_datetime(prev_ev["current_epoch"])
                t_curr = pd.to_datetime(ev["current_epoch"])
                diff_min = (t_curr - t_prev).total_seconds() / 60.0
                if diff_min <= (self.horizon_len + self.lead_time_gap + 1) and ev["capture_day"] == prev_ev["capture_day"]:
                    curr_cluster.append(ev)
                else:
                    clusters.append(curr_cluster)
                    curr_cluster = [ev]
        if curr_cluster:
            clusters.append(curr_cluster)

        independent_onset_count = len(clusters)

        audit_results = {
            "total_epochs": valid_epochs_count,
            "window_parameters": {
                "history_length_minutes": self.history_len,
                "lead_time_gap_minutes": self.lead_time_gap,
                "prediction_horizon_minutes": self.horizon_len,
                "total_window_span_minutes": self.total_window_span
            },
            "window_counts": {
                "total_eligible_windows": eligible_windows,
                "positive_onset_windows": positive_windows,
                "negative_attack_free_windows": negative_windows,
                "class_imbalance_ratio": (
                    f"1 positive : {negative_windows // positive_windows if positive_windows > 0 else 0} negative"
                ),
                "ineligible_windows_active_attack_in_history": ineligible_active_attack_in_history,
                "ineligible_windows_active_attack_in_gap": ineligible_active_attack_in_gap,
                "excluded_boundary_or_continuity_gap_windows": excluded_boundary_or_gap
            },
            "independent_attack_onsets": {
                "total_independent_onsets": independent_onset_count,
                "onset_events_detail": onset_events
            }
        }

        return audit_results
