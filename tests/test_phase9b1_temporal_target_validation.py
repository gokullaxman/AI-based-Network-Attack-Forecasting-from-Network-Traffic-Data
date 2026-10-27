"""
Test suite for Phase 9B.1: Temporal Dataset Preparation and Target Validation.

Verifies:
1. Timestamp parsing across both authentic formats (Monday with seconds, Tue-Fri without seconds).
2. Simultaneous flow aggregation within 1-minute discrete epochs (no artificial row-order sorting).
3. Forecast-window boundary definitions (10-min history, 2-min lead-time gap, 5-min horizon).
4. Window exclusion across overnight boundaries and capture continuity gaps (>1 minute).
5. Pre-onset history eligibility condition (windows with active attack in history marked ineligible).
6. Independent attack onset clustering vs ongoing attack duration.
7. Strict isolation of production model weights, production scaler, and Phase 8B artifacts.
"""

import os
import hashlib
import pytest
import pandas as pd
import numpy as np

from pipeline.temporal_preprocessor import (
    parse_timestamp_series,
    TemporalEpochAggregator,
    ForecastingTargetValidator,
    TEMPORAL_META_DIR,
    TEMPORAL_RAW_DIR
)


def test_parse_timestamp_series_monday_format_with_seconds():
    """Verifies that Monday's timestamp format (%d/%m/%Y %H:%M:%S) truncates to 1-minute floor."""
    s = pd.Series([
        "03/07/2017 08:55:00",
        "03/07/2017 08:55:14",
        "03/07/2017 08:55:59",
        "03/07/2017 08:56:01"
    ])
    parsed = parse_timestamp_series(s)
    
    assert str(parsed.iloc[0]) == "2017-07-03 08:55:00"
    assert str(parsed.iloc[1]) == "2017-07-03 08:55:00"
    assert str(parsed.iloc[2]) == "2017-07-03 08:55:00"
    assert str(parsed.iloc[3]) == "2017-07-03 08:56:00"


def test_parse_timestamp_series_tuesday_friday_format_without_seconds():
    """Verifies that Tue-Fri format (%d/%m/%Y %H:%M) parses correctly without sub-minute information."""
    s = pd.Series([
        "4/7/2017 8:54",
        "04/07/2017 08:54",
        "5/7/2017 10:05",
        "7/7/2017 15:30"
    ])
    parsed = parse_timestamp_series(s)
    
    assert str(parsed.iloc[0]) == "2017-07-04 08:54:00"
    assert str(parsed.iloc[1]) == "2017-07-04 08:54:00"
    assert str(parsed.iloc[2]) == "2017-07-05 10:05:00"
    assert str(parsed.iloc[3]) == "2017-07-07 15:30:00"


def test_simultaneous_flows_in_epoch_no_artificial_order(tmp_path):
    """Verifies that multiple flows sharing identical timestamps aggregate into one discrete epoch."""
    # Simulate 5 flows at the exact same minute
    df_chunk = pd.DataFrame({
        "Flow ID": ["f1", "f2", "f3", "f4", "f5"],
        "Source IP": ["192.168.1.1", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.1"],
        "Destination IP": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.1", "10.0.0.3"],
        "Destination Port": [80, 443, 80, 22, 8080],
        "Protocol": [6, 6, 6, 6, 17],
        "Timestamp": ["04/07/2017 09:00"] * 5,
        "Flow Duration": [1000, 2000, 1500, 3000, 500],
        "Total Fwd Packets": [10, 5, 8, 20, 2],
        "Total Backward Packets": [8, 4, 6, 15, 1],
        "Total Length of Fwd Packets": [500, 250, 400, 1000, 100],
        "Total Length of Bwd Packets": [400, 200, 300, 800, 50],
        "SYN Flag Count": [1, 0, 1, 1, 0],
        "Label": ["BENIGN", "BENIGN", "BENIGN", "BENIGN", "BENIGN"]
    })

    mock_csv = tmp_path / "Tuesday-Test_ISCX.csv"
    df_chunk.to_csv(mock_csv, index=False)

    aggregator = TemporalEpochAggregator()
    epochs_df = aggregator.process_file_to_epochs(str(mock_csv))

    assert len(epochs_df) == 1
    row = epochs_df.iloc[0]
    assert row["flow_count"] == 5
    assert row["attack_flow_count"] == 0
    assert row["total_packets"] == (10+5+8+20+2) + (8+4+6+15+1)
    assert row["distinct_src_ips"] == 3
    assert row["distinct_dst_ips"] == 3


def test_forecast_window_boundary_definitions():
    """Verifies 10-minute history, 2-minute lead-time gap, and 5-minute forecast horizon."""
    validator = ForecastingTargetValidator(history_len=10, lead_time_gap=2, horizon_len=5)
    
    # 17 continuous 1-minute epochs (09:00 to 09:16)
    times = pd.date_range("2017-07-04 09:00:00", periods=17, freq="1min")
    epochs_data = []
    for i, t in enumerate(times):
        epochs_data.append({
            "capture_day": "Tuesday",
            "epoch_timestamp": t,
            "flow_count": 100,
            "attack_flow_count": 0
        })
    df_epochs = pd.DataFrame(epochs_data)
    
    res = validator.audit_target_on_epochs(df_epochs)
    # With 17 minutes, exactly 1 window fits:
    # History: 09:00-09:09 (indices 0..9)
    # Current epoch t = 09:09
    # Lead-time gap: 09:10-09:11 (indices 10..11)
    # Horizon: 09:12-09:16 (indices 12..16)
    w_counts = res["window_counts"]
    assert w_counts["total_eligible_windows"] == 1
    assert w_counts["positive_onset_windows"] == 0
    assert w_counts["negative_attack_free_windows"] == 1


def test_exclusion_of_overnight_and_capture_gaps():
    """Verifies that windows spanning overnight or missing-minute gaps are excluded."""
    validator = ForecastingTargetValidator(history_len=10, lead_time_gap=2, horizon_len=5)
    
    # 10 minutes on Day 1, followed by overnight gap, then 7 minutes on Day 2
    times_day1 = pd.date_range("2017-07-03 16:50:00", periods=10, freq="1min")
    times_day2 = pd.date_range("2017-07-04 09:00:00", periods=7, freq="1min")
    
    epochs_data = []
    for t in times_day1:
        epochs_data.append({
            "capture_day": "Monday",
            "epoch_timestamp": t,
            "flow_count": 50,
            "attack_flow_count": 0
        })
    for t in times_day2:
        epochs_data.append({
            "capture_day": "Tuesday",
            "epoch_timestamp": t,
            "flow_count": 50,
            "attack_flow_count": 0
        })
    df_epochs = pd.DataFrame(epochs_data)
    
    res = validator.audit_target_on_epochs(df_epochs)
    # Because there are only 10 minutes on Monday (< 17 needed) and 7 on Tuesday (< 17 needed),
    # no window can be formed without crossing the day boundary.
    assert res["window_counts"]["total_eligible_windows"] == 0
    assert res["window_counts"]["excluded_boundary_or_continuity_gap_windows"] > 0


def test_pre_onset_history_eligibility_condition():
    """Verifies that an active attack occurring within the history window marks it ineligible for onset."""
    validator = ForecastingTargetValidator(history_len=10, lead_time_gap=2, horizon_len=5)
    
    # 17 continuous minutes
    times = pd.date_range("2017-07-05 10:00:00", periods=17, freq="1min")
    
    # Case A: Attack in history (at t = 10:05) -> Ineligible for onset forecasting
    epochs_a = []
    for i, t in enumerate(times):
        atk = 10 if i == 5 else 0
        epochs_a.append({
            "capture_day": "Wednesday",
            "epoch_timestamp": t,
            "flow_count": 100,
            "attack_flow_count": atk
        })
    df_a = pd.DataFrame(epochs_a)
    res_a = validator.audit_target_on_epochs(df_a)
    assert res_a["window_counts"]["total_eligible_windows"] == 0
    assert res_a["window_counts"]["ineligible_windows_active_attack_in_history"] == 1

    # Case B: Clean history, clean gap, attack in horizon (at index 14, 10:14) -> Positive onset (y=1)
    epochs_b = []
    for i, t in enumerate(times):
        atk = 50 if i == 14 else 0
        epochs_b.append({
            "capture_day": "Wednesday",
            "epoch_timestamp": t,
            "flow_count": 100,
            "attack_flow_count": atk
        })
    df_b = pd.DataFrame(epochs_b)
    res_b = validator.audit_target_on_epochs(df_b)
    assert res_b["window_counts"]["total_eligible_windows"] == 1
    assert res_b["window_counts"]["positive_onset_windows"] == 1
    assert res_b["window_counts"]["negative_attack_free_windows"] == 0


def test_independent_attack_onsets_clustering():
    """Verifies that a continuous 30-minute attack event counts as 1 independent onset."""
    validator = ForecastingTargetValidator(history_len=10, lead_time_gap=2, horizon_len=5)
    
    # 50 continuous minutes:
    # 0..19: Clean benign
    # 20..49: Continuous attack (30 minutes)
    times = pd.date_range("2017-07-06 14:00:00", periods=50, freq="1min")
    epochs_data = []
    for i, t in enumerate(times):
        atk = 500 if i >= 20 else 0
        epochs_data.append({
            "capture_day": "Thursday",
            "epoch_timestamp": t,
            "flow_count": 600,
            "attack_flow_count": atk
        })
    df_epochs = pd.DataFrame(epochs_data)
    
    res = validator.audit_target_on_epochs(df_epochs)
    onsets_info = res["independent_attack_onsets"]
    
    # There should only be 1 independent onset event detected
    assert onsets_info["total_independent_onsets"] == 1
    onset_ev = onsets_info["onset_events_detail"][0]
    assert onset_ev["capture_day"] == "Thursday"


def test_production_and_phase8b_artifact_integrity():
    """Verifies that production model weights, scaler, and Phase 8B artifacts are pristine."""
    expected_weights_hash = "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
    expected_scaler_hash = "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"
    
    def sha256_of_file(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    assert sha256_of_file("models/bilstm_weights.pt") == expected_weights_hash
    assert sha256_of_file("pipeline/scaler.pkl") == expected_scaler_hash
    
    # Verify Phase 8B multiattack directory exists and has its artifacts intact
    phase8b_dir = "models/benchmark_multiattack"
    assert os.path.exists(phase8b_dir)
    assert os.path.exists(os.path.join(phase8b_dir, "multiattack_evaluation_results.json"))
    assert os.path.exists(os.path.join(phase8b_dir, "multiattack_preprocessing_config.json"))
    assert os.path.exists(os.path.join(phase8b_dir, "baseline_multiattack_rf.pkl"))
