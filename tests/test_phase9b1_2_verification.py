"""
Test Suite for Phase 9B.1.2: Timestamp, Event Ledger, and Feature-Definition Verification.

Verifies:
1. Timestamp chronology and afternoon shift rule (+12h for raw hours 1..7 on WorkingHours files).
2. Zero within-day continuity gaps across all 5 capture days post-correction (2,209 contiguous epochs).
3. Machine-readable event ledger (57 strict ground-truth episodes, 19 forecastable onsets under Target A).
4. Target A formulation (clean 10-min history, clean 2-min gap, newly starting onset in 5-min horizon).
5. Feature definitions and bounds (normalized Shannon entropy [0, 1], SYN flag ratio [0, 1], zero NaNs/infs).
6. Chronological evaluation split (Mon-Wed train vs Thu-Fri test) with zero category overlap.
7. Strict preservation and isolation of pre-correction artifacts and production weights/scaler.
"""

import os
import json
import hashlib
import pytest
import pandas as pd
import numpy as np

EPOCHS_PARQUET = "data/benchmark/temporal/metadata/epochs_1min.parquet"
PRE_CORRECTION_PARQUET = "data/benchmark/temporal/metadata/epochs_1min_pre_correction_phase9b1_1.parquet"
TIMESTAMP_AUDIT_JSON = "data/benchmark/temporal/metadata/phase9b1_2_timestamp_audit.json"
EVENT_LEDGER_CSV = "data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv"
TARGET_AUDIT_JSON = "data/benchmark/temporal/metadata/phase9b1_2_target_audit.json"
FEATURE_AUDIT_JSON = "data/benchmark/temporal/metadata/phase9b1_2_feature_audit.json"

PRODUCTION_WEIGHTS = "models/bilstm_weights.pt"
PRODUCTION_SCALER = "pipeline/scaler.pkl"

PREDICTOR_COLUMNS = [
    "flow_count", "total_packets", "total_bytes",
    "mean_flow_duration_ms", "std_flow_duration_ms",
    "tcp_flow_ratio", "udp_flow_ratio",
    "dst_port_diversity", "dst_port_entropy",
    "distinct_src_ips", "distinct_dst_ips", "syn_flag_ratio"
]

EXCLUDED_LABEL_COLUMNS = [
    "attack_flow_count", "benign_flow_count", "is_attack_active", "attack_classes"
]


def test_timestamp_chronology_and_unbroken_continuity():
    """Verifies Task 1: Defensible afternoon timestamp correction and 100% daily continuity."""
    assert os.path.exists(TIMESTAMP_AUDIT_JSON), "Timestamp audit JSON missing"
    with open(TIMESTAMP_AUDIT_JSON, "r") as fp:
        ts_audit = json.load(fp)

    assert ts_audit["total_flow_records_shifted"] == 1_183_114
    assert ts_audit["total_flow_records_preserved"] == 1_359_027
    assert ts_audit["total_ambiguous_records"] == 0

    df_epochs = pd.read_parquet(EPOCHS_PARQUET)
    assert len(df_epochs) == 2209

    expected_daily = {
        "Monday": {"count": 487, "min": "2017-07-03 08:55:00", "max": "2017-07-03 17:01:00"},
        "Tuesday": {"count": 488, "min": "2017-07-04 08:53:00", "max": "2017-07-04 17:00:00"},
        "Wednesday": {"count": 509, "min": "2017-07-05 08:42:00", "max": "2017-07-05 17:10:00"},
        "Thursday": {"count": 241, "min": "2017-07-06 08:59:00", "max": "2017-07-06 12:59:00"},
        "Friday": {"count": 484, "min": "2017-07-07 08:59:00", "max": "2017-07-07 17:02:00"},
    }

    for day, exp in expected_daily.items():
        df_day = df_epochs[df_epochs["capture_day"] == day].sort_values("epoch_timestamp").reset_index(drop=True)
        assert len(df_day) == exp["count"], f"Mismatch in {day} epoch count"
        assert str(df_day["epoch_timestamp"].min()) == exp["min"], f"Mismatch in {day} min timestamp"
        assert str(df_day["epoch_timestamp"].max()) == exp["max"], f"Mismatch in {day} max timestamp"

        # Verify 0 within-day gaps: every step is exactly 1 minute
        diffs = (df_day["epoch_timestamp"].diff().dt.total_seconds() / 60.0).dropna()
        assert (diffs > 1.0).sum() == 0, f"Detected within-day gap > 1 minute on {day}"
        assert (diffs == 1.0).sum() == exp["count"] - 1, f"Non-continuous minute step on {day}"


def test_machine_readable_event_ledger():
    """Verifies Task 2: Machine-readable event ledger and episode reconciliations."""
    assert os.path.exists(EVENT_LEDGER_CSV), "Event ledger CSV missing"
    df_ledger = pd.read_csv(EVENT_LEDGER_CSV)

    # 57 strict ground-truth attack episodes
    assert len(df_ledger) == 57

    required_cols = [
        "event_id", "capture_day", "source_file", "start_time", "end_time",
        "duration_minutes", "attack_classes", "attack_flows",
        "preceding_10m_history_clean", "preceding_2m_gap_clean",
        "is_forecastable_target_a", "associated_positive_windows_count",
        "associated_anchor_epochs", "partition"
    ]
    for col in required_cols:
        assert col in df_ledger.columns, f"Missing required ledger column: {col}"

    # Forecastable onsets under Target A
    forecastable = df_ledger[df_ledger["is_forecastable_target_a"] == True]
    assert len(forecastable) == 19

    train_forecastable = forecastable[forecastable["partition"] == "TRAIN"]
    test_forecastable = forecastable[forecastable["partition"] == "TEST"]
    assert len(train_forecastable) == 9
    assert len(test_forecastable) == 10

    # Total associated positive forecast windows across episodes
    # Unique positive forecast windows = 65
    # Total episode-window associations = 76 (due to closely-spaced onsets sharing the same 5-min horizon)
    all_associated_anchors = []
    for anchors_str in forecastable["associated_anchor_epochs"]:
        for a in str(anchors_str).split("|"):
            if a:
                all_associated_anchors.append(a)

    assert len(all_associated_anchors) == 76
    assert len(set(all_associated_anchors)) == 65
    assert forecastable["associated_positive_windows_count"].sum() == 76

    # Unforecastable episodes have 0 associated positive windows
    unforecastable = df_ledger[df_ledger["is_forecastable_target_a"] == False]
    assert (unforecastable["associated_positive_windows_count"] == 0).all()


def test_target_a_onset_formulation_audit():
    """Verifies Task 3: Target A genuine onset semantics vs Target B future activity."""
    assert os.path.exists(TARGET_AUDIT_JSON), "Target audit JSON missing"
    with open(TARGET_AUDIT_JSON, "r") as fp:
        target_audit = json.load(fp)

    target_a = target_audit["rebuilt_target_a_onset"]
    assert target_a["eligible_windows"] == 1397
    assert target_a["positive_windows"] == 65
    assert target_a["negative_windows"] == 1332
    assert target_a["ineligible_attack_in_history"] == 704
    assert target_a["ineligible_attack_in_gap"] == 28
    assert target_a["excluded_boundary_windows"] == 80
    assert target_a["eligible_windows"] + target_a["ineligible_attack_in_history"] + target_a["ineligible_attack_in_gap"] + target_a["excluded_boundary_windows"] == 2209

    target_b = target_audit["rebuilt_target_b_activity"]
    assert target_b["eligible_windows"] == 1425
    assert target_b["positive_windows"] == 89
    assert target_b["negative_windows"] == 1336
    # Target B allows attack activity in the lead gap
    assert target_b["ineligible_attack_in_gap"] == 0


def test_feature_definitions_bounds_and_validity():
    """Verifies Task 4: Normalized Shannon entropy, SYN flag ratio, and predictor integrity."""
    assert os.path.exists(FEATURE_AUDIT_JSON), "Feature audit JSON missing"
    with open(FEATURE_AUDIT_JSON, "r") as fp:
        feat_audit = json.load(fp)

    assert feat_audit["candidate_predictor_count"] == 12
    assert feat_audit["flattened_input_dimension_10min"] == 120

    specs = feat_audit["predictor_specifications"]
    entropy_spec = specs["dst_port_entropy"]
    assert entropy_spec["valid_range"] == "[0.0, 1.0]"
    assert entropy_spec["bounds_verified"] is True
    assert "Normalized Shannon Entropy" in entropy_spec["entropy_type"]

    syn_spec = specs["syn_flag_ratio"]
    assert syn_spec["valid_range"] == "[0.0, 1.0]"
    assert syn_spec["bounds_verified"] is True

    # Empirical validation on rebuilt parquet
    df_epochs = pd.read_parquet(EPOCHS_PARQUET)
    dists = feat_audit["empirical_feature_distributions"]

    for col in PREDICTOR_COLUMNS:
        assert col in df_epochs.columns
        s = df_epochs[col]
        assert not s.isnull().any(), f"Feature {col} has nulls"
        assert not np.isinf(s).any(), f"Feature {col} has infinities"
        assert s.std() > 0.0, f"Feature {col} is constant"

        # Check recorded distribution matches dataframe
        assert dists[col]["null_count"] == 0
        assert dists[col]["inf_count"] == 0
        assert dists[col]["is_constant"] is False

    # Check bounds explicitly
    assert (df_epochs["dst_port_entropy"] >= 0.0).all()
    assert (df_epochs["dst_port_entropy"] <= 1.0).all()
    assert (df_epochs["syn_flag_ratio"] >= 0.0).all()
    assert (df_epochs["syn_flag_ratio"] <= 1.0).all()
    assert (df_epochs["tcp_flow_ratio"] >= 0.0).all()
    assert (df_epochs["tcp_flow_ratio"] <= 1.0).all()
    assert (df_epochs["udp_flow_ratio"] >= 0.0).all()
    assert (df_epochs["udp_flow_ratio"] <= 1.0).all()

    # Verify label leakage fields are excluded from predictors
    for lbl in EXCLUDED_LABEL_COLUMNS:
        assert lbl not in PREDICTOR_COLUMNS


def test_chronological_evaluation_split():
    """Verifies Task 5: Mon-Wed train vs Thu-Fri test split and zero-category overlap."""
    with open(TARGET_AUDIT_JSON, "r") as fp:
        target_audit = json.load(fp)

    split = target_audit["chronological_split_target_a"]
    train_split = split["train_mon_wed"]
    test_split = split["test_thu_fri"]

    assert train_split["eligible_windows"] == 1117
    assert train_split["positive_windows"] == 30
    assert train_split["negative_windows"] == 1087
    assert train_split["forecastable_onsets"] == 9
    assert train_split["ground_truth_episodes"] == 25

    assert test_split["eligible_windows"] == 280
    assert test_split["positive_windows"] == 35
    assert test_split["negative_windows"] == 245
    assert test_split["forecastable_onsets"] == 10
    assert test_split["ground_truth_episodes"] == 32

    # Verify zero attack-category overlap between partitions
    df_ledger = pd.read_csv(EVENT_LEDGER_CSV)
    train_eps = df_ledger[df_ledger["partition"] == "TRAIN"]
    test_eps = df_ledger[df_ledger["partition"] == "TEST"]

    def extract_categories(df_subset):
        cats = set()
        for c_str in df_subset["attack_classes"].dropna():
            for item in str(c_str).split(";"):
                item = item.strip()
                if item:
                    cats.add(item)
        return cats

    train_cats = extract_categories(train_eps)
    test_cats = extract_categories(test_eps)
    overlap = train_cats.intersection(test_cats)

    assert len(overlap) == 0, f"Unexpected category overlap between train and test: {overlap}"


def test_pre_correction_and_production_isolation():
    """Verifies that pre-correction parquet and production model artifacts are strictly preserved."""
    assert os.path.exists(PRE_CORRECTION_PARQUET), "Pre-correction parquet was deleted or overwritten"
    pre_hash = hashlib.sha256(open(PRE_CORRECTION_PARQUET, "rb").read()).hexdigest()
    assert pre_hash == "a333d3e61dcb034330f3f298d0640a1e2802f2a002f6b585105d566cf7ca7e44"

    assert os.path.exists(PRODUCTION_WEIGHTS), "Production BiLSTM weights missing"
    assert os.path.exists(PRODUCTION_SCALER), "Production scaler missing"
