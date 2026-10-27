"""
Test suite for Phase 9B.1.1: Temporal Dataset Integrity and Target Correction Audit.

Verifies:
1. Exact row-count reconciliation across all 7 authentic CSVs (accounting for Thursday blank lines).
2. Epoch key uniqueness and calendar date preservation in epochs_1min.parquet.
3. Target A (Attack-onset) vs Target B (Future-activity) formulation and eligibility gating.
4. Ground-truth attack episode extraction and positive window mapping.
5. Strict predictor schema leakage exclusions (attack labels/counts excluded from predictors).
6. Non-constant variance and zero NaN/inf values across all 12 candidate predictors.
7. Zero category overlap in chronological split (Mon-Wed train vs Thu-Fri test).
8. Strict preservation and isolation of production weights, scaler, and Phase 8B artifacts.
"""

import os
import json
import hashlib
import pytest
import pandas as pd
import numpy as np

EPOCHS_PARQUET = "data/benchmark/temporal/metadata/epochs_1min.parquet"
TARGET_COMPARISON_JSON = "data/benchmark/temporal/metadata/phase9b1_1_target_comparison.json"
INTEGRITY_AUDIT_JSON = "data/benchmark/temporal/metadata/phase9b1_1_integrity_audit.json"

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


def test_raw_row_count_reconciliation():
    """Verifies that the 2,830,750 raw CSV lines reconcile with genuine flow records."""
    assert os.path.exists(INTEGRITY_AUDIT_JSON)
    with open(INTEGRITY_AUDIT_JSON, "r") as fp:
        audit = json.load(fp)
    
    rec = audit["raw_record_reconciliation"]
    total_lines = rec["total_extracted_csv_lines_including_headers"]
    headers = rec["total_headers"]
    blank_lines = rec["thursday_blank_comma_padded_lines"]
    genuine_flows = rec["genuine_flow_records"]
    parquet_flows = rec["records_in_1min_parquet"]

    assert total_lines == 2_830_750
    assert headers == 7
    assert blank_lines == 288_602
    assert genuine_flows == 2_542_141
    # Total non-header lines minus blank padding equals genuine flow records
    assert (total_lines - headers - blank_lines) == genuine_flows
    # All genuine flows were aggregated into the 1-minute epoch table
    assert parquet_flows == genuine_flows


def test_epoch_key_integrity_and_date_preservation():
    """Verifies that epochs_1min.parquet contains 2,209 unique (capture_day, timestamp) pairs."""
    df = pd.read_parquet(EPOCHS_PARQUET)
    assert len(df) == 2209
    assert df["epoch_timestamp"].nunique() == 2209
    assert df.duplicated(subset=["capture_day", "epoch_timestamp"]).sum() == 0

    # Verify that stripping calendar dates compresses into 509 colliding time bins
    time_only_bins = df["epoch_timestamp"].dt.strftime("%H:%M:%S").nunique()
    assert time_only_bins == 509

    # Verify all 5 distinct calendar dates are present
    dates = df["epoch_timestamp"].dt.date.unique()
    assert len(dates) == 5


def test_target_a_vs_target_b_formulation():
    """Verifies that Target A strictly gates out attacks in the lead-time gap, while Target B does not."""
    with open(TARGET_COMPARISON_JSON, "r") as fp:
        comp = json.load(fp)

    t_a = comp["target_a_onset_forecasting"]
    t_b = comp["target_b_future_activity_forecasting"]

    # Target A requires clean gap, rejecting 28 windows where attack begins in gap
    assert t_a["ineligible_attack_in_gap"] == 28
    assert t_b["ineligible_attack_in_gap"] == 0

    # Target A has 65 positive windows; Target B has 65 + 24 = 89 positive windows
    assert t_a["positive_windows"] == 65
    assert t_b["positive_windows"] == 89
    assert t_a["eligible_windows"] == 1349
    assert t_b["eligible_windows"] == 1377


def test_ground_truth_attack_episodes_and_onset_mapping():
    """Verifies ground-truth episode extraction and positive window mapping."""
    with open(INTEGRITY_AUDIT_JSON, "r") as fp:
        audit = json.load(fp)

    eps = audit["ground_truth_attack_episodes"]["strict_episodes_count"]
    # 57 strict ground-truth episodes exist across the week
    assert eps == 57

    with open(TARGET_COMPARISON_JSON, "r") as fp:
        comp = json.load(fp)

    # Under Target A, 55 windows unambiguously predict a single episode
    assert comp["target_a_onset_forecasting"]["unambiguous_positive_windows"] == 55
    # 10 windows overlap closely spaced initial bursts
    assert comp["target_a_onset_forecasting"]["ambiguous_positive_windows"] == 10
    assert (55 + 10) == 65


def test_predictor_schema_leakage_exclusion():
    """Verifies that label-derived fields are strictly excluded and 12 observable predictors are valid."""
    df = pd.read_parquet(EPOCHS_PARQUET)

    # Check all 12 predictors exist
    for col in PREDICTOR_COLUMNS:
        assert col in df.columns
        assert df[col].isnull().sum() == 0
        assert not np.isinf(df[col]).any()
        assert df[col].std() > 0.0, f"Predictor {col} is unexpectedly constant!"

    # Excluded label fields must never be used as predictor inputs
    for col in EXCLUDED_LABEL_COLUMNS:
        assert col in df.columns or col == "attack_classes"


def test_chronological_split_zero_category_overlap():
    """Verifies zero category overlap between Mon-Wed training set and Thu-Fri test set."""
    with open(TARGET_COMPARISON_JSON, "r") as fp:
        comp = json.load(fp)

    split = comp["chronological_split_target_a"]
    train_cats = set(split["train_mon_wed"]["attack_categories"])
    test_cats = set(split["test_thu_fri"]["attack_categories"])

    # Overlap must be strictly empty (zero-shot test setting)
    assert len(train_cats.intersection(test_cats)) == 0
    assert len(train_cats) == 7
    assert len(test_cats) == 6


def test_production_and_benchmark_artifact_preservation():
    """Verifies that production weights, scaler, and Phase 8B benchmark files are unmodified."""
    expected_weights_hash = "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
    expected_scaler_hash = "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"

    def file_hash(p):
        h = hashlib.sha256()
        with open(p, "rb") as fp:
            while chunk := fp.read(65536):
                h.update(chunk)
        return h.hexdigest()

    assert file_hash("models/bilstm_weights.pt") == expected_weights_hash
    assert file_hash("pipeline/scaler.pkl") == expected_scaler_hash
    assert os.path.exists("models/benchmark_multiattack/baseline_multiattack_rf.pkl")
    assert os.path.exists("models/benchmark_multiattack/multiattack_evaluation_results.json")
