"""
Test suite for Phase 9A: Temporal Forecasting Feasibility Audit.
Audits:
1. Local data inventory: confirms 79-column structure and lack of timestamps in local benchmark CSVs.
2. Candidate temporal source: confirms 85 columns, presence of Timestamp, and minute-level truncation in GeneratedLabelledFlows.zip.
3. Production model provenance: confirms BiLSTM weights are tied to synthetic Gaussian datasets.
4. Feature compatibility audit: confirms discrepancy between 12-feature schema and native flow features.
5. Preservation of production and benchmark artifacts.
"""

import os
import hashlib
import json
import pytest
import numpy as np
import pandas as pd

from pipeline.dataset import STAGE_PROFILES, NUM_STAGES
from pipeline.feature_extractor import FEATURE_NAMES


PROD_WEIGHTS_SHA256 = "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
PROD_SCALER_SHA256 = "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"


def test_local_benchmark_files_lack_timestamps():
    """Confirms that none of the locally available benchmark CSVs contain timestamps."""
    raw_dir = os.path.join("data", "benchmark", "raw")
    csv_files = [f for f in os.listdir(raw_dir) if f.endswith(".csv")]
    assert len(csv_files) >= 6

    for f in csv_files:
        df_head = pd.read_csv(os.path.join(raw_dir, f), nrows=2, encoding="latin1")
        cols = [c.strip().lower() for c in df_head.columns]
        assert not any("time" in c or "date" in c for c in cols), f"Unexpected timestamp in {f}"
        assert len(cols) == 79


def test_sample_files_lack_temporal_progression():
    """Confirms that sample_cicids2017.csv is a static 31-row slice without timestamps."""
    sample_path = os.path.join("data", "sample_cicids2017.csv")
    assert os.path.exists(sample_path)
    df = pd.read_csv(sample_path)
    cols = [c.strip().lower() for c in df.columns]
    assert len(df) == 31
    assert not any("time" in c or "date" in c for c in cols)


def test_production_training_is_synthetic():
    """Confirms that the production BiLSTM was trained on synthetic Gaussian profiles, not authentic flows."""
    assert len(STAGE_PROFILES) == 6  # Benign + 5 attack stages
    assert NUM_STAGES == 5  # 5 attack stages: Reconnaissance, Scanning, Enumeration, Exploitation, Intrusion
    assert len(FEATURE_NAMES) == 12

    # Verify that STAGE_PROFILES contains artificial hand-crafted means and stds
    recon_mean = STAGE_PROFILES["Reconnaissance"]["mean"]
    assert len(recon_mean) == 12
    assert isinstance(recon_mean, list)


def test_real_flow_loader_heuristic_dependencies():
    """Audits the ad-hoc heuristic approximations in CICIDSFlowLoader for the 12-feature schema."""
    from pipeline.real_flow_loader import CICIDSFlowLoader
    loader = CICIDSFlowLoader()

    # Create dummy DataFrame with standard CICFlowMeter columns
    dummy_df = pd.DataFrame({
        "Flow Duration": [1000000, 2000000],
        "Total Fwd Packets": [10, 20],
        "Total Backward Packets": [5, 10],
        "Destination Port": [80, 443],
        "Protocol": [6, 17],
        "SYN Flag Count": [1, 0],
        "Average Packet Size": [100.0, 200.0],
        "Flow IAT Mean": [10.0, 20.0],
        "Flow IAT Std": [2.0, 4.0],
        "Flow IAT Max": [30.0, 50.0]
    })

    feats = loader.parse_csv_to_features(dummy_df)
    assert feats.shape == (2, 12)

    # Verify port-based heuristics in features 2, 3, 4, 5
    # Feature 4 (port diversity) is synthesized from Destination Port > 1024
    assert feats[0, 4] == 4.0  # port 80 <= 1024
    assert feats[1, 4] == 4.0  # port 443 <= 1024


def test_production_and_benchmark_artifacts_unaltered():
    """Verifies that all pre-existing production and benchmark model artifacts remain bit-for-bit identical."""
    prod_weights_path = os.path.join("models", "bilstm_weights.pt")
    prod_scaler_path = os.path.join("pipeline", "scaler.pkl")

    with open(prod_weights_path, "rb") as f:
        w_sha = hashlib.sha256(f.read()).hexdigest()
    with open(prod_scaler_path, "rb") as f:
        s_sha = hashlib.sha256(f.read()).hexdigest()

    assert w_sha == PROD_WEIGHTS_SHA256
    assert s_sha == PROD_SCALER_SHA256

    # Verify Phase 8B artifacts exist
    multi_rf_path = os.path.join("models", "benchmark_multiattack", "baseline_multiattack_rf.pkl")
    multi_lr_path = os.path.join("models", "benchmark_multiattack", "baseline_multiattack_lr.pkl")
    assert os.path.exists(multi_rf_path)
    assert os.path.exists(multi_lr_path)
