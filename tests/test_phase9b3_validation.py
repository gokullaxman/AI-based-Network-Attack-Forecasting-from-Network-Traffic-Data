"""
Test Suite for Phase 9B.3: Validation and Pre-Modeling Audit of Forecasting Baselines.

Verifies:
1. Deliverable existence and artifact integrity under data/benchmark/temporal/phase9b3/.
2. Exact metric reproduction directly from Phase 9B.2 predictions.csv (100% numerical match).
3. Event-level matching discrepancy resolution: anchor 13:48:00 credits EVT_FRI_19 and EVT_FRI_20 under Rule 1.
4. Single-event attribution (Rule 2: 2 detections) vs Multi-event credit (Rule 1: 3 detections) vs Scenario-level (Rule 3: 2/5 scenarios).
5. False alarm episode grouping: 11 false positive windows group into 8 distinct episodes.
6. Statistical robustness: 95% bootstrap CI of PR-AUC delta crosses zero.
7. Strict preservation of production weights and scaler.
"""

import os
import json
import hashlib
import pytest
import pandas as pd
import numpy as np

PHASE9B3_DIR = "data/benchmark/temporal/phase9b3"
REPRODUCED_METRICS_JSON = os.path.join(PHASE9B3_DIR, "reproduced_metrics.json")
EVENT_MATCHING_CSV = os.path.join(PHASE9B3_DIR, "event_matching_audit.csv")
VALIDITY_REPORT_MD = os.path.join(PHASE9B3_DIR, "validity_report.md")

PREDICTIONS_CSV = "data/benchmark/temporal/phase9b2/predictions.csv"
EVENT_LEDGER_CSV = "data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv"
PRODUCTION_WEIGHTS = "models/bilstm_weights.pt"
PRODUCTION_SCALER = "pipeline/scaler.pkl"


def test_phase9b3_deliverables_exist():
    """Verifies that all Phase 9B.3 audit deliverables were generated."""
    assert os.path.exists(REPRODUCED_METRICS_JSON), "reproduced_metrics.json missing"
    assert os.path.exists(EVENT_MATCHING_CSV), "event_matching_audit.csv missing"
    assert os.path.exists(VALIDITY_REPORT_MD), "validity_report.md missing"


def test_phase9b3_exact_metrics_reproduction():
    """Verifies that reproduced_metrics.json confirms 100% exact numerical match with Phase 9B.2."""
    with open(REPRODUCED_METRICS_JSON, "r") as fp:
        reprod = json.load(fp)

    wm = reprod["reproduced_window_metrics"]
    for m in ["dummy_prior", "dummy_stratified", "logistic_regression", "random_forest"]:
        assert wm[m]["exact_match_with_phase9b2"] is True, f"Mismatch in reproduced metrics for {m}"

    # Verify specific metrics
    assert wm["dummy_prior"]["pr_auc"] == 0.1250
    assert wm["dummy_prior"]["roc_auc"] == 0.5000
    assert wm["logistic_regression"]["pr_auc"] == 0.1554
    assert wm["logistic_regression"]["roc_auc"] == 0.5370
    assert wm["logistic_regression"]["precision"] == 0.1538
    assert wm["logistic_regression"]["recall"] == 0.0571
    assert wm["random_forest"]["pr_auc"] == 0.1402
    assert wm["random_forest"]["roc_auc"] == 0.4901


def test_phase9b3_event_matching_discrepancy_and_rules():
    """Verifies why 2 TP windows yielded 3 detected onsets and validates matching rules."""
    df_audit = pd.read_csv(EVENT_MATCHING_CSV)
    assert len(df_audit) == 10

    # Rule 1 (Multi-Event Credit)
    assert df_audit["rule1_multi_credit_detected"].sum() == 3
    r1_detected = set(df_audit[df_audit["rule1_multi_credit_detected"]]["event_id"])
    assert r1_detected == {"EVT_FRI_19", "EVT_FRI_20", "EVT_FRI_27"}

    # Verify anchor 13:48:00 credited both EVT_FRI_19 and EVT_FRI_20
    row_19 = df_audit[df_audit["event_id"] == "EVT_FRI_19"].iloc[0]
    row_20 = df_audit[df_audit["event_id"] == "EVT_FRI_20"].iloc[0]
    row_27 = df_audit[df_audit["event_id"] == "EVT_FRI_27"].iloc[0]

    assert row_19["rule1_credited_by_anchor"] == "2017-07-07 13:48:00"
    assert row_20["rule1_credited_by_anchor"] == "2017-07-07 13:48:00"
    assert row_27["rule1_credited_by_anchor"] == "2017-07-07 15:50:00"

    # Rule 2 (Single Earliest Attribution)
    # Anchor 13:48:00 is consumed by EVT_FRI_19 (13:52), leaving EVT_FRI_20 (13:55) uncredited
    assert df_audit["rule2_single_credit_detected"].sum() == 2
    r2_detected = set(df_audit[df_audit["rule2_single_credit_detected"]]["event_id"])
    assert r2_detected == {"EVT_FRI_19", "EVT_FRI_27"}
    assert row_20["rule2_single_credit_detected"] == False
    assert "already consumed" in str(row_20["rule2_attribution_note"])

    # Rule 3 (Scenario-Level Campaign Matching)
    # Test contains 5 scenarios: THU_BRUTE_FORCE, THU_XSS, FRI_BOTNET, FRI_PORTSCAN, FRI_DDOS
    scenarios = df_audit.groupby("scenario_id")["rule1_multi_credit_detected"].any()
    assert len(scenarios) == 5
    assert scenarios.sum() == 2
    assert scenarios["SCENARIO_FRI_02_PORTSCAN"] == True
    assert scenarios["SCENARIO_FRI_03_DDOS"] == True
    assert scenarios["SCENARIO_FRI_01_BOTNET"] == False
    assert scenarios["SCENARIO_THU_01_BRUTE_FORCE"] == False
    assert scenarios["SCENARIO_THU_02_XSS"] == False


def test_phase9b3_false_alarm_episode_grouping():
    """Verifies that 11 false positive windows group into 8 distinct episodes."""
    with open(REPRODUCED_METRICS_JSON, "r") as fp:
        reprod = json.load(fp)

    fa_audit = reprod["false_alarm_episodes_audit"]
    assert fa_audit["total_false_positive_windows"] == 11
    assert fa_audit["total_false_alarm_episodes"] == 8

    # Sum of episode durations equals total false positive windows
    durations = [ep["duration_minutes"] for ep in fa_audit["false_alarm_episode_details"]]
    assert sum(durations) == 11
    # 6 single-minute, 1 two-minute, 1 three-minute
    assert sorted(durations) == [1, 1, 1, 1, 1, 1, 2, 3]


def test_phase9b3_bootstrap_confidence_intervals_cross_zero():
    """Verifies statistical fragility: PR-AUC delta 95% CI crosses zero and ROC-AUC spans 0.5."""
    with open(REPRODUCED_METRICS_JSON, "r") as fp:
        reprod = json.load(fp)

    boot = reprod["bootstrap_statistical_tests"]
    delta_ci = boot["delta_pr_auc_ci_95"]
    roc_ci = boot["logistic_regression_roc_auc_ci_95"]

    # Lower bound of delta PR-AUC must be <= 0 (crosses zero)
    assert delta_ci[0] <= 0.0, f"Delta PR-AUC lower bound {delta_ci[0]} unexpectedly positive"
    assert delta_ci[1] > 0.0, f"Delta PR-AUC upper bound {delta_ci[1]} unexpectedly negative"

    # ROC-AUC 95% CI must span 0.5000 (random coin toss)
    assert roc_ci[0] < 0.5000, f"ROC-AUC lower bound {roc_ci[0]} unexpectedly above 0.5"
    assert roc_ci[1] > 0.5000, f"ROC-AUC upper bound {roc_ci[1]} unexpectedly below 0.5"


def test_phase9b3_production_isolation():
    """Verifies that production BiLSTM model weights and scaler are untouched."""
    assert os.path.exists(PRODUCTION_WEIGHTS)
    assert os.path.exists(PRODUCTION_SCALER)

    h_weights = hashlib.sha256(open(PRODUCTION_WEIGHTS, "rb").read()).hexdigest()
    h_scaler = hashlib.sha256(open(PRODUCTION_SCALER, "rb").read()).hexdigest()

    assert h_weights == "35807897ae6c2fc11cb54f911d5a0d610970796ee4f12604eb19b292a0f42a8e"
    assert h_scaler == "7ffea55f48ad656d2eb20fceecb7d18a9f84fe8c0b13a3184b6b1cef18e73fe9"
