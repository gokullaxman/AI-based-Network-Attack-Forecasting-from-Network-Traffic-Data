"""
Phase 9B.2: Temporal Forecasting Lightweight Baselines & Signal Audit Engine.

This reproducible script implements:
1. Target A window extraction on authentic 1-minute epochs (10m history, 2m gap, 5m horizon).
2. Strict Monday-Wednesday (Train) vs Thursday-Friday (Test) chronological split.
3. Preprocessing fit strictly on training set only (StandardScaler).
4. Training of 3 CPU-compatible lightweight baselines:
   - Dummy Baseline (Prior & Stratified)
   - Logistic Regression (class_weight='balanced')
   - Random Forest (class_weight='balanced', max_depth=6, n_estimators=100)
5. Fixed threshold evaluation (0.5) with window-level and event-level metrics.
6. Export of predictions.csv, event_evaluation.csv, metrics.json, and trained models.
"""

import os
import sys
import json
import hashlib
import joblib
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

# Project paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
TEMPORAL_META_DIR = os.path.join(PROJECT_ROOT, "data/benchmark/temporal/metadata")
PHASE9B2_DIR = os.path.join(PROJECT_ROOT, "data/benchmark/temporal/phase9b2")
MODELS_DIR = os.path.join(PHASE9B2_DIR, "models")

EPOCHS_PARQUET = os.path.join(TEMPORAL_META_DIR, "epochs_1min.parquet")
EVENT_LEDGER_CSV = os.path.join(TEMPORAL_META_DIR, "phase9b1_2_event_ledger.csv")

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


def compute_sha256(fpath: str) -> str:
    h = hashlib.sha256()
    with open(fpath, "rb") as fp:
        while chunk := fp.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def extract_target_a_dataset(epochs_df: pd.DataFrame, strict_starts: set):
    """
    Extracts valid Target A observation windows:
    - History: [t-9, t] (10 minutes, must be 100% attack-free)
    - Lead gap: [t+1, t+2] (2 minutes, must be 100% attack-free)
    - Horizon: [t+3, t+7] (5 minutes, positive if a strict episode onset starts here)
    - Input: 12 observable features across 10 history epochs = 120 flattened features.
    """
    feature_names = [f"{col}_lag_{9-step}" for step in range(10) for col in PREDICTOR_COLUMNS]

    records = []
    for day, df_day in epochs_df.groupby("capture_day"):
        df_day = df_day.sort_values("epoch_timestamp").reset_index(drop=True)
        n = len(df_day)
        time_diffs = (df_day["epoch_timestamp"].diff().dt.total_seconds() / 60.0).fillna(1.0)
        is_cont = (time_diffs == 1.0)

        for i in range(n):
            # Window span boundary check (17 minutes)
            if (i - 9) < 0 or (i + 2 + 5) >= n:
                continue

            span = list(range(i - 9, i + 2 + 5 + 1))
            if not is_cont.iloc[span[1:]].all():
                continue

            hist = df_day.iloc[range(i - 9, i + 1)]
            gap = df_day.iloc[range(i + 1, i + 3)]
            horizon = df_day.iloc[range(i + 3, i + 8)]

            # Target A clean pre-conditions
            if (hist["attack_flow_count"] > 0).any() or (gap["attack_flow_count"] > 0).any():
                continue

            # Genuine onset condition
            horizon_times = set(horizon["epoch_timestamp"])
            has_onset = len(horizon_times.intersection(strict_starts)) > 0
            label = 1 if has_onset else 0

            # Observable features only (strictly zero label leakage)
            feat_mat = hist[PREDICTOR_COLUMNS].values  # shape (10, 12)
            feat_vec = feat_mat.flatten()              # shape (120,)

            records.append({
                "capture_day": day,
                "anchor_epoch": df_day.iloc[i]["epoch_timestamp"],
                "horizon_start": horizon.iloc[0]["epoch_timestamp"],
                "horizon_end": horizon.iloc[-1]["epoch_timestamp"],
                "target": label,
                "features": feat_vec
            })

    df_windows = pd.DataFrame(records)
    X = np.stack(df_windows["features"].values)
    y = df_windows["target"].values.astype(int)
    meta = df_windows.drop(columns=["features"])
    return X, y, meta, feature_names


def calculate_window_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict:
    """Calculates comprehensive window-level binary classification metrics."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    n_pos = int((y_true == 1).sum())
    n_neg = int((y_true == 0).sum())
    n_total = len(y_true)

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / n_neg) if n_neg > 0 else 0.0

    # Handle AUC for degenerate probabilities
    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except Exception:
        pr_auc = float(n_pos / n_total) if n_total > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        roc_auc = 0.5

    return {
        "n_samples": n_total,
        "n_positive": n_pos,
        "n_negative": n_neg,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "pr_auc": round(pr_auc, 4),
        "roc_auc": round(roc_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "fp_per_eligible_negative_window": round(fpr, 4),
        "confusion_matrix": [[tn, fp], [fn, tp]]
    }


def run_phase9b2_experiment():
    print("=" * 80)
    print("PHASE 9B.2: TEMPORAL FORECASTING BASELINES & SIGNAL AUDIT")
    print("=" * 80)

    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Inspect and validate source files
    parquet_hash = compute_sha256(EPOCHS_PARQUET)
    ledger_hash = compute_sha256(EVENT_LEDGER_CSV)
    print(f"\n[Step 1/5] Loading and verifying source data:")
    print(f"  Epochs Parquet:  {EPOCHS_PARQUET} (SHA-256: {parquet_hash})")
    print(f"  Event Ledger:    {EVENT_LEDGER_CSV} (SHA-256: {ledger_hash})")

    epochs_df = pd.read_parquet(EPOCHS_PARQUET)
    df_ledger = pd.read_csv(EVENT_LEDGER_CSV)
    strict_starts = set(pd.to_datetime(df_ledger["start_time"]))

    # 2. Extract clean Target A windows
    print(f"\n[Step 2/5] Extracting Target A observation windows (12 features x 10 history lags = 120 dims)...")
    train_epochs = epochs_df[epochs_df["capture_day"].isin(["Monday", "Tuesday", "Wednesday"])]
    test_epochs = epochs_df[epochs_df["capture_day"].isin(["Thursday", "Friday"])]

    X_train, y_train, meta_train, feature_names = extract_target_a_dataset(train_epochs, strict_starts)
    X_test, y_test, meta_test, _ = extract_target_a_dataset(test_epochs, strict_starts)

    print(f"  Train Split (Mon-Wed): {X_train.shape[0]} windows, Positives: {int(y_train.sum())} ({y_train.mean()*100:.2f}%)")
    print(f"  Test Split  (Thu-Fri): {X_test.shape[0]} windows, Positives: {int(y_test.sum())} ({y_test.mean()*100:.2f}%)")
    assert X_train.shape[0] == 1117 and y_train.sum() == 30, "Train window count mismatch!"
    assert X_test.shape[0] == 280 and y_test.sum() == 35, "Test window count mismatch!"

    # 3. Fit Preprocessing strictly on Training Split
    print(f"\n[Step 3/5] Fitting StandardScaler strictly on Training Split...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "standard_scaler.joblib"))

    # 4. Train 3 CPU-compatible Lightweight Baselines
    print(f"\n[Step 4/5] Training 3 lightweight CPU models...")

    # Model 1a: Dummy Prior Baseline
    dummy_prior = DummyClassifier(strategy="prior")
    dummy_prior.fit(X_train, y_train)
    p_dummy_prior = dummy_prior.predict_proba(X_test)[:, 1]
    y_dummy_prior = dummy_prior.predict(X_test)
    joblib.dump(dummy_prior, os.path.join(MODELS_DIR, "dummy_prior.joblib"))

    # Model 1b: Dummy Stratified Baseline (random seed 42)
    dummy_strat = DummyClassifier(strategy="stratified", random_state=42)
    dummy_strat.fit(X_train, y_train)
    p_dummy_strat = dummy_strat.predict_proba(X_test)[:, 1]
    y_dummy_strat = dummy_strat.predict(X_test)
    joblib.dump(dummy_strat, os.path.join(MODELS_DIR, "dummy_stratified.joblib"))

    # Model 2: Logistic Regression (class_weight='balanced')
    lr_model = LogisticRegression(
        penalty="l2",
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        max_iter=1000,
        random_state=42
    )
    lr_model.fit(X_train_scaled, y_train)
    p_lr = lr_model.predict_proba(X_test_scaled)[:, 1]
    y_lr = (p_lr >= 0.5).astype(int)
    joblib.dump(lr_model, os.path.join(MODELS_DIR, "logistic_regression.joblib"))

    # Model 3: Random Forest (class_weight='balanced', max_depth=6)
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    p_rf = rf_model.predict_proba(X_test)[:, 1]
    y_rf = (p_rf >= 0.5).astype(int)
    joblib.dump(rf_model, os.path.join(MODELS_DIR, "random_forest.joblib"))

    # Assemble predictions dataframe
    predictions_df = meta_test.copy()
    predictions_df["prob_dummy_prior"] = p_dummy_prior
    predictions_df["pred_dummy_prior"] = y_dummy_prior
    predictions_df["prob_dummy_stratified"] = p_dummy_strat
    predictions_df["pred_dummy_stratified"] = y_dummy_strat
    predictions_df["prob_logistic_regression"] = p_lr
    predictions_df["pred_logistic_regression"] = y_lr
    predictions_df["prob_random_forest"] = p_rf
    predictions_df["pred_random_forest"] = y_rf

    pred_csv_path = os.path.join(PHASE9B2_DIR, "predictions.csv")
    predictions_df.to_csv(pred_csv_path, index=False)
    print(f"  Saved window predictions to: {pred_csv_path}")

    # 5. Dual-Level Evaluation
    print(f"\n[Step 5/5] Evaluating Window-Level and Event-Level Performance...")

    # A. Window-Level Evaluation
    models_dict = {
        "dummy_prior": (y_dummy_prior, p_dummy_prior),
        "dummy_stratified": (y_dummy_strat, p_dummy_strat),
        "logistic_regression": (y_lr, p_lr),
        "random_forest": (y_rf, p_rf)
    }

    metrics_report = {
        "experiment_metadata": {
            "target": "Target A (Clean 10m History, Clean 2m Gap, 5m Horizon Episode Onset)",
            "training_split": "Monday, Tuesday, Wednesday (1,117 windows, 30 positive)",
            "evaluation_split": "Thursday, Friday (280 windows, 35 positive)",
            "shared_attack_categories": [],
            "evaluation_framing": "Exploratory zero-shot cross-category attack transfer",
            "decision_threshold": 0.5,
            "feature_count": 120,
            "epochs_parquet_sha256": parquet_hash,
            "event_ledger_sha256": ledger_hash,
            "random_seed": 42
        },
        "overall_window_metrics": {},
        "by_day_window_metrics": {},
        "by_attack_category_metrics": {},
        "event_level_summary": {}
    }

    for name, (preds, probs) in models_dict.items():
        metrics_report["overall_window_metrics"][name] = calculate_window_metrics(y_test, preds, probs)

    # Sub-evaluations by Day
    for day in ["Thursday", "Friday"]:
        mask_day = (predictions_df["capture_day"] == day).values
        metrics_report["by_day_window_metrics"][day] = {}
        for name, (preds, probs) in models_dict.items():
            metrics_report["by_day_window_metrics"][day][name] = calculate_window_metrics(
                y_test[mask_day], preds[mask_day], probs[mask_day]
            )

    # B. Event-Level Evaluation (Across the 10 Forecastable Test Onsets)
    test_onsets = df_ledger[(df_ledger["partition"] == "TEST") & (df_ledger["is_forecastable_target_a"])].copy()
    assert len(test_onsets) == 10, f"Expected exactly 10 test onsets, found {len(test_onsets)}"

    event_rows = []
    for idx, r in test_onsets.iterrows():
        event_id = r["event_id"]
        start_ts = pd.to_datetime(r["start_time"])
        day = r["capture_day"]
        atk_cls = r["attack_classes"]
        anchors = [pd.to_datetime(a) for a in str(r["associated_anchor_epochs"]).split("|") if a]

        # Slices from test predictions matching associated anchor epochs
        sub_preds = predictions_df[predictions_df["anchor_epoch"].isin(anchors)]

        row = {
            "event_id": event_id,
            "capture_day": day,
            "start_time": str(start_ts),
            "attack_classes": atk_cls,
            "attack_flows": r["attack_flows"],
            "associated_anchor_count": len(sub_preds),
            # Dummy Prior
            "detected_dummy_prior": bool((sub_preds["pred_dummy_prior"] == 1).any()),
            "max_prob_dummy_prior": round(float(sub_preds["prob_dummy_prior"].max()), 4),
            "lead_time_min_dummy_prior": None,
            # Dummy Stratified
            "detected_dummy_stratified": bool((sub_preds["pred_dummy_stratified"] == 1).any()),
            "max_prob_dummy_stratified": round(float(sub_preds["prob_dummy_stratified"].max()), 4),
            "lead_time_min_dummy_stratified": None,
            # Logistic Regression
            "detected_logistic_regression": bool((sub_preds["pred_logistic_regression"] == 1).any()),
            "max_prob_logistic_regression": round(float(sub_preds["prob_logistic_regression"].max()), 4),
            "lead_time_min_logistic_regression": None,
            # Random Forest
            "detected_random_forest": bool((sub_preds["pred_random_forest"] == 1).any()),
            "max_prob_random_forest": round(float(sub_preds["prob_random_forest"].max()), 4),
            "lead_time_min_random_forest": None
        }

        # Calculate lead times (minutes prior to onset start)
        for m_name in ["dummy_stratified", "logistic_regression", "random_forest"]:
            det_sub = sub_preds[sub_preds[f"pred_{m_name}"] == 1]
            if len(det_sub) > 0:
                earliest_anchor = det_sub["anchor_epoch"].min()
                lead_min = (start_ts - earliest_anchor).total_seconds() / 60.0
                row[f"lead_time_min_{m_name}"] = round(float(lead_min), 1)

        event_rows.append(row)

    df_events = pd.DataFrame(event_rows)
    events_csv_path = os.path.join(PHASE9B2_DIR, "event_evaluation.csv")
    df_events.to_csv(events_csv_path, index=False)
    print(f"  Saved event evaluations to: {events_csv_path}")

    # Event level summary counts
    for m_name in ["dummy_prior", "dummy_stratified", "logistic_regression", "random_forest"]:
        detected_cnt = int(df_events[f"detected_{m_name}"].sum())
        missed_cnt = 10 - detected_cnt
        recall_rate = round(detected_cnt / 10.0, 4)
        leads = [float(x) for x in df_events[f"lead_time_min_{m_name}"].dropna().values]
        metrics_report["event_level_summary"][m_name] = {
            "total_test_onsets": 10,
            "detected_onsets": detected_cnt,
            "missed_onsets": missed_cnt,
            "event_level_recall": recall_rate,
            "lead_times_minutes": leads,
            "mean_lead_time_minutes": round(float(np.mean(leads)), 2) if leads else None
        }

    # Save metrics JSON
    metrics_json_path = os.path.join(PHASE9B2_DIR, "metrics.json")
    with open(metrics_json_path, "w") as fp:
        json.dump(metrics_report, fp, indent=2)
    print(f"  Saved machine-readable metrics to: {metrics_json_path}")

    # Print summary table
    print("\n" + "=" * 80)
    print("PHASE 9B.2 EVALUATION SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Model Name':<22} | {'PR-AUC':<8} | {'ROC-AUC':<8} | {'Prec':<7} | {'Rec':<7} | {'F1':<7} | {'FPR':<7} | {'Events Det/10'}")
    print("-" * 88)
    for name in ["dummy_prior", "dummy_stratified", "logistic_regression", "random_forest"]:
        wm = metrics_report["overall_window_metrics"][name]
        em = metrics_report["event_level_summary"][name]
        print(
            f"{name:<22} | {wm['pr_auc']:<8.4f} | {wm['roc_auc']:<8.4f} | "
            f"{wm['precision']:<7.4f} | {wm['recall']:<7.4f} | {wm['f1_score']:<7.4f} | "
            f"{wm['false_positive_rate']:<7.4f} | {em['detected_onsets']}/10 ({em['event_level_recall']*100:.0f}%)"
        )
    print("=" * 80)


if __name__ == "__main__":
    run_phase9b2_experiment()
