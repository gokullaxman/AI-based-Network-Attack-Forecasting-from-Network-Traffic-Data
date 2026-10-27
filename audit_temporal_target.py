"""
Audit execution script for Phase 9B.1: Temporal Dataset Preparation and Target Validation.
Processes all 7 extracted GeneratedLabelledFlows CSVs, extracts 1-minute behavioral epochs,
and audits candidate attack-onset forecasting windows across the weekly schedule.
Saves epoch tables and target validation metrics to data/benchmark/temporal/metadata/.
"""

import os
import sys
import json
import time
import pandas as pd

from pipeline.temporal_preprocessor import (
    TemporalEpochAggregator,
    ForecastingTargetValidator,
    TEMPORAL_META_DIR
)


def run_temporal_audit():
    print("=" * 80)
    print("PHASE 9B.1: TEMPORAL DATASET PREPARATION AND TARGET VALIDATION AUDIT")
    print("=" * 80)

    os.makedirs(TEMPORAL_META_DIR, exist_ok=True)
    t0 = time.time()

    # Step 1: Process all raw temporal CSVs into 1-minute discrete epochs
    print("\n[Step 1/3] Aggregating authentic flow records into 1-minute epochs...")
    aggregator = TemporalEpochAggregator()
    epochs_df = aggregator.process_all_files()
    process_duration = time.time() - t0

    print(f"\nCompleted aggregation in {process_duration:.2f}s:")
    print(f"  Total Valid 1-Minute Epochs: {len(epochs_df):,}")
    print(f"  Chronological Span:          {epochs_df['epoch_timestamp'].min()} to {epochs_df['epoch_timestamp'].max()}")

    # Day-by-day epoch breakdown
    print("\nEpoch Breakdown by Capture Day:")
    for day, df_day in epochs_df.groupby("capture_day"):
        tot_flows = df_day["flow_count"].sum()
        atk_flows = df_day["attack_flow_count"].sum()
        atk_epochs = (df_day["attack_flow_count"] > 0).sum()
        pct_atk_epochs = (atk_epochs / len(df_day)) * 100
        print(f"  {day:10s} | Epochs: {len(df_day):4d} | Attack Epochs: {atk_epochs:3d} ({pct_atk_epochs:5.1f}%) | Total Flows: {tot_flows:8,d} | Attack Flows: {atk_flows:8,d}")

    # Save aggregated epochs table
    epochs_parquet_path = os.path.join(TEMPORAL_META_DIR, "epochs_1min.parquet")
    epochs_df.to_parquet(epochs_parquet_path, index=False)
    print(f"\nSaved 1-minute epoch table to: {epochs_parquet_path}")

    # Step 2: Validate Candidate Forecasting Target (10-min history, 2-min lead, 5-min horizon)
    print("\n[Step 2/3] Auditing candidate attack-onset forecasting windows...")
    validator = ForecastingTargetValidator(
        history_len=10,
        lead_time_gap=2,
        horizon_len=5
    )
    target_audit = validator.audit_target_on_epochs(epochs_df)

    print("\nTarget Window Audit Results:")
    w_counts = target_audit["window_counts"]
    print(f"  Total Eligible Windows:           {w_counts['total_eligible_windows']:,}")
    print(f"  Positive Onset Windows (y=1):      {w_counts['positive_onset_windows']:,}")
    print(f"  Negative Benign Windows (y=0):     {w_counts['negative_attack_free_windows']:,}")
    print(f"  Class Imbalance Ratio:             {w_counts['class_imbalance_ratio']}")
    print(f"  Ineligible (Attack in History):    {w_counts['ineligible_windows_active_attack_in_history']:,}")
    print(f"  Excluded (Capture Gap / Boundary): {w_counts['excluded_boundary_or_continuity_gap_windows']:,}")

    # Step 3: Independent Attack Onsets Audit
    print("\n[Step 3/3] Auditing independent attack onsets across weekly schedule...")
    onsets_info = target_audit["independent_attack_onsets"]
    print(f"  Total Independent Onset Events:    {onsets_info['total_independent_onsets']}")

    print("\nOnset Events Detail:")
    for idx, event in enumerate(onsets_info["onset_events_detail"], 1):
        print(f"  [{idx:2d}] Day: {event['capture_day']:10s} | Epoch: {event['current_epoch']} | Horizon: {event['horizon_start']} - {event['horizon_end']} | Attack Flows: {event['attack_flows_in_horizon']}")

    # Save target audit report
    target_audit_path = os.path.join(TEMPORAL_META_DIR, "target_validation_audit.json")
    with open(target_audit_path, "w") as f:
        json.dump(target_audit, f, indent=2)
    print(f"\nSaved target audit report to: {target_audit_path}")
    print("\nPhase 9B.1 temporal data preparation and target audit completed successfully.")


if __name__ == "__main__":
    run_temporal_audit()
