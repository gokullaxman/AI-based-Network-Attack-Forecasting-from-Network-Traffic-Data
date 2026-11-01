# Phase 9B.1.1 Task Plan: Temporal Dataset Integrity and Target Correction Audit
## Objective
Audit and correct the Phase 9B.1 temporal dataset and experimental specification before any model training.
Strict audit and correction phase only. No model training, no production model modifications, no dashboard alterations, no Phase 9B.2 execution.
## Phases & Milestones
### Phase 9B.1.1: Tasks Breakdown
- [ ] **Task 1: Reconcile Raw-Record Counts and Epoch Keys**
  - Count raw lines and data rows in each of the 7 extracted CSV files.
  - Audit actual parsed rows, skipped rows, and unparseable rows per file.
  - Reconcile 2,209 total epochs vs 2,847 daily epoch sum (investigate Friday multi-file aggregation vs concatenation).
  - Verify `(capture_day, epoch_timestamp)` uniqueness and full calendar date integrity in `epochs_1min.parquet`.
  - Record input/output file hashes before/after any rebuild.
- [ ] **Task 2: Audit Timestamp Parsing and Temporal Continuity**
  - Verify Monday parsing (%d/%m/%Y %H:%M:%S) and Tue-Fri (%d/%m/%Y %H:%M).
  - Verify no time zone guessing; strict capture-day boundaries; zero synthetic missing-minute filling.
  - Count valid vs excluded epochs; audit first observed attack flow time vs true attack onset.
- [ ] **Task 3: Formalize the Research Target (Target A vs Target B)**
  - Formulate Target A (Attack-onset forecasting: clean history AND clean gap).
  - Formulate Target B (Future attack-activity forecasting: clean history only).
  - Calculate empirical window metrics, exclusions, and class imbalance for both targets.
  - Recommend Target A or B based on scientific defensibility.
- [ ] **Task 4: Validate Event Definitions and Clustering**
  - Extract ground-truth attack episodes from minute-level labels.
  - Compare ground-truth episodes vs the 14 onset clusters reported in Phase 9B.1.
  - Define episode boundaries, benign gaps, multi-category concurrency, and independence limitations.
- [ ] **Task 5: Freeze Leakage-Safe Predictor Schema**
  - Partition 15 epoch fields into: A) Observable predictors, B) Label-derived targets, C) Metadata.
  - Exclude label-derived columns (`attack_flow_count`, `benign_flow_count`, `is_attack_active`).
  - Document predictor names, units, missing-value handling, constant features, and flattened input dimensions ($10 \times P$).
- [ ] **Task 6: Reassess Chronological Split Feasibility**
  - Evaluate Mon–Wed training vs Thu–Fri testing with corrected targets and episodes.
  - Check category distribution, cross-split category shifts, and statistical sample size limitations.
- [ ] **Task 7: Deliverables & Test Verification**
  - Create `data/benchmark/temporal/metadata/phase9b1_1_integrity_audit.json`.
  - Create `data/benchmark/temporal/metadata/phase9b1_1_target_comparison.json`.
  - Create `data/benchmark/temporal/metadata/phase9b1_1_audit_report.md`.
  - Implement focused regression tests in `tests/test_phase9b1_1_target_correction.py`.
  - Run full pytest regression suite and verify 100% passing rate.
  - Provide final verdict and await approval.

