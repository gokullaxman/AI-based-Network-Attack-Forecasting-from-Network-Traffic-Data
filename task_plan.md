# Master Task Plan: Real-Time Network Threat Forecasting Product

## Objective
Transform the existing repository into a reliable, validated, scientifically defensible, real-time network threat forecasting system with strict truth-in-advertising, reproducible metrics, clean temporal semantics, robust live capture and flow assembly, an analyst-grade SOC dashboard, and complete documentation.

---

## Phases & Milestones

### Phase 1: Repository Discovery & Baseline Audit
- [x] 1.1 Complete repository inspection (backend, models, pipeline, UI, tests, data).
- [x] 1.2 Establish baseline audit & create foundational documents:
  - Created `docs/BASELINE_AUDIT.md`
  - Created `docs/ARCHITECTURE.md`
  - Created `docs/KNOWN_LIMITATIONS.md`
- [x] 1.3 Identify actual model paths & disambiguate model routing:
  - Documented BiLSTM kill-chain stage classifier/forecaster vs. Target A temporal onset forecaster.
  - Eliminated ambiguous routing between experimental and production inference.

### Phase 2: Establish a Correct Forecasting Problem
- [x] 2.1 Formalize prediction target taxonomy:
  - Disambiguated Task A (current active attack detection) vs Task B (future attack onset forecasting Target A: $[t+3, t+7]$).
  - Documented non-linear attack progressions vs conceptual kill chains in `docs/DATA_AND_LABELS.md`.
- [x] 2.2 Formalize prediction horizons ($T_{hist}=10$ min, $T_{gap}=2$ min, $T_{horiz}=5$ min).
- [x] 2.3 Verify zero temporal leakage in splits, scalers, and window builders.
- [x] 2.4 Add reproducible unit tests for boundary conditions and label generation.

### Phase 3: Fix Live Network Data Pipeline & Feature Schema
- [x] 3.1 Verify live capture preservation (Scapy + Npcap, Windows host sockets, PCAP ingestion, honest health diagnostics).
- [x] 3.2 Audit & strengthen bidirectional flow extraction in `StreamingFlowAssembler` (IPv4/IPv6, TCP/UDP/ICMP, canonical keys, bounded capacity).
- [x] 3.3 Validate numerical accounting: prevent NaN/Inf, zero durations, negative durations, or division by zero.
- [x] 3.4 Verify temporal window aggregation: 1-minute discrete epochs, sliding 10-epoch sequences, thread safety.
- [x] 3.5 Formalize canonical 12-feature schema contract shared between training, offline evaluation, and live inference.

### Phase 4: Model Training Pipeline & Baseline Comparisons
- [x] 4.1 Inspect existing models (BiLSTM, Compact LSTM, Random Forest, Logistic Regression, Dummy Priors).
- [x] 4.2 Establish meaningful benchmark baselines and record comparative metrics.
- [x] 4.3 Evaluate model capacity vs over-parameterization on small attack episode counts.
- [x] 4.4 Verify class imbalance handling (class weighting, no synthetic oversampling before train/test split).
- [x] 4.5 Ensure model loading validates schema compatibility and metadata before enabling inference.

### Phase 5: Repair Evaluation & Early-Warning Metrics
- [x] 5.1 Verify event evaluation logic: strict earliest-warning attribution (onset $[t+3, t+7]$ with clean history and lead gap).
- [x] 5.2 Validate complementary metrics: Precision, Recall, F1, PR-AUC, ROC-AUC, FPR, false alarms per hour, median lead time.
- [x] 5.3 Verify threshold calibration on validation data (avoiding final test set leakage).
- [x] 5.4 Document out-of-distribution transfer limitations (Mon-Wed train vs Thu-Fri test).
- [x] 5.5 Produce machine-readable evaluation report in `data/benchmark/temporal/` and human-readable summary.

### Phase 6: Make Live Inference Reliable
- [x] 6.1 Connect end-to-end inference pipeline: Packets -> Flows -> Epochs -> 10-Window Sequence -> Feature Scaling -> Gated Model Inference -> Alerting.
- [x] 6.2 Implement strict inference readiness checks (return `INSUFFICIENT_HISTORY` or `MODEL_UNAVAILABLE` without fabricated fallback predictions).
- [x] 6.3 Ensure predictions are semantically explicit (timestamp, model version, target, horizon, probability/score, readiness).
- [x] 6.4 Implement alert deduplication, cooldown, severity thresholds, and transparent evidence rationales.

### Phase 7: Harden API and Backend
- [x] 7.1 Verify FastAPI request/response contracts, error handling, status codes, and health endpoints.
- [x] 7.2 Concurrency and resource safety: bounded buffers, background thread management, clean shutdown hooks.
- [x] 7.3 Security hardening: input validation, least privilege, no credential or packet payload leakage.

### Phase 8: Complete Dashboard as a Trustworthy Product
- [x] 8.1 Responsive layout verification across viewport sizes (360x800, 768x1024, 1366x768, 1920x1080) in `style.css`.
- [x] 8.2 Operational overview: real telemetry, capture health status, honest model readiness indicators.
- [x] 8.3 Trustworthy 3D topology & device inventory: verified observations only, router color distinct, active/stale/unknown states.
- [x] 8.4 Scientifically accurate charts with labeled axes, units, horizons, and explicit empty/unavailable states.
- [x] 8.5 Clear operational feedback for all capture and inference states.

### Phase 9: Comprehensive Test Suite Verification
- [x] 9.1 Run and verify unit tests (packet parsing, flow assembly, entropy, temporal aggregation, risk engine).
- [x] 9.2 Run integration tests (PCAP dissection -> flow aggregation -> inference -> API contract).
- [x] 9.3 Run failure tests (missing artifacts, malformed packets, invalid thresholds, corrupted inputs).
- [x] 9.4 Verify live capture tests vs offline tests without requiring administrator privilege in CI.
- [x] 9.5 Ensure 100% of tests pass cleanly (228/228 passing).

### Phase 10: Performance & Resource Management
- [x] 10.1 Measure and document throughput (packets/sec, flows/sec) and latency (window aggregation, inference).
- [x] 10.2 Verify memory bounds and resource cleanup on capture stop/clear.

### Phase 11: Configuration, Logging, and Operations
- [x] 11.1 Consolidate configuration options (environment variables, defaults, buffer limits, thresholds).
- [x] 11.2 Structured logging for lifecycle events, capture errors, schema validation, and inference.

### Phase 12: Documentation and Product Delivery
- [x] 12.1 Update `README.md` with complete architecture, installation, operation, and verification commands.
- [x] 12.2 Author full documentation suite in `docs/`:
  - `docs/BASELINE_AUDIT.md`
  - `docs/ARCHITECTURE.md`
  - `docs/KNOWN_LIMITATIONS.md`
  - `docs/MODEL_CARD.md`
  - `docs/DATA_AND_LABELS.md`
  - `docs/EVALUATION.md`
  - `docs/LIVE_CAPTURE_SETUP.md`
  - `docs/TROUBLESHOOTING.md`
  - `docs/FINAL_VERIFICATION_REPORT.md`

### Phase 13: Final Verification & Engineering Report
- [x] 13.1 Run complete verification across tests, demo server, API, and UI.
- [x] 13.2 Deliver final 10-section engineering report.
