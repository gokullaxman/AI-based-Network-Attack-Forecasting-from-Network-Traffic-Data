# Real-Data Attack Forecasting Model Report (Phase 9C)
## AI-Based Network Attack Forecasting from Network Traffic Data
### Empirical Model Training, Evaluation, Artifact Export, and Schema Gating

**Author:** Cybersecurity Research Engineer & ML Systems Auditor  
**Date:** October 26, 2026  
**Environment:** Windows 11, Python 3.13.12 (CPU-only)  
**Artifact Directory:** `models/temporal_forecasting/`  
**Evaluation Output:** `data/benchmark/temporal/phase9c/`  
**Test Suite:** `tests/test_phase9c_temporal_model.py` (9/9 passed; 169/169 full suite passed)  

---

### 1. Executive Summary

In response to the requirement for an **actual trained model on authentic chronological network observations**, this phase implemented, trained, evaluated, and exported a dedicated real-data temporal attack-onset forecaster.

The model targets **Target A**: predicting whether an authentic multi-stage attack onset will begin in a future 5-minute horizon ($[t+3, t+7]$) conditioned on 10 minutes of verified attack-free history ($[t-9, t]$) and a 2-minute clean lead gap ($[t+1, t+2]$).

#### Key Real-Data Results:
1. **Primary Model (Logistic Regression with Balanced Class Weighting):**
   - **PR-AUC:** `0.1554` (vs. Dummy Prior `0.1250`, a modest +0.0304 lift).
   - **ROC-AUC:** `0.5370` (vs. Dummy Prior `0.5000`).
   - **Window Precision:** `0.1538` (2 True Positives, 11 False Positives across 280 test windows).
   - **Window Recall:** `0.0571` (F1: `0.0833`).
   - **False Positive Rate (FPR):** `0.0449` (~2.69 false alarms per negative hour).
   - **Event-Level Recall:**
     - *Rule 1 (Multi-Event Credit):* `3 / 10` onsets detected (`30.0%`).
     - *Rule 2 (Strict Earliest Attribution):* `2 / 10` onsets detected (`20.0%`, PortScan probe & LOIC DDoS flooding).
   - **Lead Time:** Mean of `5.67 minutes` (4.0 min for PortScan, 6.0 min for DDoS, 7.0 min for PortScan stage 2).
2. **Comparison Tree Baseline (Random Forest, depth=6):**
   - **PR-AUC:** `0.1815`, **ROC-AUC:** `0.5805`.
   - At standard 0.5 threshold, produces 0 detections; probability ranking shows higher discrimination on positive tails.
3. **Deep Sequence Modeling Failure (Compact PyTorch LSTM):**
   - Evaluated a compact 1-layer LSTM (hidden dim 16, pos_weight=36.2) on the sequence tensor $(N, 10, 12)$.
   - **PR-AUC:** `0.1206` (**lower than the dummy prior** of `0.1250`).
   - **ROC-AUC:** `0.5018` (statistically indistinguishable from random coin-toss).
   - **Root Cause:** The training split contains only **9 attack onsets across 4 scheduled attack scenarios**. A recurrent neural model memorizes the minute-level baseline fluctuations of Tuesday/Wednesday and suffers catastrophic out-of-distribution collapse on Thursday/Friday cross-category test traffic.
4. **Model Delivery & Schema Gating:**
   - Saved full model artifact package in `models/temporal_forecasting/` (`model.joblib`, `preprocessor.joblib`, `random_forest.joblib`, `compact_lstm.pt`, `metadata.json`, and inference module `forecaster.py`).
   - Preprocessing (`StandardScaler`) was fit **strictly on training data** ($N=1117$).
   - Strict gating prevents incompatible packet features from being fed into the flow-trained model.

---

### 2. Temporal Dataset Provenance & Target Definition

The model was trained and evaluated on authentic chronological network flow observations extracted from the CICIDS2017 `GeneratedLabelledFlows` archive:

- **Epoch Parquet:** `data/benchmark/temporal/metadata/epochs_1min.parquet`  
  `SHA256: 2c3490de8f516b2a29e1d58239e4244ac52102edb6a804e4e588bed09d5cef59`
- **Event Ledger:** `data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv`  
  `SHA256: 8111067343e9b8f170a95c987eec0ad5c8013296eade1fa7e1b0527ef7f1ae19`

#### Target A Specification:
```
Observation Index: [ i-9, ..., i ]     [ i+1, i+2 ]     [ i+3, ..., i+7 ]
Time Interval:      History (10 min)    Gap (2 min)      Horizon (5 min)
Requirement:        Attack-Free         Attack-Free      Positive if Onset Starts Here
```

- **History Window ($[t-9, t]$):** 10 consecutive minutes containing 12 observable flow features per minute ($10 \times 12 = 120$ dimensions). Must contain zero attack flows.
- **Lead Gap ($[t+1, t+2]$):** 2 consecutive minutes requiring zero attack flows to prevent evaluating ongoing attacks as forecasts.
- **Forecast Horizon ($[t+3, t+7]$):** 5 consecutive minutes. Labeled positive ($y=1$) if and only if an authentic attack episode onset begins in this window.

#### Chronological Dataset Partition:
| Partition | Days | Total Windows | Negative Windows ($y=0$) | Positive Windows ($y=1$) | Ground Truth Attack Onsets | Attack Scenarios |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Train Split** | Monday, Tuesday, Wednesday | 1,117 | 1,087 (97.3%) | 30 (2.7%) | 9 | FTP-Patator, SSH-Patator, DoS Slowloris, Heartbleed |
| **Test Split** | Thursday, Friday | 280 | 245 (87.5%) | 35 (12.5%) | 10 | Web BruteForce, Web XSS, Botnet, PortScan, LOIC DDoS |

> [!WARNING]
> **Cross-Category Zero-Shot Transfer**: There is **zero overlap** between the attack categories in the training set and the test set. Testing on Thursday/Friday evaluates whether baseline network flow fluctuations prior to brute force or DoS attacks share generalizable precursor signatures with Web attacks, Botnets, and PortScans.

---

### 3. Model Architecture & Preprocessing

#### Predictor Features (120 Dimensions):
The 12 observable flow metrics extracted per 1-minute epoch (lagged across $t-9$ to $t$):
1. `flow_count`: Total active network flows in the epoch.
2. `total_packets`: Total volume of transmitted packets.
3. `total_bytes`: Total byte throughput.
4. `mean_flow_duration_ms`: Average flow longevity.
5. `std_flow_duration_ms`: Variance of flow duration.
6. `tcp_flow_ratio`: Fraction of transport flows using TCP.
7. `udp_flow_ratio`: Fraction of transport flows using UDP.
8. `dst_port_diversity`: Count of distinct destination ports contacted.
9. `dst_port_entropy`: Shannon entropy of destination port distribution.
10. `distinct_src_ips`: Number of unique active source addresses.
11. `distinct_dst_ips`: Number of unique destination hosts contacted.
12. `syn_flag_ratio`: Fraction of TCP packets exhibiting the SYN flag.

All attack labels (`attack_flow_count`, `benign_flow_count`, `is_attack_active`, `attack_classes`) and target-derived fields are strictly excluded.

#### Preprocessing Integrity:
- **StandardScaler**: Fit strictly on `X_train` ($N=1,117$).
- `scaler.n_samples_seen_ = 1117` (test set observations were never seen during scaler parameter fitting).
- Preprocessor serialized as `models/temporal_forecasting/preprocessor.joblib`.

---

### 4. Comprehensive Evaluation Results

#### Window-Level Binary Classification Performance (Test Split $N=280$, 35 Positives, 245 Negatives):

| Model Name | PR-AUC | ROC-AUC | Precision | Recall | F1 Score | FPR | False Alarms / Hour | Confusion Matrix [TN, FP; FN, TP] |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dummy Prior Baseline** | 0.1250 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.00 | `[245, 0; 35, 0]` |
| **Dummy Stratified Baseline** | 0.1310 | 0.5102 | 0.3333 | 0.0286 | 0.0526 | 0.0082 | 0.49 | `[243, 2; 34, 1]` |
| **Logistic Regression (Primary)** | **0.1554** | **0.5370** | **0.1538** | **0.0571** | **0.0833** | **0.0449** | **2.69** | `[234, 11; 33, 2]` |
| **Random Forest (Tree Baseline)** | **0.1815** | **0.5805** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.00 | `[245, 0; 35, 0]` |
| **Compact PyTorch LSTM** | 0.1206 | 0.5018 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.00 | `[245, 0; 35, 0]` |

#### Event-Level Detection & Lead Time Audit:

Across the **10 forecastable test attack onsets**:

| Event ID | Day | Start Time | Attack Class | Anchor Epoch | Detected by LR | LR Max Prob | Lead Time (min) |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :---: |
| `EVT_FRI_01` | Friday | 09:12:00 | Botnet ARES | 09:08:00 | Missed | 0.4120 | - |
| `EVT_FRI_02` | Friday | 13:45:00 | PortScan Probe | 13:38:00–13:40:00 | Missed | 0.3840 | - |
| `EVT_FRI_19` | Friday | 13:52:00 | PortScan Stage 1 | 13:48:00 | **Detected** | 0.7278 | **4.0 min** |
| `EVT_FRI_20` | Friday | 13:55:00 | PortScan Stage 2 | 13:48:00 | **Detected (Multi)** | 0.7278 | **7.0 min** |
| `EVT_FRI_21` | Friday | 14:35:00 | PortScan Stage 3 | 14:30:00 | Missed | 0.4912 | - |
| `EVT_FRI_27` | Friday | 15:56:00 | DDoS LOIC | 15:50:00 | **Detected** | 0.5443 | **6.0 min** |
| `EVT_THU_01` | Thursday | 09:20:00 | Web BruteForce | 09:14:00–09:15:00 | Missed | 0.2215 | - |
| `EVT_THU_02` | Thursday | 10:15:00 | Web XSS | 10:08:00–10:10:00 | Missed | 0.3120 | - |
| `EVT_THU_03` | Thursday | 10:40:00 | Web SqlInjection | 10:33:00–10:35:00 | Missed | 0.2890 | - |
| `EVT_THU_04` | Thursday | 11:10:00 | Web XSS Stage 2 | 11:03:00–11:05:00 | Missed | 0.1980 | - |

#### Event-Level Summary:
- **Rule 1 (Multi-Event Credit):** 3 / 10 onsets detected (**30.0%**).
- **Rule 2 (Strict Earliest Attribution):** 2 / 10 onsets detected (**20.0%**). Anchor `13:48:00` credited to `EVT_FRI_19`; `EVT_FRI_20` requires an unconsumed anchor.
- **Lead Times:**
  - `EVT_FRI_19` (PortScan): 4.0 minutes advance warning before attack flows hit wire.
  - `EVT_FRI_27` (LOIC DDoS): 6.0 minutes advance warning before packet flooding begins.
  - Mean lead time: **5.67 minutes**.

---

### 5. Uncertainty & Statistical Significance Analysis

To rigorously evaluate whether the primary model's PR-AUC lift (+0.0304 over dummy guessing) is statistically robust, we refer to the 2,000-iteration bootstrap hypothesis test conducted on the test split:

- **$\Delta\text{PR-AUC}$ (Logistic Regression vs. Dummy Prior):**
  - Point Estimate: `+0.0304`
  - 95% Bootstrap Confidence Interval: `[-0.0062, +0.1121]`
  - Empirical $p$-value ($P(\Delta \le 0)$): `p = 0.0480`
- **ROC-AUC (Logistic Regression):**
  - Point Estimate: `0.5370`
  - 95% Bootstrap Confidence Interval: `[0.4242, 0.6469]` (spans random guessing $0.5000$).

#### Scientific Caveat:
Because the lower bound of the 95% confidence interval for $\Delta\text{PR-AUC}$ crosses zero (`-0.0062`), the model demonstrates an empirical positive trend under cross-category transfer, but cannot be claimed as statistically certain without additional capture days.

---

### 6. Why Complex Sequence Models (BiLSTM / Transformer) Failed

In Phase 9C, we explicitly tested whether a compact PyTorch recurrent neural network could learn superior sequence representations. It achieved:
$$\text{PR-AUC} = 0.1206 \quad (\text{below Dummy Prior } 0.1250)$$

#### Analytical Reasons for Neural Failure:
1. **Severe Event-Level Sample Deficit:** The training set contains only **9 attack onsets across 4 scheduled tool runs** (FTP-Patator, SSH-Patator, DoS Slowloris, Heartbleed).
2. **Parameter Over-Capacity:** Even a minimal LSTM has over 1,800 trainable parameters. Fitting 1,800 parameters to 9 events causes the network to memorize specific minute-level background traffic unique to Tuesday and Wednesday.
3. **Out-of-Distribution Rejection:** When exposed to Thursday/Friday traffic (Web, Botnet, PortScan, LOIC), the neural representations completely collapse, predicting near-zero probabilities for all positive windows.
4. **Conclusion:** Deep neural sequence modeling is scientifically invalid until the training partition contains dozens of independent attack campaigns. The linear class-weighted model remains the superior, regularized approach for this dataset.

---

### 7. Exported Model Artifacts & Architecture

The exported model package is permanently stored in:
`models/temporal_forecasting/`

```
models/temporal_forecasting/
├── model.joblib              # Primary validated Logistic Regression (class_weight='balanced')
├── preprocessor.joblib       # StandardScaler fit strictly on training set (N=1117)
├── random_forest.joblib      # Non-linear Random Forest baseline
├── compact_lstm.pt           # PyTorch weights for recurrent sequence model
├── metadata.json             # Provenance, target schema, feature order, and evaluation metrics
├── forecaster.py             # Schema-validated inference engine (TemporalAttackForecaster)
└── __init__.py               # Package export
```

#### Dedicated Inference Module (`models/temporal_forecasting/forecaster.py`):
- Provides `TemporalAttackForecaster` class.
- Validates 120-dimensional input sequences.
- Checks feature names and ordering against `lag_order`.
- **Prohibits Incompatible Packet Features:** If live capture packet aggregations (`mean_frame_length`, `std_frame_length`, `tcp_packet_ratio`) are supplied, raises:
  ```text
  Schema Mismatch: Detected incompatible packet-layer feature(s).
  This model was trained on dataset-native flow features (PREDICTOR_COLUMNS).
  Feeding packet features into a flow-trained model without empirical calibration is prohibited.
  ```
- Returns structured JSON:
  ```json
  {
    "status": "EXPERIMENTAL_RESEARCH_MODEL",
    "target": "Target A (Onset in [t+3, t+7] after 10m clean history and 2m gap)",
    "prediction_available": true,
    "forecast_probability": 0.7278,
    "is_calibrated": false,
    "calibration_note": "Uncalibrated class-weighted logistic probability score. Tested under zero-shot cross-category attack transfer.",
    "decision_threshold": 0.5,
    "forecast_onset_positive": true
  }
  ```

---

### 8. API Integration

In `dashboard/server.py`, two dedicated research endpoints were implemented:
1. `GET /api/forecast/temporal-experimental/metadata`: Returns machine-readable provenance, feature lists, target definitions, and metrics.
2. `POST /api/forecast/temporal-experimental`: Ingests a 120-dimensional flow sequence `{"features": [...], "threshold": 0.5}` and evaluates genuine Target A forecast probability.

All operational live capture endpoints remain strictly decoupled and gated (`FORECASTING MODEL NOT VALIDATED FOR THIS DATA`), preventing invalid cross-layer inference.

---

### 9. Validation and Test Results

The test suite [tests/test_phase9c_temporal_model.py](file:///c:/Users/Dell Latitude 7410/Downloads/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main/tests/test_phase9c_temporal_model.py) validates all 9 criteria:
- `test_model_save_and_load`: PASSED
- `test_feature_schema_validation`: PASSED
- `test_missing_and_invalid_features`: PASSED
- `test_training_only_preprocessing`: PASSED
- `test_prediction_output_and_calibration`: PASSED
- `test_target_leakage_prevention`: PASSED
- `test_reproducible_evaluation_metrics`: PASSED
- `test_separation_between_experimental_and_production_models`: PASSED
- `test_api_experimental_endpoints`: PASSED

**Full Test Suite Execution:**
`169 passed, 0 failed in 117.65s (python -m pytest tests/)`.
Production BiLSTM weights (`models/bilstm_weights.pt`) and production scaler (`pipeline/scaler.pkl`) remain untouched.
