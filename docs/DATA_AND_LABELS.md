# Data, Labels & Forecasting Target Specification

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Document Version:** 2.1-Production  
**Date:** November 1, 2026  

---

## 1. Problem Formulation: Detection vs. Forecasting

A primary objective of this architecture is strict mathematical and operational distinction between:
1. **Active Attack Detection**: Classifying whether an ongoing network flow or current time epoch contains malicious activity ($y_t \in \{0, 1\}$).
2. **Current Attack Stage Classification**: Determining which attack phase is actively executing at time $t$ ($\text{Stage}_t \in \{1 \dots 5\}$).
3. **Attack-Onset Forecasting (Target A)**: Estimating the probability that a new, authentic attack episode will begin in a future time horizon, given that the historical observation window is verified attack-free.
4. **Stage Transition Forecasting**: Predicting the probability distribution over the subsequent kill-chain phase conditioned on observed sequence history.

These tasks address fundamentally different operational needs and must never share conflated metrics or misleading labels.

---

## 2. Target A: Attack-Onset Forecasting Specification

Target A is formulated to provide actionable, early-warning lead time before an adversary executes intrusion or exploitation activity.

### 2.1 Window Topology & Temporal Boundaries
The continuous temporal sequence of 1-minute discrete epochs is evaluated using a 17-minute sliding span:

```
[ t-9, t-8, t-7, t-6, t-5, t-4, t-3, t-2, t-1, t ]   [ t+1, t+2 ]   [ t+3, t+4, t+5, t+6, t+7 ]
<---------------- History Window (10 min) -------------->   <-- Lead Gap -->   <---- Forecast Horizon (5 min) ---->
                 Zero Attack Flows                             Zero Attack         Positive if Onset Starts Here
```

- **Historical Observation Window ($[t-9, t]$)**:
  - Duration: Exactly 10 consecutive 1-minute epochs.
  - Content: 12 observable flow metrics per epoch ($10 \times 12 = 120$ continuous dimensions).
  - Pre-condition: Must be **100% attack-free** ($\sum_{k=t-9}^t \text{attack\_flows}_k = 0$).
- **Lead-Time Gap ($[t+1, t+2]$)**:
  - Duration: Exactly 2 consecutive 1-minute epochs.
  - Purpose: Enforces an unambiguous buffer between observation time $t$ and event onset. Prevents concurrent detection from masquerading as forecasting.
  - Pre-condition: Must be **100% attack-free** ($\sum_{k=t+1}^{t+2} \text{attack\_flows}_k = 0$).
- **Forecast Horizon ($[t+3, t+7]$)**:
  - Duration: Exactly 5 consecutive 1-minute epochs.
  - Label Assignment:
    $$y_t = \begin{cases} 1 & \text{if } \sum_{k=t+3}^{t+7} \text{attack\_flows}_k > 0 \\ 0 & \text{if } \sum_{k=t+3}^{t+7} \text{attack\_flows}_k = 0 \end{cases}$$

### 2.2 Window Eligibility & Filtering
| Category | Definition | Action |
| :--- | :--- | :--- |
| **Eligible Positive ($y=1$)** | History clean, Gap clean, Attack flows appear in $[t+3, t+7]$ | Included in training/evaluation |
| **Eligible Negative ($y=0$)** | History clean, Gap clean, Horizon clean ($[t+3, t+7]$ attack-free) | Included in training/evaluation |
| **Ineligible (Active Attack in History)** | Attack flows present in $[t-9, t]$ | **Excluded** (Ongoing attack, not onset) |
| **Ineligible (Active Attack in Gap)** | Attack flows present in $[t+1, t+2]$ | **Excluded** (Insufficient lead-time) |
| **Continuity Boundary Exclusion** | Missing minutes or day boundaries | **Excluded** (No cross-day stitching) |

---

## 3. Prevention of Temporal & Information Leakage

Strict auditing guarantees that future information is never leaked into historical features:

1. **Chronological Splitting**:
   - Random K-fold splitting across overlapping sliding windows is **strictly prohibited**, as adjacent sliding windows share 90% of their feature values.
   - All datasets are partitioned chronologically by capture day:
     - **Training Set**: Monday, Tuesday, Wednesday ($N=1,117$ eligible windows).
     - **Test Set**: Thursday, Friday ($N=280$ eligible windows).
2. **Scaler & Preprocessor Fitting**:
   - `StandardScaler` parameters ($\mu, \sigma$) are computed **strictly on the training partition**.
   - `scaler.n_samples_seen_ = 1117`. The test partition was never observed during parameter fitting.
3. **Exclusion of Label-Derived Metadata**:
   - All ground-truth label columns (`attack_flow_count`, `benign_flow_count`, `is_attack_active`, `attack_classes`) are removed from feature tables prior to model input.
4. **Boundary Gap Preservation**:
   - Time continuity is enforced via monotonic timestamp checking. Daily capture files are never concatenated without zero-padded boundary handling.

---

## 4. The Canonical 12-Feature Schema Contract

Both the training pipeline and the live `StreamingFlowAssembler` adhere to the identical 12-feature schema contract:

| # | Feature Name | Data Type | Physical Unit | Missing Value Policy | Valid Range |
| :- | :--- | :---: | :--- | :--- | :--- |
| 1 | `flow_count` | `float64` | flows / min | Zero if empty | $[0, \infty)$ |
| 2 | `total_packets` | `float64` | packets / min | Zero if empty | $[0, \infty)$ |
| 3 | `total_bytes` | `float64` | bytes / min | Zero if empty | $[0, \infty)$ |
| 4 | `mean_flow_duration_ms` | `float64` | milliseconds | 0.0 if no flows | $[0.001, 60000.0]$ |
| 5 | `std_flow_duration_ms` | `float64` | milliseconds | 0.0 if $<2$ flows | $[0, \infty)$ |
| 6 | `tcp_flow_ratio` | `float64` | ratio (dimensionless) | 0.0 if no flows | $[0.0, 1.0]$ |
| 7 | `udp_flow_ratio` | `float64` | ratio (dimensionless) | 0.0 if no flows | $[0.0, 1.0]$ |
| 8 | `dst_port_diversity` | `float64` | distinct count | 0.0 if no flows | $[0, 65535]$ |
| 9 | `dst_port_entropy` | `float64` | normalized Shannon $[0, 1]$ | 0.0 if $\le 1$ port | $[0.0, 1.0]$ |
| 10 | `distinct_src_ips` | `float64` | distinct count | 0.0 if no flows | $[0, \infty)$ |
| 11 | `distinct_dst_ips` | `float64` | distinct count | 0.0 if no flows | $[0, \infty)$ |
| 12 | `syn_flag_ratio` | `float64` | ratio (dimensionless) | 0.0 if no TCP pkts | $[0.0, 1.0]$ |

### 4.1 Lagged Feature Flattening
Over the 10-epoch observation window $[t-9, t]$, the 12 base features are concatenated in chronological order from lag 9 down to lag 0, generating exactly $120$ continuous dimensions:
$$\mathbf{x}_t = \left[ f_{1}^{(t-9)}, f_{2}^{(t-9)}, \dots, f_{12}^{(t-9)}, f_{1}^{(t-8)}, \dots, f_{12}^{(t)} \right] \in \mathbb{R}^{120}$$

---

## 5. Machine-Readable Event Ledger

The ground-truth attack episodes across the weekly evaluation schedule are documented in `data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv`:

| Episode ID | Capture Day | Attack Category | Onset Timestamp | Cessation Timestamp | Duration | Attack Flows |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | Tuesday | FTP-Patator | 2017-07-04 09:20:00 | 2017-07-04 10:20:00 | 60 min | 7,938 |
| 2 | Tuesday | SSH-Patator | 2017-07-04 14:00:00 | 2017-07-04 15:00:00 | 60 min | 5,897 |
| 3 | Wednesday | DoS Slowloris | 2017-07-05 09:47:00 | 2017-07-05 10:10:00 | 23 min | 5,796 |
| 4 | Wednesday | DoS Slowhttptest | 2017-07-05 10:14:00 | 2017-07-05 10:35:00 | 21 min | 5,499 |
| 5 | Wednesday | DoS Hulk | 2017-07-05 10:43:00 | 2017-07-05 11:00:00 | 17 min | 231,073 |
| 6 | Wednesday | DoS GoldenEye | 2017-07-05 11:10:00 | 2017-07-05 11:23:00 | 13 min | 10,293 |
| 7 | Wednesday | Heartbleed | 2017-07-05 15:12:00 | 2017-07-05 15:32:00 | 20 min | 11 |
| 8 | Thursday | Web Attack - Brute Force | 2017-07-06 09:20:00 | 2017-07-06 10:00:00 | 40 min | 1,507 |
| 9 | Thursday | Web Attack - XSS | 2017-07-06 10:15:00 | 2017-07-06 10:35:00 | 20 min | 652 |
| 10 | Thursday | Web Attack - Sql Injection | 2017-07-06 10:40:00 | 2017-07-06 10:42:00 | 2 min | 21 |
| 11 | Thursday | Infiltration (Dropbox Download) | 2017-07-06 14:19:00 | 2017-07-06 14:35:00 | 16 min | 36 |
| 12 | Thursday | Infiltration (PortScan) | 2017-07-06 14:53:00 | 2017-07-06 15:00:00 | 7 min | 12 |
| 13 | Friday | Botnet (ARES) | 2017-07-07 10:02:00 | 2017-07-07 11:20:00 | 78 min | 1,966 |
| 14 | Friday | PortScan (Probe Stage 1) | 2017-07-07 13:58:00 | 2017-07-07 14:34:00 | 36 min | 45,920 |
| 15 | Friday | PortScan (Probe Stage 2) | 2017-07-07 14:51:00 | 2017-07-07 15:29:00 | 38 min | 113,010 |
| 16 | Friday | LOIC DDoS | 2017-07-07 15:56:00 | 2017-07-07 16:16:00 | 20 min | 128,027 |

Total: **19 distinct attack onsets** across the 5 recording days (9 training onsets, 10 testing onsets).
