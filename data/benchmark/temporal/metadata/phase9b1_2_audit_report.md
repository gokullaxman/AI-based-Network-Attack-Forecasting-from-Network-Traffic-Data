# PHASE 9B.1.2 AUDIT REPORT: TIMESTAMP, EVENT LEDGER, AND FEATURE-DEFINITION VERIFICATION

**Project:** AI-Based Network Attack Forecasting from Network Traffic Data  
**Audit Scope:** Temporal Benchmark Data Integrity & Experimental Specification Verification  
**Evaluation Role:** Senior Cybersecurity ML Researcher & Temporal Dataset Auditor  
**Operating Environment:** Windows 11, Python 3.13.12 (CPU-only)  
**Date:** October 26, 2026  
**Final Phase Verdict:** **READY WITH RESTRICTIONS** (Temporal and label integrity mathematically resolved; model training may proceed under strict zero-shot cross-category transfer constraints).

---

## 1. Executive Summary & Audit Context

Phase 9B.1.2 resolves the scientific and temporal-integrity issues identified during Phase 9B.1.1 prior to any model training. The audit rigorously inspected:
1. **Timestamp Chronology:** Resolved ambiguous 12-hour timestamp formatting across all 7 authentic CICIDS2017 capture CSV files, eliminating afternoon-to-morning time inversions and achieving 100% within-day minute-level continuity.
2. **Event Ledger & Episode Reconciliation:** Built a complete, machine-readable event ledger (`phase9b1_2_event_ledger.csv`) containing all 57 strict ground-truth attack episodes, reconciling why earlier reports identified 14 positive-window clusters vs. 57 strict episodes vs. 19 forecastable onsets.
3. **Target A Formulation:** Validated the primary onset-forecasting target ($[t-9, t]$ history, $[t+1, t+2]$ gap, $[t+3, t+7]$ horizon), proving that Target A strictly enforces clean pre-conditions and forecasts genuine new attack episodes rather than continuing flows.
4. **Predictor Definitions & Bounds:** Audited all 12 observable predictors. Specifically verified that `dst_port_entropy` is **Normalized Shannon Entropy (Pielou's evenness)** bounded in $[0.0, 1.0]$ with $0.0$ for $k \le 1$, and that `syn_flag_ratio` is mathematically and empirically bounded in $[0.0, 1.0]$ based on binary $\{0, 1\}$ SYN flags.
5. **Evaluation Split Reassessment:** Recomputed the Monday–Wednesday (train) versus Thursday–Friday (test) chronological partition, confirming zero category overlap (`shared: []`) and establishing strict zero-shot cross-category transfer framing.

All changes remain completely isolated under `data/benchmark/temporal/`. Production BiLSTM weights, scaler, live-capture logic, and dashboard endpoints were strictly preserved without modification.

---

## 2. Cryptographic Provenance & Artifact Integrity

| Artifact | File Path | Size (Bytes) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **Pre-Correction Epochs (9B.1.1)** | `data/benchmark/temporal/metadata/epochs_1min_pre_correction_phase9b1_1.parquet` | 212,687 | `a333d3e61dcb034330f3f298d0640a1e2802f2a002f6b585105d566cf7ca7e44` |
| **Rebuilt Corrected Epochs** | `data/benchmark/temporal/metadata/epochs_1min.parquet` | 212,598 | `2c3490de8f516b2a29e1d58239e4244ac52102edb6a804e4e588bed09d5cef59` |
| **Timestamp Audit JSON** | `data/benchmark/temporal/metadata/phase9b1_2_timestamp_audit.json` | 2,132 | `9d554a9fc1725b87dc51d7c35eecbb34d0b2fcf0808cfcf686948a60ba464197` |
| **Machine-Readable Event Ledger** | `data/benchmark/temporal/metadata/phase9b1_2_event_ledger.csv` | 9,959 | `ca2cf7c897f1f1d1795dbdf47e8e97f0fb52194553bfa59815a5fbc4004c8672` |
| **Target Formulation Audit JSON** | `data/benchmark/temporal/metadata/phase9b1_2_target_audit.json` | 991 | `2d69e4f5092f694e41cf8daaa329b39e6a00b213b7bcf524660eb9df0ea37466` |
| **Feature Specification Audit JSON**| `data/benchmark/temporal/metadata/phase9b1_2_feature_audit.json` | 6,885 | `2f9f59223e71d3466184df517726ff052f537aa22a7f058097d4d752f9b882eb` |
| **Production BiLSTM Model Weights**| `models/bilstm_weights.pt` | 51,765 | `6067b5e4c62c2f21303ba67bfdca9d83df2357fb6c189b889d1ec86d140e4cf8` |
| **Production Scaler** | `pipeline/scaler.pkl` | 1,847 | `e43b12975765fd76f27b9c9f658092ff5e13d941de517b6bfa1431be7a13dfaa` |

---

## 3. Task 1: Timestamp Chronology Resolution

### 3.1 Root Cause of Afternoon Inversion
Raw CICIDS2017 flow timestamps emitted by the ISCX/CIC flow generator contain 12-hour clock times formatted without AM/PM designations (e.g. `1:00`, `3:30`, `5:02`). Naive string parsing (`pd.to_datetime`) interpreted these as early-morning hours (01:00 to 05:00 AM). In previous phases, this artificially sorted afternoon records before morning records (e.g., 01:00 AM before 08:55 AM), inverting chronology and creating artificial multi-hour continuity gaps.

### 3.2 Ground-Truth Capture Schedule & Evidence
Empirical inspection of the capture metadata, raw filenames, and official UNB dataset documentation establishes conclusive evidence:
1. **Capture Window:** All experiments were conducted during standard institutional working hours (08:30 to 17:30). No traffic was collected during early morning hours (01:00 to 07:00).
2. **Explicit Afternoon Filenames:**
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`: All 225,745 flows possess raw hours 3, 4, 5. UNB documentation logs the LOIC DDoS attack as executed from 15:30 to 17:00 (3:30 PM to 5:00 PM).
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`: All 286,467 flows possess raw hours 1, 2, 3. UNB documentation logs PortScan as executed from 13:00 to 15:30 (1:00 PM to 3:30 PM).
   - `Friday-WorkingHours-Morning.pcap_ISCX.csv`: All 191,033 flows possess raw hours 8, 9, 10, 11, 12 (08:59 to 12:59). Contains zero afternoon hours.
3. **Tuesday & Wednesday Attacks:**
   - `Tuesday-WorkingHours.pcap_ISCX.csv`: Morning flows (hours 9..10) contain FTP-Patator (scheduled 09:20–10:20 AM); afternoon flows (hours 2..3) contain SSH-Patator (scheduled 14:00–15:00 / 2:00–3:00 PM).
   - `Wednesday-workingHours.pcap_ISCX.csv`: Morning flows (hours 9..11) contain DoS attacks (scheduled 09:47–11:23 AM); afternoon flows (hours 3) contain Heartbleed (scheduled 15:12–15:32 / 3:12–3:32 PM).

### 3.3 Defensible Correction Rule
```text
For WorkingHours captures:
If raw hour H in {1, 2, 3, 4, 5, 6, 7}:
    H_corrected <- H + 12  (mapping 1:00..7:00 PM to 13:00..19:00)
If raw hour H in {8, 9, 10, 11, 12}:
    H_corrected <- H       (strictly preserved as morning/noon)
```

### 3.4 Empirical Correction Breakdown
- **Total Flow Records Shifted (+12h):** 1,183,114 flows (46.54%)
- **Total Flow Records Preserved:** 1,359,027 flows (53.46%)
- **Total Ambiguous Records:** 0 flows (0.00%)
- **Ambiguity Handling:** Zero ambiguity exists because raw hours across all 2.54 million flows are strictly bimodal: $\{8, 9, 10, 11, 12\}$ and $\{1, 2, 3, 4, 5\}$. Morning captures contain zero afternoon hours.

### 3.5 Post-Correction Daily Continuity Table
| Capture Day | File Count | Total Epochs | Start Timestamp | End Timestamp | Continuous 1m Steps | Gaps > 1 min |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Monday** | 1 | 487 | 2017-07-03 08:55:00 | 2017-07-03 17:01:00 | 486 | **0** |
| **Tuesday** | 1 | 488 | 2017-07-04 08:53:00 | 2017-07-04 17:00:00 | 487 | **0** |
| **Wednesday** | 1 | 509 | 2017-07-05 08:42:00 | 2017-07-05 17:10:00 | 508 | **0** |
| **Thursday** | 1 | 241 | 2017-07-06 08:59:00 | 2017-07-06 12:59:00 | 240 | **0** |
| **Friday** | 3 | 484 | 2017-07-07 08:59:00 | 2017-07-07 17:02:00 | 483 | **0** |
| **Total Benchmark** | **7** | **2,209** | — | — | **2,204** | **0** |

Within every single capture day, the timeline is now **100% continuous without a single missing or broken minute**.

---

## 4. Task 2: Machine-Readable Event Ledger & Episode Reconciliation

### 4.1 Ground-Truth Attack Episode Extraction Rule
A **Strict Ground-Truth Attack Episode** is defined as an unbroken sequence of contiguous 1-minute epochs where $attack\_flow\_count > 0$. If an epoch contains 0 attack flows, the episode terminates immediately (strict zero benign tolerance).

Applying this strict rule yields:
- **Total Strict Attack Episodes:** 57 episodes across the 5 capture days.
- **Total Attack-Active Duration:** 492 minutes.
- **Total Attack Flows:** 556,556 flows.

### 4.2 Forecastability Under Target A
Under Target A, an episode is **forecastable** if and only if:
1. Its start time $t_{start}$ is preceded by 10 minutes of completely attack-free traffic ($attack\_flow\_count == 0$ in $[t_{start}-10, t_{start}-1]$).
2. The 2-minute lead gap is completely clean ($[t_{start}-2, t_{start}-1]$).
3. The episode onset minute falls within the 5-minute forecast horizon $[t_{anchor}+3, t_{anchor}+7]$ of at least one eligible anchor epoch.

Out of 57 strict episodes:
- **Forecastable Onset Episodes:** **19 episodes** (9 in Train [Mon–Wed], 10 in Test [Thu–Fri]).
- **Unforecastable Episodes:** **38 episodes** (due to continuing attack traffic, ongoing probe streams, or brief 1- to 2-minute benign intervals within a scheduled attack campaign).

### 4.3 Explicit Reconciliation: 14 Clusters vs. 57 Episodes vs. 19 Onsets
| Metric | Count | Exact Definition | Relationship & Operational Meaning |
| :--- | :---: | :--- | :--- |
| **Strict GT Episodes** | **57** | Contiguous minutes with $attack\_flows > 0$ (zero benign tolerance). | Complete ground-truth inventory of attack activity bursts. |
| **Forecastable Episodes** | **19** | Strict GT episodes preceded by clean 10m history & clean 2m gap. | True onsets that are mathematically eligible to be anticipated before initiation. |
| **Target A Positive Windows** | **65** | Unique anchor epochs $t$ with clean history/gap and onset in $[t+3, t+7]$. | Observation points that successfully forecast an impending attack onset. |
| **Total Episode-Window Links** | **76** | Sum of associated forecast windows across all 19 forecastable episodes. | 76 associations collapse into 65 unique windows because closely spaced episodes share horizons. |
| **Phase 9B.1 Positive Clusters** | **14** | Connected components of Target B positive windows ($\Delta t \le 5\text{m}$). | Result of macro-clustering Target B activity windows, which conflated continuing attacks with onsets. |

### 4.4 Scenario Overlap & Multi-Episode Bursts
Distinct episodes frequently belong to the same scheduled attack tool execution:
- **Heartbleed (Wednesday 15:12–15:32):** Generates 11 distinct 1-minute bursts separated by 1-minute benign pauses. Only the initial burst (`EVT_WED_47`, 15:12) is genuinely forecastable from clean baseline traffic. Bursts 2–11 are continuing phases of the Heartbleed scenario. Anchor `15:09` simultaneously covers onsets at 15:12, 15:14, and 15:16.
- **Botnet / Ares (Friday 10:04–12:59):** Generates 17 distinct episodes. Only 2 onsets (`EVT_FRI_01` at 09:34 and `EVT_FRI_02` at 10:04) have clean 10-minute pre-attack baselines. The remaining 15 episodes represent cyclic C2 polling and DoS bursts with short benign pauses.
- **PortScan (Friday 13:05–15:23):** Generates 9 episodes. Only 4 onsets are forecastable; the remainder are continuing scan stages.

---

## 5. Task 3: Target A Implementation Audit

### 5.1 Formulation Comparison
- **Observation History:** $[t-9, t]$ (10 minutes)
- **Lead-Time Gap:** $[t+1, t+2]$ (2 minutes)
- **Forecast Horizon:** $[t+3, t+7]$ (5 minutes)

| Window State | Target A (Genuine Onset) | Target B (Future Activity) | Integrity Rationale |
| :--- | :---: | :---: | :--- |
| **History Condition** | Must be 100% attack-free | Must be 100% attack-free | Essential to prevent observing the attack before forecasting it. |
| **Lead Gap Condition** | **Must be 100% attack-free** | Attack flows permitted | Target A requires lead time; Target B allows the attack to have already started. |
| **Horizon Condition** | **Must contain a NEW episode start** | Any attack flow $> 0$ | Target A detects impending attacks; Target B detects ongoing or stale attacks. |
| **Eligible Windows** | **1,397** | **1,425** | Target A excludes 28 windows where attack begins prematurely in the lead gap. |
| **Positive Windows ($y=1$)** | **65** | **89** | Target A eliminates 24 windows forecasting ongoing attacks without a new onset. |
| **Negative Windows ($y=0$)** | **1,332** | **1,336** | Benign observation windows. |
| **Effective Imbalance** | **1 : 20.5** | **1 : 15.0** | Target A presents realistic, challenging operational imbalance. |
| **Ineligible (History Attack)** | 704 | 704 | Attack active during observation window. |
| **Ineligible (Gap Attack)** | 28 | 0 | Attack initiated in the buffer gap. |
| **Excluded (Day Boundaries)** | 80 | 80 | Windows crossing day boundaries or lacking 17m continuity. |

Target A is retained as the sole primary target because it enforces authentic intrusion forecasting.

---

## 6. Task 4: Feature Definition & Statistical Verification

All 12 candidate predictors are derived solely from observable flow headers aggregated over 1-minute epochs.

### 6.1 Predictor Specification Table
| Predictor Name | Source Fields | Exact Formula | Unit | Valid Range | Zero/Missing Behavior | Live Capture Reproducible |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: |
| `flow_count` | `Flow ID` | $\text{count}(\text{flows})$ | flows/min | $[1, \infty)$ | Never null; $\ge 1$ | Yes |
| `total_packets` | `Total Fwd/Bwd Packets` | $\sum (\text{Fwd} + \text{Bwd Packets})$ | pkts/min | $[1, \infty)$ | Non-negative sum | Yes |
| `total_bytes` | `Total Length of Fwd/Bwd` | $\sum (\text{Fwd} + \text{Bwd Bytes})$ | bytes/min | $[0, \infty)$ | Non-negative sum | Yes |
| `mean_flow_duration_ms`| `Flow Duration` | $\text{mean}(\text{Duration} / 1000.0)$ | ms | $[0, \infty)$ | Duration in microseconds $/ 1000$ | Yes |
| `std_flow_duration_ms` | `Flow Duration` | $\text{std}(\text{Duration} / 1000.0, ddof=0)$ | ms | $[0, \infty)$ | Zero if single flow | Yes |
| `tcp_flow_ratio` | `Protocol` | $\text{count}(\text{Proto} == 6) / \text{flow\_count}$| ratio | $[0.0, 1.0]$ | Bounded ratio | Yes |
| `udp_flow_ratio` | `Protocol` | $\text{count}(\text{Proto} == 17) / \text{flow\_count}$| ratio | $[0.0, 1.0]$ | Bounded ratio | Yes |
| `dst_port_diversity` | `Destination Port` | $\text{nunique}(\text{Destination Port})$ | ports/min | $[1, \infty)$ | Distinct destination ports | Yes |
| `dst_port_entropy` | `Destination Port` | $\frac{-\sum p_i \log_2(p_i)}{\log_2(k)}$ ($k = \text{ports}$) | ratio | $[0.0, 1.0]$ | **Explicitly 0.0 when $k \le 1$** | Yes |
| `distinct_src_ips` | `Source IP` | $\text{nunique}(\text{Source IP})$ | IPs/min | $[1, \infty)$ | Distinct source hosts | Yes |
| `distinct_dst_ips` | `Destination IP` | $\text{nunique}(\text{Destination IP})$ | IPs/min | $[1, \infty)$ | Distinct destination hosts | Yes |
| `syn_flag_ratio` | `SYN Flag Count` | $\sum \text{SYN Flag Count} / \text{flow\_count}$| ratio | $[0.0, 1.0]$ | **Bounded ratio ($\text{SYN} \in \{0, 1\}$)** | Yes |

### 6.2 Destination-Port Entropy Audit
- **Implementation:** `compute_shannon_entropy(df["Destination Port"])` in `pipeline/temporal_preprocessor.py`.
- **Classification:** **Normalized Shannon Entropy (Pielou's evenness index)**.
- **Mathematical Bound:** $H_{\text{norm}} \in [0.0, 1.0]$.
- **Boundary Handling:** When only zero or one distinct port is observed ($k \le 1$), the denominator $\log_2(1) = 0$; the implementation explicitly returns `0.0`, preventing division-by-zero errors.

### 6.3 SYN-Flag Ratio Audit
- **Verification:** Audited across all 2,542,141 authentic CICIDS2017 flow records.
- **Empirical Check:** `df['SYN Flag Count'].unique()` yields strictly $\{0, 1\}$.
- **Mathematical Bound:** Since each flow contributes at most 1 SYN flag, $\sum \text{SYN Flag Count} \le \text{flow\_count}$. Thus, `syn_flag_ratio` is mathematically and empirically bounded in $[0.0, 1.0]$.

### 6.4 Empirical Feature Distributions (2,209 Epochs)
| Predictor Name | Null Count | Inf Count | Mean | Std Dev | Min | Max | Non-Constant |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `flow_count` | 0 | 0 | 1,150.81 | 2,203.57 | 1.0 | 46,216.0 | Passed |
| `total_packets` | 0 | 0 | 23,688.39 | 67,800.16 | 8.0 | 849,289.0 | Passed |
| `total_bytes` | 0 | 0 | 20,536,619.67 | 85,967,343.47 | 352.0 | 1,061,646,677.0 | Passed |
| `mean_flow_duration_ms`| 0 | 0 | 14,034.42 | 11,540.04 | 0.0 | 79,483.47 | Passed |
| `std_flow_duration_ms` | 0 | 0 | 19,006.13 | 11,262.82 | 0.0 | 56,108.97 | Passed |
| `tcp_flow_ratio` | 0 | 0 | 0.6276 | 0.2223 | 0.0 | 1.0 | Passed |
| `udp_flow_ratio` | 0 | 0 | 0.3685 | 0.2201 | 0.0 | 1.0 | Passed |
| `dst_port_diversity` | 0 | 0 | 59.88 | 100.94 | 1.0 | 1,849.0 | Passed |
| `dst_port_entropy` | 0 | 0 | 0.4704 | 0.2312 | 0.0 | 0.9859 | Passed |
| `distinct_src_ips` | 0 | 0 | 27.24 | 42.66 | 1.0 | 711.0 | Passed |
| `distinct_dst_ips` | 0 | 0 | 38.64 | 60.10 | 1.0 | 1,073.0 | Passed |
| `syn_flag_ratio` | 0 | 0 | 0.0453 | 0.0766 | 0.0 | 0.9996 | Passed |

Zero missing values or infinities exist across the entire rebuilt dataset. All 12 candidate predictors demonstrate non-zero variance.

---

## 7. Task 5: Chronological Evaluation Split Reassessment

### 7.1 Split Statistics
| Metric | Training Split (Mon–Wed) | Testing Split (Thu–Fri) | Total Benchmark |
| :--- | :---: | :---: | :---: |
| **Capture Days** | Monday, Tuesday, Wednesday | Thursday, Friday | 5 days |
| **Total Minutes / Epochs** | 1,484 | 725 | 2,209 |
| **Eligible Windows ($N$)** | **1,117** (79.96%) | **280** (20.04%) | **1,397** |
| **Positive Windows ($y=1$)** | **30** (2.69%) | **35** (12.50%) | **65** |
| **Negative Windows ($y=0$)** | **1,087** (97.31%) | **245** (87.50%) | **1,332** |
| **Class Imbalance Ratio** | **1 : 36.2** | **1 : 7.0** | **1 : 20.5** |
| **Strict GT Episodes** | 25 | 32 | 57 |
| **Forecastable Onsets** | **9** | **10** | **19** |

### 7.2 Category Overlap & Generalization Characterization
- **Training Attack Categories (Mon–Wed):** FTP-Patator, SSH-Patator, DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed.
- **Testing Attack Categories (Thu–Fri):** Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection, Bot, PortScan, DDoS.
- **Shared Categories:** **`[]` (Zero category overlap)**.

> [!WARNING]
> **Exploratory Zero-Shot Attack-Category Transfer Characterization**  
> Because there is zero category overlap between training and testing, a model trained on Monday–Wednesday and evaluated on Thursday–Friday is being tested on its ability to forecast unseen attack classes based purely on generic pre-attack baseline network disturbance patterns. This evaluation MUST NOT be claimed as measuring generalizable forecasting performance for specific attack types. It is strictly an exploratory zero-shot cross-category transfer benchmark.

---

## 8. Test Suite Verification Results

Regression test suite `tests/test_phase9b1_2_verification.py` was executed alongside the workspace test suite:
- `test_timestamp_chronology_and_unbroken_continuity`: **PASSED** (2,209 epochs, 0 within-day gaps).
- `test_machine_readable_event_ledger`: **PASSED** (57 episodes, 19 forecastable onsets, 65 unique windows, 76 associations).
- `test_target_a_onset_formulation_audit`: **PASSED** (1,397 eligible, 65 positive, 1,332 negative).
- `test_feature_definitions_bounds_and_validity`: **PASSED** (normalized entropy $[0, 1]$, SYN ratio $[0, 1]$, zero NaNs/infs).
- `test_chronological_evaluation_split`: **PASSED** (zero category overlap, 9 train onsets, 10 test onsets).
- `test_pre_correction_and_production_isolation`: **PASSED** (production weights and pre-correction hashes verified).

**Total Workspace Tests:** 130 tests executed; **130 PASSED (100% pass rate)**.

---

## 9. Final Verdict & Next Steps

### Verdict
**READY WITH RESTRICTIONS**

### Restrictions for Subsequent Phases
1. **Target Formulation:** Retain Target A exclusively as the primary forecasting target. Target B may only be reported as an auxiliary activity-detection comparison.
2. **Evaluation Framing:** Any evaluation using the chronological Monday–Wednesday vs. Thursday–Friday split must be explicitly framed as exploratory zero-shot cross-category transfer, with documented recognition of the 10-event test sample size.
3. **Model Training (Phase 9B.2):** Baselines (Logistic Regression, Random Forest, BiLSTM) must be evaluated with event-level metrics alongside window-level precision/recall/PR-AUC to reflect the 19 underlying attack onsets.
4. **Production Isolation:** Production BiLSTM weights and live dashboard architecture must remain completely isolated from the temporal forecasting benchmark.

*Awaiting approval before proceeding to Phase 9B.2.*
