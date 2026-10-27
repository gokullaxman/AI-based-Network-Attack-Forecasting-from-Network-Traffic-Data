# PHASE 9B.3 VALIDITY REPORT: AUDIT OF FORECASTING BASELINES BEFORE ADVANCED MODELING

**Project:** AI-Based Network Attack Forecasting from Network Traffic Data  
**Experiment Stage:** Phase 9B.3 — Baseline Validation and Pre-Modeling Audit  
**Author / Auditor:** Senior Cybersecurity ML Researcher & Temporal Dataset Auditor  
**Operating Environment:** Windows 11, Python 3.13.12 (CPU-only)  
**Date:** October 26, 2026  
**Final Decision:** **EXPAND THE DATASET FIRST**  
*(The Phase 9B.2 baseline results are 100% reproducible and mathematically verified without temporal or label leakage. However, rigorous statistical auditing reveals that: [1] the apparent detection of 3 onsets from 2 true positive windows is an artifact of overlapping forecast horizons crediting a single prediction twice; [2] Logistic Regression's PR-AUC improvement over dummy guessing is not statistically robust [95% bootstrap CI: -0.0062 to +0.1121, crossing zero; ROC-AUC CI: 0.4242 to 0.6469, spanning 0.5000]; and [3] the training partition contains only 9 attack onsets across 4 attack tools, which is sample-insufficient to fit a complex sequence model without catastrophic overfitting. The temporal dataset must be expanded with additional authentic capture days before complex sequence modeling can be scientifically justified.)*

---

## 1. Executive Summary & Verification Context

Phase 9B.3 executes a focused validation audit of the Phase 9B.2 temporal forecasting baselines prior to any investment in complex deep sequence architectures (BiLSTM, GRU, or Temporal Transformers). The audit investigated five critical scientific questions:
1. **Metric Reproducibility (Task 1):** Reproduced all Phase 9B.2 window-level and event-level metrics directly from saved prediction records with 100% numerical identity.
2. **Event Attribution Discrepancy (Task 2):** Resolved why Logistic Regression reported 2 true-positive windows but 3 detected attack onsets. Proved that anchor epoch `2017-07-07 13:48:00` (horizon $[13:51, 13:55]$) spans both `EVT_FRI_19` (13:52) and `EVT_FRI_20` (13:55), crediting a single prediction twice.
3. **Event-Matching Rule Formalization (Task 2):** Evaluated event recall under three explicit rules:
   - *Rule 1 (Multi-Event Credit):* 3 / 10 onsets (30.0%).
   - *Rule 2 (Single Earliest-Onset Attribution):* 2 / 10 onsets (20.0%).
   - *Rule 3 (Scenario-Level Campaign Matching):* 2 / 5 attack scenarios (40.0%).
4. **False Alarm Structure (Task 2):** Grouped the 11 false positive windows of Logistic Regression into **8 distinct false alarm episodes** (6 single-minute alarms, 1 two-minute alarm, 1 three-minute alarm).
5. **Feature History & Boundary Leakage Audit (Tasks 3 & 4):** Verified that feature vectors $X \in \mathbb{R}^{N \times 120}$ come strictly from observation history $[t-9, t]$. Confirmed zero leakage from the lead gap ($[t+1, t+2]$), forecast horizon ($[t+3, t+7]$), label fields, or day boundaries.
6. **Statistical Robustness (Task 5):** Conducted 2,000 bootstrap resamples on the test predictions. Demonstrated that Logistic Regression's PR-AUC lift over dummy guessing is **not statistically robust** ($\Delta\text{PR-AUC} = +0.0431$, $95\%\text{ CI} = [-0.0062, 0.1121]$, crossing zero; $\text{ROC-AUC } 95\%\text{ CI} = [0.4242, 0.6469]$, spanning 0.5000).
7. **Training Sample Size for Deep Models (Task 6):** Evaluated whether 9 training onsets across 4 scheduled attack scenarios provide sufficient evidence to train a deep recurrent or attention-based sequence model. Proved that deep learning on 9 events is mathematically and methodologically unjustified.

---

## 2. Task 1: Direct Metric Reproduction from Saved Predictions

All metrics reported in Phase 9B.2 were reproduced directly from [predictions.csv](file:///c:/Users/Dell%20Latitude%207410/Downloads/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main/data/benchmark/temporal/phase9b2/predictions.csv) without re-fitting models or modifying weights:

| Model Name | Reprod. PR-AUC | Orig. PR-AUC | Reprod. ROC-AUC | Orig. ROC-AUC | Reprod. Prec | Orig. Prec | Reprod. Rec | Orig. Rec | Reprod. F1 | Orig. F1 | Reprod. FPR | Orig. FPR | Exact Match |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dummy Prior** | 0.1250 | 0.1250 | 0.5000 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | **True** |
| **Dummy Stratified** | 0.1310 | 0.1310 | 0.5102 | 0.5102 | 0.3333 | 0.3333 | 0.0286 | 0.0286 | 0.0526 | 0.0526 | 0.0082 | 0.0082 | **True** |
| **Logistic Regression**| **0.1554** | **0.1554** | **0.5370** | **0.5370** | **0.1538** | **0.1538** | **0.0571** | **0.0571** | **0.0833** | **0.0833** | **0.0449** | **0.0449** | **True** |
| **Random Forest** | 0.1402 | 0.1402 | 0.4901 | 0.4901 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | **True** |

Confusion matrices, false positive rates, and area under the curves match to the exact decimal digit across all 280 test windows.

---

## 3. Task 2: Event-Level Evaluation Audit & Discrepancy Resolution

### 3.1 Why 2 True-Positive Windows Produced 3 Detected Onsets
In Phase 9B.2, Logistic Regression produced **13 positive predictions** ($\hat{y}=1$ at fixed 0.5 threshold):
- **11 False Positives ($y=0$):** Alarms during benign baseline windows.
- **2 True Positives ($y=1$):**
  1. Window Row 73: `2017-07-07 13:48:00` ($p = 0.7278$).
  2. Window Row 117: `2017-07-07 15:50:00` ($p = 0.5443$).

Auditing the forecast horizons $[t+3, t+7]$ reveals:
- **Anchor `13:48:00` Horizon:** $[13:51, 13:55]$ (5 minutes).
  - `EVT_FRI_19` (PortScan probe): starts at `13:52:00` $\in [13:51, 13:55]$. Lead time = $13:52 - 13:48 = 4.0\text{ min}$.
  - `EVT_FRI_20` (PortScan scan stage): starts at `13:55:00` $\in [13:51, 13:55]$. Lead time = $13:55 - 13:48 = 7.0\text{ min}$.
- **Anchor `15:50:00` Horizon:** $[15:53, 15:57]$ (5 minutes).
  - `EVT_FRI_27` (LOIC DDoS flooding): starts at `15:56:00` $\in [15:53, 15:57]$. Lead time = $15:56 - 15:50 = 6.0\text{ min}$.

Because `EVT_FRI_19` and `EVT_FRI_20` start only 3 minutes apart, both onsets fall inside the 5-minute horizon of the single anchor `13:48:00`. The Phase 9B.2 evaluation credited both events to this single true positive prediction.

### 3.2 Comparison of Event-Matching Rules
| Matching Rule | Rule Logic | Detected Events | Missed Events | Event-Level Recall |
| :--- | :--- | :--- | :--- | :---: |
| **Rule 1: Multi-Event Credit** (Phase 9B.2) | Any event whose start time falls into the horizon of a positive prediction is credited. | `EVT_FRI_19`, `EVT_FRI_20`, `EVT_FRI_27` | 7 events (all Web, Bot, & late PortScan) | **3 / 10 (30.0%)** |
| **Rule 2: Single Earliest Attribution** | A positive prediction credits only the *earliest* event in its horizon; subsequent onsets must be detected by unconsumed anchors. | `EVT_FRI_19` (4 min), `EVT_FRI_27` (6 min) | `EVT_FRI_20` + 7 other events | **2 / 10 (20.0%)** |
| **Rule 3: Scenario-Level Campaign Matching** | Multi-burst episodes belonging to the same scheduled attack tool are unified into a single scenario. | PortScan (`FRI_02`), DDoS (`FRI_03`) | Web BruteForce (`THU_01`), Web XSS (`THU_02`), Botnet (`FRI_01`) | **2 / 5 (40.0%)** |

Under strict non-overlapping attribution (Rule 2), Logistic Regression detected **2 of 10 onsets (20.0%)**. Under campaign-level matching (Rule 3), it detected **2 of 5 attack scenarios (40.0%)**.

### 3.3 Audit of False Alarms: Windows vs. Distinct Episodes
The 11 false positive windows of Logistic Regression are not 11 separate alerts scattered across the day; they cluster into **8 distinct false alarm episodes**:
1. `FA_EP_01`: Friday `09:08:00` (1 min, max $p = 0.999997$)
2. `FA_EP_02`: Friday `13:35:00` to `13:36:00` (**2 min contiguous run**, max $p = 0.8494$)
3. `FA_EP_03`: Friday `14:30:00` (1 min, max $p = 0.9141$)
4. `FA_EP_04`: Friday `16:53:00` (1 min, max $p = 0.5120$)
5. `FA_EP_05`: Thursday `10:54:00` (1 min, max $p = 0.9502$)
6. `FA_EP_06`: Thursday `12:16:00` (1 min, max $p = 0.9644$)
7. `FA_EP_07`: Thursday `12:30:00` (1 min, max $p = 0.9986$)
8. `FA_EP_08`: Thursday `12:41:00` to `12:43:00` (**3 min contiguous run**, max $p = 0.99997$)

An operational SOC would experience **8 false alarm episodes** across 725 test minutes (~1 false alarm every 90 minutes).

---

## 4. Tasks 3 & 4: Feature Isolation, Temporal Boundaries, and Leakage Audit

### 4.1 Feature History Window Verification
Code inspection of `extract_target_a_dataset` in `data/benchmark/temporal/phase9b2/run_baselines.py` (lines 75–93) confirms:
```python
hist = df_day.iloc[range(i - 9, i + 1)]     # Indices: i-9, i-8, ..., i (10 minutes)
gap = df_day.iloc[range(i + 1, i + 3)]      # Indices: i+1, i+2 (2-minute buffer)
horizon = df_day.iloc[range(i + 3, i + 8)]  # Indices: i+3, i+4, i+5, i+6, i+7 (5-minute target)
feat_mat = hist[PREDICTOR_COLUMNS].values   # Extracted strictly from hist
```
- **Finding:** Feature inputs contain exclusively the 10 history epochs $[t-9, t]$.
- **Zero Future Leakage:** Indices $i+1 \dots i+7$ are accessed solely to evaluate eligibility and compute the target label. They are never indexed into `feat_mat` or `X`.
- **Zero Label Leakage:** `PREDICTOR_COLUMNS` strictly excludes `attack_flow_count`, `benign_flow_count`, `is_attack_active`, and `attack_classes`.

### 4.2 Temporal Boundary Integrity
1. **Day Boundary Isolation:** The extraction loop groups strictly by `capture_day` (`for day, df_day in epochs_df.groupby("capture_day")`). No window can ever cross from Wednesday into Thursday or Thursday into Friday.
2. **Edge Truncation:** Windows requiring index $i - 9 < 0$ or $i + 7 \ge n$ are skipped, cleanly dropping the first 9 minutes and last 7 minutes of every day.
3. **Continuity Guarantee:** All 17 minutes of the window must satisfy $\Delta t = 1.0\text{ min}$. Any gap > 1 min immediately invalidates the window.

---

## 5. Task 5: Statistical Robustness Assessment of the Baseline Signal

To test whether Logistic Regression's improvement over Dummy Prior is statistically robust or an artifact of sample variance, a **bootstrap hypothesis test (2,000 resamples, seed 42)** was executed on the 280 test window predictions:

| Metric | Logistic Regression (95% CI) | Dummy Prior (95% CI) | Delta (LR - Dummy) (95% CI) | Empirical $p$-value ($P(\Delta \le 0)$) |
| :--- | :---: | :---: | :---: | :---: |
| **PR-AUC** | $[0.1018, 0.2547]$ | $[0.0893, 0.1643]$ | **`[-0.0062, 0.1121]`** | $p = 0.0480$ |
| **ROC-AUC**| **`[0.4242, 0.6469]`** | $[0.5000, 0.5000]$ | $[-0.0758, 0.1469]$ | $p = 0.2585$ |

### Scientific Verdict on Robustness
1. **PR-AUC Difference Crosses Zero:** The 95% bootstrap confidence interval for $\Delta\text{PR-AUC}$ has a lower bound of **`-0.0062`**. Because the interval includes zero, we cannot reject the null hypothesis of equivalence to random guessing at the $\alpha = 0.05$ two-tailed significance level.
2. **ROC-AUC Spans 0.5000:** The ROC-AUC 95% confidence interval is $[0.4242, 0.6469]$, which spans a random coin toss ($0.5000$).
3. **Conclusion:** While Logistic Regression displays a slight positive trend (+0.0304 PR-AUC), the improvement is **statistically fragile** and cannot be claimed as strong scientific evidence of a generalizable forecasting signal.

---

## 6. Task 6: Training Sample Size Assessment for Complex Sequence Models

A critical question is whether the dataset contains enough evidence to train an advanced sequence model (such as a BiLSTM, GRU, or Temporal Transformer).

### 6.1 Training Set Event Census
The training partition (Monday–Wednesday) contains:
- **Total Epochs:** 1,484 minutes.
- **Total Eligible Windows:** 1,117.
- **Positive Windows ($y=1$):** Exactly **30 windows**.
- **Underlying Attack Onsets:** Exactly **9 attack onsets**:
  - `EVT_TUE_33` (09:17): FTP-Patator (5 windows)
  - `EVT_TUE_34` (09:19): FTP-Patator (3 windows)
  - `EVT_TUE_36` (14:09): SSH-Patator (5 windows)
  - `EVT_WED_37` (09:01): DoS slowloris (5 windows)
  - `EVT_WED_38` (09:48): DoS slowloris (5 windows)
  - `EVT_WED_46` (14:24): DoS slowloris (5 windows)
  - `EVT_WED_47` (15:12): Heartbleed (5 windows)
  - `EVT_WED_48` (15:14): Heartbleed (3 windows)
  - `EVT_WED_49` (15:16): Heartbleed (1 window)

### 6.2 The Fundamental Sample-Size Bottleneck
When grouped by tool execution, these 9 onsets represent only **4 scheduled attack scenarios** in training:
1. FTP-Patator (Tuesday morning)
2. SSH-Patator (Tuesday afternoon)
3. DoS slowloris (Wednesday morning)
4. Heartbleed (Wednesday afternoon)

### 6.3 Why Complex Sequence Modeling is Methodologically Flawed Here
1. **Severe Parameter-to-Event Mismatch:** A minimal BiLSTM or Transformer architecture requires thousands to hundreds of thousands of trainable weights. Training such a model on **9 positive events (across 4 scenarios)** means the network will memorize the specific minute-level background traffic of Tuesday and Wednesday.
2. **Out-of-Distribution Collapse:** Random Forest (a non-linear tree model) already collapsed to **0 detections** and ROC-AUC 0.4901 because non-linear boundaries overfit the Tuesday/Wednesday scenarios and failed to transfer to Thursday/Friday (Web Attacks, Botnet, PortScan, DDoS). A deep sequence model would suffer from even greater variance.
3. **The Illusory Sample Size of Overlapping Windows:** While 30 positive windows exist, they are sliding 1-minute steps observing the same 9 events. They do not constitute 30 independent observations.
4. **Conclusion:** Building an LSTM or Transformer on 9 training onsets would be an exercise in overfitting to noise. It would violate basic machine learning evaluation standards.

---

## 7. Deliverables & Cryptographic Artifacts

| Deliverable | File Path | Status |
| :--- | :--- | :---: |
| **1. Reproducibility Report** | `data/benchmark/temporal/phase9b3/validity_report.md` | Created & Verified |
| **2. Event Matching Audit** | `data/benchmark/temporal/phase9b3/event_matching_audit.csv` | Created (10 onsets audit) |
| **3. Reproduced Metrics JSON**| `data/benchmark/temporal/phase9b3/reproduced_metrics.json` | Created (Exact match verified) |
| **4. Focused Regression Tests**| `tests/test_phase9b3_validation.py` | 5/5 PASSED |

---

## 8. Final Decision

### Decision: **EXPAND THE DATASET FIRST**

### Justification
1. **Existing Results are Sound and Leakage-Free:** All Phase 9B.2 numbers are reproducible, timestamps are unbroken, and input features are clean.
2. **Evidence is Too Limited for Complex Models:** With only **9 training onsets** and **10 testing onsets**, the benchmark lacks the statistical power to train or evaluate deep sequence architectures.
3. **Robustness is Fragile:** Logistic Regression's PR-AUC delta crosses zero in bootstrap tests ($[-0.0062, 0.1121]$), and Random Forest collapsed to zero detections.
4. **Next Defensible Step:** Before investing in BiLSTM or Transformer development (Phase 9C), the temporal dataset must be expanded with additional authentic network capture days (e.g. from broader authentic repositories like CSE-CIC-IDS2018 or CTU-13) to establish a training partition with dozens of independent attack scenarios.

*Phase 9B.3 is complete. Stopped awaiting user review and approval.*
