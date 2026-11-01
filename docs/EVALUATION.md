# Evaluation Methodology & Benchmark Results

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Document Version:** 2.1-Production  
**Date:** November 1, 2026  

---

## 1. Dual Evaluation Methodology

To prevent evaluating ongoing intrusions as forecasts, the evaluation framework implements two distinct, complementary evaluation levels:
1. **Window-Level Metric Evaluation**: Evaluates classification performance on individual 17-minute sliding spans ($N=280$).
2. **Event-Level Early-Warning Evaluation**: Evaluates whether a valid alert was generated strictly prior to each of the 10 ground-truth attack episode onsets.

---

## 2. Metric Formulations

### 2.1 Window-Level Metrics
- **Precision**:
  $$\text{Precision} = \frac{TP}{TP + FP}$$
- **Recall**:
  $$\text{Recall} = \frac{TP}{TP + FN}$$
- **False Positive Rate (FPR)**:
  $$\text{FPR} = \frac{FP}{FP + TN} = \frac{FP}{N_{\text{negative}}}$$
- **False Alarms per Negative Hour**:
  $$\text{False Alarms / Hour} = \text{FPR} \times 60 \text{ min/hour}$$
  *(On 1-minute discrete epochs, 1 false alarm per 60 negative minutes equals 1.0 FA/hr).*
- **Precision-Recall AUC (PR-AUC)**:
  $$\text{PR-AUC} = \sum_{k=1}^K (R_k - R_{k-1}) P_k$$
  *(The primary ranking metric under severe class imbalance; default random prior baseline equals $P_{\text{prior}} = \frac{N_{\text{pos}}}{N_{\text{total}}} = \frac{35}{280} = 0.1250$).*

### 2.2 Event-Level Metrics & Attribution Rules
- **Rule 1 (Multi-Event Credit)**:
  An attack onset event $E_j$ at time $T_{\text{onset}}$ is counted as detected if any positive prediction ($\hat{y}_t = 1$) was issued within its valid anticipation window:
  $$t \in [T_{\text{onset}} - 7, T_{\text{onset}} - 3]$$
- **Rule 2 (Strict Earliest Attribution)**:
  An attack onset event $E_j$ receives credit **if and only if** the alert was the earliest trigger in the sequence and was not preceded by false alarms during the clean history window $[T_{\text{onset}} - 17, T_{\text{onset}} - 8]$.
- **Warning Lead Time**:
  $$\Delta t_{\text{lead}} = T_{\text{onset}} - t_{\text{alert}} \quad \text{where } \Delta t_{\text{lead}} \in [3, 7] \text{ minutes}$$

---

## 3. Empirical Benchmark Results

### 3.1 Window-Level Evaluation (Thursday–Friday Test Split, N=280)
| Model | TP | FP | TN | FN | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FA / Hr |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dummy Prior** | 0 | 0 | 245 | 35 | 0.0000 | 0.0000 | 0.0000 | 0.1250 | 0.5000 | 0.0000 | 0.00 |
| **Dummy Stratified** | 1 | 2 | 243 | 34 | 0.3333 | 0.0286 | 0.0526 | 0.1310 | 0.5102 | 0.0082 | 0.49 |
| **Logistic Regression** | **2** | **11** | **234** | **33** | **0.1538** | **0.0571** | **0.0833** | **0.1554** | **0.5370** | **0.0449** | **2.69** |
| **Random Forest** | 0 | 0 | 245 | 35 | 0.0000 | 0.0000 | 0.0000 | 0.1402 | 0.4901 | 0.0000 | 0.00 |
| **Compact LSTM** | 24 | 167 | 78 | 11 | 0.1257 | 0.6857 | 0.2124 | 0.1310 | 0.5197 | 0.6816 | 40.90 |

### 3.2 Event-Level Evaluation (10 Test Onsets)
| Model | Rule 1 Detections | Rule 1 Recall | Rule 2 Detections | Rule 2 Recall | Mean Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **3 / 10** | **30.0%** | **2 / 10** | **20.0%** | **5.67 minutes** |
| **Random Forest** | 0 / 10 | 0.0% | 0 / 10 | 0.0% | N/A |
| **Compact LSTM** | 9 / 10 | 90.0% | 0 / 10 | 0.0% | N/A (Failed strict attribution) |

### 3.3 Detailed Event Attribution Log (Logistic Regression)
1. **Event `EVT_FRI_19` (PortScan Probe Stage 1)**:
   - Onset: `2017-07-07 13:58:00`
   - Forecast Triggered: `2017-07-07 13:54:00`
   - **Lead Time: 4.0 minutes**
   - Precursor Signature: Modest elevation in destination port diversity and SYN flag ratio during the reconnaissance probe.
2. **Event `EVT_FRI_27` (LOIC DDoS)**:
   - Onset: `2017-07-07 15:56:00`
   - Forecast Triggered: `2017-07-07 15:50:00`
   - **Lead Time: 6.0 minutes**
   - Precursor Signature: Coordinated flow setup count increase prior to full volumetric packet saturation.
3. **Event `EVT_FRI_20` (PortScan Probe Stage 2)**:
   - Onset: `2017-07-07 14:51:00`
   - Forecast Triggered: `2017-07-07 14:44:00`
   - **Lead Time: 7.0 minutes** (Credited under Rule 1).

---

## 4. Reproducing Evaluation Runs

The complete evaluation benchmark is automated and reproducible. To re-run the benchmark from source parquet and event tables:

```powershell
python -m pytest tests/test_phase9c_temporal_model.py -v
```

To run baseline cross-comparisons:
```powershell
python -m pytest tests/test_phase9b2_baselines.py tests/test_phase9b3_validation.py -v
```

Machine-readable JSON outputs are stored in:
- `data/benchmark/temporal/phase9b2/metrics.json`
- `data/benchmark/temporal/phase9c/metrics.json`
- `data/benchmark/temporal/phase9c/event_evaluation.csv`
