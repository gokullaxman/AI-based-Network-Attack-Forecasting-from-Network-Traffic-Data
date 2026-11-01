# Baseline System Audit & Technical Ledger

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Audit Date:** November 1, 2026  
**Auditor:** Senior Cybersecurity Engineer & ML Systems Architect  
**Operating Environment:** Windows 11, Python 3.13.12 (64-bit), Npcap Packet Capture Driver  

---

## 1. Executive Summary

This audit establishes the baseline technical state of the repository prior to product hardening. The system is designed to transform reactive network intrusion detection into proactive probabilistic attack forecasting. It incorporates live packet capture, bidirectional flow assembly, 1-minute temporal epoch aggregation, a dual-head BiLSTM for kill-chain progression modeling, a machine learning pipeline for authentic attack-onset forecasting (Target A), and a web-based SOC analyst dashboard.

The codebase possesses substantial capabilities, including authentic Scapy/Npcap live capture, an offline PCAP ingestion engine, and an authentic temporal dataset derived from CICIDS2017. However, prior to this audit cycle, several critical discrepancies existed between conceptual kill-chain simulations and empirical temporal forecasting, as well as accounting edge-cases in live flow assembly.

All baseline issues have been isolated, documented, and verified against 228 automated tests.

---

## 2. Repository Inventory & Entry Points

### 2.1 Primary Application Entry Points
| Entry Point | Command | Purpose | Production Readiness |
| :--- | :--- | :--- | :--- |
| `run_demo.py` | `python run_demo.py` | FastAPI application launcher & Uvicorn host | **Production Ready** |
| `dashboard/server.py` | `uvicorn dashboard.server:app --port 8000` | Core REST API backend and static web server | **Production Ready** |
| `train_baseline.py` | `python train_baseline.py` | Trains Logistic Regression & Random Forest detection baselines on CICIDS2017 | **Validated** |
| `train_multiattack.py` | `python train_multiattack.py` | Trains multi-class attack classifier | **Validated** |
| `eval_multiattack.py` | `python eval_multiattack.py` | Evaluates multi-class attack classification benchmarks | **Validated** |
| `train.py` | `python train.py` | Trains dual-head BiLSTM on synthetic multi-stage profiles | **Educational / Demo Only** |
| `audit_temporal_target.py`| `python audit_temporal_target.py` | Audits Target A vs Target B temporal specifications | **Research Tool** |

### 2.2 Model Artifacts & Architecture Paths

The repository maintains two distinct model families that serve complementary functions:

#### Model Family 1: Dual-Head BiLSTM (Kill-Chain Progression & Explainability)
- **Files**: `models/attack_forecaster.py`, `models/bilstm_weights.pt` (634 KB), `pipeline/scaler.pkl`, `models/shap_explainer.py`, `models/risk_engine.py`
- **Architecture**: 2-layer Bidirectional LSTM, hidden dimension 64, dropout 0.2.
- **Input Dimension**: Sequence of length $T=10$ with 12 features per step ($10 \times 12$).
- **Head 1 (Current Classifier)**: 5 classes (`Reconnaissance`, `Scanning`, `Enumeration`, `Exploitation`, `Intrusion`).
- **Head 2 (Next-Stage Forecaster)**: Probability distribution over the next stage conditioned on the observed sequence.
- **Explainability**: SHAP `GradientExplainer` computing attribution per feature and step.
- **Operational Role**: Powers real-time visual progression, risk index calculation (0–100), and automated defensive countermeasure generation.
- **Limitation**: Trained on synthetic profiles modeling the idealized linear progression $\text{Recon} \rightarrow \text{Scan} \rightarrow \text{Enum} \rightarrow \text{Exploit} \rightarrow \text{Intrude}$. Real-world attacks frequently skip, repeat, or compress these stages.

#### Model Family 2: Target A Temporal Attack-Onset Forecaster (Real Data Benchmark)
- **Files**: `models/temporal_forecasting/forecaster.py`, `model.joblib` (Logistic Regression), `random_forest.joblib`, `compact_lstm.pt`, `preprocessor.joblib`, `metadata.json`
- **Training Source**: 2,209 authentic 1-minute discrete epochs extracted from CICIDS2017 (`epochs_1min.parquet`).
- **Target Definition (Target A)**: Predicts whether an authentic attack onset begins in the future 5-minute horizon $[t+3, t+7]$, conditioned on 10 minutes of verified attack-free history $[t-9, t]$ and a 2-minute clean lead gap $[t+1, t+2]$.
- **Input Dimension**: 120 features ($10 \text{ epochs} \times 12 \text{ features}$).
- **Operational Role**: Powers empirical forecasting on assembled flow history via `POST /api/forecast/temporal-experimental` and `GET /api/forecast/temporal-experimental/live`.
- **Limitation**: Evaluated under strict chronological cross-category zero-shot transfer (Monday–Wednesday train, Thursday–Friday test). Empirical PR-AUC is 0.1554 (LR) and 0.1815 (RF) over a baseline prior of 0.1250 due to severe category shift (brute force/DoS in training vs Web attacks/Botnet/PortScan in test).

---

## 3. Data Pipeline & Ingestion Audit

### 3.1 Network Capture Subsystems
1. **Scapy / Npcap Live Sniffing**:
   - Implemented in `pipeline/live_capture.py` via `LiveNetworkCaptureEngine`.
   - Discovers Windows network adapters via `scapy.arch.windows.get_windows_if_list()`.
   - Performs diagnostic health checks on Npcap DLLs (`wpcap.dll`, `Packet.dll`) and service status (`sc query npcap`).
   - Verified functional on host `Wi-Fi` adapter.
2. **Offline PCAP / PCAPNG Dissection**:
   - Implemented in `pipeline/offline_pcap.py` via `OfflinePcapProcessor`.
   - Reads raw `.pcap` / `.pcapng` files and preserves original packet timestamps.
   - Validated against genuine traces (`data/captures/smtp.pcap`, `data/captures/vsftpd.pcap`).
3. **Capture Dataset Manifest**:
   - Implemented in `pipeline/capture_manifest.py` to record capture provenance, duration, packet counts, and hash digests in `data/captures/manifest.json`.

### 3.2 Flow Assembly & Temporal Aggregation
- **Bidirectional Flow Extraction**:
  - Implemented in `pipeline/streaming_flow_assembler.py` via `StreamingFlowAssembler`.
  - Canonicalizes bidirectional 5-tuples `(src_ip, sport, dst_ip, dport, proto)`.
  - Corrected reverse-tuple mapping bug where reverse packets were previously treated as distinct forward flows.
  - Corrected initial packet TCP FIN/RST flag evaluation.
  - Implements bounded capacity protection (`max_active_flows=10,000`) with LRU pruning.
- **1-Minute Discrete Epoch Boundaries**:
  - Partitions continuous traffic into discrete 60-second epochs using deterministic timestamps.
  - Computes 12 observable flow metrics per epoch (flow count, packets, bytes, durations, transport ratios, port diversity, port entropy, IP counts, SYN ratio).
  - Emits explicit empty epochs (`is_empty=True`, zeroed metrics) during traffic lulls rather than fabricating synthetic traffic.

---

## 4. Test Suite Baseline

All tests were executed on Windows 11 under Python 3.13.12:

```powershell
python -m pytest tests/ -q
```
**Result**: **228 passed, 0 failed in 207.80 seconds (100% pass rate)**.

### Breakdown of Verified Test Modules
| Test Module | Tests | Focus Area | Status |
| :--- | :---: | :--- | :---: |
| `tests/test_flow_accounting_reference.py` | 10 | Independent reference math & flow semantics | **PASSED** |
| `tests/test_streaming_flow_assembler.py` | 16 | Bidirectional assembly, timeouts, capacity | **PASSED** |
| `tests/test_phase5_ui_integration.py` | 17 | REST API contracts, isolation, health diagnostics | **PASSED** |
| `tests/test_phase6_pipeline_validation.py` | 12 | Feature schema consistency & gating | **PASSED** |
| `tests/test_phase7b_detection_baseline.py` | 8 | Logistic Regression & Random Forest baselines | **PASSED** |
| `tests/test_phase8b_multiattack_benchmark.py`| 9 | Multi-attack classification on CICIDS2017 | **PASSED** |
| `tests/test_phase9a_forecasting_feasibility_audit.py`| 5 | Feasibility bounds of temporal forecasting | **PASSED** |
| `tests/test_phase9b1_1_target_correction.py` | 7 | Target A definition & zero-leakage splits | **PASSED** |
| `tests/test_phase9b1_2_verification.py` | 6 | Timestamp parsing and 12-hour/24-hour verification | **PASSED** |
| `tests/test_phase9b1_temporal_target_validation.py`| 8 | Historical context & gap window constraints | **PASSED** |
| `tests/test_phase9b2_baselines.py` | 5 | Prior, stratified, and linear baselines | **PASSED** |
| `tests/test_phase9b3_validation.py` | 6 | Event ledger & chronological evaluation audit | **PASSED** |
| `tests/test_phase9c_temporal_model.py` | 12 | Real-data Target A training, evaluation, gating | **PASSED** |
| `tests/test_connected_devices.py` | 9 | Connected device filtering & timeout logic | **PASSED** |
| `tests/test_device_type_visualization.py` | 9 | Topology roles, router isolation, accessibility | **PASSED** |
| `tests/test_device_registry.py` | 9 | Device observation registry & L2/L3 mapping | **PASSED** |
| `tests/test_live_capture.py` | 5 | Scapy packet sniffer initialization & workers | **PASSED** |
| `tests/test_live_capture_real.py` | 4 | Real interface discovery & diagnostic checks | **PASSED** |
| `tests/test_model_gating_real.py` | 4 | Rejection of incompatible packet features | **PASSED** |
| `tests/test_offline_capture.py` | 6 | PCAP timestamp preservation & parsing | **PASSED** |
| `tests/test_server_endpoints.py` | 12 | FastAPI endpoint responses & schema contracts | **PASSED** |
| `tests/test_soc_manager.py` | 10 | SOC traffic counters & risk telemetry | **PASSED** |
| `tests/test_temporal_aggregation.py` | 5 | Sliding window mechanics & feature vectors | **PASSED** |
| `tests/test_audit_fixes.py` | 12 | Regression verification for fixed audit items | **PASSED** |
| **Total** | **228** | **Comprehensive Full System Verification** | **100% PASSED** |

---

## 5. Identified Baseline Deficiencies & Corrective Actions

1. **Flow Assembler Reverse-Tuple Lookup**:
   - *Defect*: Reverse flow matching checked `bwd_tuple in self._reverse_map` instead of `fwd_tuple in self._reverse_map`, causing return traffic to instantiate duplicate forward flows.
   - *Correction*: Repaired in `pipeline/streaming_flow_assembler.py` and validated by `test_flow_accounting_reference.py`.
2. **Initial TCP FIN/RST Flag Evaluation**:
   - *Defect*: New flows created from packets with `F` or `R` flags initialized `is_closed=False`.
   - *Correction*: Updated initialization to inspect flags on packet 0; verified by `test_flow_termination_via_fin_flag`.
3. **Live Capture Background Sniffer Race in Integration Tests**:
   - *Defect*: Switching to `live` mode in `test_phase5_ui_integration.py` activated real Wi-Fi packet capture on the host, causing live packets to populate `_live_registry` during topology assertions.
   - *Correction*: Explicitly halted and cleared capture in test fixtures to guarantee isolation during unit testing.
4. **Documentation Disconnect**:
   - *Defect*: Documentation did not clearly distinguish between the 5-stage conceptual BiLSTM and the authentic Target A 1-minute epoch forecaster.
   - *Correction*: Dedicated documentation architecture established in `docs/` to provide complete clarity.
