# Complete Evidence-Driven Code Audit & Reliability Report

**Repository:** AI-Based Network Attack Forecasting from Network Traffic Data  
**Audit Date:** October 28, 2026  
**Auditor Roles:** Senior Python Engineer, Cybersecurity Specialist, ML Engineer, Network Traffic Analyst, Software Testing Specialist  

---

## 1. Executive Summary

A comprehensive, evidence-driven code audit of the attack forecasting system was executed across packet capture, temporal aggregation, dataset preprocessing, neural network inference, risk estimation, explainability, API safety, and web dashboard integration.

All findings were checked against real source code and empirically verified with automated tests. No code was rewritten wholesale; instead, targeted, non-breaking architectural and algorithmic fixes were applied to address critical vulnerabilities, data leakage risks, schema incompatibilities, race conditions, and unvalidated client inputs.

---

## 2. Issue Checklist & Confirmed Findings

| Issue ID | Priority | Category | Affected File(s) | Status | Description |
|---|---|---|---|---|---|
| **ISSUE-01** | **P0** | Dependencies | `requirements.txt` | **FIXED & TESTED** | Missing core dependencies: `scapy`, `joblib`, `pyarrow` omitted from manifest, causing runtime import crashes on clean installs. |
| **ISSUE-02** | **P0** | Security / Network | `run_demo.py` | **FIXED & TESTED** | Hardcoded `0.0.0.0` wildcard interface binding exposed API and management dashboard to unauthenticated local network hosts by default. |
| **ISSUE-03** | **P0** | Concurrency / Lifecycle | `pipeline/live_capture.py` | **FIXED & TESTED** | `stop_capture()` returned immediately while sniffer worker thread was still alive, causing race conditions in start/stop cycles. |
| **ISSUE-04** | **P0** | Windows Capture Engine | `pipeline/live_capture.py` | **FIXED & TESTED** | Passing Windows GUIDs (`{GUID}`) directly to Scapy raised `ValueError: Interface not found !`; redundant `-0000` NDIS sub-adapters flooded interface list. |
| **ISSUE-05** | **P0** | Data Integrity | `pipeline/temporal_preprocessor.py` | **FIXED & TESTED** | Unconditional +12h shift on hours 1..7 converted genuine early-morning captures (1 AM - 7 AM) into afternoon timestamps. |
| **ISSUE-06** | **P1** | ML Architecture | `models/attack_forecaster.py` | **FIXED & TESTED** | Bidirectional LSTM used `lstm_out[:, -1, :]`, which only captured the backward LSTM's initial state (t=0 backward context). Added `sequence_pooling="bidirectional_endpoints"`. |
| **ISSUE-07** | **P1** | Risk Engine & SHAP | `models/risk_engine.py` | **FIXED & TESTED** | Missing bounds/type validation for `confidence` and `anomaly_intensity` (accepted NaN/Inf). When SHAP was absent, hardcoded fake attributions (`0.45`, `0.38`) were presented as model explanations. |
| **ISSUE-08** | **P1** | Schema Validation | `models/temporal_forecasting/forecaster.py` | **FIXED & TESTED** | `INCOMPATIBLE_PACKET_SIGNATURES` only checked 7 of 13 packet-level aggregation features; `predict()` lacked finite threshold bounds check [0.0, 1.0]. |
| **ISSUE-09** | **P1** | API Robustness | `dashboard/server.py` | **FIXED & TESTED** | `predict_temporal_experimental` performed unsafe `float(body.get("threshold", 0.5))`, crashing with 500 on non-numeric or NaN values; failed model loading was retried on every single request. |
| **ISSUE-10** | **P1** | Endpoint Inventory | `pipeline/device_registry.py` | **FIXED & TESTED** | Registry lacked thread-safe record expiration (`cleanup_stale`), allowing unbounded memory growth over long-running captures. |

---

## 3. Deep Dive: Root Causes & Implemented Fixes

### 3.1 ISSUE-01: Missing Dependencies
- **Root Cause:** `scapy`, `joblib`, and `pyarrow` were imported across `pipeline/live_capture.py` and `models/temporal_forecasting/forecaster.py` but were not specified in `requirements.txt`.
- **Fix:** Added `scapy>=2.5.0`, `joblib>=1.3.0`, and `pyarrow>=12.0.0` with explicit compatible versions to `requirements.txt`.

### 3.2 ISSUE-02: Unsafe Default Network Binding
- **Root Cause:** `run_demo.py` invoked `uvicorn.run("dashboard.server:app", host="0.0.0.0", port=8000)`. In enterprise and shared LAN environments, this binds to all network adapters without authentication.
- **Fix:** Added `argparse` CLI options for `--host` (defaulting safely to loopback `127.0.0.1`) and `--port` (default `8000`), allowing deliberate remote access only when explicitly opted in by the administrator.

### 3.3 ISSUE-03 & ISSUE-04: Windows Packet Capture & Thread Lifecycle
- **Root Cause:**
  1. On Windows, Scapy's `dev_from_name()` searches `iface.name` (friendly name) and `iface.description`, but fails when passed Windows GUID device strings.
  2. Windows creates virtual NDIS sub-adapters suffixed with `-0000`, causing interface enumeration to produce non-functional duplicate entries.
  3. `stop_capture()` flipped a flag but released locks without joining the worker thread, causing subsequent starts to collide with lingering threads.
- **Fix:**
  1. Implemented `resolve_scapy_interface()` in `pipeline/live_capture.py`, matching by GUID regex, dictionary key, description, or network name, returning `None` if invalid.
  2. Filtered `-0000` NDIS sub-adapters without active IP assignments and sorted routable interfaces (`Wi-Fi`, `Ethernet`) to the top.
  3. Added thread joining (`capture_thread.join(timeout=2.0)`) outside the lock so callers block until the worker has genuinely terminated.

### 3.4 ISSUE-05: Temporal Timestamp Distortion
- **Root Cause:** CICIDS2017 raw CSVs recorded hours in 12-hour format without AM/PM tags for certain afternoon captures, prompting an unconditional +12h offset rule for hours 1 through 7. This rule erroneously shifted genuine morning files (such as Friday Morning capture starting at 01:00) into 13:00-19:00.
- **Fix:** Added `file_context` parameter to `parse_timestamp_series()`. If the filename indicates morning traffic (`"morning" in file_context.lower()`), the +12h PM correction is strictly suppressed.

### 3.5 ISSUE-06: BiLSTM Sequence Pooling
- **Root Cause:** In PyTorch, bidirectional LSTM outputs concatenate `[forward_hidden, backward_hidden]` across the sequence. Slicing `lstm_out[:, -1, :]` yields the forward hidden state at step $T$ (full context) and the backward hidden state at step $T$ (initial context step with zero history).
- **Fix:** Added `sequence_pooling: str = "last"` parameter to `AttackForecasterBiLSTM`. Preserved `"last"` as default to guarantee 100% weight-compatibility with pretrained checkpoint `models/bilstm_weights.pt`, while introducing `"bidirectional_endpoints"` pooling (`torch.cat([lstm_out[:, -1, :hidden_dim], lstm_out[:, 0, hidden_dim:]], dim=-1)`) for newer trained models.

### 3.6 ISSUE-07: Risk Engine Validation & Deceptive SHAP Attributions
- **Root Cause:**
  1. `compute_risk()` accepted unbounded, negative, NaN, or Infinite values for confidence and anomaly intensity.
  2. `get_recommendation()` had hardcoded fallback strings: `"conn_frequency" (0.45)` and `"dst_ip_fanout" (0.38)` when SHAP features were absent. This falsely claimed that arbitrary numbers were model-derived attributions.
- **Fix:**
  1. Added strict validation in `compute_risk()`: confidence and anomaly intensity must be finite floats within $[0.0, 1.0]$.
  2. Removed all hardcoded attribution numbers in fallback mode. When `top_features` is None or empty, the engine emits clear defensive policy rationales labeled with `"SHAP attribution unavailable"`, and sets `"attribution_available": False`. When genuine SHAP rankings are provided, real feature names and rounded attributions are rendered with `"attribution_available": True`.

### 3.7 ISSUE-08 & ISSUE-09: Schema Gating & API Threshold Validation
- **Root Cause:**
  1. Live aggregation calculates 13 packet-level statistics (`packet_count`, `total_captured_bytes`, `iat_mean`, etc.), whereas the Target A forecaster was trained on 12 flow-level statistics across 10 lags (120 dimensions). The prohibited signatures set only included 7 features.
  2. In `dashboard/server.py`, `threshold = float(body.get("threshold", 0.5))` crashed with HTTP 500 when non-numeric strings or NaN were supplied.
  3. When model loading failed, `get_temporal_forecaster()` kept `_temporal_forecaster = None`, causing repeated expensive disk and import operations on every request.
- **Fix:**
  1. Updated `INCOMPATIBLE_PACKET_SIGNATURES` in `forecaster.py` to cover all packet aggregation features and their lagged variants.
  2. Added input validation in `predict()` and `dashboard/server.py`: non-numeric, NaN, Infinite, or out-of-range thresholds return clean HTTP 422 errors.
  3. Cached permanent model loading failures with `_temporal_forecaster_failed` and recorded `_temporal_forecaster_error`, preventing redundant reload loops while providing a `force_reload=True` option.

### 3.8 ISSUE-10: Device Registry Stale Pruning
- **Root Cause:** The registry tracked all observed endpoints indefinitely without an automated mechanism to prune stale nodes.
- **Fix:** Added thread-safe `cleanup_stale(max_age_seconds: float, mode: Optional[str] = None) -> int` to remove observations older than the specified age threshold.

---

## 4. Scientific Limitations

1. **Target A Rare-Event Imbalance:**
   - In the CICIDS2017 benchmark dataset, positive attack onsets represent only 35 out of 280 temporal test windows (12.5% base rate).
   - Precision for all baseline models remains low under zero-shot transfer:
     - Dummy Prior Baseline: PR-AUC 0.1250, ROC-AUC 0.5000
     - Logistic Regression: PR-AUC 0.1554, ROC-AUC 0.5370
     - Random Forest: PR-AUC 0.1402, ROC-AUC 0.4901
     - Compact LSTM: PR-AUC 0.1310, ROC-AUC 0.5197
2. **Packet-Level vs. Flow-Level Schema Asymmetry:**
   - Real-time packet sniffers observe raw L2/L3 frames and generate packet rate/byte statistics.
   - The temporal forecaster was trained on bidirectional flow features (`mean_flow_duration_ms`, `dst_port_entropy`, etc.) extracted from post-processed PCAPs.
   - Live packet aggregation cannot be substituted into the flow model without empirical calibration. The system correctly reports the model as gated and unavailable for live packet feeds.
3. **Generalization across Heterogeneous Networks:**
   - The models were trained and benchmarked on CICIDS2017. Performance on modern enterprise traffic (e.g. QUIC/HTTP3, encrypted SNI) will require continuous retraining on live domain flow exports.

---

## 5. Deployment & Hardware Limitations

1. **Local Adapter Access:**
   - Live packet sniffing requires Npcap (on Windows) or `libpcap` with `CAP_NET_RAW`/`CAP_NET_ADMIN` permissions (on Linux).
   - Hosted cloud containers (e.g., AWS ECS, GCP Cloud Run) cannot directly access the local user's physical Wi-Fi or Ethernet adapter.
2. **Promiscuous Mode & Switched Networks:**
   - In standard switched Ethernet or WPA2/WPA3 enterprise Wi-Fi environments, an adapter in non-promiscuous mode only sees unicast traffic destined for the host and broadcast/multicast traffic.
3. **No Synthetic Fallback:**
   - In accordance with non-negotiable data integrity rules, when live packet capture is stopped or inactive, counters remain at zero. No simulated packets are fabricated.
