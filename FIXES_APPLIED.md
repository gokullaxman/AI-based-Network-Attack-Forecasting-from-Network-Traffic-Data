# Record of Fixes Applied

This document details every source file modified during the codebase audit and reliability hardening process, explaining the rationale, exact code changes, associated automated tests, test outcomes, and compatibility guarantees.

---

## 1. Summary of Modified Files

| # | File Path | Primary Modification | Tests Validating Fix | Result |
|---|---|---|---|---|
| 1 | `requirements.txt` | Added missing runtime dependencies: `scapy`, `joblib`, `pyarrow` | `tests/test_audit_fixes.py` | PASS |
| 2 | `run_demo.py` | Replaced hardcoded `0.0.0.0` binding with CLI arguments and safe `127.0.0.1` default | Manual startup verification | PASS |
| 3 | `pipeline/live_capture.py` | Implemented `resolve_scapy_interface()`, filtered `-0000` sub-adapters, joined sniffer thread in `stop_capture()` | `tests/test_audit_fixes.py`, `tests/test_live_capture.py` | PASS |
| 4 | `pipeline/temporal_preprocessor.py` | Added `file_context` argument to suppress erroneous +12h PM shift on morning captures | `tests/test_audit_fixes.py` | PASS |
| 5 | `models/attack_forecaster.py` | Added `sequence_pooling="bidirectional_endpoints"` while keeping `"last"` default for checkpoint compatibility | `tests/test_audit_fixes.py`, `tests/test_pipeline.py` | PASS |
| 6 | `models/risk_engine.py` | Added input validation for `confidence`/`anomaly_intensity`; eliminated fabricated SHAP attributions in recommendations | `tests/test_audit_fixes.py`, `tests/test_pipeline.py` | PASS |
| 7 | `models/temporal_forecasting/forecaster.py` | Expanded `INCOMPATIBLE_PACKET_SIGNATURES` to cover all packet aggregation features; added threshold bounds check in `predict()` | `tests/test_audit_fixes.py`, `tests/test_phase9c_temporal_model.py` | PASS |
| 8 | `dashboard/server.py` | Validated API threshold inputs (HTTP 422 on NaN/Inf/invalid); cached model loading failures | `tests/test_audit_fixes.py`, `tests/test_server_endpoints.py` | PASS |
| 9 | `pipeline/device_registry.py` | Added thread-safe `cleanup_stale()` method for pruning expired records | `tests/test_audit_fixes.py`, `tests/test_device_registry.py` | PASS |
| 10 | `.gitignore` | Excluded large benchmark CSVs (`>100MB`) to comply with GitHub remote push constraints | Git push verification | PASS |

---

## 2. Detailed File Modifications

### 2.1 `requirements.txt`
- **Why Modified:** Clean virtual environments failed during imports because Scapy (packet sniffer), Joblib (model loading), and PyArrow (parquet datasets) were absent from `requirements.txt`.
- **What Changed:**
  ```diff
  +scapy>=2.5.0
  +joblib>=1.3.0
  +pyarrow>=12.0.0
  ```
- **Relevant Tests:** `tests/test_audit_fixes.py` (import checks).
- **Compatibility:** Pinning `>=` ensures compatibility with Python 3.10 through 3.13 without breaking existing dependencies.

---

### 2.2 `run_demo.py`
- **Why Modified:** Prevented unintentional binding of an unauthenticated administrative web server to `0.0.0.0` (all public/LAN network interfaces).
- **What Changed:**
  ```python
  parser = argparse.ArgumentParser(description="Run Network Attack Forecasting Demo Server")
  parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
  parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
  args = parser.parse_args()
  ```
- **Relevant Tests:** Direct invocation and local HTTP health queries.
- **Compatibility:** Fully backward-compatible; `--host 0.0.0.0` can still be passed if remote access is intentionally desired.

---

### 2.3 `pipeline/live_capture.py`
- **Why Modified:**
  1. Passing raw Windows GUIDs to Scapy failed with `ValueError: Interface not found !`.
  2. Windows created redundant `-0000` NDIS filter sub-adapters that flooded the interface dropdown.
  3. `stop_capture()` did not wait for the worker thread to exit, risking race conditions.
- **What Changed:**
  1. Added `resolve_scapy_interface()` to map GUIDs, friendly names, descriptions, or device paths to Scapy `NetworkInterface_Win` objects; returns `None` if unresolvable.
  2. Filtered `-0000` sub-adapters without active IP assignments and sorted routable interfaces (`Wi-Fi`, `Ethernet`) to the top.
  3. Added `capture_thread.join(timeout=2.0)` outside the lock in `stop_capture()`.
- **Relevant Tests:**
  - `tests/test_audit_fixes.py::test_resolve_scapy_interface_fallback`
  - `tests/test_audit_fixes.py::test_stop_capture_waits_for_thread_termination`
  - `tests/test_live_capture.py`

---

### 2.4 `pipeline/temporal_preprocessor.py`
- **Why Modified:** Unconditional +12h PM correction shifted genuine morning files (such as 01:00 AM captures) to 13:00 PM.
- **What Changed:**
  ```python
  def parse_timestamp_series(ts_series: pd.Series, file_context: str = "") -> pd.Series:
      ...
      is_morning_file = "morning" in file_context.lower()
      if not is_morning_file:
          # Apply +12h only for afternoon captures where AM/PM was truncated
          ...
  ```
  Updated `process_file_to_epochs()` to pass `file_context=fname`.
- **Relevant Tests:** `tests/test_audit_fixes.py::test_timestamp_parser_preserves_morning_files`.

---

### 2.5 `models/attack_forecaster.py`
- **Why Modified:** Bidirectional LSTM slicing `lstm_out[:, -1, :]` dropped the backward LSTM's full-sequence context.
- **What Changed:**
  Added `sequence_pooling: str = "last"` parameter to `AttackForecasterBiLSTM`.
  - If `"last"` (default): uses `lstm_out[:, -1, :]` (ensures 100% backward compatibility with `bilstm_weights.pt`).
  - If `"bidirectional_endpoints"`: uses `torch.cat([lstm_out[:, -1, :hidden_dim], lstm_out[:, 0, hidden_dim:]], dim=-1)`.
- **Relevant Tests:**
  - `tests/test_audit_fixes.py::test_bilstm_supports_bidirectional_endpoints`
  - `tests/test_pipeline.py::test_step3_and_4_bilstm_forward_pass`

---

### 2.6 `models/risk_engine.py`
- **Why Modified:**
  1. Accepted NaN, Infinite, and negative confidence/anomaly scores.
  2. Fabricated `"conn_frequency" (0.45)` and `"dst_ip_fanout" (0.38)` when SHAP features were unavailable.
- **What Changed:**
  1. In `compute_risk()`: strictly validated that `confidence` and `anomaly_intensity` are finite numbers in $[0.0, 1.0]$.
  2. In `get_recommendation()`: when `top_features` is None or empty, genuine defensive policies are rendered without fabricated numbers, labeled `"SHAP attribution unavailable"`, and `"attribution_available": False` is returned. When real SHAP features are present, authentic names and attributions are rendered with `"attribution_available": True`.
- **Relevant Tests:**
  - `tests/test_audit_fixes.py::test_risk_engine_validates_confidence_bounds`
  - `tests/test_audit_fixes.py::test_risk_engine_validates_anomaly_intensity_bounds`
  - `tests/test_audit_fixes.py::test_risk_engine_no_fake_shap_values_when_unavailable`

---

### 2.7 `models/temporal_forecasting/forecaster.py`
- **Why Modified:**
  1. Packet feature rejection only checked 7 of 13 aggregation features.
  2. Threshold parameter lacked bounds validation, allowing invalid values.
- **What Changed:**
  1. Expanded `INCOMPATIBLE_PACKET_SIGNATURES` to include all 13 packet aggregation features and added logic to detect lagged column names (e.g., `packet_count_lag1`).
  2. In `predict()`: validated that `threshold` is a finite float in $[0.0, 1.0]$.
- **Relevant Tests:**
  - `tests/test_audit_fixes.py::test_forecaster_rejects_all_incompatible_packet_features`
  - `tests/test_audit_fixes.py::test_forecaster_predict_validates_threshold_bounds`
  - `tests/test_phase9c_temporal_model.py`

---

### 2.8 `dashboard/server.py`
- **Why Modified:**
  1. `predict_temporal_experimental()` failed with 500 on malformed threshold values.
  2. `get_temporal_forecaster()` retried failed initialization on every request.
- **What Changed:**
  1. Added request parsing and validation: invalid, NaN, Infinite, or out-of-range thresholds return HTTP 422.
  2. Cached model loading failure in `_temporal_forecaster_failed` and recorded `_temporal_forecaster_error`, providing diagnostic messages on HTTP 503 without redundant reloading loops.
- **Relevant Tests:**
  - `tests/test_audit_fixes.py::test_api_predict_rejects_malformed_threshold`
  - `tests/test_audit_fixes.py::test_api_predict_rejects_missing_features`

---

### 2.9 `pipeline/device_registry.py`
- **Why Modified:** Lacked a thread-safe cleanup method to remove expired endpoint observations.
- **What Changed:**
  Added `cleanup_stale(max_age_seconds: float, mode: Optional[str] = None) -> int` to prune observations under `self._lock` where `last_seen < (now - max_age_seconds)`.
- **Relevant Tests:** `tests/test_audit_fixes.py::test_device_registry_cleanup_stale`.

---

### 2.10 `.gitignore`
- **Why Modified:** GitHub blocks git pushes containing files larger than 100MB. Uncompressed raw benchmark datasets (`Monday-WorkingHours.pcap_ISCX.csv` etc.) were >200MB.
- **What Changed:** Added `data/benchmark/raw/`, `data/benchmark/temporal/raw/`, `*.csv.gz`, and `*.pcapng` to `.gitignore`.
- **Relevant Tests:** Verified successful git commit and push to remote repository.
