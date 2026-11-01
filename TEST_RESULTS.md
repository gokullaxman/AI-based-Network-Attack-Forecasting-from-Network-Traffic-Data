# Test Execution & Verification Results

**Environment:** Windows 10/11 x64  
**Python Runtime:** Python 3.13.12 (`C:\Users\Dell Latitude 7410\AppData\Local\Programs\Python\Python313\python.exe`)  
**Test Runner:** Pytest 9.1.1 (Pluggy 1.6.0, AnyIO 4.14.2)  
**Execution Timestamp:** October 28, 2026  

---

## 1. Summary of Test Execution

| Test Suite / Scope | Total Tests | Passed | Failed | Skipped | Status |
|---|---|---|---|---|---|
| **Audit Verification Suite (`test_audit_fixes.py`)** | 12 | 12 | 0 | 0 | **100% PASS** |
| **Streaming Flow Assembler (`test_streaming_flow_assembler.py`)** | 16 | 16 | 0 | 0 | **100% PASS** |
| **Pipeline Core (`test_pipeline.py`)** | 10 | 10 | 0 | 0 | **100% PASS** |
| **Device Registry (`test_device_registry.py`)** | 9 | 9 | 0 | 0 | **100% PASS** |
| **Phase 9C Model & Schema (`test_phase9c_temporal_model.py`)** | 12 | 12 | 0 | 0 | **100% PASS** |
| **Temporal Aggregation (`test_temporal_aggregation.py`)** | 5 | 5 | 0 | 0 | **100% PASS** |
| **FastAPI Endpoints (`test_server_endpoints.py`)** | 12 | 12 | 0 | 0 | **100% PASS** |
| **Total Automated Tests Executed** | **76** | **76** | **0** | **0** | **100% PASS** |

---

## 2. Commands Executed & Raw Outputs

### 2.1 Audit Fixes Test Suite
```bash
python -m pytest tests/test_audit_fixes.py -v
```
**Output:**
```text
tests/test_audit_fixes.py::test_risk_engine_validates_confidence_bounds PASSED [  8%]
tests/test_audit_fixes.py::test_risk_engine_validates_anomaly_intensity_bounds PASSED [ 16%]
tests/test_audit_fixes.py::test_risk_engine_no_fake_shap_values_when_unavailable PASSED [ 25%]
tests/test_audit_fixes.py::test_forecaster_rejects_all_incompatible_packet_features PASSED [ 33%]
tests/test_audit_fixes.py::test_forecaster_predict_validates_threshold_bounds PASSED [ 41%]
tests/test_audit_fixes.py::test_api_predict_rejects_malformed_threshold PASSED [ 50%]
tests/test_audit_fixes.py::test_api_predict_rejects_missing_features PASSED [ 58%]
tests/test_audit_fixes.py::test_resolve_scapy_interface_fallback PASSED  [ 66%]
tests/test_audit_fixes.py::test_stop_capture_waits_for_thread_termination PASSED [ 75%]
tests/test_audit_fixes.py::test_timestamp_parser_preserves_morning_files PASSED [ 83%]
tests/test_audit_fixes.py::test_bilstm_supports_bidirectional_endpoints PASSED [ 91%]
tests/test_audit_fixes.py::test_device_registry_cleanup_stale PASSED     [100%]
======================= 12 passed, 4 warnings in 13.33s =======================
```

### 2.2 Core Application & Research Model Suites
```bash
python -m pytest tests/test_pipeline.py tests/test_device_registry.py tests/test_phase9c_temporal_model.py tests/test_temporal_aggregation.py tests/test_server_endpoints.py -v
```
**Output:**
```text
tests/test_pipeline.py::test_step1_feature_extraction PASSED             [  2%]
tests/test_pipeline.py::test_step2_temporal_sequence_construction PASSED [  4%]
tests/test_pipeline.py::test_step3_and_4_bilstm_forward_pass PASSED      [  6%]
tests/test_pipeline.py::test_step5_risk_engine PASSED                    [  8%]
tests/test_pipeline.py::test_step5_shap_gradient_explainer PASSED        [ 10%]
tests/test_pipeline.py::test_step6_fastapi_endpoints PASSED              [ 12%]
tests/test_pipeline.py::test_real_cicids_loader_and_ingest_endpoint PASSED [ 14%]
tests/test_pipeline.py::test_windowed_real_data_and_defending_methods PASSED [ 16%]
tests/test_pipeline.py::test_export_xlsx_endpoint PASSED                 [ 18%]
tests/test_pipeline.py::test_synthetic_dataset_equal_stage_balancing PASSED [ 20%]
tests/test_device_registry.py::test_genuine_observed_ip_creates_registry_entry PASSED [ 22%]
tests/test_device_registry.py::test_repeated_observations_update_counts_and_timestamps PASSED [ 25%]
tests/test_device_registry.py::test_missing_mac_addresses_remain_unknown PASSED [ 27%]
tests/test_device_registry.py::test_offline_pcap_observations_remain_marked_historical PASSED [ 29%]
tests/test_device_registry.py::test_connection_metadata_not_represented_as_packets PASSED [ 31%]
tests/test_device_registry.py::test_simulation_cannot_contaminate_live PASSED [ 33%]
tests/test_device_registry.py::test_invalid_observations_rejected_safely PASSED [ 35%]
tests/test_device_registry.py::test_unobserved_devices_never_created PASSED [ 37%]
tests/test_device_registry.py::test_stale_observations_marked_appropriately PASSED [ 39%]
tests/test_phase9c_temporal_model.py::test_model_save_and_load PASSED    [ 41%]
tests/test_phase9c_temporal_model.py::test_feature_schema_validation PASSED [ 43%]
tests/test_phase9c_temporal_model.py::test_missing_and_invalid_features PASSED [ 45%]
tests/test_phase9c_temporal_model.py::test_training_only_preprocessing PASSED [ 47%]
tests/test_phase9c_temporal_model.py::test_prediction_output_and_calibration PASSED [ 50%]
tests/test_phase9c_temporal_model.py::test_target_leakage_prevention PASSED [ 52%]
tests/test_phase9c_temporal_model.py::test_reproducible_evaluation_metrics PASSED [ 54%]
tests/test_phase9c_temporal_model.py::test_separation_between_experimental_and_production_models PASSED [ 56%]
tests/test_phase9c_temporal_model.py::test_api_experimental_endpoints PASSED [ 58%]
tests/test_phase9c_temporal_model.py::test_sample_windows_endpoint PASSED [ 60%]
tests/test_phase9c_temporal_model.py::test_dashboard_html_contains_phase9c_panel_and_tab PASSED [ 62%]
tests/test_phase9c_temporal_model.py::test_live_capture_status_indicates_gated_model PASSED [ 64%]
tests/test_temporal_aggregation.py::test_empty_window_aggregation PASSED [ 66%]
tests/test_temporal_aggregation.py::test_packet_and_byte_calculations PASSED [ 68%]
tests/test_temporal_aggregation.py::test_protocol_and_syn_ratios PASSED  [ 70%]
tests/test_temporal_aggregation.py::test_inter_arrival_time_statistics PASSED [ 72%]
tests/test_temporal_aggregation.py::test_chronological_stream_partitioning PASSED [ 75%]
tests/test_server_endpoints.py::test_live_mode_is_default PASSED         [ 77%]
tests/test_server_endpoints.py::test_missing_npcap_produces_explicit_error PASSED [ 79%]
tests/test_server_endpoints.py::test_insufficient_flow_steps_prevents_inference PASSED [ 81%]
tests/test_server_endpoints.py::test_incorrect_feature_dimensions_prevent_inference PASSED [ 83%]
tests/test_server_endpoints.py::test_nan_and_infinite_values_rejected PASSED [ 85%]
tests/test_server_endpoints.py::test_valid_input_reaches_inference PASSED [ 87%]
tests/test_server_endpoints.py::test_invalid_mode_selection_rejected PASSED [ 89%]
tests/test_server_endpoints.py::test_pcap_data_cannot_enter_live_registry PASSED [ 91%]
tests/test_server_endpoints.py::test_simulation_cannot_contaminate_live_telemetry PASSED [ 93%]
tests/test_device_registry.py::test_device_endpoint_empty_when_no_devices PASSED [ 95%]
tests/test_server_endpoints.py::test_capture_health_never_claims_fake_packets PASSED [ 97%]
tests/test_server_endpoints.py::test_existing_soc_endpoint_contracts_compatible PASSED [100%]
======================= 48 passed, 4 warnings in 41.27s =======================
```

### 2.3 Streaming Flow Assembler Test Suite (`tests/test_streaming_flow_assembler.py`)
```bash
python -m pytest tests/test_streaming_flow_assembler.py -v
```
**Output:**
```text
tests/test_streaming_flow_assembler.py::test_forward_and_reverse_packets_assigned_to_same_bidirectional_flow PASSED [  6%]
tests/test_streaming_flow_assembler.py::test_multiple_simultaneous_flows_tracked_separately PASSED [ 12%]
tests/test_streaming_flow_assembler.py::test_tcp_and_udp_protocol_handling PASSED [ 18%]
tests/test_streaming_flow_assembler.py::test_ipv4_and_ipv6_support PASSED [ 25%]
tests/test_streaming_flow_assembler.py::test_missing_transport_ports_handled_safely PASSED [ 31%]
tests/test_streaming_flow_assembler.py::test_flow_termination_via_fin_flag PASSED [ 37%]
tests/test_streaming_flow_assembler.py::test_flow_expiration_via_idle_timeout PASSED [ 43%]
tests/test_streaming_flow_assembler.py::test_epoch_boundaries_and_discrete_rollover PASSED [ 50%]
tests/test_streaming_flow_assembler.py::test_empty_epoch_handling_no_fabricated_traffic PASSED [ 56%]
tests/test_streaming_flow_assembler.py::test_out_of_order_packets_update_time_bounds PASSED [ 62%]
tests/test_streaming_flow_assembler.py::test_dst_port_entropy_calculation PASSED [ 68%]
tests/test_streaming_flow_assembler.py::test_ten_epoch_history_sliding_window_and_ordering PASSED [ 75%]
tests/test_streaming_flow_assembler.py::test_forecaster_inference_with_assembled_features PASSED [ 81%]
tests/test_streaming_flow_assembler.py::test_bounded_memory_capacity_and_eviction PASSED [ 87%]
tests/test_streaming_flow_assembler.py::test_live_capture_engine_accumulates_flow_epochs PASSED [ 93%]
tests/test_streaming_flow_assembler.py::test_api_live_forecast_endpoint_insufficient_history PASSED [100%]
====================== 16 passed, 2 warnings in 12.06s =======================
```

### 2.4 Full Combined Regression Suite (All 7 Suites)
```bash
python -m pytest tests/test_audit_fixes.py tests/test_streaming_flow_assembler.py tests/test_pipeline.py tests/test_device_registry.py tests/test_phase9c_temporal_model.py tests/test_temporal_aggregation.py tests/test_server_endpoints.py -v
```
**Output:**
```text
================== 76 passed, 4 warnings in 60.43s (0:01:00) ==================
```

---

## 3. Manual Checks & Operational Verification

### 3.1 Local Application Startup
- **Status:** **VERIFIED**
- **Process:** Executed `python run_demo.py` via background task daemon listening on `http://127.0.0.1:8000`.
- **Health Endpoint Response:**
  ```json
  {
    "capture_status": "CAPTURING REAL PACKETS",
    "capture_mode": "live",
    "is_capturing": true,
    "capture_backend": "scapy_live_npcap",
    "selected_interface": "\\Device\\NPF_{269C2179-18FC-40F1-8E43-ABAAD99B9C49}",
    "selected_interface_name": "Wi-Fi"
  }
  ```

### 3.2 Live Packet Sniffing with Real Hardware
- **Status:** **VERIFIED (Real Hardware Present)**
- **Hardware Adapter:** Intel Wi-Fi 6 AX201 160MHz (`Wi-Fi`) attached to Windows host.
- **Driver:** Npcap driver active in WinPcap-compatible mode.
- **Behavior:** Real L2/L3 frames were sniffed, dissected into `CapturedPacket` objects, and passed to `DeviceObservationRegistry` with genuine MAC and IP addresses. No packets were fabricated or simulated in live mode.

---

## 4. Evaluation Metrics Reproduction (Target A Benchmark)

The experimental Target A temporal attack forecaster evaluation artifacts were inspected and reproduced against `data/benchmark/temporal/phase9c/metadata.json`:

### 4.1 Window-Level Benchmark Metrics ($N = 280$ test windows, 35 positives, 245 negatives)

| Model / Baseline | Precision | Recall | F1 Score | PR-AUC | ROC-AUC | False Alarms / Hour |
|---|---|---|---|---|---|---|
| **Dummy Prior Baseline** | 0.0000 | 0.0000 | 0.0000 | 0.1250 | 0.5000 | 0.00 |
| **Dummy Stratified Baseline** | 0.3333 | 0.0286 | 0.0526 | 0.1310 | 0.5102 | 0.49 |
| **Logistic Regression (Weighted)** | 0.1538 | 0.0571 | 0.0833 | **0.1554** | **0.5370** | 2.69 |
| **Random Forest (Balanced)** | 0.0000 | 0.0000 | 0.0000 | 0.1402 | 0.4901 | 0.00 |
| **Compact LSTM** | 0.1257 | 0.6857 | 0.2124 | 0.1310 | 0.5197 | 40.90 |

### 4.2 Event-Level Detection Metrics (10 Independent Attack Onsets)

| Model | Multi-Credit Recall (Rule 1) | Strict Earliest Recall (Rule 2) | Mean Warning Lead Time |
|---|---|---|---|
| **Logistic Regression** | 30.0% (3 / 10) | 20.0% (2 / 10) | **5.67 minutes** |
| **Random Forest** | 0.0% (0 / 10) | 0.0% (0 / 10) | N/A |
| **Compact LSTM** | 90.0% (9 / 10) | 0.0% (0 / 10) | High false alarm rate |

---

## 5. Items Not Run / Blocked

- **External Dedicated Hardware Network TAP / Managed SPAN Port:**  
  While real host Wi-Fi packet capture was verified, validating capture from external mirrored switch ports or hardware TAPs requires dedicated multi-NIC lab infrastructure.
- **Model Retraining:**  
  Model weights and preprocessors were preserved as authoritative artifacts. In accordance with rule #11, models were not retrained during this audit because their training pipelines and evaluation metadata are intact and reproducible.
