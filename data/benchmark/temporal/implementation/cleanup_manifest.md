# System Cleanup Manifest
## Real Packet Processing, Wireshark Integration, and Obsolete Component Removal

### 1. Executive Summary
This manifest records all file modifications, additions, and obsolete component removals executed during the Master Implementation Task. All changes strictly preserve existing research benchmark artifacts and model weights while eliminating misleading synthetic simulation fallbacks from production capture and operational paths.

---

### 2. File Status Manifest

| File Path | Status | Primary Purpose / Change Summary | Tests Affected |
| :--- | :--- | :--- | :--- |
| `pipeline/packet_record.py` | **NEW** | Shared internal packet record schema (`PacketMetadata`) and unified Scapy parser (`parse_scapy_packet`). Extracts headers, lengths, and flags without payload retention. | `tests/test_offline_capture.py`, `tests/test_temporal_aggregation.py` |
| `pipeline/offline_pcap.py` | **NEW** | Reusable Wireshark-compatible PCAP / PCAPNG reader with format validation, streaming memory-safe iteration, error tracking, and capture summaries. | `tests/test_offline_capture.py` |
| `pipeline/temporal_aggregator.py` | **NEW** | Discrete 1-minute time-window feature aggregation component. Computes 13 observable features, handles empty intervals, and prevents future-window leakage. | `tests/test_temporal_aggregation.py` |
| `pipeline/capture_manifest.py` | **NEW** | Dataset manifest manager registering imported and recorded captures under `data/captures/manifest.json`. Excludes sensitive raw identifiers. | `tests/test_model_gating_real.py` |
| `pipeline/live_capture.py` | **MODIFIED** | Integrated shared packet parser, truthful capture states (`MONITOR NOT DETECTED`, `INTERFACE NOT AVAILABLE`, `CAPTURE INITIALIZING`, `CAPTURING REAL PACKETS`, `NO PACKETS OBSERVED`, `CAPTURE ERROR`, `INSUFFICIENT PERMISSIONS`, `STOPPED`), 1-minute discrete temporal window aggregation, and eliminated synthetic fallback in live mode. | `tests/test_live_capture.py`, `tests/test_live_capture_real.py` |
| `dashboard/server.py` | **MODIFIED** | Implemented Phase G model gating in `process_sequence` (`FORECASTING MODEL NOT VALIDATED FOR THIS DATA` on real traffic), updated `/api/capture/upload-pcap` with `OfflinePcapProcessor`, added `/api/capture/temporal-windows` and `/api/captures/manifest`. | `tests/test_server_endpoints.py`, `tests/test_model_gating_real.py` |
| `dashboard/static/index.html` | **MODIFIED** | Removed `simulation` mode option from health banner and removed `attack_replay` from ingestion source options. | Manual UI inspection |
| `dashboard/static/app.js` | **MODIFIED** | Cleaned operational mode handling and verified empty state rendering when forecasting is gated. | UI verification |
| `tests/test_offline_capture.py` | **NEW** | Comprehensive unit test suite for valid, missing, empty, truncated, and malformed PCAP files. | 6 tests passed |
| `tests/test_live_capture_real.py` | **NEW** | Unit tests for live capture states, interface enumeration, resource cleanup, and zero synthetic fallback. | 4 tests passed |
| `tests/test_temporal_aggregation.py` | **NEW** | Unit tests for 1-minute windowing, mathematical definitions, protocol ratios, SYN ratios, IAT stats, and empty windows. | 5 tests passed |
| `tests/test_model_gating_real.py` | **NEW** | Unit tests verifying that model readiness is decoupled from capture readiness and that real data triggers strict unvalidated gating. | 4 tests passed |
| `tests/test_server_endpoints.py` | **MODIFIED** | Updated capture health test to acknowledge truthful `MONITOR NOT DETECTED` state when Npcap is missing. | 12 tests passed |
| `tests/test_live_capture.py` | **MODIFIED** | Updated PCAP test assertion from obsolete synthetic prediction expectation to Phase G gated expectation. | 5 tests passed |
| `models/bilstm_weights.pt` | **RETAINED (UNMODIFIED)** | Original production weights preserved exactly (SHA256: `35807897ae6c`, size: 634,157 bytes). | All model architecture tests |
| `pipeline/scaler.pkl` | **RETAINED (UNMODIFIED)** | Original fitted StandardScaler preserved exactly (SHA256: `7ffea55f48ad`, size: 704 bytes). | All scaler tests |
| `data/benchmark/temporal/*` | **RETAINED (UNMODIFIED)** | All Phase 7B–9B research datasets, metadata JSONs, parquet files, and evaluation reports preserved. | All research benchmark tests |

---

### 3. Classification of Components

| Component / File | Classification | Status & Action Taken |
| :--- | :--- | :--- |
| `pipeline/live_capture.py` (live mode) | **REQUIRED PRODUCTION CODE** | Maintained. Upgraded with truthful capture states and shared parser. |
| `pipeline/offline_pcap.py` | **REQUIRED PRODUCTION CODE** | Implemented. Streaming Wireshark PCAP/PCAPNG reader. |
| `pipeline/temporal_aggregator.py` | **REQUIRED PRODUCTION CODE** | Implemented. 1-minute discrete aggregation without future leakage. |
| `pipeline/device_registry.py` | **REQUIRED PRODUCTION CODE** | Maintained. Tracks exclusively verified observed endpoints. |
| `dashboard/server.py` | **REQUIRED PRODUCTION CODE** | Maintained. Added strict Phase G gating and new capture/temporal routes. |
| `data/benchmark/temporal/*` | **REQUIRED RESEARCH OR BENCHMARK CODE** | Preserved intact. Kept strictly isolated from operational capture. |
| `data/sample_network_attack.pcap` | **DEVELOPMENT-ONLY FIXTURE** | Retained strictly for unit test execution. |
| `generate_sample_attack_pcap` | **DEVELOPMENT-ONLY FIXTURE** | Retained in `live_capture.py` solely as a test fixture generator. |
| `pipeline/live_capture.py` (`_simulation_worker`) | **OBSOLETE OR MISLEADING CODE** | Quarantined. Completely removed from live capture and operational fallback paths. |
| UI Dropdown `simulation` mode | **OBSOLETE OR MISLEADING CODE** | Removed from dashboard UI (`index.html`). |
| Unvalidated BiLSTM inference on real traffic | **OBSOLETE OR MISLEADING CODE** | Replaced with Phase G gate: `FORECASTING MODEL NOT VALIDATED FOR THIS DATA`. |
