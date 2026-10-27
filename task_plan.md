# Master Implementation Task Plan
## AI-Based Network Attack Forecasting from Network Traffic Data: Wireshark Integration, Real Packet Processing, Removal of Synthetic Components, and Project Cleanup

### Objective
Implement the real-data pipeline, integrate Wireshark-compatible packet capture (offline PCAP/PCAPNG and live capture via Npcap/Scapy), remove obsolete and synthetic components (simulation fallback, fake devices, random threat scores), separate benchmark research data, establish strict model readiness gating (independent of capture status), clean frontend and API to present honest operational states, run comprehensive testing, and document deliverables.

---

### Phase Plan

- [x] **Phase A — Remove Misleading and Obsolete Components**
  - [x] Audit codebase (`pipeline/live_capture.py`, `dashboard/soc_manager.py`, `dashboard/server.py`, `pipeline/device_registry.py`, `dashboard/static/app.js`) for synthetic traffic generators, fictional device creation, mock counters, and random threat scores.
  - [x] Classify all findings (Required Production, Required Research, Dev Fixture, Obsolete/Misleading, Uncertain).
  - [x] Remove simulation fallback and fake packet generation from production capture paths.
  - [x] Remove fake device discovery and random threat score calculations in production.

- [x] **Phase B — Implement Wireshark-Compatible Offline Capture Processing**
  - [x] Implement robust offline PCAP and PCAPNG reader module (using `scapy` / maintained library).
  - [x] Support user-selected capture file validation (missing, invalid, empty captures, malformed packets).
  - [x] Stream packets without excessive memory buffering; extract timestamps, frame lengths, IP/TCP/UDP headers.
  - [x] Track packet counts, parsing errors, capture duration, and timestamp coverage accurately.

- [x] **Phase C — Implement Live Packet Capture**
  - [x] Enumerate Windows network interfaces via Scapy / Npcap.
  - [x] Implement interface selection, validation, and safe start/stop capture lifecycle.
  - [x] Implement truthful capture states: `MONITOR NOT DETECTED`, `INTERFACE NOT AVAILABLE`, `CAPTURE INITIALIZING`, `CAPTURING REAL PACKETS`, `NO PACKETS OBSERVED`, `CAPTURE ERROR`, `INSUFFICIENT PERMISSIONS`, `STOPPED`.
  - [x] Strictly prevent any synthetic fallback traffic.

- [x] **Phase D — Build a Shared Packet-Metadata Pipeline**
  - [x] Define shared packet record schema: timestamp, frame length, network protocol, transport protocol, IP src/dst, ports, TCP flags, parse status.
  - [x] Unify parsing logic across offline and live captures.
  - [x] Avoid deriving fictional services, operating systems, or decrypting payloads.

- [x] **Phase E — Implement Temporal Feature Aggregation**
  - [x] Implement 1-minute discrete time-window aggregation for real packet observations.
  - [x] Observable features: packet count, total bytes, frame length mean/std, TCP/UDP/other protocol ratios, distinct IPs, distinct ports, SYN flag ratio, inter-arrival time stats.
  - [x] Handle missing intervals honestly (no silent zero-filling; distinguish empty interval vs capture outage).
  - [x] Prevent future-window data leakage.

- [x] **Phase F — Separate Real Traffic from Benchmark Data**
  - [x] Isolate captured live/offline traffic from CICIDS2017 benchmark datasets and research artifacts.
  - [x] Build capture dataset manifest recording metadata (source, date, interface/file, duration, packet count, status).
  - [x] Never label live traffic as benign or attacks without ground truth.

- [x] **Phase G — Repair Model Readiness and Forecasting Gates**
  - [x] Decouple capture status from model readiness.
  - [x] Implement strict gate: if model feature schema, sequence length, or weights are unvalidated for real packet features, report: `FORECASTING MODEL NOT VALIDATED FOR THIS DATA`.
  - [x] Preserve existing production BiLSTM weights (`models/bilstm_weights.pt`) and scaler (`pipeline/scaler.pkl`) without modification.

- [x] **Phase H — Clean the Frontend and API**
  - [x] Clean API endpoints (`dashboard/server.py`) to serve genuine capture stats, device observations, and model readiness.
  - [x] Update frontend (`dashboard/static/app.js`, `index.html`) to eliminate fake graphs, fictional counters, and mock topology.
  - [x] Provide truthful empty states and clear status indicators for capture, detection, and forecasting.

- [x] **Phase I — Testing and Validation**
  - [x] Write unit tests for offline capture (valid, missing, invalid, empty, malformed PCAPs).
  - [x] Write unit tests for live capture states, lifecycle, and zero-synthetic-fallback enforcement.
  - [x] Write unit tests for temporal feature aggregation and model readiness gating.
  - [x] Run full test suite (`python -m pytest tests/`) and resolve any regressions.

- [x] **Phase J — Final Project Cleanup & Documentation**
  - [x] Generate `data/benchmark/temporal/implementation/implementation_report.md`.
  - [x] Generate `data/benchmark/temporal/implementation/cleanup_manifest.md`.
  - [x] Update `README.md` with Wireshark PCAP guide, Npcap setup, and operational instructions.

- [x] **Phase 9C — Implement the Real-Data Attack Forecasting Model**
  - [x] Train primary validated Logistic Regression model on authentic 1-minute temporal flow observations (Target A).
  - [x] Train Random Forest and evaluate compact PyTorch LSTM sequence model (analyzing sample bottleneck and out-of-distribution failure).
  - [x] Fit preprocessing (`StandardScaler`) strictly on training data ($N=1117$).
  - [x] Export trained artifacts, preprocessor, feature schema, and metadata to `models/temporal_forecasting/`.
  - [x] Implement schema-validated inference module `models/temporal_forecasting/forecaster.py` prohibiting packet/flow contamination.
  - [x] Connect experimental API endpoints (`/api/forecast/temporal-experimental`).
  - [x] Implement unit tests in `tests/test_phase9c_temporal_model.py` (9 passed, 169 total passed).
  - [x] Generate final research report at `data/benchmark/temporal/phase9c/real_data_model_report.md`.
