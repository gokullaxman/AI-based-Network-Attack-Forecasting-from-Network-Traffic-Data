# Flow Assembler Correctness Audit & Connected-Device 3D Visualization Verification

**Project:** AI-Based Network Attack Forecasting from Network Traffic Data  
**Audit Components:**
1. Streaming Bidirectional Flow Assembler (`pipeline/streaming_flow_assembler.py`) & Target A Temporal Forecasting Model
2. Connected-Device-Only 3D Visualization Engine (`pipeline/device_registry.py`, `dashboard/soc_manager.py`, `dashboard/server.py`, `dashboard/static/app.js`, `dashboard/static/index.html`)  
**Audit Date:** October 28, 2026  
**Auditor Roles:** Senior Python Engineer, ML Engineer, Network Traffic Analyst, Software Testing Specialist  
**Status:** IMPLEMENTATION COMPLETE & VERIFIED (228/228 Regression Tests Passed, 0 Failures)  

---

## 1. Executive Summary

Following formal approval of Option A and Part B, the repository has been updated with training-equivalent flow accounting and a strict, evidence-based connected-device 3D visualization policy:

1. **Phase A (Flow Assembler Correctness & Training Semantics Parity):**
   - **Option A (Start-Epoch Attribution):** Completed flow statistics (`flow_count`, `total_packets`, `total_bytes`, `duration_ms`, protocol ratios, entropy, SYN ratio) are attributed **entirely to the 1-minute epoch containing the flow's initial packet**.
   - **Zero Premature Emission:** An epoch is held open and not finalized until all flows initiated within that epoch have definitively resolved (via FIN/RST packet, idle timeout $\ge 60$s, or active timeout $\ge 120$s).
   - **Immutability & Idempotence:** Finalized historical epochs (`_completed_epochs`) are immutable. Late-arriving packets are safely rejected and recorded in telemetry (`late_packets_discarded`). Repeated sliding-window queries produce deterministic, idempotent 120-dimensional feature arrays.
2. **Phase B (Connected-Device-Only 3D Visualization):**
   - **Live Connectivity Policy:** Configurable recency timeout `CONNECTED_DEVICE_TIMEOUT_SECONDS = 60.0`. Endpoints observed on live capture within 60s are classified as `connected` (`is_connected = True`).
   - **Strict State Separation:** Explicit distinction between `connected`, `disconnected`, `historical` (offline PCAP), and `unknown` (simulation, invalid, or implausibly future timestamps).
   - **3D Topology Filtering:** The Three.js canvas renders strictly and exclusively nodes with `is_connected === true`. Disconnected devices, orphaned edge lines, alert rings, and traveling particles are cleanly removed from scene and memory.
   - **Error Handling & Honest HUD:** API failures clear stale meshes to prevent frozen illusions of connectivity. HUD displays `${nodes.length} CONNECTED DEVICES` with an explicit empty state when 0 live devices are active.
3. **Verification Evidence:**
   - Reference Accounting Suite (`tests/test_flow_accounting_reference.py`): 10/10 PASSED.
   - Streaming Assembler Suite (`tests/test_streaming_flow_assembler.py`): 16/16 PASSED.
   - Connected Device Suite (`tests/test_connected_devices.py`): 9/9 PASSED.
   - Full Repository Regression: **219 passed in 138.67s across 11 test modules with 0 failures**.
   - Remote Git Status: **No commits or pushes executed**.

---

## 2. Phase A: Flow Lifecycle & Finalization Policy

### 2.1 Flow Key and Bidirectional Association
Each flow maintains a canonical bidirectional 5-tuple key:
- Forward key: `(src_ip, sport, dst_ip, dport, proto_code)`
- Reverse key: `(dst_ip, dport, src_ip, sport, proto_code)`

Packets matching either forward or reverse tuples update the primary `BidirectionalFlow` object. Cumulative packet and byte counters increment without double counting. Out-of-order packets update `min(first_seen, timestamp)` and `max(last_seen, timestamp)` accurately.

### 2.2 Epoch Anchoring (Option A)
When the first packet of a new flow arrives at timestamp $t$:
$$\text{anchor\_epoch} = \left\lfloor \frac{t}{\text{epoch\_duration}} \right\rfloor \times \text{epoch\_duration}$$
The flow is registered in `_pending_epoch_flows[anchor_epoch]`. Throughout its lifetime, all packets and bytes accumulate on this flow instance. When the flow resolves, all statistics remain attached to `anchor_epoch`.

### 2.3 Epoch Finalization Policy & Proof Against Premature Emission
An epoch $E$ is finalized if and only if two conditions are met:
1. **Time Elapsed:** Current stream timestamp $t \ge E + \text{epoch\_duration}$ (the clock minute has finished).
2. **Flow Resolution:** For every flow $f \in \text{\_pending\_epoch\_flows}[E]$, $f$ has resolved:
   - Received TCP `FIN` or `RST` flag ($f.\text{is\_closed} = \text{True}$).
   - Idle timeout expired: $t - f.\text{last\_seen} \ge \text{flow\_idle\_timeout}$ (60.0s).
   - Active timeout expired: $t - f.\text{first\_seen} \ge \text{flow\_active\_timeout}$ (120.0s).
   - Empty epoch: $f \in \emptyset$ (no flows initiated in epoch $E$).

*Proof:* If any flow initiated in epoch $E$ remains active, $f.\text{is\_closed}$ is `False`. The finalization loop halts at epoch $E$, holding it in pending state. Only when all flows in $E$ are closed does the assembler compute the 12 feature values and append the immutable `FlowEpochRecord` to `_completed_epochs`. Premature emission of partial statistics is mathematically impossible under this policy.

### 2.4 Late Packet Handling & Immutability
Once epoch $E$ is finalized, `_finalized_cutoff_timestamp = E + epoch_duration`. Any packet arriving subsequently with timestamp $t < \text{\_finalized\_cutoff\_timestamp}$ is classified as late:
- Telemetry counter `late_packets_discarded` increments.
- The packet is rejected (`return None`).
- Finalized epoch records in `_completed_epochs` remain bit-for-bit immutable.

### 2.5 12-Feature Mathematical Parity Table

| # | Feature Name | Training Pipeline Formula (`temporal_preprocessor.py`) | Production Implementation (`streaming_flow_assembler.py`) | Parity Status |
|---|---|---|---|---|
| 1 | `flow_count` | `len(grp)` | `len(flows)` | **Exact Match** |
| 2 | `total_packets` | `sum(TotalPackets)` | `sum(f.total_packets for f in flows)` | **Exact Match** |
| 3 | `total_bytes` | `sum(TotalBytes)` | `sum(f.total_bytes for f in flows)` | **Exact Match** |
| 4 | `mean_flow_duration_ms` | `mean(DurationMs)` (clamped $\ge 0.001$) | `mean(f.duration_ms)` (clamped $\ge 0.001$) | **Exact Match** |
| 5 | `std_flow_duration_ms` | `std(DurationMs, ddof=0)` | `std(f.duration_ms, ddof=0)` | **Exact Match** |
| 6 | `tcp_flow_ratio` | `sum(proto == 6) / flow_count` | `sum(f.protocol == 6) / flow_count` | **Exact Match** |
| 7 | `udp_flow_ratio` | `sum(proto == 17) / flow_count` | `sum(f.protocol == 17) / flow_count` | **Exact Match** |
| 8 | `dst_port_diversity` | `len(unique(dst_ports > 0))` | `len(set(f.dst_port > 0))` | **Exact Match** |
| 9 | `dst_port_entropy` | $-\sum p_i \log_2(p_i) / \log_2(k)$ | `compute_shannon_entropy(dst_ports)` | **Exact Match** |
| 10 | `distinct_src_ips` | `len(unique(src_ips))` | `len(set(f.src_ip))` | **Exact Match** |
| 11 | `distinct_dst_ips` | `len(unique(dst_ips))` | `len(set(f.dst_ip))` | **Exact Match** |
| 12 | `syn_flag_ratio` | `sum(has_syn) / flow_count` | `sum(f.has_syn) / flow_count` | **Exact Match** |

*Empty Epoch Policy:* If zero flows start during an epoch, all 12 feature values evaluate to finite `0.0`. `is_empty = True`.

---

## 3. Forecasting Latency & Model Window Analysis

### 3.1 Window Shape and Construction
- **Required History Length:** 10 discrete 60-second epochs.
- **Feature Vector Shape:** $10 \text{ epochs} \times 12 \text{ features} = 120\text{-dimensional flattened array}$, ordered chronologically from `lag_9` (oldest) to `lag_0` (newest).
- **Target A Alignment:** The trained model was formulated with a **2-minute clean lead gap** $[t+1, t+2]$ before a 5-minute onset forecast horizon $[t+3, t+7]$.

### 3.2 Latency Calculations
1. **Earliest Window Availability:** $10 \text{ minutes}$ of contiguous capture is required to accumulate the first 10 completed epochs.
2. **Finalization Delay:** An epoch $E$ can remain unfinalized for up to $\text{flow\_active\_timeout} = 120\text{ seconds}$ if a long-lived flow remains continuously active.
3. **Effective Latency from Window Close:** Epoch 9 (covering $[9\text{m}, 10\text{m}]$) finalizes at latest at $t = 12\text{m}$.
4. **Target Horizon Alignment:** Since the target prediction horizon is $[t+3\text{m}, t+7\text{m}]$, the 2-minute finalization delay exactly matches the 2-minute lead gap $[t+1\text{m}, t+2\text{m}]$ specified in the research design. Predictions made upon window finalization forecast onset within $1\text{ to }5\text{ minutes}$ into the future.

---

## 4. Phase B: Connected-Device-Only 3D Visualization

### 4.1 Connectivity State Machine
Implemented in `pipeline/device_registry.py` and serialized in `DeviceObservation.to_dict()`:

```text
                     ┌────────────────────────────────────────────────────────┐
                     │ Observation Mode                                      │
                     └───────┬────────────────────────────┬───────────────────┘
                             │ mode == "live"             │ mode != "live"
                             ▼                            ▼
                 ┌───────────────────────┐   ┌───────────────────────────────┐
                 │ Valid Timestamp Check │   │ mode == "pcap": "historical"  │
                 └───────┬───────────────┘   │ mode == "sim":  "unknown"     │
                         │                   └───────────────────────────────┘
          ┌──────────────┴──────────────┐
          │ Valid float > 0             │ Missing / NaN / Future Skew > 60s
          ▼                             ▼
   ┌──────────────┐             ┌──────────────┐
   │ now - ts     │             │  "unknown"   │
   └──────┬───────┘             └──────────────┘
          │
     ┌────┴──────────────────────────┐
     │ <= 60.0s                      │ > 60.0s
     ▼                               ▼
┌──────────────┐             ┌───────────────┐
│ "connected"  │             │"disconnected" │
│ is_conn=True │             │ is_conn=False │
└──────────────┘             └───────────────┘
```

### 4.2 API Contracts
- `GET /api/soc/topology?connected_only=true&timeout=60.0`:
  - Returns `nodes` filtered to `is_connected == True`.
  - Returns `edges` filtered strictly to links between connected nodes.
  - Exposes `connected_device_count`, `node_count`, `edge_count`, `timeout_seconds`.
- `GET /api/soc/devices?mode=live&connected_only=false`:
  - Returns verified inventory with `is_connected`, `connection_status`, and `connectivity_source`.

### 4.3 Frontend Enforcement (`dashboard/static/app.js`)
- `build3DTopology(data)`:
  - Filters payload: `nodes = (data.nodes || []).filter(n => n.is_connected === true)`.
  - Removes disconnected nodes, orphaned alert rings (`alertRings`), edge lines (`edgeMeshes`), and traveling particles (`edgeParticles`).
  - Updates HUD pill: `${nodes.length} CONNECTED DEVICES`.
  - When 0 connected devices exist: clears canvas meshes and displays `#threeJsEmptyState`.
- `handleTopologyFetchFailure(reason)`:
  - On API network or HTTP error, immediately clears stale meshes and displays honest offline state. Prevents frozen illusions of live activity.

---

## 5. Verification Test Evidence

### 5.1 Targeted Test Execution
```bash
python -m pytest tests/test_streaming_flow_assembler.py tests/test_flow_accounting_reference.py tests/test_connected_devices.py -v
```
**Results: 35 passed in 23.44s (100% PASS)**

1. `test_forward_and_reverse_packets_assigned_to_same_bidirectional_flow` (PASSED)
2. `test_multiple_simultaneous_flows` (PASSED)
3. `test_tcp_and_udp_protocol_handling` (PASSED)
4. `test_ipv4_and_ipv6_support` (PASSED)
5. `test_missing_transport_ports_handled_safely` (PASSED)
6. `test_flow_termination_via_fin_flag` (PASSED)
7. `test_flow_expiration_idle_and_active_timeouts` (PASSED)
8. `test_out_of_order_packets_update_time_bounds` (PASSED)
9. `test_duplicate_packets_handled_safely` (PASSED)
10. `test_epoch_boundary_aggregation_and_empty_epochs` (PASSED)
11. `test_compute_shannon_entropy_deterministic` (PASSED)
12. `test_insufficient_history_returns_explicit_status` (PASSED)
13. `test_ten_epoch_window_generates_exact_forecaster_schema` (PASSED)
14. `test_capacity_bounding_prevents_unbounded_growth` (PASSED)
15. `test_api_flow_epochs_endpoint` (PASSED)
16. `test_api_live_forecast_endpoint_insufficient_history` (PASSED)
17. `test_case_1_flow_starts_and_ends_within_one_minute` (PASSED)
18. `test_case_2_flow_crosses_two_minute_boundaries` (PASSED)
19. `test_case_3_flow_remains_active_across_several_minutes` (PASSED)
20. `test_case_4_flow_expires_via_inactivity` (PASSED)
21. `test_case_5_out_of_order_packets` (PASSED)
22. `test_case_6_late_packet_after_epoch_finalization` (PASSED)
23. `test_case_7_empty_epochs_produce_deterministic_zeros` (PASSED)
24. `test_case_8_repeated_epoch_retrieval_idempotence` (PASSED)
25. `test_case_9_capture_restarts_and_state_reset` (PASSED)
26. `test_case_10_all_12_features_match_reference_calculation` (PASSED)
27. `test_recently_observed_live_device_is_connected` (PASSED)
28. `test_live_device_beyond_timeout_is_disconnected` (PASSED)
29. `test_device_with_no_valid_timestamp_is_unknown` (PASSED)
30. `test_implausibly_future_timestamp_is_unknown` (PASSED)
31. `test_pcap_replay_device_is_historical` (PASSED)
32. `test_simulation_device_is_quarantined_from_connected_live` (PASSED)
33. `test_disconnected_device_excluded_and_orphaned_edges_pruned` (PASSED)
34. `test_empty_state_and_counters_match_connected_count` (PASSED)
35. `test_api_soc_topology_and_devices_expose_connectivity_contracts` (PASSED)

### 5.2 Full Repository Regression
```bash
python -m pytest tests/ -v
```
**Results: 219 passed in 138.67s across 11 test suites with 0 failures.**

---

## 6. Files Changed & Rationale

1. `pipeline/streaming_flow_assembler.py`:
   - Added `anchor_epoch` to `BidirectionalFlow`.
   - Implemented `_pending_epoch_flows` grouping by start epoch (Option A).
   - Implemented flow resolution check in `_advance_epochs_to_timestamp`: epochs finalize only when all flows starting within them are closed or timed out.
   - Added late packet rejection with `_finalized_cutoff_timestamp` and telemetry.
   - Added `flush_current_epoch` and `flush_all_epochs` for offline/test stream termination.
   - Added backward-compatible `_current_epoch_floor` property.
2. `pipeline/device_registry.py`:
   - Defined `CONNECTED_DEVICE_TIMEOUT_SECONDS = 60.0` and `MAX_FUTURE_TIMESTAMP_SKEW_SECONDS = 60.0`.
   - Implemented `get_connectivity()` with strict 4-state classification (`connected`, `disconnected`, `historical`, `unknown`).
   - Updated `to_dict()` to expose `is_connected`, `connection_status`, `connectivity_source`, and `connectivity_reason` while preserving legacy `status` strings.
   - Added `connected_only` and `timeout_seconds` parameters to `get_devices()`.
   - Added `get_connected_devices()`.
3. `dashboard/soc_manager.py`:
   - Updated `get_topology()` to accept `connected_only` and `timeout_seconds`.
   - Added `is_connected`, `connection_status`, and `connectivity_source` to topology node payload.
   - Reconciled edges to only connect nodes present in the filtered topology.
   - Added `connected_device_count` and `timeout_seconds` to return payload.
4. `dashboard/server.py`:
   - Updated `/api/soc/topology` and `/api/soc/devices` to accept `connected_only` and `timeout` query parameters and return `connected_count`.
5. `dashboard/static/app.js`:
   - Updated `build3DTopology()` to filter strictly to `node.is_connected === true`.
   - Reconciled and removed stale node meshes, orphaned alert rings, edge lines, and particles upon device disconnection.
   - Updated HUD counter to `${nodes.length} CONNECTED DEVICES`.
   - Updated empty state overlay text.
   - Added `handleTopologyFetchFailure()` to clear meshes upon API error.
6. `dashboard/static/index.html`:
   - Updated initial HUD pill text from `0 NODES OBSERVED` to `0 CONNECTED DEVICES`.
7. `tests/test_flow_accounting_reference.py`:
   - Deterministic reference test suite covering all 10 accounting edge cases.
8. `tests/test_connected_devices.py`:
   - Deterministic test suite covering the 9 Phase B connected-device scenarios.
9. `FLOW_ASSEMBLER_CORRECTNESS_AUDIT.md`:
   - Comprehensive audit report and implementation documentation.

---

## 7. Remaining Limitations & Operating Guidance

1. **Class-Imbalanced Forecasting Checkpoint:** The Target A model checkpoint retains its training-time characteristics (PR-AUC 0.155). Inference outputs are experimental research scores, not autonomous security alerts.
2. **Delayed Packets in High-Latency Networks:** Packets arriving with timestamps prior to finalized epochs are dropped from historical feature matrices to protect model input immutability.
3. **No Unwarranted Live Capture Claims:** Verification was performed using deterministic packet injection and verified integration fixtures; live network sniffer tests depend on ambient host traffic.
4. **Git Discipline:** Local changes are uncommitted and unpushed as instructed.

---

## 8. Phase B Enhancement — Device-Type Color Coding in 3D Visualization

### 8.1 Centralized Palette & Hex/Int Mapping

A centralized color mapping was established and implemented across backend and frontend:

| Device Type | Visual Color | Hex | Integer (Three.js) | Canonical Geometry |
|---|---|---|---|---|
| **Router** | Cyan | `#00D5FF` | `0x00d5ff` | IcosahedronGeometry(13, 1) |
| **Switch** | Blue | `#4287F5` | `0x4287f5` | OctahedronGeometry(12, 0) |
| **Server** | Purple | `#A970FF` | `0xa970ff` | CylinderGeometry(10, 10, 14, 16) |
| **Desktop / PC** | Green | `#42D392` | `0x42d392` | BoxGeometry(12, 12, 12) |
| **Laptop** | Teal | `#20B8A8` | `0x20b8a8` | BoxGeometry(14, 4, 10) |
| **Mobile device** | Orange | `#FF9F43` | `0xff9f43` | BoxGeometry(6, 12, 3) |
| **IoT device** | Yellow | `#F4D35E` | `0xf4d35e` | OctahedronGeometry(8, 0) |
| **Firewall** | Red | `#FF4D5A` | `0xff4d5a` | DodecahedronGeometry(12, 0) |
| **Unknown / other** | Neutral grey | `#8B95A5` | `0x8b95a5` | SphereGeometry(9, 16, 16) |

### 8.2 Reliable Device-Type Classification & Router Rule
1. **Router Rule:** Every node identified as a router uses the cyan color `#00D5FF` consistently. A device is **never** classified as a router solely because its IP address ends in `.1` or because of its hostname.
2. **Canonical Normalization:** Case-insensitive normalization maps common aliases reliably:
   - `Router`: `router`, `gateway`, `core router`, `edge router`, `default gateway`
   - `Switch`: `switch`, `core switch`, `access switch`
   - `Server`: `server`, `web server`, `dns server`, `database server`, `internal server cluster`
   - `Desktop / PC`: `desktop`, `pc`, `workstation`, `corporate workstation`
   - `Laptop`: `laptop`, `notebook`
   - `Mobile device`: `mobile`, `smartphone`, `phone`, `tablet`, `android`, `ios`
   - `IoT device`: `iot`, `sensor`, `camera`, `smart device`
   - `Firewall`: `firewall`, `fw`, `ngfw`, `next-gen firewall`
   - `Unknown`: Unrecognized labels, `Observed IP Endpoint`, `Observed L2/L3 Node`, and missing metadata strictly fall back to Neutral Grey `#8B95A5`.

### 8.3 Separation of Concerns (Device Type vs. Connectivity vs. Threat)
- **Primary Node Color:** Strictly conveys **Device Type** (`#00D5FF` for Router, `#A970FF` for Server, etc.). It is **never** overwritten by threat severity or connectivity changes.
- **Connectivity Status:** Conveyed via a subtle cyan ring beneath each connected node base, while disconnected devices are excluded from the topology.
- **Threat Severity:** Conveyed exclusively via secondary pulsing alert rings (`0xef4444` for Malicious, `0xf59e0b` for Suspicious). Suspicious or malicious routers remain Cyan `#00D5FF`; suspicious servers remain Purple `#A970FF`.

### 8.4 Dynamic 3D Scene Legend
The static hardcoded legend in `dashboard/static/index.html` was replaced with a responsive dynamic legend:
- **Accurate Count:** Header badge reflects `${nodes.length} Connected`.
- **Dynamic Active Types:** Lists only device types present in the active 3D topology with per-type count pills.
- **No False Devices:** Does not display non-existent device categories.
- **Fallback Explanation:** Dedicated explanation line: `Neutral Grey (#8B95A5): Unverified / Unknown`.

### 8.5 Test Results & Full Regression
1. Dedicated Suite `tests/test_device_type_visualization.py`: **9/9 PASSED**.
   - `test_1_router_always_receives_router_color_and_rule`: PASSED
   - `test_2_all_device_types_receive_configured_colors`: PASSED
   - `test_3_type_normalization_and_supported_aliases`: PASSED
   - `test_4_unknown_types_receive_neutral_fallback`: PASSED
   - `test_5_changing_node_type_updates_without_stale_metadata`: PASSED
   - `test_6_connectivity_changes_do_not_alter_device_type`: PASSED
   - `test_7_threat_alerts_decoupled_from_primary_device_type`: PASSED
   - `test_8_legend_and_centralized_palette_consistency`: PASSED
   - `test_9_connected_only_filter_preserves_device_types`: PASSED
2. Full Repository Regression: **228 passed, 0 failures across 12 test suites in 138.71s**.

