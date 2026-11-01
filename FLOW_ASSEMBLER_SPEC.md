# Streaming Bidirectional Flow Assembler Specification (Phase 9D)

**System Component:** `pipeline/streaming_flow_assembler.py`  
**Integration Points:** `pipeline/live_capture.py`, `dashboard/server.py`, `models/temporal_forecasting/forecaster.py`  
**Author:** AI Network Traffic Analysis & Software Engineering Specialist  
**Status:** IMPLEMENTED & TESTED (76/76 Tests Passing)  

---

## 1. Executive Summary & Objective

The experimental temporal forecasting model (Target A) was trained on 1-minute discrete epochs extracted from CICIDS2017 bidirectional flow records (`PREDICTOR_COLUMNS`). In contrast, live packet capture operates on discrete layer-2 and layer-3 network frames. Previously, live packet features and flow features were incompatible, requiring the forecasting model to remain gated and unavailable for live packet feeds.

Phase 9D resolves this architectural gap by implementing `StreamingFlowAssembler`: a streaming state machine that unifies incoming packets into bidirectional 5-tuple flows, aggregates active flows into discrete 60-second temporal epochs, and constructs the exact 12-feature schema and 120-dimensional lagged sequence required by the Target A Forecaster.

---

## 2. Architecture & Data Flow

```
                      +-----------------------------+
                      |   Live Npcap Sniffer /      |
                      |   Offline PCAP Stream       |
                      +--------------+--------------+
                                     |
                             CapturedPacket
                                     |
                                     v
                 +---------------------------------------+
                 |       StreamingFlowAssembler          |
                 +---------------------------------------+
                 | 1. Canonical 5-Tuple Lookup           |
                 |    (src_ip, sport, dst_ip, dport, proto)
                 |    Forward vs. Backward unification   |
                 |                                       |
                 | 2. Flow State Tracking                |
                 |    Bytes, packets, SYN flags, duration|
                 |                                       |
                 | 3. Expiration Engine                  |
                 |    FIN/RST termination, idle timeout  |
                 |                                       |
                 | 4. 60-Second Epoch Windowing          |
                 |    Discrete boundary aggregation      |
                 +-------------------+-------------------+
                                     |
                    Completed 1-Minute Flow Epochs
                                     |
                                     v
                 +---------------------------------------+
                 |      10-Epoch Sliding Deque           |
                 | (lag_9, lag_8, ..., lag_0 = 120 dims) |
                 +-------------------+-------------------+
                                     |
                     Is History Count == 10?
                     /                      \
                   No                        Yes
                  /                            \
                 v                              v
    +-------------------------+   +-------------------------------+
    | INSUFFICIENT_HISTORY    |   | Target A Temporal Forecaster  |
    | (Honest Gating: 0/10)   |   | (Uncalibrated Onset Prob [0,1]|
    +-------------------------+   +-------------------------------+
```

---

## 3. Bidirectional Flow Identity & State Machine

### 3.1 Five-Tuple Definition
Each bidirectional flow is uniquely identified by the 5-tuple:
$$\text{Key}_{\text{forward}} = (\text{IP}_{\text{src}}, \text{Port}_{\text{src}}, \text{IP}_{\text{dst}}, \text{Port}_{\text{dst}}, \text{Proto})$$
$$\text{Key}_{\text{reverse}} = (\text{IP}_{\text{dst}}, \text{Port}_{\text{dst}}, \text{IP}_{\text{src}}, \text{Port}_{\text{src}}, \text{Proto})$$

- **Direction Assignment:** The direction of the first observed packet defines the forward direction ($\text{IP}_{\text{src}} \to \text{IP}_{\text{dst}}$). Subsequent packets matching the forward key increment forward counters; packets matching the reverse key increment reverse counters.
- **Protocol Codes:** TCP is mapped to 6, UDP to 17, ICMP to 1, IPv6-ICMP to 58.
- **Port Handling:** Packets lacking transport ports (e.g. ICMP or raw IP) default safely to $\text{Port}_{\text{src}} = 0, \text{Port}_{\text{dst}} = 0$.
- **IPv4 and IPv6:** Fully supported. IP strings are normalized to prevent hash mismatches.

### 3.2 Flow Expiration & Termination Policies
1. **TCP Connection Termination:** An incoming packet with TCP `FIN` or `RST` flags immediately marks `flow.is_closed = True`.
2. **Inactivity Timeout (Idle Timeout):** If no packets are observed for a flow for $> 60.0$ seconds, the flow is marked expired and pruned at the next epoch boundary.
3. **Maximum Flow Lifetime (Active Timeout):** Long-lived flows exceeding $120.0$ seconds are flushed to match 1-minute discrete epoch boundaries.
4. **Capacity Bounding:** Active flows are capped at `max_active_flows` (default: 50,000). If capacity is reached, the oldest inactive flow is evicted, preventing memory exhaustion.

---

## 4. The 12 Authoritative Flow Features & Mathematical Definitions

Each 60-second discrete epoch produces exactly 12 numerical features:

| # | Feature Name | Mathematical Definition | Units / Range |
|---|---|---|---|
| 1 | `flow_count` | Total distinct flows active or initiated during the 60s epoch: $N_{\text{flows}}$ | Integer $\ge 0$ |
| 2 | `total_packets` | Sum of all packets across all flows in epoch: $\sum (N_{\text{fwd}} + N_{\text{bwd}})$ | Float $\ge 0.0$ |
| 3 | `total_bytes` | Sum of all frame lengths across all flows in epoch: $\sum (B_{\text{fwd}} + B_{\text{bwd}})$ | Float $\ge 0.0$ (bytes) |
| 4 | `mean_flow_duration_ms` | Mean elapsed time between first and last packet per flow: $\frac{1}{N} \sum \max(0.001, (t_{\text{last}} - t_{\text{first}}) \times 1000)$ | Float $\ge 0.001$ (ms) |
| 5 | `std_flow_duration_ms` | Population standard deviation ($ddof=0$) of flow durations | Float $\ge 0.0$ (ms) |
| 6 | `tcp_flow_ratio` | Fraction of flows where $\text{Protocol} == 6$: $\frac{N_{\text{TCP}}}{N_{\text{flows}}}$ | Float $\in [0.0, 1.0]$ |
| 7 | `udp_flow_ratio` | Fraction of flows where $\text{Protocol} == 17$: $\frac{N_{\text{UDP}}}{N_{\text{flows}}}$ | Float $\in [0.0, 1.0]$ |
| 8 | `dst_port_diversity` | Count of unique forward destination ports: $|\{\text{Port}_{\text{dst}} \mid \text{Port}_{\text{dst}} > 0\}|$ | Integer $\ge 0$ |
| 9 | `dst_port_entropy` | Normalized Shannon entropy: $-\frac{\sum p_i \log_2(p_i)}{\log_2(k)}$ for $k > 1$, else $0.0$ | Float $\in [0.0, 1.0]$ |
| 10 | `distinct_src_ips` | Count of unique forward source IP addresses: $|\{\text{IP}_{\text{src}}\}|$ | Integer $\ge 0$ |
| 11 | `distinct_dst_ips` | Count of unique forward destination IP addresses: $|\{\text{IP}_{\text{dst}}\}|$ | Integer $\ge 0$ |
| 12 | `syn_flag_ratio` | Fraction of flows where at least one packet had the SYN flag: $\frac{N_{\text{SYN}}}{N_{\text{flows}}}$ | Float $\in [0.0, 1.0]$ |

### 4.1 Empty Epoch Policy
If zero traffic is observed during an active 60-second window:
- An explicit empty epoch record is created (`is_empty=True`).
- All 12 feature values are set to finite $0.0$.
- No packets, flows, or predictions are fabricated.

---

## 5. Ten-Epoch Sliding History & Lag Order

The Target A model expects 120 features representing 10 historical epochs in descending lag order:
$$\text{Features} = [\text{feat}_1(t-9), \dots, \text{feat}_{12}(t-9), \dots, \text{feat}_1(t), \dots, \text{feat}_{12}(t)]$$
Matching the lag names registered in `models/temporal_forecasting/metadata.json`:
- `flow_count_lag_9`, ..., `syn_flag_ratio_lag_9`
- `flow_count_lag_8`, ..., `syn_flag_ratio_lag_8`
- ...
- `flow_count_lag_0`, ..., `syn_flag_ratio_lag_0`

### 5.1 Gating Rules
- **If epochs completed $< 10$:** Assembler returns `ready=False`, `status="INSUFFICIENT_HISTORY"`, `features=None`.
- **If epochs completed $\ge 10$:** Assembler extracts the latest 10 consecutive epochs, builds a 2D numpy array of shape `(1, 120)`, and returns `ready=True`, `status="READY"`.

---

## 6. Training vs. Live Streaming Comparison

| Property | CICIDS2017 Training Pipeline (`temporal_preprocessor.py`) | Live Streaming Assembler (`streaming_flow_assembler.py`) | Compatibility Status |
|---|---|---|---|
| **Input Source** | GeneratedLabelledFlows CSV flow summaries | Raw L2/L3 packets from Scapy / Npcap / PCAP | **Resolved via 5-tuple state machine** |
| **Duration Units** | Microseconds $\div 1000.0$ (clamped to $\ge 0.001$ ms) | Milliseconds from packet timestamps (clamped $\ge 0.001$ ms) | **Identical** |
| **Port Entropy** | Normalized Shannon entropy over destination ports | Normalized Shannon entropy over destination ports | **Identical** |
| **SYN Flag Count** | Flow-level SYN flag column | Tracked across packets in flow | **Identical** |
| **Epoch Duration** | 60.0 seconds (truncated via `floor("min")`) | 60.0 seconds (truncated via `floor(ts / 60.0) * 60.0`) | **Identical** |
| **Historical Lags** | 10 epochs (lag 9 to lag 0, 120 features) | 10 epochs (lag 9 to lag 0, 120 features) | **Identical** |

---

## 7. Exposed API Endpoints

1. **`GET /api/capture/flow-epochs`**
   - Returns completed 1-minute flow epochs assembled from real traffic.
   - Includes schema definition, total completed epochs, and sliding window readiness.
2. **`GET /api/forecast/temporal-experimental/live`**
   - Directly queries the live Target A forecaster on genuine assembled flow epochs.
   - If $< 10$ epochs exist: returns HTTP 200 with `ready: false`, `status: "INSUFFICIENT_HISTORY"`, `forecast: null`.
   - If $\ge 10$ epochs exist: passes the 120-dim feature vector to `TemporalAttackForecaster.predict()` and returns the uncalibrated onset forecast.

---

## 8. Verification Results

All 16 deterministic tests in `tests/test_streaming_flow_assembler.py` and the full 76-test regression suite passed:
- Bidirectional packet pairing: Verified.
- TCP/UDP and IPv4/IPv6 support: Verified.
- Missing ports and out-of-order timestamps: Verified.
- Flow expiration and capacity limits: Verified.
- Shannon entropy math: Verified.
- Insufficient history gating: Verified.
- Direct model inference compatibility: Verified.
