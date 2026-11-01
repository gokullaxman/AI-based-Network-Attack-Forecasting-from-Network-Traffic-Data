# Known System & Research Limitations

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Document Version:** 2.1-Production  
**Date:** November 1, 2026  

---

## 1. Scientific & Machine Learning Limitations

### 1.1 Cross-Category Zero-Shot Generalization (Target A)
- **Observed Metrics**: On the authentic CICIDS2017 temporal benchmark, the primary Logistic Regression model achieves an area under the Precision-Recall curve (**PR-AUC**) of `0.1554` and a Random Forest achieves `0.1815`, compared to a dummy prior baseline of `0.1250`.
- **Root Cause**: The benchmark enforces a strict chronological split where training occurs on Monday through Wednesday and testing occurs on Thursday and Friday. 
  - **Training Split**: Contains FTP-Patator, SSH-Patator, DoS Slowloris, and Heartbleed.
  - **Testing Split**: Contains Web BruteForce, Web XSS, Botnet, PortScan, and LOIC DDoS.
  - There is **zero overlap** between attack categories across splits.
- **Scientific Implication**: Flow statistics prior to a brute-force SSH intrusion share very few observable precursors with flow statistics prior to a distributed LOIC flood. The modest lift (+0.03 to +0.05 over random prior) demonstrates the difficulty of zero-shot cross-category precursor detection. Unvalidated predictions must never be presented as confirmed security findings.

### 1.2 Deep Sequential Modeling on Small Attack Episode Counts
- **LSTM Evaluation**: A compact 1-layer PyTorch LSTM trained on the same temporal sequence data achieved a PR-AUC of `0.1206` (**worse than the dummy prior** of `0.1250`) and an ROC-AUC of `0.5018` (random chance).
- **Root Cause**: The entire 5-day dataset contains only 19 ground-truth attack episodes (9 in training, 10 in testing). With only 9 positive training episodes, recurrent neural architectures with hundreds of parameters easily overfit to the idiosyncratic baseline noise of Tuesday and Wednesday, failing to generalize to Thursday and Friday.
- **Remediation Policy**: The production system defaults to balanced Logistic Regression and Random Forest models rather than over-parameterized deep neural networks for real-data temporal onset forecasting.

### 1.3 Linear Kill-Chain Progression vs. Non-Linear Attacker Behavior
- **Conceptual Assumption**: The Dual-Head BiLSTM assumes an idealized sequence:
  $$\text{Reconnaissance} \longrightarrow \text{Scanning} \longrightarrow \text{Enumeration} \longrightarrow \text{Exploitation} \longrightarrow \text{Intrusion}$$
- **Operational Reality**: Sophisticated cyber threats do not follow a strict linear progression. Attackers may skip reconnaissance when attacking known endpoints, perform simultaneous scanning and exploitation, loop repeatedly across enumeration stages, or maintain long dormant periods.
- **Intended Role**: The kill-chain model provides a structured framework for risk scoring (0–100), visual analyst tracking, and prioritized countermeasure synthesis, but must not be interpreted as a rigid physical law of attack progression.

---

## 2. Ingestion & Network Telemetry Limitations

### 2.1 Windows Npcap Privilege & Driver Dependencies
- **Privilege Requirements**: Real-time packet capture on Windows requires the Npcap packet capture driver installed in WinPcap-compatible mode. Capturing raw ethernet frames requires elevated administrator privileges.
- **Graceful Fallback**: If Npcap or elevated privileges are absent, the capture engine cleanly transitions to `MONITOR NOT DETECTED` or `INTERFACE NOT AVAILABLE`, reporting actionable diagnostic guidance without throwing unhandled exceptions.

### 2.2 Python / Scapy Sniffer Throughput Bounds
- **Single-Threaded Scapy Throughput**: Pure Python Scapy packet parsing processes approximately 1,500 to 3,500 packets per second on standard laptop hardware.
- **Enterprise High-Volume Traffic**: In enterprise backbone environments with traffic exceeding 50,000 packets per second, user-space Scapy will drop packets at the OS socket buffer. For high-volume networks, hardware capture cards or kernel-level aggregation (e.g., DPDK, eBPF, Suricata flow logs) should be positioned upstream.

### 2.3 1-Minute Epoch Aggregation Warm-Up Latency
- **Windowing Delay**: The `StreamingFlowAssembler` operates on discrete 60-second temporal epochs to mirror the training pipeline.
- **History Requirement**: The Target A model requires 10 consecutive 1-minute epochs ($T=10$ minutes) to construct its 120-dimensional input vector.
- **Cold-Start Policy**: During the first 9 minutes following capture initiation, the live forecasting endpoint reports `ready: false` with status `INSUFFICIENT_HISTORY`. The system refuses to fabricate synthetic predictions to fill incomplete history windows.

### 2.4 Encrypted Traffic & Zero Payload Inspection
- **Encrypted Payloads (TLS 1.3 / HTTPS / SSH)**: The system inspects packet headers and flow statistics only (source/destination ports, packet sizes, inter-arrival times, TCP flags, flow longevity). It does not decrypt application payloads.
- **Defense-in-Depth**: In modern zero-trust environments, flow-based statistical forecasting serves as an early-warning tripwire that complements host-based EDR agents and application-layer WAFs.

---

## 3. Operational & User Interface Considerations

### 3.1 Device Role Heuristics
- **Passive Inference**: Device classification in the `DeviceObservationRegistry` is inferred passively from observed transport ports (e.g., port 80/443 for web servers, port 53 for DNS, port 22 for SSH, ephemeral ports for client workstations).
- **Labeling Standard**: If an endpoint does not expose recognized service ports, it is classified as `Observed L2/L3 Node` rather than claiming unwarranted certainty.

### 3.2 Connectivity vs. Observation Recency
- **Ephemeral Traffic**: An IP address observed in a packet capture indicates historical traffic presence, not guaranteed active socket connectivity.
- **Timeout Semantics**: Devices that have not transmitted packets within a configurable window (default: 60 seconds) are marked `is_connected: false` in SOC topology views to prevent ghost node accumulation.
