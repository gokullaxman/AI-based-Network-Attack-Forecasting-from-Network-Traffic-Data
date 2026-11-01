# Live Network Packet Capture Setup & Operational Guide

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Target Platform:** Windows 10/11 (Primary), Linux / macOS (Supported via libpcap)  
**Packet Ingestion Engine:** Scapy + Npcap (WinPcap-API Compatible Mode)  

---

## 1. Prerequisites & Architecture

The live packet capture engine operates via `LiveNetworkCaptureEngine` (`pipeline/live_capture.py`). It sniffs live Ethernet/Wi-Fi frames, parses transport headers (TCP, UDP, ICMP), updates the `DeviceObservationRegistry`, and feeds the `StreamingFlowAssembler` to produce 1-minute discrete behavioral epochs.

### 1.1 Requirements
- **Operating System**: Windows 10 or 11 (64-bit).
- **Python**: Python 3.10, 3.11, 3.12, or 3.13.
- **Capture Driver**: **Npcap** (v1.70 or newer).
  - Download from: [https://npcap.com/#download](https://npcap.com/#download)
  - > [!IMPORTANT]
  - > During installation, you **MUST** ensure the checkbox **"Install Npcap in WinPcap API-compatible Mode"** is **CHECKED**.
  - Without WinPcap compatibility, Scapy cannot access the underlying Npcap kernel driver.

---

## 2. Step-by-Step Installation on Windows

### Step 2.1: Verify Python Environment
Open Windows PowerShell (Run as Administrator for live packet capture) and check your Python version:

```powershell
python --version
```
*(Should return Python 3.10.x, 3.11.x, 3.12.x, or 3.13.x)*

### Step 2.2: Clone / Navigate to Repository
```powershell
cd "c:\Users\Dell Latitude 7410\Downloads\AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main\AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data-main"
```

### Step 2.3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 2.4: Verify Npcap Installation & Service Status
Run the built-in diagnostic checker directly from PowerShell:

```powershell
python -c "from pipeline.live_capture import check_npcap_diagnostics; import json; print(json.dumps(check_npcap_diagnostics(), indent=2))"
```

Expected Output:
```json
{
  "installed": true,
  "scapy_use_pcap": true,
  "wpcap_dll_present": true,
  "packet_dll_present": true,
  "service_running": true,
  "npcap_folder_present": true,
  "status": "READY",
  "error_message": "",
  "recovery_instruction": ""
}
```

If `"installed": false`, download Npcap from [npcap.com](https://npcap.com/#download) and reinstall with WinPcap API-compatible mode enabled.

---

## 3. Discovering Host Network Adapters

To inspect all physical, virtual, and loopback network adapters discovered on your machine:

```powershell
python -c "from pipeline.live_capture import get_network_interfaces; import json; print(json.dumps(get_network_interfaces(), indent=2))"
```

Each enumerated adapter displays:
- `id`: Windows interface GUID or Scapy interface identifier.
- `name`: Friendly interface name (e.g., `Wi-Fi`, `Ethernet`, `Loopback Pseudo-Interface 1`).
- `description`: Network adapter hardware description.
- `ip`: Assigned IPv4 address.
- `mac`: Physical hardware address.
- `is_active`: True if assigned a valid IP address.

---

## 4. Starting the Server & Managing Capture

### Step 4.1: Launch the Application Server
```powershell
python run_demo.py
```
This starts Uvicorn hosting FastAPI on `http://127.0.0.1:8000`.

### Step 4.2: Access the Dashboard
Open your web browser and navigate to:
- **Analyst Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Step 4.3: Interface Selection & Live Sniffing
1. At the top of the dashboard, locate the **Capture Health Status Banner**.
2. If status displays **READY**, your active network adapter (`Wi-Fi` or `Ethernet`) is selected.
3. Click **Start Capture** (or send `POST /api/capture/start`).
4. As traffic flows, watch:
   - **Packets Captured**: Live count of raw packets received.
   - **Captured Throughput**: Measured kilobits per second.
   - **3D Topology**: Real devices appearing dynamically with distinct router identification (Cyan `#00D5FF`).
   - **Flow Epochs**: Assembling 60-second discrete traffic summaries.

---

## 5. Offline PCAP Playback (Non-Privileged Mode)

If running in an environment without administrative privileges or without Npcap, you can use the verified offline PCAP engine:

### 5.1 Using Curated Captures
Sample verified PCAP traces with preserved historical timestamps are located in `data/captures/`:
- `data/captures/smtp.pcap` (101 KB)
- `data/captures/vsftpd.pcap` (5.7 MB)

### 5.2 Dissecting via API
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/mode/select" -Method Post -ContentType "application/json" -Body '{"mode": "pcap", "pcap_path": "data/captures/vsftpd.pcap"}'
```

The system will parse the pcap packets, maintain original timestamps, assemble bidirectional flows, and populate the 3D topology and device registry without requiring network hardware access.
