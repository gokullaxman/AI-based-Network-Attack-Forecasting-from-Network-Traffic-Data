# Troubleshooting & Operational Diagnostics Guide

**Project:** AI-Based Network Attack Forecasting System (SIH26153)  
**Document Version:** 2.1-Production  
**Date:** November 1, 2026  

---

## 1. Common Issues & Resolution Procedures

### 1.1 "MONITOR NOT DETECTED" or Npcap Initialization Error
- **Symptom**: The dashboard banner displays `MONITOR NOT DETECTED` and `GET /api/capture/health` returns `"installed": false`.
- **Root Cause**: The Npcap driver is not installed on the Windows host, or was installed without the WinPcap compatibility option enabled.
- **Resolution**:
  1. Download the latest Npcap installer from [https://npcap.com/#download](https://npcap.com/#download).
  2. Right-click the installer and select **Run as Administrator**.
  3. On the installation options screen, **CHECK** the box marked:
     `[x] Install Npcap in WinPcap API-compatible Mode`
  4. Complete the installation and restart the application server:
     ```powershell
     python run_demo.py
     ```

### 1.2 "Access is Denied" / Socket Permission Error
- **Symptom**: Scapy throws `PermissionError: [WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions`.
- **Root Cause**: Raw packet sniffing and promiscuous adapter binding require elevated privileges on Windows.
- **Resolution**:
  - Launch Windows PowerShell with **Run as Administrator**.
  - Re-run `python run_demo.py`.
  - Alternatively, if administrator privilege is restricted, switch to **PCAP Mode** (`data/captures/vsftpd.pcap`) or **Connection Metadata Mode**, which run unprivileged.

### 1.3 Port 8000 Already in Use (`Errno 10048`)
- **Symptom**: `OSError: [WinError 10048] Only one usage of each socket address (protocol/network address/port) is normally permitted`.
- **Root Cause**: A previous server instance is already running on port 8000.
- **Resolution**:
  - Identify and terminate the occupying process:
    ```powershell
    $proc = (Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue).OwningProcess
    if ($proc) { Stop-Process -Id $proc -Force }
    ```
  - Or launch the server on an alternate port:
    ```powershell
    python run_demo.py --port 8080
    ```

### 1.4 Live Forecasting Returns `INSUFFICIENT_HISTORY`
- **Symptom**: `GET /api/forecast/temporal-experimental/live` returns:
  ```json
  {
    "ready": false,
    "status": "INSUFFICIENT_HISTORY",
    "epochs_available": 3,
    "epochs_required": 10,
    "message": "Insufficient history: 3 of 10 consecutive 1-minute epochs completed."
  }
  ```
- **Explanation**: This is an **intentional safety feature**, not a defect. The authentic Target A model requires a complete 10-minute historical sequence ($T=10$ discrete 1-minute epochs) to compute its 120-dimensional input vector.
- **Action**: Allow the capture engine to run for at least 10 minutes. Once 10 epochs are assembled, the endpoint automatically transitions to `FORECAST_AVAILABLE`. The system strictly refuses to manufacture synthetic feature values during the initial warm-up period.

### 1.5 Topology Nodes Appear Gray or Show "Disconnected"
- **Symptom**: Devices in the 3D topology display gray status or disappear when "Connected Only" filter is active.
- **Explanation**: The `DeviceObservationRegistry` applies an evidence-based activity timeout ($T_{\text{timeout}}=60\text{ seconds}$). If an IP address has not transmitted a packet in over 60 seconds, it is marked `is_connected: false` to prevent stale "ghost nodes" from cluttering the operational topology.
- **Action**: To view all historically observed devices regardless of recency, uncheck the **"Connected Only"** filter in the topology control panel.

### 1.6 Excel (.xlsx) Download Issues
- **Symptom**: Clicking "Export Forecast Log" throws a 500 error or fails to download.
- **Resolution**:
  - Verify that `openpyxl` is installed:
    ```powershell
    python -c "import openpyxl; print('openpyxl installed')"
    ```
  - Ensure write access to the download path. The server generates the spreadsheet in-memory as a streaming byte response (`Response(content=excel_bytes, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")`), avoiding temp file locking conflicts.

---

## 2. Diagnostic API Endpoints

When troubleshooting, consult the following diagnostic REST endpoints:

| Endpoint | Method | Diagnostic Value |
| :--- | :---: | :--- |
| `/api/capture/health` | GET | Comprehensive Npcap driver, DLL, and service diagnostics |
| `/api/capture/status` | GET | Live packet counter, capture rate, and last error message |
| `/api/capture/interfaces` | GET | Enumerates host network interfaces with GUIDs, IPs, and MACs |
| `/api/forecast/temporal-experimental/metadata` | GET | Validates model artifact availability, schema, and metrics |
| `/api/capture/flow-epochs` | GET | Inspects completed 1-minute flow epochs and 12-feature values |
| `/docs` | GET | Interactive Swagger UI for manual endpoint testing |
