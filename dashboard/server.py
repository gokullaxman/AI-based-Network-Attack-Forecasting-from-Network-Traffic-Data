"""
FastAPI Server for Network Attack Forecasting System (SIH26153)
STRICT REAL-DATA-ONLY ARCHITECTURE (Phase 4: Server API & Model Gating)

Exposes:
- GET  /api/capture/health    : Comprehensive Npcap diagnostics and live capture health status
- POST /api/mode/select       : Explicit operating mode selector (live, pcap, simulation, connection_metadata)
- GET  /api/capture/status    : Real-time telemetry, packet counter, and capture state
- GET  /api/capture/interfaces: Discovered host network interfaces with friendly names, IPs, MACs
- POST /api/capture/start     : Starts capture on selected interface in specified mode
- POST /api/capture/stop      : Stops capture and releases sniffer resources
- POST /api/capture/clear     : Clears packet buffer and sliding flow sequence
- GET  /api/capture/feed      : Rolling packet stream, telemetry, and gated AI prediction
- POST /api/capture/upload-pcap: Dissects uploaded PCAP trace with preserved timestamps
- GET  /api/soc/overview      : High-level SOC telemetry, verified traffic categories, and threat stats
- GET  /api/soc/topology      : 3D network topology generated strictly from verified endpoint registry
- GET  /api/soc/devices       : Verified device & endpoint inventory from DeviceObservationRegistry
- GET  /api/soc/threat-logs   : Threat logs filtered by severity, status, event type, and mode
- POST /api/forecast          : Computes attack stage forecast and SHAP attribution for flow sequence
- GET  /                      : Serves the analyst security dashboard UI
"""

import os
import sys
import pickle
import json
import math
from datetime import datetime
import numpy as np
import torch
from fastapi import FastAPI, HTTPException, UploadFile, File, Response, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.dataset import (
    STAGE_NAMES, STAGE_TO_IDX, NUM_STAGES,
    generate_multi_stage_sequence, generate_balanced_attack_timeline
)
from pipeline.feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS
from pipeline.real_flow_loader import CICIDSFlowLoader
from pipeline.excel_exporter import export_forecasts_to_bytes
from pipeline.live_capture import (
    LiveNetworkCaptureEngine,
    generate_sample_attack_pcap,
    check_npcap_diagnostics,
    get_network_interfaces
)
from pipeline.offline_pcap import validate_pcap_file, OfflinePcapProcessor
from pipeline.temporal_aggregator import AGGREGATION_FEATURE_NAMES, TemporalAggregator, TemporalWindow
from pipeline.capture_manifest import register_capture, load_manifest, CAPTURES_DIR
from models.attack_forecaster import AttackForecasterBiLSTM
from models.risk_engine import DynamicRiskEngine
from models.shap_explainer import AttackForecasterSHAPExplainer

try:
    from dashboard.soc_manager import SOCTrafficManager
except ImportError:
    from soc_manager import SOCTrafficManager

app = FastAPI(title="AI-Based Network Attack Forecasting System", version="2.0-RealData")

# Live Network Traffic Capture Engine & SOC Manager
# Strict Real-Data Default: Mode is 'live'; do NOT automatically launch synthetic socket generators.
capture_engine = LiveNetworkCaptureEngine(max_packet_buffer=500, sequence_length=10)
soc_manager = SOCTrafficManager(device_registry=capture_engine.device_registry)

# Load model, scaler, and SHAP explainer
MODELS_DIR = os.path.join(BASE_DIR, "models")
PIPELINE_DIR = os.path.join(BASE_DIR, "pipeline")

# Initialize BiLSTM
model = AttackForecasterBiLSTM(
    input_dim=len(FEATURE_NAMES),
    hidden_dim=64,
    num_layers=2,
    num_classes=NUM_STAGES,
    dropout=0.2
)
weights_path = os.path.join(MODELS_DIR, "bilstm_weights.pt")
if os.path.exists(weights_path):
    model.load_state_dict(torch.load(weights_path, map_location=torch.device("cpu")))
model.eval()

# Load feature scaler
scaler_path = os.path.join(PIPELINE_DIR, "scaler.pkl")
with open(scaler_path, "rb") as f:
    scaler = pickle.load(f)

# Load background samples for GradientExplainer
bg_path = os.path.join(PIPELINE_DIR, "background_samples.npy")
background_data = np.load(bg_path)
shap_explainer = AttackForecasterSHAPExplainer(model, background_data)

# Risk Engine
risk_engine = DynamicRiskEngine()

# In-memory session history of all forecasts computed so far
session_forecast_history: List[Dict[str, Any]] = []

# Real Flow Loader for CICIDS2017/2018 CSV ingestion
real_flow_loader = CICIDSFlowLoader(sequence_length=10)


def process_sequence(seq_features: Optional[np.ndarray], is_real_data: bool = False) -> Dict[str, Any]:
    """
    STRICT MODEL INFERENCE GATING (Phase G & Rule E)
    Validates that:
    1. Input sequence is non-null and a valid 2D NumPy array.
    2. Input has at least 10 genuine chronological flow steps.
    3. Input has exactly 12 behavioral features per flow step.
    4. Input contains only finite numerical values (no NaN or Inf).
    5. Scaler and model are loaded and active.
    6. Model has a validated training record on the target data domain.
       If the data is authentic real packet traffic, gating reports:
       'FORECASTING MODEL NOT VALIDATED FOR THIS DATA'
    """
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Null / Type check
    if seq_features is None:
        return {
            "prediction_available": False,
            "status": "UNAVAILABLE",
            "reason": "Prediction unavailable — insufficient validated real traffic data (Collected: 0/10 flow steps).",
            "current_stage": "Insufficient Data",
            "current_stage_idx": None,
            "predicted_next_stage": "Insufficient Data",
            "predicted_next_stage_idx": None,
            "confidence": None,
            "confidence_raw": None,
            "risk_score": None,
            "risk_level": "UNAVAILABLE",
            "candidate_forecasts": [],
            "recommendation": "Maintain network traffic capture until at least 10 genuine temporal flows are observed.",
            "formatted_output": "Prediction unavailable — insufficient validated real traffic data (0/10 flows).",
            "shap": None,
            "timestamp": timestamp_str
        }

    if not isinstance(seq_features, np.ndarray):
        try:
            seq_features = np.array(seq_features, dtype=np.float32)
        except Exception as e:
            return {
                "prediction_available": False,
                "status": "ERROR",
                "reason": f"Invalid sequence input: unable to convert to NumPy array ({str(e)}).",
                "risk_level": "UNAVAILABLE",
                "timestamp": timestamp_str
            }

    if seq_features.ndim != 2:
        return {
            "prediction_available": False,
            "status": "ERROR",
            "reason": f"Invalid input dimensionality. Expected 2D array [steps, 12], got {seq_features.ndim}D.",
            "risk_level": "UNAVAILABLE",
            "timestamp": timestamp_str
        }

    steps, num_features = seq_features.shape

    # 2. Sequence length check (Minimum 10 flow steps required for BiLSTM temporal window)
    if steps < 10:
        return {
            "prediction_available": False,
            "status": "INSUFFICIENT_DATA",
            "reason": f"Prediction unavailable — insufficient validated real traffic data (Collected: {steps}/10 flow steps).",
            "current_stage": "Insufficient Data",
            "current_stage_idx": None,
            "predicted_next_stage": "Insufficient Data",
            "predicted_next_stage_idx": None,
            "confidence": None,
            "confidence_raw": None,
            "risk_score": None,
            "risk_level": "UNAVAILABLE",
            "candidate_forecasts": [],
            "recommendation": "Capture or load genuine network traffic to accumulate at least 10 valid flow steps.",
            "reason": f"Insufficient validated real traffic data ({steps}/10 flows).",
            "formatted_output": f"Prediction unavailable — insufficient validated real traffic data ({steps}/10 flows).",
            "shap": None,
            "timestamp": timestamp_str
        }

    # 3. Phase G: Real-data gating — production weights were trained on synthetic Gaussian sequences
    if is_real_data:
        return {
            "prediction_available": False,
            "status": "FORECASTING MODEL NOT VALIDATED FOR THIS DATA",
            "model_readiness": "NOT_VALIDATED_FOR_REAL_DATA",
            "reason": "Production BiLSTM weights and scaler were trained on synthetic Gaussian distributions and are not validated for authentic network traffic data.",
            "current_stage": "Model Not Validated",
            "current_stage_idx": None,
            "predicted_next_stage": "Model Not Validated",
            "predicted_next_stage_idx": None,
            "confidence": None,
            "confidence_raw": None,
            "risk_score": None,
            "risk_level": "UNAVAILABLE",
            "candidate_forecasts": [],
            "recommendation": "Network capture and temporal feature aggregation are operational. To enable attack forecasting, train and evaluate a model on an authentic chronological dataset.",
            "formatted_output": "FORECASTING MODEL NOT VALIDATED FOR THIS DATA",
            "shap": None,
            "timestamp": timestamp_str
        }

    # 3. Feature dimension check (Must be exactly 12 features)
    if num_features != len(FEATURE_NAMES):
        return {
            "prediction_available": False,
            "status": "INVALID_SCHEMA",
            "reason": f"Invalid feature count. Expected {len(FEATURE_NAMES)} features, received {num_features}.",
            "risk_level": "UNAVAILABLE",
            "timestamp": timestamp_str
        }

    # 4. Finiteness check (No NaN or Inf)
    if not np.all(np.isfinite(seq_features)):
        return {
            "prediction_available": False,
            "status": "INVALID_VALUES",
            "reason": "Feature sequence contains non-finite, NaN, or Inf values.",
            "risk_level": "UNAVAILABLE",
            "timestamp": timestamp_str
        }

    # 5. Model & Scaler availability check
    if model is None or scaler is None:
        return {
            "prediction_available": False,
            "status": "MODEL_UNAVAILABLE",
            "reason": "BiLSTM model weights or feature scaler are not available.",
            "risk_level": "UNAVAILABLE",
            "timestamp": timestamp_str
        }

    # Extract exactly the latest 10 steps for BiLSTM input window
    eval_window = seq_features[-10:]

    # Step 1: Scale features using calibrated scaler
    seq_scaled = scaler.transform(eval_window)
    x_tensor = torch.tensor(seq_scaled[np.newaxis, :, :], dtype=torch.float32)

    # Step 2: Model classification & probabilistic next-stage forecast
    curr_probs, next_probs = model.predict_probabilities(x_tensor)
    curr_probs_np = curr_probs.numpy()[0]
    next_probs_np = next_probs.numpy()[0]

    curr_stage_idx = int(np.argmax(curr_probs_np))
    next_stage_idx = int(np.argmax(next_probs_np))

    current_stage = STAGE_NAMES[curr_stage_idx]
    predicted_next_stage = STAGE_NAMES[next_stage_idx]
    confidence_val = float(next_probs_np[next_stage_idx])
    confidence_pct = int(round(confidence_val * 100))

    # Step 3: Anomaly intensity
    recent_flow_norm = float(np.mean(np.abs(seq_scaled[-1])))
    anomaly_intensity = min(1.0, recent_flow_norm / 4.0)

    # Step 4: Dynamic Risk Score
    risk_score, risk_level = risk_engine.compute_risk(
        current_stage=current_stage,
        predicted_next_stage=predicted_next_stage,
        confidence=confidence_val,
        anomaly_intensity=anomaly_intensity
    )

    # Step 5: SHAP feature attribution
    shap_results = shap_explainer.explain(
        input_sequence=seq_scaled,
        predicted_next_stage_idx=next_stage_idx,
        predicted_prob=confidence_val
    )

    top_feats = shap_results.get("feature_ranking", [])[:3]
    recommendation = risk_engine.get_recommendation(predicted_next_stage, top_features=top_feats)

    formatted_output = f"Current: {current_stage} → Predicted Next: {predicted_next_stage} → Confidence: {confidence_pct}% → Risk: {risk_level}"

    candidates = []
    for idx, name in enumerate(STAGE_NAMES):
        candidates.append({
            "stage": name,
            "probability": round(float(next_probs_np[idx]), 4),
            "percentage": int(round(float(next_probs_np[idx]) * 100))
        })
    candidates.sort(key=lambda c: c["probability"], reverse=True)

    result = {
        "prediction_available": True,
        "status": "VALID",
        "timestamp": timestamp_str,
        "formatted_output": formatted_output,
        "current_stage": current_stage,
        "current_stage_idx": curr_stage_idx,
        "predicted_next_stage": predicted_next_stage,
        "predicted_next_stage_idx": next_stage_idx,
        "confidence": confidence_pct,
        "confidence_raw": confidence_val,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "candidate_forecasts": candidates,
        "recommendation": recommendation,
        "shap": shap_results,
        "stages": STAGE_NAMES,
        "latest_features": {
            FEATURE_NAMES[i]: round(float(eval_window[-1, i]), 3)
            for i in range(num_features)
        }
    }

    session_forecast_history.append(result)
    if len(session_forecast_history) > 300:
        session_forecast_history.pop(0)

    return result


# =====================================================================
# API Endpoints: Capture Health & Diagnostics (Phase 4)
# =====================================================================

@app.get("/api/capture/health")
def get_capture_health():
    """
    Returns verified capture health diagnostics:
    - Capture backend and status
    - Active interface selection
    - Npcap DLL and driver installation status
    - Actual packet count (incremented only upon real frame arrival)
    - Last successfully captured packet timestamp
    - Actionable error and recovery guidance if capture failed
    """
    diag = check_npcap_diagnostics()
    status = capture_engine.get_status()

    return JSONResponse(content={
        "capture_status": status.get("capture_status"),
        "capture_mode": status.get("capture_mode"),
        "is_capturing": status.get("is_capturing"),
        "capture_backend": status.get("capture_backend"),
        "selected_interface": status.get("selected_interface"),
        "selected_interface_name": status.get("selected_interface_name"),
        "actual_packets_captured": status.get("actual_packets_captured", 0),
        "total_bytes": status.get("total_bytes", 0),
        "packet_rate": status.get("packet_rate", 0.0),
        "last_packet_timestamp": status.get("last_packet_timestamp") if status.get("actual_packets_captured", 0) > 0 else None,
        "last_error": status.get("last_error"),
        "recovery_instruction": status.get("recovery_instruction"),
        "npcap_diagnostics": diag
    })


class ModeSelectRequest(BaseModel):
    mode: str  # 'live', 'pcap', 'simulation', 'connection_metadata'
    interface_id: Optional[str] = None
    bpf_filter: Optional[str] = None
    pcap_path: Optional[str] = None


@app.post("/api/mode/select")
def select_operating_mode(req: ModeSelectRequest):
    """
    Switches system operating mode with explicit quarantine:
    - 'live': Real network packet sniffing on selected Windows interface
    - 'pcap': Offline historical PCAP dissection (requires valid file)
    - 'simulation': Isolated test simulation mode (explicitly labeled)
    - 'connection_metadata': Explicit OS socket connection poller (netstat)
    """
    valid_modes = ("live", "pcap", "simulation", "connection_metadata")
    mode = req.mode.strip().lower()
    if mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Unsupported mode '{req.mode}'. Valid modes: {valid_modes}")

    if req.interface_id:
        ifaces = get_network_interfaces()
        match = next((i for i in ifaces if i["id"] == req.interface_id or i["name"] == req.interface_id or i["guid"] == req.interface_id), None)
        if not match:
            raise HTTPException(status_code=400, detail=f"Invalid network interface: '{req.interface_id}'. Adapter not found on host.")

    # Stop current session before switching
    if capture_engine.is_capturing:
        capture_engine.stop_capture()

    # Clear current buffers and histories to maintain strict isolation
    capture_engine.clear_buffer()
    capture_engine.device_registry.clear(mode=mode)
    soc_manager.clear()
    session_forecast_history.clear()

    if mode == "pcap":
        if not req.pcap_path or not os.path.exists(req.pcap_path):
            raise HTTPException(status_code=400, detail=f"Valid PCAP file path is required for mode 'pcap'. Given: '{req.pcap_path}'")
        try:
            with open(req.pcap_path, "rb") as f:
                content = f.read()
            pkts = capture_engine.parse_pcap_bytes(content)
            return JSONResponse(content={
                "status": "started",
                "mode": "pcap",
                "packets_parsed": len(pkts),
                "file": os.path.basename(req.pcap_path)
            })
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to dissect PCAP file: {str(e)}")

    start_res = capture_engine.start_capture(
        mode=mode,
        interface_id=req.interface_id,
        bpf_filter=req.bpf_filter or ""
    )
    return JSONResponse(content=start_res)


class InterfaceSelectRequest(BaseModel):
    interface_id: str


@app.post("/api/capture/interface/select")
def select_network_interface(req: InterfaceSelectRequest):
    """
    Selects active network interface, validates against genuine host adapters,
    stops any capture on old interface, and resets buffers to avoid cross-adapter observation blending.
    """
    ifaces = get_network_interfaces()
    match = next((i for i in ifaces if i["id"] == req.interface_id or i["name"] == req.interface_id or i["guid"] == req.interface_id), None)
    if not match:
        raise HTTPException(status_code=400, detail=f"Invalid network interface '{req.interface_id}'. Adapter not found on host.")

    was_capturing = capture_engine.is_capturing
    if was_capturing:
        capture_engine.stop_capture()

    # Clear buffers so observations from different physical adapters are never blended
    capture_engine.clear_buffer()
    capture_engine.device_registry.clear(mode="live")
    soc_manager.clear()
    session_forecast_history.clear()

    res = capture_engine.set_interface(req.interface_id)
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))

    if was_capturing:
        start_res = capture_engine.start_capture(mode=capture_engine.capture_mode, interface_id=req.interface_id)
        return JSONResponse(content={"status": "restarted", "interface": match, "capture_status": start_res.get("capture_status")})

    return JSONResponse(content={"status": "selected", "interface": match, "capture_status": capture_engine.capture_status})


class CaptureStartRequest(BaseModel):
    mode: Optional[str] = "live"
    interface_id: Optional[str] = None
    bpf_filter: Optional[str] = None


@app.post("/api/capture/start")
def start_live_capture(req: Optional[CaptureStartRequest] = None):
    """Starts network capture in designated mode ('live' by default)."""
    mode = req.mode if req and req.mode else "live"
    iface = req.interface_id if req else None
    bpf = req.bpf_filter if req and req.bpf_filter else ""

    if iface:
        ifaces = get_network_interfaces()
        match = next((i for i in ifaces if i["id"] == iface or i["name"] == iface or i["guid"] == iface), None)
        if not match:
            raise HTTPException(status_code=400, detail=f"Invalid network interface: '{iface}'. Adapter not found on host.")

    status = capture_engine.start_capture(mode=mode, interface_id=iface, bpf_filter=bpf)
    return JSONResponse(content=status)


@app.post("/api/capture/stop")
def stop_live_capture():
    """Stops network capture gracefully."""
    status = capture_engine.stop_capture()
    return JSONResponse(content=status)


@app.post("/api/capture/clear")
def clear_live_capture():
    """Clears captured packet buffers, endpoint registry, and resets sliding flow sequence."""
    status = capture_engine.clear_buffer()
    capture_engine.device_registry.clear(mode=capture_engine.capture_mode)
    soc_manager.clear()
    session_forecast_history.clear()
    return JSONResponse(content=status)


@app.get("/api/capture/status")
def get_capture_status():
    """Returns real-time packet capture telemetry and engine state."""
    status = capture_engine.get_status()
    return JSONResponse(content=status)


@app.get("/api/capture/interfaces")
def get_interfaces():
    """
    Returns genuine host network interfaces enumerated with friendly names, IPs, MACs, and GUIDs.
    """
    ifaces = get_network_interfaces()
    return JSONResponse(content={"interfaces": ifaces, "count": len(ifaces)})


@app.get("/api/capture/feed")
def get_capture_feed(packet_count: int = 40):
    """
    Delivers:
    1. Real-time capture telemetry
    2. Latest verified captured packets with header dissection
    3. The sliding 10-step window and latest 12 feature values (or null if insufficient)
    4. Gated BiLSTM model assessment (marked unavailable if < 10 valid flows)
    """
    telemetry = capture_engine.get_status()
    recent_pkts = capture_engine.get_recent_packets(count=packet_count)
    window_seq = capture_engine.get_sliding_window()

    # Model inference is strictly gated behind data validation (real traffic gated per Phase G)
    prediction = process_sequence(window_seq, is_real_data=True)

    # Feature values of latest window slice (only if valid window exists)
    if window_seq is not None and len(window_seq) > 0:
        latest_feats = {
            FEATURE_NAMES[i]: round(float(window_seq[-1, i]), 3)
            for i in range(len(FEATURE_NAMES))
        }
    else:
        latest_feats = None

    return JSONResponse(content={
        "telemetry": telemetry,
        "recent_packets": recent_pkts,
        "latest_features": latest_feats,
        "prediction": prediction,
        "temporal_windows_count": len(capture_engine.temporal_windows)
    })


@app.post("/api/capture/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Dissects uploaded .pcap or .pcapng binary packet capture via streaming OfflinePcapProcessor,
    extracts packets, computes genuine 1-minute discrete temporal feature windows,
    registers the capture in data/captures/manifest.json, and reports truthful model readiness.
    """
    try:
        content = await file.read()
        os.makedirs(CAPTURES_DIR, exist_ok=True)
        safe_filename = os.path.basename(file.filename or "upload.pcap")
        save_path = os.path.join(CAPTURES_DIR, safe_filename)
        with open(save_path, "wb") as f:
            f.write(content)

        # Process through reusable OfflinePcapProcessor
        processor = OfflinePcapProcessor()
        parsed_metas, summary = processor.process_file(save_path)

        if summary.status == "ERROR":
            raise HTTPException(status_code=400, detail=f"Failed to process PCAP file: {summary.error_message}")

        # Register in capture dataset manifest
        register_capture(
            source=f"User Upload ({safe_filename})",
            filename=save_path,
            file_format=summary.format_detected,
            duration_seconds=summary.duration_seconds,
            packet_count=summary.successfully_parsed,
            total_bytes=summary.total_captured_bytes,
            timestamp_quality="VALID_TIMESTAMPS" if summary.invalid_timestamps == 0 else "PARTIAL_INVALID_TIMESTAMPS",
            parsing_status=summary.status
        )

        # Ingest into capture_engine
        parsed_pkts = capture_engine.parse_pcap_bytes(content)
        window_seq = capture_engine.get_sliding_window()
        prediction = process_sequence(window_seq, is_real_data=True)
        prediction["data_source"] = f"Uploaded PCAP: {safe_filename}"

        return JSONResponse(content={
            "filename": safe_filename,
            "packets_parsed": summary.successfully_parsed,
            "parsing_errors": summary.parsing_errors,
            "duration_seconds": summary.duration_seconds,
            "format_detected": summary.format_detected,
            "total_bytes": summary.total_captured_bytes,
            "temporal_windows_count": len(capture_engine.temporal_windows),
            "recent_packets": [p.to_dict() for p in reversed(parsed_pkts[:40])],
            "prediction": prediction
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse PCAP file: {str(e)}")


@app.post("/api/capture/load-sample-pcap")
def load_sample_pcap():
    """
    Loads pre-bundled sample attack PCAP file (with real Recon, Scan, Enum, Exploit, Intrusion packets),
    dissects frames, and runs the working model on it.
    """
    try:
        sample_path = os.path.join(BASE_DIR, "data", "sample_network_attack.pcap")
        if not os.path.exists(sample_path):
            generate_sample_attack_pcap(sample_path)

        with open(sample_path, "rb") as f:
            content = f.read()

        parsed_pkts = capture_engine.parse_pcap_bytes(content)
        window_seq = capture_engine.get_sliding_window()
        prediction = process_sequence(window_seq)
        prediction["data_source"] = "Pre-bundled Multi-Stage Attack PCAP"

        return JSONResponse(content={
            "filename": "sample_network_attack.pcap",
            "packets_parsed": len(parsed_pkts),
            "recent_packets": [p.to_dict() for p in reversed(parsed_pkts[:40])],
            "prediction": prediction
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load sample PCAP: {str(e)}")


class PingRequest(BaseModel):
    target: Optional[str] = "8.8.8.8"
    count: Optional[int] = 4


@app.post("/api/capture/inject-ping")
def inject_ping_post(req: Optional[PingRequest] = None):
    """
    Executes a real ping on the operating system and captures the resulting ICMP request & reply frames.
    """
    target = (req.target if req and req.target else "8.8.8.8").strip()
    count = req.count if req and req.count else 4
    pkts = capture_engine.inject_ping(target_host=target, count=count) if hasattr(capture_engine, "inject_ping") else []
    soc_manager.inject_live_ping_event(target, len(pkts))
    window_seq = capture_engine.get_sliding_window()
    prediction = process_sequence(window_seq)
    prediction["data_source"] = f"Live Host ICMP Ping to {target}"
    return JSONResponse(content={
        "target": target,
        "packets_injected": len(pkts),
        "recent_packets": [p.to_dict() for p in reversed(pkts)],
        "prediction": prediction
    })


@app.get("/api/capture/inject-ping")
def inject_ping_get(target: str = "8.8.8.8", count: int = 4):
    """Convenience GET endpoint to trigger real host ICMP ping."""
    pkts = capture_engine.inject_ping(target_host=target, count=count) if hasattr(capture_engine, "inject_ping") else []
    soc_manager.inject_live_ping_event(target, len(pkts))
    window_seq = capture_engine.get_sliding_window()
    prediction = process_sequence(window_seq)
    prediction["data_source"] = f"Live Host ICMP Ping to {target}"
    return JSONResponse(content={
        "target": target,
        "packets_injected": len(pkts),
        "recent_packets": [p.to_dict() for p in reversed(pkts)],
        "prediction": prediction
    })


# =====================================================================
# SOC Threat Visualization Dashboard APIs (Phase 4 Integration)
# =====================================================================

@app.get("/api/soc/overview")
def get_soc_overview():
    """
    Returns SOC high-level monitoring metrics:
    - Normal, Suspicious, Malicious traffic counters
    - Packet rate, bandwidth, active flows, uptime
    - Dynamic risk level, AI stage forecast, and confidence
    - Historical time-series traffic samples for interactive chart
    - Active security alert info
    """
    telemetry = capture_engine.get_status()
    window_seq = capture_engine.get_sliding_window()
    prediction = process_sequence(window_seq, is_real_data=True)

    soc_manager.tick_traffic(
        live_packet_count=telemetry.get("actual_packets_captured", telemetry.get("packet_counter", 0)),
        live_rate=telemetry.get("packet_rate", 0.0),
        latest_prediction=prediction,
        is_capturing=telemetry.get("is_capturing", False)
    )

    overview = soc_manager.get_traffic_overview(
        capture_status=telemetry,
        latest_prediction=prediction,
        registry=capture_engine.device_registry,
        mode=capture_engine.capture_mode
    )
    return JSONResponse(content=overview)


@app.get("/api/soc/topology")
def get_soc_topology():
    """
    Returns 3D network topology graph nodes and edges strictly derived from verified observations.
    """
    recent = capture_engine.get_recent_packets(count=25)
    recent_dicts = [p if isinstance(p, dict) else p.to_dict() for p in recent]
    topology = soc_manager.get_topology(
        recent_packets=recent_dicts,
        registry=capture_engine.device_registry,
        mode=capture_engine.capture_mode
    )
    topology["mode"] = capture_engine.capture_mode
    return JSONResponse(content=topology)


@app.get("/api/soc/devices")
def get_soc_devices(mode: Optional[str] = None):
    """
    Returns verified endpoint inventory from DeviceObservationRegistry for the selected mode.
    Exposes IP, MAC, source, first/last seen timestamps, and identity caveats.
    """
    target_mode = mode if mode else capture_engine.capture_mode
    devices = capture_engine.device_registry.get_devices(mode=target_mode)
    return JSONResponse(content={
        "count": len(devices),
        "mode": target_mode,
        "devices": devices
    })


@app.get("/api/soc/threat-logs")
def get_soc_threat_logs(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    mode: Optional[str] = None
):
    """
    Returns filtered cybersecurity threat event logs with investigation details.
    """
    target_mode = mode if mode else capture_engine.capture_mode
    logs = soc_manager.get_threat_logs(
        severity=severity,
        status=status,
        event_type=event_type,
        search=search,
        mode=target_mode
    )
    return JSONResponse(content={"count": len(logs), "logs": logs})


class ThreatLogStatusUpdate(BaseModel):
    status: str


@app.post("/api/soc/threat-logs/{log_id}/status")
def update_threat_log_status(log_id: str, req: ThreatLogStatusUpdate):
    """
    Updates investigation status of an alert or threat event log (New, Acknowledged, Investigating, Resolved).
    """
    updated = soc_manager.update_log_status(log_id, req.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Log entry not found or invalid status")
    return JSONResponse(content={"status": "success", "log": updated})


class ForecastRequest(BaseModel):
    sequence: Optional[List[List[float]]] = None


@app.post("/api/forecast")
def get_forecast(req: Optional[ForecastRequest] = None):
    """
    Computes attack stage forecast and attribution for an input sequence.
    Strictly gates execution: returns prediction_available=False if fewer than 10 steps exist.
    """
    if req and req.sequence:
        seq = np.array(req.sequence, dtype=np.float32)
    else:
        seq = capture_engine.get_sliding_window()

    result = process_sequence(seq)
    return JSONResponse(content=result)


@app.get("/api/stream")
def get_stream_step():
    """
    Delivers the next flow sequence in the timeline for testing transitions.
    """
    window_seq = capture_engine.get_sliding_window()
    result = process_sequence(window_seq)
    return JSONResponse(content=result)


@app.get("/api/ingest-real")
def ingest_real_csv():
    """
    Parses sample CICIDS2017 flow CSV records, runs inference across all sliding windows,
    and returns window-by-window forecasting results.
    """
    csv_path = os.path.join(BASE_DIR, "data", "sample_cicids2017.csv")
    if not os.path.exists(csv_path):
        raise HTTPException(status_code=404, detail="sample_cicids2017.csv not found")

    sequences = real_flow_loader.extract_sequences(csv_path)
    window_results = []
    for seq in sequences:
        res = process_sequence(seq)
        window_results.append(res)

    last_res = window_results[-1] if window_results else process_sequence(None)
    response_data = dict(last_res)
    response_data["data_source"] = "CICIDS2017 Sample Flow CSV"
    response_data["windows"] = window_results
    response_data["window_count"] = len(window_results)
    return JSONResponse(content=response_data)


@app.get("/api/export-xlsx")
def export_xlsx():
    """
    Exports in-memory forecast history into a formatted Excel sheet with colored risk levels.
    """
    excel_bytes = export_forecasts_to_bytes(session_forecast_history)
    filename = f"attack_forecast_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return Response(
        content=excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )



@app.get("/api/capture/temporal-windows")
def get_temporal_windows():
    """
    Returns genuine 1-minute discrete temporal feature windows computed from observed traffic.
    Includes feature schema, mathematical definitions, units, and aggregation health.
    """
    windows = capture_engine.get_temporal_windows()
    return JSONResponse(content={
        "feature_schema": AGGREGATION_FEATURE_NAMES,
        "aggregation_interval_seconds": 60.0,
        "total_windows": len(windows),
        "windows": windows,
        "missing_value_policy": "Zero observations during active capture are recorded with is_empty=True; capture outages are recorded as gaps.",
        "model_readiness": "FORECASTING MODEL NOT VALIDATED FOR THIS DATA"
    })


@app.get("/api/captures/manifest")
def get_capture_manifest():
    """Returns the capture dataset manifest recording metadata for all imported captures."""
    manifest = load_manifest()
    return JSONResponse(content={"total_captures": len(manifest), "captures": manifest})


# ============================================================================
# EXPERIMENTAL REAL-DATA TEMPORAL FORECASTING ENDPOINTS (Phase 9C)
# ============================================================================
_temporal_forecaster = None
_temporal_forecaster_failed: bool = False
_temporal_forecaster_error: Optional[str] = None

def get_temporal_forecaster(force_reload: bool = False):
    global _temporal_forecaster, _temporal_forecaster_failed, _temporal_forecaster_error
    if force_reload:
        _temporal_forecaster = None
        _temporal_forecaster_failed = False
        _temporal_forecaster_error = None

    if _temporal_forecaster is None and not _temporal_forecaster_failed:
        try:
            from models.temporal_forecasting import TemporalAttackForecaster
            _temporal_forecaster = TemporalAttackForecaster()
            _temporal_forecaster_error = None
        except Exception as e:
            logger.warning(f"Failed to load experimental temporal forecaster: {e}")
            _temporal_forecaster = None
            _temporal_forecaster_failed = True
            _temporal_forecaster_error = str(e)
    return _temporal_forecaster


@app.get("/api/forecast/temporal-experimental/metadata")
def get_temporal_experimental_metadata():
    """Returns provenance, target definition, feature schema, and evaluation metrics for Phase 9C model."""
    forecaster = get_temporal_forecaster()
    if forecaster is None:
        diag = _temporal_forecaster_error or "Artifacts missing or uninitialized"
        return JSONResponse(
            status_code=503,
            content={
                "error": "Experimental temporal forecasting model not available.",
                "diagnostic": diag
            }
        )
    return JSONResponse(content=forecaster.get_metadata())


@app.post("/api/forecast/temporal-experimental")
async def predict_temporal_experimental(request: Request):
    """
    Evaluates real-data Target A attack onset forecast for a 120-dim flow-feature sequence.
    Strictly validates feature schema, rejects incompatible packet-layer features,
    and enforces finite threshold bounds [0.0, 1.0].
    """
    forecaster = get_temporal_forecaster()
    if forecaster is None:
        diag = _temporal_forecaster_error or "Model uninitialized or failed to load"
        return JSONResponse(
            status_code=503,
            content={
                "error": "Experimental temporal forecasting model not available.",
                "diagnostic": diag
            }
        )
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Expected JSON object body"})

    features = body.get("features")
    if features is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'features' key in payload"})

    raw_thresh = body.get("threshold", 0.5)
    try:
        if raw_thresh is None or isinstance(raw_thresh, (list, dict)):
            raise ValueError("Threshold must be a scalar numeric value.")
        threshold = float(raw_thresh)
        if math.isnan(threshold) or math.isinf(threshold):
            raise ValueError("Threshold cannot be NaN or Infinite.")
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(f"Threshold {threshold} out of supported range [0.0, 1.0].")
    except (ValueError, TypeError) as e:
        return JSONResponse(status_code=422, content={"error": f"Invalid threshold: {e}"})

    try:
        result = forecaster.predict(features, threshold=threshold)
        return JSONResponse(content=result)
    except ValueError as ve:
        return JSONResponse(status_code=422, content={"error": str(ve)})
    except Exception as e:
        logger.error(f"Prediction execution failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Forecasting inference failed."})


@app.get("/api/forecast/temporal-experimental/sample-windows")
def get_temporal_sample_windows():
    """Returns curated genuine Target A test windows from Phase 9C benchmark."""
    sample_path = os.path.join(BASE_DIR, "data", "benchmark", "temporal", "phase9c", "sample_windows.json")
    if not os.path.exists(sample_path):
        return JSONResponse(status_code=404, content={"error": "Sample windows not found."})
    with open(sample_path, "r") as fp:
        samples = json.load(fp)
    return JSONResponse(content={"total_samples": len(samples), "samples": samples})


static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
def serve_dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))
