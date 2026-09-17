"""
FastAPI Server for Network Attack Forecasting System (SIH26153)
Exposes strictly:
- POST /api/forecast : Computes forecast, risk, and SHAP attribution for a flow sequence
- GET  /api/stream   : Chronological multi-stage attack stream delivering sequential flow windows
- GET  /             : Serves the analyst security dashboard UI
"""

import os
import sys
import pickle
from datetime import datetime
import numpy as np
import torch
from fastapi import FastAPI, HTTPException, UploadFile, File, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Ensure project root is in sys.path for serverless and package imports
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
from models.attack_forecaster import AttackForecasterBiLSTM
from models.risk_engine import DynamicRiskEngine
from models.shap_explainer import AttackForecasterSHAPExplainer

app = FastAPI(title="AI-Based Network Attack Forecasting System", version="1.0")

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

# Simulated multi-stage attack live timeline generator for /api/stream
class LiveAttackTimelineStream:
    """Maintains an ongoing balanced multi-stage attack timeline sequence."""
    def __init__(self, sequence_length: int = 10, steps_per_stage: int = 8):
        self.sequence_length = sequence_length
        self.steps_per_stage = steps_per_stage
        self.reset()

    def reset(self):
        self.timeline = generate_balanced_attack_timeline(
            steps_per_stage=self.steps_per_stage,
            warmup_steps=self.sequence_length - 1
        )
        self.current_step = self.sequence_length

    def next_window(self) -> np.ndarray:
        if self.current_step > len(self.timeline):
            self.reset()
            
        window = self.timeline[self.current_step - self.sequence_length : self.current_step]
        self.current_step += 1
        features_seq = np.array([ev["features"] for ev in window], dtype=np.float32)
        return features_seq

live_stream = LiveAttackTimelineStream(sequence_length=10, steps_per_stage=8)


def process_sequence(seq_features: np.ndarray) -> Dict[str, Any]:
    """
    Executes Steps 1-5 of the pipeline on a [seq_len, 12] sequence.
    """
    seq_len, num_features = seq_features.shape
    
    # Scale features
    seq_scaled = scaler.transform(seq_features)
    x_tensor = torch.tensor(seq_scaled[np.newaxis, :, :], dtype=torch.float32)
    
    # Step 3 & 4: Model classification & probabilistic next-stage forecast
    curr_probs, next_probs = model.predict_probabilities(x_tensor)
    curr_probs_np = curr_probs.numpy()[0]
    next_probs_np = next_probs.numpy()[0]
    
    curr_stage_idx = int(np.argmax(curr_probs_np))
    next_stage_idx = int(np.argmax(next_probs_np))
    
    current_stage = STAGE_NAMES[curr_stage_idx]
    predicted_next_stage = STAGE_NAMES[next_stage_idx]
    confidence_val = float(next_probs_np[next_stage_idx])
    confidence_pct = int(round(confidence_val * 100))
    
    # Behavioral anomaly intensity based on deviation in recent flow
    recent_flow_norm = float(np.mean(np.abs(seq_scaled[-1])))
    anomaly_intensity = min(1.0, recent_flow_norm / 4.0)
    
    # Step 5: Dynamic Risk Score
    risk_score, risk_level = risk_engine.compute_risk(
        current_stage=current_stage,
        predicted_next_stage=predicted_next_stage,
        confidence=confidence_val,
        anomaly_intensity=anomaly_intensity
    )
    
    # SHAP feature attribution via GradientExplainer
    shap_results = shap_explainer.explain(
        input_sequence=seq_scaled,
        predicted_next_stage_idx=next_stage_idx,
        predicted_prob=confidence_val
    )
    
    # Preventive recommendation for analyst review (using top SHAP features for rationales)
    top_feats = shap_results.get("feature_ranking", [])[:3]
    recommendation = risk_engine.get_recommendation(predicted_next_stage, top_features=top_feats)
    
    # Exact required output format string
    # e.g.: Current: Scanning → Predicted Next: Enumeration → Confidence: 87% → Risk: HIGH
    formatted_output = f"Current: {current_stage} → Predicted Next: {predicted_next_stage} → Confidence: {confidence_pct}% → Risk: {risk_level}"
    
    # Stage candidate forecast distribution
    candidates = []
    for idx, name in enumerate(STAGE_NAMES):
        candidates.append({
            "stage": name,
            "probability": round(float(next_probs_np[idx]), 4),
            "percentage": int(round(float(next_probs_np[idx]) * 100))
        })
    candidates.sort(key=lambda c: c["probability"], reverse=True)
    
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    result = {
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
            FEATURE_NAMES[i]: round(float(seq_features[-1, i]), 3)
            for i in range(num_features)
        }
    }
    
    # Track in session history (keep up to 300 entries)
    session_forecast_history.append(result)
    if len(session_forecast_history) > 300:
        session_forecast_history.pop(0)
        
    return result


class ForecastRequest(BaseModel):
    sequence: Optional[List[List[float]]] = None


@app.post("/api/forecast")
def get_forecast(req: Optional[ForecastRequest] = None):
    """
    Computes attack stage forecast and attribution for an input sequence
    or uses an active window if none provided.
    """
    if req and req.sequence and len(req.sequence) >= 5:
        seq = np.array(req.sequence, dtype=np.float32)
        if seq.shape[1] != len(FEATURE_NAMES):
            raise HTTPException(status_code=400, detail=f"Expected {len(FEATURE_NAMES)} features per flow step.")
    else:
        seq = live_stream.next_window()
        
    result = process_sequence(seq)
    return JSONResponse(content=result)


@app.get("/api/stream")
def get_stream_step():
    """
    Delivers the next chronological flow sequence in the multi-stage attack timeline.
    Drives dashboard real-time transition animations.
    """
    seq = live_stream.next_window()
    result = process_sequence(seq)
    return JSONResponse(content=result)


class RealCICIDSStreamer:
    """Maintains sequential window streaming through real CICIDS CSV flows."""
    def __init__(self):
        self.seqs = None
        self.idx = 0
        
    def load(self, path: str):
        self.seqs = real_flow_loader.extract_sequences(path)
        self.idx = 0
        
    def next_window(self):
        if self.seqs is None or len(self.seqs) == 0:
            path = os.path.join(BASE_DIR, "data", "sample_cicids2017.csv")
            self.load(path)
        window = self.seqs[self.idx]
        self.idx = (self.idx + 1) % len(self.seqs)
        return window

real_streamer = RealCICIDSStreamer()


@app.post("/api/ingest-real")
async def ingest_real(file: Optional[UploadFile] = File(None), file_path: Optional[str] = None):
    """
    Ingests actual CICIDS2017/2018 CSV flow records from uploaded file or local path,
    walks through sequential T=10 sliding windows, and emits one forecast per window in order.
    """
    try:
        if file and file.filename:
            content = await file.read()
            seqs = real_flow_loader.extract_sequences(content)
        else:
            path = file_path or os.path.join(BASE_DIR, "data", "sample_cicids2017.csv")
            if not os.path.exists(path):
                raise HTTPException(status_code=404, detail=f"CICIDS CSV file not found: {path}")
            seqs = real_flow_loader.extract_sequences(path)
            
        windows_results = []
        for seq in seqs:
            w_res = process_sequence(seq)
            w_res["data_source"] = "CICIDS2017 Real Traffic Flow"
            windows_results.append(w_res)
            
        # Top-level contains windows list, plus the active window
        response_payload = {
            "window_count": len(windows_results),
            "windows": windows_results,
            **windows_results[0]
        }
        return JSONResponse(content=response_payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to ingest real flow data: {str(e)}")


@app.get("/api/ingest-real")
def ingest_real_get(file_path: Optional[str] = None):
    """
    Convenience GET endpoint to trigger windowed sequential ingestion of sample or specified CICIDS CSV.
    """
    try:
        path = file_path or os.path.join(BASE_DIR, "data", "sample_cicids2017.csv")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail=f"CICIDS CSV file not found: {path}")
        seqs = real_flow_loader.extract_sequences(path)
        
        windows_results = []
        for seq in seqs:
            w_res = process_sequence(seq)
            w_res["data_source"] = "CICIDS2017 Real Traffic Flow"
            windows_results.append(w_res)
            
        response_payload = {
            "window_count": len(windows_results),
            "windows": windows_results,
            **windows_results[0]
        }
        return JSONResponse(content=response_payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to ingest real flow data: {str(e)}")


@app.get("/api/ingest-real-stream")
def ingest_real_stream():
    """
    Delivers the next chronological real CICIDS window step to drive streaming animations.
    """
    seq = real_streamer.next_window()
    res = process_sequence(seq)
    res["data_source"] = "CICIDS2017 Real Traffic Flow"
    return JSONResponse(content=res)


class ExportRequest(BaseModel):
    history: Optional[List[Dict[str, Any]]] = None


@app.post("/api/export-xlsx")
def export_xlsx_post(req: Optional[ExportRequest] = None):
    """
    Generates and returns a professionally styled .xlsx workbook containing
    all forecast records with SHAP attributions and recommended defenses.
    """
    records = (req.history if req and req.history else None) or session_forecast_history
    if not records:
        # If no history accumulated yet, generate current active forecast
        seq = live_stream.next_window()
        records = [process_sequence(seq)]
        
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"attack_forecast_export_{timestamp_file}.xlsx"
    xlsx_bytes = export_forecasts_to_bytes(records)
    
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )


@app.get("/api/export-xlsx")
def export_xlsx_get():
    """
    GET endpoint to download an Excel export of the current session forecast history.
    """
    records = session_forecast_history
    if not records:
        seq = live_stream.next_window()
        records = [process_sequence(seq)]
        
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"attack_forecast_export_{timestamp_file}.xlsx"
    xlsx_bytes = export_forecasts_to_bytes(records)
    
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )


# Mount static directory for dashboard UI
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
def serve_dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))
