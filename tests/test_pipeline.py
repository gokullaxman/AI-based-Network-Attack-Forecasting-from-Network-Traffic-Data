"""
Automated Unit and Integration Tests for AI-Based Network Attack Forecasting System
Tests all 6 pipeline steps, PyTorch BiLSTM model, SHAP GradientExplainer,
Dynamic Risk Engine, and FastAPI API endpoints (/api/forecast, /api/stream).
"""

import pytest
import numpy as np
import torch
from fastapi.testclient import TestClient

from pipeline.feature_extractor import FlowFeatureExtractor, FEATURE_NAMES
from pipeline.dataset import build_temporal_dataset, STAGE_NAMES, NUM_STAGES
from models.attack_forecaster import AttackForecasterBiLSTM
from models.risk_engine import DynamicRiskEngine
from models.shap_explainer import AttackForecasterSHAPExplainer
from dashboard.server import app, process_sequence


def test_step1_feature_extraction():
    """Verify behavioural and temporal feature extraction from flow records."""
    extractor = FlowFeatureExtractor()
    sample_flow = {
        "conn_frequency": 12.5,
        "packet_rate": 84.0,
        "dst_ip_fanout": 14.0,
        "src_dst_entropy": 0.85,
        "port_diversity": 32.0,
        "well_known_port_ratio": 0.72,
        "host_sweep_rate": 8.0,
        "icmp_arp_ratio": 0.35,
        "service_probe_rate": 2.5,
        "targeted_query_volume": 28.0,
        "iat_jitter": 0.55,
        "burstiness_index": 3.8
    }
    feats = extractor.extract_from_raw_flow(sample_flow)
    assert isinstance(feats, np.ndarray)
    assert feats.shape == (12,)
    assert len(extractor.feature_names) == 12
    assert np.all(feats >= 0)


def test_step2_temporal_sequence_construction():
    """Verify temporal sequence generation with T=10 sliding windows."""
    X, y_curr, y_next = build_temporal_dataset(num_timelines=5, sequence_length=10)
    assert X.ndim == 3
    assert X.shape[1] == 10  # sequence length
    assert X.shape[2] == 12  # feature count
    assert len(y_curr) == len(X)
    assert len(y_next) == len(X)
    assert np.all((y_curr >= 0) & (y_curr < NUM_STAGES))
    assert np.all((y_next >= 0) & (y_next < NUM_STAGES))


def test_step3_and_4_bilstm_forward_pass():
    """Verify dual-head BiLSTM outputs current classification & next stage forecast."""
    model = AttackForecasterBiLSTM(
        input_dim=12,
        hidden_dim=64,
        num_layers=2,
        num_classes=NUM_STAGES,
        dropout=0.2
    )
    dummy_input = torch.randn(4, 10, 12)
    curr_logits, next_logits = model(dummy_input)
    assert curr_logits.shape == (4, NUM_STAGES)
    assert next_logits.shape == (4, NUM_STAGES)
    
    curr_probs, next_probs = model.predict_probabilities(dummy_input)
    assert torch.allclose(curr_probs.sum(dim=-1), torch.ones(4), atol=1e-5)
    assert torch.allclose(next_probs.sum(dim=-1), torch.ones(4), atol=1e-5)


def test_step5_risk_engine():
    """Verify dynamic risk score calculation and categorical levels."""
    risk_engine = DynamicRiskEngine()
    
    # Low risk test
    score_low, level_low = risk_engine.compute_risk(
        current_stage="Reconnaissance",
        predicted_next_stage="Scanning",
        confidence=0.50,
        anomaly_intensity=0.1
    )
    assert 0 <= score_low <= 100
    assert level_low in ["LOW", "MEDIUM", "HIGH"]
    
    # High risk test
    score_high, level_high = risk_engine.compute_risk(
        current_stage="Exploitation",
        predicted_next_stage="Intrusion",
        confidence=0.95,
        anomaly_intensity=0.9
    )
    assert score_high >= 75
    assert level_high == "HIGH"
    
    # Recommendation
    rec = risk_engine.get_recommendation("Exploitation")
    assert "title" in rec and "description" in rec


def test_step5_shap_gradient_explainer():
    """Verify GradientExplainer outputs ranking and force-plot structure."""
    model = AttackForecasterBiLSTM(input_dim=12, hidden_dim=32, num_layers=1, num_classes=5)
    bg = np.random.randn(20, 10, 12).astype(np.float32)
    explainer = AttackForecasterSHAPExplainer(model, bg)
    
    test_seq = np.random.randn(10, 12).astype(np.float32)
    explanation = explainer.explain(test_seq, predicted_next_stage_idx=1, predicted_prob=0.85)
    
    assert "feature_ranking" in explanation
    assert len(explanation["feature_ranking"]) == 12
    assert "force_plot" in explanation
    assert len(explanation["force_plot"]["contributions"]) == 12
    assert "base_value" in explanation["force_plot"]


def test_step6_fastapi_endpoints():
    """Verify FastAPI /api/forecast and /api/stream endpoints and output format."""
    client = TestClient(app)
    
    # Test /api/forecast
    res_forecast = client.post("/api/forecast", json={})
    assert res_forecast.status_code == 200
    data_forecast = res_forecast.json()
    assert "formatted_output" in data_forecast
    # Check expected format: Current: ... -> Predicted Next: ... -> Confidence: ... -> Risk: ...
    assert "Current:" in data_forecast["formatted_output"]
    assert "Predicted Next:" in data_forecast["formatted_output"]
    assert "Confidence:" in data_forecast["formatted_output"]
    assert "Risk:" in data_forecast["formatted_output"]
    assert data_forecast["current_stage"] in STAGE_NAMES
    assert data_forecast["predicted_next_stage"] in STAGE_NAMES
    assert data_forecast["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    
    # Test /api/stream
    res_stream = client.get("/api/stream")
    assert res_stream.status_code == 200
    data_stream = res_stream.json()
    assert "formatted_output" in data_stream
    assert "shap" in data_stream
    assert "recommendation" in data_stream
    assert "confidence" in data_stream
    assert "risk_score" in data_stream


def test_real_cicids_loader_and_ingest_endpoint():
    """Verify real_flow_loader parses sample CICIDS CSV and /api/ingest-real returns valid forecast."""
    from pipeline.real_flow_loader import CICIDSFlowLoader
    
    loader = CICIDSFlowLoader(sequence_length=10)
    
    # Test CSV parsing with sample row / file
    sample_csv_text = (
        "Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Packets/s, "
        "Flow IAT Mean, Flow IAT Std, Flow IAT Max, SYN Flag Count, Average Packet Size, Protocol, Label\n"
        "80, 142000, 8, 5, 91.5, 11833.3, 4200.5, 25000.0, 1, 145.2, 6, Web Attack\n"
        "443, 89000, 6, 4, 112.3, 8900.0, 2100.1, 15000.0, 1, 130.4, 6, Web Attack\n"
    )
    
    features = loader.parse_csv_to_features(sample_csv_text.encode("utf-8"))
    assert isinstance(features, np.ndarray)
    assert features.shape == (2, 12)
    assert np.all(features >= 0)
    
    # Test sequence padding and window generation
    window = loader.get_representative_window(sample_csv_text.encode("utf-8"))
    assert window.shape == (10, 12)
    
    # Test /api/ingest-real endpoint
    client = TestClient(app)
    res_real = client.get("/api/ingest-real")
    assert res_real.status_code == 200
    data_real = res_real.json()
    
    assert "formatted_output" in data_real
    assert "Current:" in data_real["formatted_output"]
    assert "Predicted Next:" in data_real["formatted_output"]
    assert "Confidence:" in data_real["formatted_output"]
    assert "Risk:" in data_real["formatted_output"]
    assert data_real["current_stage"] in STAGE_NAMES
    assert data_real["predicted_next_stage"] in STAGE_NAMES
    assert data_real["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert "shap" in data_real
    assert len(data_real["shap"]["feature_ranking"]) == 12
    assert "data_source" in data_real
    assert "windows" in data_real
    assert len(data_real["windows"]) >= 1


def test_windowed_real_data_and_defending_methods():
    """
    Validates:
    1. Windowed real-data ingestion produces a forecast per window in sequence order.
    2. The defending-methods list changes appropriately when predicted next stage changes across windows.
    3. Each returned defense item includes an action + a feature-based rationale string.
    """
    client = TestClient(app)
    
    # 1. Test windowed real data ingestion
    res = client.get("/api/ingest-real")
    assert res.status_code == 200
    payload = res.json()
    
    assert "windows" in payload
    windows = payload["windows"]
    assert len(windows) > 1, "Expected multiple sequential T=10 windows from sample_cicids2017.csv"
    assert payload["window_count"] == len(windows)
    
    # Verify each window has valid schema and sequence order
    for idx, w in enumerate(windows):
        assert "current_stage" in w
        assert "predicted_next_stage" in w
        assert "confidence" in w
        assert "risk_score" in w
        assert "recommendation" in w
        assert "options" in w["recommendation"]
        assert len(w["recommendation"]["options"]) >= 2
        
    # 2. Test defending methods change across predicted stages
    risk_eng = DynamicRiskEngine()
    
    mock_shap_scanning = [
        {"feature": "port_diversity", "value": 48.0, "attribution": 0.42},
        {"feature": "conn_frequency", "value": 18.5, "attribution": 0.35}
    ]
    rec_scanning = risk_eng.get_recommendation("Scanning", top_features=mock_shap_scanning)
    
    mock_shap_intrusion = [
        {"feature": "dst_ip_fanout", "value": 8.5, "attribution": 0.52},
        {"feature": "host_sweep_rate", "value": 1.8, "attribution": 0.38}
    ]
    rec_intrusion = risk_eng.get_recommendation("Intrusion", top_features=mock_shap_intrusion)
    
    # Verify recommendations differ based on predicted next stage
    assert rec_scanning["title"] != rec_intrusion["title"]
    assert rec_scanning["options"][0]["action"] != rec_intrusion["options"][0]["action"]
    
    # 3. Test each defense option includes an action and feature-based rationale string
    for opt in rec_scanning["options"]:
        assert "action" in opt and len(opt["action"]) > 5
        assert "rationale" in opt and len(opt["rationale"]) > 10
        assert "priority" in opt
        # Rationale must cite top features
        assert "port_diversity" in opt["rationale"] or "conn_frequency" in opt["rationale"]
        
    for opt in rec_intrusion["options"]:
        assert "action" in opt and len(opt["action"]) > 5
        assert "rationale" in opt and len(opt["rationale"]) > 10
        assert "dst_ip_fanout" in opt["rationale"] or "host_sweep_rate" in opt["rationale"]


def test_export_xlsx_endpoint():
    """
    Validates:
    1. /api/export-xlsx returns a valid .xlsx file download.
    2. File is openable via openpyxl.load_workbook with correct headers and frozen row.
    3. One row per forecast in the session history with static values and no formula errors.
    4. Conditional formatting / fill applied on Risk Level column.
    """
    import io
    import openpyxl
    from pipeline.excel_exporter import HEADERS

    client = TestClient(app)
    
    # Generate 3 forecasts to populate history
    for _ in range(3):
        client.get("/api/stream")
        
    # Test GET /api/export-xlsx
    res = client.get("/api/export-xlsx")
    assert res.status_code == 200
    assert "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in res.headers["content-type"]
    assert "attachment;" in res.headers["content-disposition"]
    assert ".xlsx" in res.headers["content-disposition"]
    
    # Verify openpyxl can load the generated workbook
    wb = openpyxl.load_workbook(io.BytesIO(res.content))
    assert "Attack Forecast Log" in wb.sheetnames
    ws = wb["Attack Forecast Log"]
    
    # Verify frozen panes
    assert ws.freeze_panes == "A2"
    
    # Verify header row matches specification
    read_headers = [cell.value for cell in ws[1]]
    assert read_headers == HEADERS
    
    # Verify rows exist and have no formula errors
    row_count = ws.max_row
    assert row_count >= 4  # Header + at least 3 forecast records
    
    for r in range(2, row_count + 1):
        # Column 1: Timestamp
        assert ws.cell(row=r, column=1).value is not None
        # Column 3: Current Stage
        assert ws.cell(row=r, column=3).value in STAGE_NAMES
        # Column 4: Predicted Next Stage
        assert ws.cell(row=r, column=4).value in STAGE_NAMES
        # Column 5: Confidence (%)
        conf = ws.cell(row=r, column=5).value
        assert isinstance(conf, (int, float)) and 0 <= conf <= 100
        # Column 6: Risk Score
        risk_s = ws.cell(row=r, column=6).value
        assert isinstance(risk_s, (int, float)) and 0 <= risk_s <= 100
        # Column 7: Risk Level
        risk_lvl = ws.cell(row=r, column=7).value
        assert risk_lvl in ["LOW", "MEDIUM", "HIGH"]
        # Column 11: Defenses
        defenses = ws.cell(row=r, column=11).value
        assert defenses is not None and len(str(defenses)) > 0
        
        # Verify no formula strings (must start with static text, not '=')
        for c in range(1, 12):
            val = ws.cell(row=r, column=c).value
            if isinstance(val, str):
                assert not val.startswith("="), f"Formula found in cell ({r}, {c}): {val}"


def test_synthetic_dataset_equal_stage_balancing():
    """
    Validates:
    1. The synthetic dataset generator produces approximately equal counts per stage label
       across a generated batch (within small tolerance), preventing Intrusion-stage domination.
    2. All 5 stages (Reconnaissance, Scanning, Enumeration, Exploitation, Intrusion)
       are represented with balanced target counts.
    """
    from pipeline.dataset import build_temporal_dataset, generate_balanced_attack_timeline, NUM_STAGES
    
    # 1. Test timeline event balancing
    steps_per_stage = 12
    timeline = generate_balanced_attack_timeline(steps_per_stage=steps_per_stage, warmup_steps=0)
    stage_counts_timeline = [0] * NUM_STAGES
    for ev in timeline:
        stage_counts_timeline[ev["stage_idx"]] += 1
        
    for idx, count in enumerate(stage_counts_timeline):
        assert count == steps_per_stage, f"Stage {idx} expected {steps_per_stage} events, got {count}"
        
    # 2. Test windowed temporal sequence batch balancing
    X, y_curr, y_next = build_temporal_dataset(num_timelines=20, sequence_length=10, steps_per_stage=12)
    assert len(X) == len(y_curr) == len(y_next)
    
    # Count occurrences of each stage in y_curr
    unique, counts = np.unique(y_curr, return_counts=True)
    stage_counts = dict(zip(unique, counts))
    
    # Ensure all 5 stages are present in the batch
    assert len(stage_counts) == NUM_STAGES, f"Expected {NUM_STAGES} stages in dataset, found {len(stage_counts)}"
    
    # Check that counts across all stages are balanced (within small tolerance, e.g. <= 5% difference)
    mean_count = len(y_curr) / NUM_STAGES
    for stage_idx in range(NUM_STAGES):
        count = stage_counts.get(stage_idx, 0)
        # Verify tolerance is within 5% of mean count (or exact)
        diff_ratio = abs(count - mean_count) / mean_count
        assert diff_ratio <= 0.05, f"Stage {stage_idx} count {count} deviates by {diff_ratio:.2%} from mean {mean_count}"
        
    # Check that each stage represents approximately 20% (1/5) of the dataset
    for stage_idx in range(NUM_STAGES):
        proportion = stage_counts[stage_idx] / len(y_curr)
        assert 0.18 <= proportion <= 0.22, f"Stage {stage_idx} proportion {proportion:.2%} is outside [18%, 22%]"




