"""
Pipeline Step 5: SHAP Explainability Engine using PyTorch GradientExplainer
Computes feature attributions explaining the probabilistic next-stage forecast.
Outputs:
1. Feature attribution ranking (mean absolute gradient attribution per behavioural feature)
2. Force-plot-style attribution data (base value, output value, directional positive/negative contributions)
"""

import torch
import numpy as np
import shap
from typing import Dict, List, Any
from pipeline.feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS
from .attack_forecaster import AttackForecasterBiLSTM, NextStageForecasterWrapper


class AttackForecasterSHAPExplainer:
    """Explains Next-Stage Forecasting predictions using shap.GradientExplainer."""

    def __init__(self, model: AttackForecasterBiLSTM, background_data: np.ndarray):
        """
        model: Trained AttackForecasterBiLSTM
        background_data: numpy array [N, seq_len, num_features] of reference baseline flows
        """
        self.model = model
        self.wrapper = NextStageForecasterWrapper(model)
        self.wrapper.eval()
        
        # Take a subset of background flows (e.g. 40 samples) for fast, stable gradient baseline
        n_samples = min(40, len(background_data))
        bg_subset = torch.tensor(background_data[:n_samples], dtype=torch.float32)
        
        # Initialize GradientExplainer on PyTorch wrapper model
        self.explainer = shap.GradientExplainer(self.wrapper, bg_subset)
        self.feature_names = FEATURE_NAMES
        self.feature_descriptions = FEATURE_DESCRIPTIONS

    def explain(
        self,
        input_sequence: np.ndarray,
        predicted_next_stage_idx: int,
        predicted_prob: float
    ) -> Dict[str, Any]:
        """
        input_sequence: [seq_len, num_features] or [1, seq_len, num_features]
        predicted_next_stage_idx: index of forecasted stage (0 to 4)
        predicted_prob: confidence of forecast
        
        Returns dictionary with:
        - feature_ranking: list of features sorted by attribution magnitude
        - force_plot_data: base_value, target_value, feature contributions
        """
        if input_sequence.ndim == 2:
            input_tensor = torch.tensor(input_sequence[np.newaxis, :, :], dtype=torch.float32)
        else:
            input_tensor = torch.tensor(input_sequence, dtype=torch.float32)

        # Compute SHAP values via GradientExplainer
        # Output is either list of arrays [num_classes] or [1, seq_len, num_features, num_classes]
        shap_raw = self.explainer.shap_values(input_tensor)
        
        if isinstance(shap_raw, list):
            class_shap = shap_raw[predicted_next_stage_idx]  # shape: [1, seq_len, num_features]
        elif isinstance(shap_raw, np.ndarray) and shap_raw.ndim == 4:
            class_shap = shap_raw[0, :, :, predicted_next_stage_idx]  # shape: [seq_len, num_features]
        else:
            class_shap = np.array(shap_raw)[0]
            
        if class_shap.ndim == 3:
            class_shap = class_shap[0]  # [seq_len, num_features]
            
        # Aggregate across temporal sequence (time steps) to get net feature attribution
        # Temporal mean across sequence steps
        feature_attributions = np.mean(class_shap, axis=0)  # [num_features]
        
        # Latest observation values for reference in force plot
        current_feature_values = input_sequence[-1] if input_sequence.ndim == 2 else input_sequence[0, -1]
        
        # Baseline reference
        base_value = float(self.explainer.expected_value[predicted_next_stage_idx]) if hasattr(self.explainer, "expected_value") and self.explainer.expected_value is not None else 0.20
        
        # 1. Feature attribution ranking
        ranking = []
        for i, name in enumerate(self.feature_names):
            attr_val = float(feature_attributions[i])
            ranking.append({
                "feature": name,
                "description": self.feature_descriptions.get(name, name),
                "attribution": round(attr_val, 4),
                "abs_attribution": round(abs(attr_val), 4),
                "direction": "increases_risk" if attr_val >= 0 else "decreases_risk",
                "value": round(float(current_feature_values[i]), 3)
            })
            
        ranking.sort(key=lambda item: item["abs_attribution"], reverse=True)
        
        # 2. Force plot data
        force_contributions = []
        for item in ranking:
            force_contributions.append({
                "feature": item["feature"],
                "description": item["description"],
                "value": item["value"],
                "contribution": item["attribution"],
                "is_positive": item["attribution"] >= 0
            })
            
        return {
            "predicted_class_idx": int(predicted_next_stage_idx),
            "confidence": float(predicted_prob),
            "feature_ranking": ranking,
            "force_plot": {
                "base_value": round(base_value, 4),
                "forecast_probability": round(predicted_prob, 4),
                "contributions": force_contributions
            }
        }
