"""
Temporal Attack Forecaster Module (Phase 9C).

Dedicated research inference engine for real-data Target A attack-onset forecasting.
Validates input schemas, prevents incompatible packet/flow feature leakage, and provides
uncalibrated forecast probabilities for the 5-minute future horizon.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Union, Optional, List

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_DIR = MODULE_DIR

# Flow predictors expected per epoch (12 features)
EXPECTED_FLOW_FEATURES = [
    "flow_count", "total_packets", "total_bytes",
    "mean_flow_duration_ms", "std_flow_duration_ms",
    "tcp_flow_ratio", "udp_flow_ratio",
    "dst_port_diversity", "dst_port_entropy",
    "distinct_src_ips", "distinct_dst_ips", "syn_flag_ratio"
]

# Signatures of incompatible packet-layer features from live capture
INCOMPATIBLE_PACKET_SIGNATURES = {
    "packet_count", "total_captured_bytes", "mean_frame_length", "std_frame_length",
    "tcp_packet_ratio", "udp_packet_ratio", "other_protocol_ratio", "distinct_dst_ports",
    "iat_mean", "iat_std"
}


class TemporalAttackForecaster:
    """
    Experimental attack onset forecaster trained on authentic CICIDS2017 temporal flow data.
    
    Target A Definition:
    - 10-minute clean historical context [t-9, t]
    - 2-minute clean lead gap [t+1, t+2]
    - 5-minute forecast horizon [t+3, t+7]
    - Positive target: an authentic multi-stage attack onset begins in the forecast horizon.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        self.model_path = os.path.join(self.model_dir, "model.joblib")
        self.preprocessor_path = os.path.join(self.model_dir, "preprocessor.joblib")
        self.metadata_path = os.path.join(self.model_dir, "metadata.json")

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found at {self.model_path}")
        if not os.path.exists(self.preprocessor_path):
            raise FileNotFoundError(f"Preprocessor file not found at {self.preprocessor_path}")
        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError(f"Metadata file not found at {self.metadata_path}")

        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.preprocessor_path)

        with open(self.metadata_path, "r") as fp:
            self.metadata = json.load(fp)

        self.expected_feature_count = self.metadata["feature_schema"]["feature_dim"]
        self.expected_columns = self.metadata["feature_schema"]["lag_order"]

    def validate_features(self, features: Union[np.ndarray, pd.DataFrame, List[float]]) -> np.ndarray:
        """
        Validates feature dimensionality, column schema, and prohibits incompatible packet features.
        Returns a 2D numpy array of shape (N, 120).
        """
        if features is None:
            raise ValueError("Input features cannot be None")

        if isinstance(features, list) and len(features) > 0 and isinstance(features[0], dict):
            features = pd.DataFrame(features)
        elif isinstance(features, dict):
            features = pd.DataFrame([features])

        # DataFrame handling
        if isinstance(features, pd.DataFrame):
            cols = set(features.columns)

            # Check for illegal packet feature contamination (exact match or lagged variants)
            detected_incompatible = set()
            for col in cols:
                base_col = col.split("_lag")[0] if "_lag" in col else col
                if base_col in INCOMPATIBLE_PACKET_SIGNATURES or col in INCOMPATIBLE_PACKET_SIGNATURES:
                    detected_incompatible.add(col)

            if detected_incompatible:
                raise ValueError(
                    f"Schema Mismatch: Detected incompatible packet-layer feature(s) {sorted(list(detected_incompatible))}. "
                    "This model was trained on dataset-native flow features (PREDICTOR_COLUMNS). "
                    "Feeding packet features into a flow-trained model without empirical calibration is prohibited."
                )

            # Check if columns match expected lag order
            if len(features.columns) != self.expected_feature_count:
                raise ValueError(
                    f"Expected exactly {self.expected_feature_count} features (12 features x 10 lags), "
                    f"received {len(features.columns)}"
                )

            # Reindex if columns are named
            if all(col in features.columns for col in self.expected_columns):
                arr = features[self.expected_columns].to_numpy(dtype=float)
            else:
                # If columns don't match expected names
                missing = [col for col in self.expected_columns if col not in features.columns]
                raise ValueError(f"Feature schema missing required columns (first 5 missing: {missing[:5]})")
        elif isinstance(features, list):
            arr = np.array(features, dtype=float)
        elif isinstance(features, np.ndarray):
            arr = features.astype(float)
        else:
            raise TypeError(f"Unsupported features type: {type(features)}")

        # Ensure 2D array
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)

        if arr.shape[1] != self.expected_feature_count:
            raise ValueError(
                f"Invalid feature dimensions: shape {arr.shape}, expected (*, {self.expected_feature_count})"
            )

        # Check for NaN / Inf
        if np.isnan(arr).any():
            raise ValueError("Input features contain NaN values. Missing values must be explicitly resolved.")
        if np.isinf(arr).any():
            raise ValueError("Input features contain infinite values.")

        return arr

    def predict_proba(self, features: Union[np.ndarray, pd.DataFrame, List[float]]) -> Dict[str, Any]:
        """
        Validates input, applies training-only scaling, and returns forecast probability.
        """
        X = self.validate_features(features)
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)[:, 1]

        prob_value = float(probs[0]) if len(probs) == 1 else probs.tolist()

        return {
            "status": "EXPERIMENTAL_RESEARCH_MODEL",
            "target": "Target A (Onset in [t+3, t+7] after 10m clean history and 2m gap)",
            "prediction_available": True,
            "forecast_probability": prob_value,
            "is_calibrated": False,
            "calibration_note": (
                "Uncalibrated class-weighted logistic probability score. "
                "Tested under zero-shot cross-category attack transfer."
            ),
            "sample_count": len(X)
        }

    def predict(
        self,
        features: Union[np.ndarray, pd.DataFrame, List[float]],
        threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Calculates binary attack onset forecast based on the specified threshold.
        Validates that threshold is a finite numeric value in [0.0, 1.0].
        """
        if threshold is None or not isinstance(threshold, (int, float)) or np.isnan(threshold) or np.isinf(threshold):
            raise ValueError(f"Invalid threshold: {threshold}. Expected finite float in [0.0, 1.0].")
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(f"Threshold {threshold} out of supported range [0.0, 1.0].")

        res = self.predict_proba(features)
        raw_prob = res["forecast_probability"]
        if isinstance(raw_prob, (float, int)):
            pred_value = int(raw_prob >= threshold)
            res["decision_threshold"] = float(threshold)
            res["forecast_onset_positive"] = bool(pred_value == 1)
        else:
            probs = np.array(raw_prob)
            preds = (probs >= threshold).astype(int).tolist()
            res["decision_threshold"] = float(threshold)
            res["forecast_onset_positive"] = [bool(p == 1) for p in preds]
        return res

    def get_metadata(self) -> Dict[str, Any]:
        """Returns the full provenance and evaluation metadata."""
        return self.metadata
