"""
Benchmark dataset pipeline for authentic CICIDS2017 network traffic data.
Implements data loading, label mapping, leakage-resistant splitting,
and preprocessor fitting exclusively on training data.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List
from sklearn.preprocessing import StandardScaler

# Constants
DEFAULT_RAW_PATH = os.path.join("data", "benchmark", "raw", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
BENCHMARK_ARTIFACTS_DIR = os.path.join("models", "benchmark")
PREPROCESSING_CONFIG_PATH = os.path.join("pipeline", "baseline_preprocessing_config.json")
SCALER_PATH = os.path.join("pipeline", "baseline_scaler.pkl")

# Binary Label Mapping
LABEL_MAPPING = {
    "BENIGN": 0,
    "PortScan": 1
}

# Constant (zero-variance) columns in Friday-WorkingHours-Afternoon-PortScan
CONSTANT_COLUMNS = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]

# Duplicate/redundant columns
REDUNDANT_COLUMNS = [
    "Fwd Header Length.1"
]

# Host/target identifiers excluded to prevent shortcut learning
METADATA_EXCLUDED_COLUMNS = [
    "Destination Port"
]


class BenchmarkDatasetPipeline:
    """
    Leakage-resistant benchmark data preparation and preprocessing pipeline.
    """

    def __init__(self, raw_csv_path: str = DEFAULT_RAW_PATH):
        self.raw_csv_path = raw_csv_path
        self.feature_columns: List[str] = []
        self.imputation_medians: Dict[str, float] = {}
        self.imputation_max_finite: Dict[str, float] = {}
        self.scaler: StandardScaler = StandardScaler()
        self.is_fitted: bool = False

    def load_and_clean_raw(self, deduplicate: bool = True) -> pd.DataFrame:
        """
        Loads raw CICIDS2017 CSV, strips column names, validates labels,
        and optionally drops exact duplicates.
        """
        if not os.path.exists(self.raw_csv_path):
            raise FileNotFoundError(f"Raw benchmark file not found: {self.raw_csv_path}")

        df = pd.read_csv(self.raw_csv_path)
        # Strip leading/trailing whitespaces in column names
        df.columns = df.columns.str.strip()

        if "Label" not in df.columns:
            raise ValueError("Required column 'Label' not found in dataset")

        # Strip whitespace from label strings
        df["Label"] = df["Label"].astype(str).str.strip()

        # Validate that all labels exist in mapping
        unknown_labels = set(df["Label"].unique()) - set(LABEL_MAPPING.keys())
        if unknown_labels:
            raise ValueError(f"Unexpected labels encountered in benchmark: {unknown_labels}")

        if deduplicate:
            # Drop exact duplicate rows to prevent train-test data leakage
            df = df.drop_duplicates().reset_index(drop=True)

        return df

    def select_feature_columns(self, df: pd.DataFrame, exclude_port: bool = True) -> List[str]:
        """
        Identifies and validates valid behavioral traffic features.
        Excludes target label, zero-variance columns, redundant duplicate columns,
        and host/port identifiers.
        """
        excluded = set(CONSTANT_COLUMNS + REDUNDANT_COLUMNS + ["Label"])
        if exclude_port:
            excluded.update(METADATA_EXCLUDED_COLUMNS)

        feature_cols = [c for c in df.columns if c not in excluded]
        return feature_cols

    def chronological_split(
        self, df: pd.DataFrame, train_ratio: float = 0.70, val_ratio: float = 0.15
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Splits dataset chronologically into Train, Validation, and Test sets.
        Preserves natural traffic sequence order to test temporal generalization.
        """
        n = len(df)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train_df = df.iloc[:n_train].copy().reset_index(drop=True)
        val_df = df.iloc[n_train : n_train + n_val].copy().reset_index(drop=True)
        test_df = df.iloc[n_train + n_val :].copy().reset_index(drop=True)

        return train_df, val_df, test_df

    def fit_preprocessing(self, train_df: pd.DataFrame, feature_cols: List[str]) -> None:
        """
        Fits all preprocessing transformations EXCLUSIVELY on training data:
        1. Calculates column medians for NaN imputation.
        2. Calculates upper finite bounds for infinite value replacement.
        3. Fits StandardScaler.
        """
        self.feature_columns = list(feature_cols)
        self.imputation_medians = {}
        self.imputation_max_finite = {}

        X_train_clean = pd.DataFrame(index=train_df.index)

        for col in self.feature_columns:
            series = pd.to_numeric(train_df[col], errors="coerce")
            
            # Find finite values on train
            finite_mask = np.isfinite(series)
            if not finite_mask.any():
                median_val = 0.0
                max_finite_val = 0.0
            else:
                median_val = float(series[finite_mask].median())
                max_finite_val = float(series[finite_mask].max())

            self.imputation_medians[col] = median_val
            self.imputation_max_finite[col] = max_finite_val

            # Replace inf with max finite on train, then fill NaN with train median
            clean_col = series.replace([np.inf, -np.inf], max_finite_val)
            clean_col = clean_col.fillna(median_val)
            X_train_clean[col] = clean_col

        self.scaler = StandardScaler()
        self.scaler.fit(X_train_clean.values)
        self.is_fitted = True

    def transform_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Applies fitted preprocessing to a dataframe (Train, Val, or Test).
        Uses ONLY the statistics fitted from training data.
        """
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fitted on training data before transforming")

        X_clean = pd.DataFrame(index=df.index)
        for col in self.feature_columns:
            series = pd.to_numeric(df[col], errors="coerce")
            max_val = self.imputation_max_finite.get(col, 0.0)
            median_val = self.imputation_medians.get(col, 0.0)

            clean_col = series.replace([np.inf, -np.inf], max_val)
            clean_col = clean_col.fillna(median_val)
            X_clean[col] = clean_col

        return self.scaler.transform(X_clean.values)

    def extract_labels(self, df: pd.DataFrame) -> np.ndarray:
        """
        Maps raw string labels to integer classes (0: Benign, 1: Attack).
        """
        labels = df["Label"].astype(str).str.strip().map(LABEL_MAPPING)
        if labels.isnull().any():
            raise ValueError("Encountered unmapped labels during label extraction")
        return labels.values.astype(int)

    def save_artifacts(
        self,
        config_path: str = PREPROCESSING_CONFIG_PATH,
        scaler_path: str = SCALER_PATH
    ) -> None:
        """
        Persists feature schema and preprocessor configuration.
        """
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        config = {
            "feature_columns": self.feature_columns,
            "feature_count": len(self.feature_columns),
            "label_mapping": LABEL_MAPPING,
            "imputation_medians": self.imputation_medians,
            "imputation_max_finite": self.imputation_max_finite,
            "constant_columns_excluded": CONSTANT_COLUMNS,
            "redundant_columns_excluded": REDUNDANT_COLUMNS,
            "metadata_excluded": METADATA_EXCLUDED_COLUMNS,
            "scaler_type": "StandardScaler"
        }
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
        with open(scaler_path, "wb") as f:
            pickle.dump(self.scaler, f)

    def load_artifacts(
        self,
        config_path: str = PREPROCESSING_CONFIG_PATH,
        scaler_path: str = SCALER_PATH
    ) -> None:
        """
        Loads preprocessor configuration and scaler.
        """
        with open(config_path, "r") as f:
            config = json.load(f)

        self.feature_columns = config["feature_columns"]
        self.imputation_medians = config["imputation_medians"]
        self.imputation_max_finite = config["imputation_max_finite"]

        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        self.is_fitted = True
