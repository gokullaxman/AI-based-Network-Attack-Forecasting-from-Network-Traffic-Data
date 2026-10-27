"""
Pipeline module for authentic multi-attack CICIDS2017 flow data.
Implements the 6-class intrusion-detection benchmark:
  0: BENIGN
  1: PortScan
  2: DoS_DDoS
  3: BruteForce
  4: WebAttacks
  5: Botnet

Features 66 native flow attributes. Excludes metadata (Destination Port),
10 constant columns, and 1 duplicate column.
Enforces zero feature-vector overlap across train, validation, and test splits.
"""

import os
import glob
import json
import pickle
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

BENCHMARK_MULTIATTACK_DIR = os.path.join("models", "benchmark_multiattack")
RAW_DATA_DIR = os.path.join("data", "benchmark", "raw")

# 6-Class Normalized Taxonomy
CLASS_MAPPING = {
    "BENIGN": 0,
    "PortScan": 1,
    "DoS_DDoS": 2,
    "BruteForce": 3,
    "WebAttacks": 4,
    "Botnet": 5
}
CLASS_NAMES = ["BENIGN", "PortScan", "DoS_DDoS", "BruteForce", "WebAttacks", "Botnet"]

# Excluded constant and duplicate columns
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
REDUNDANT_COLUMNS = ["Fwd Header Length.1"]
METADATA_EXCLUDED_COLUMNS = ["Destination Port"]


def normalize_raw_label(raw: Any) -> Optional[str]:
    """
    Normalizes raw CICIDS2017 label strings into one of the 6 canonical classes.
    Handles encoding defects (e.g. \\ufffd replacement chars, latin1 en-dashes).
    Returns 'EXCLUDED' for Heartbleed/Infiltration, or None for unknown.
    """
    if pd.isna(raw):
        return None
    s = str(raw).strip()
    s = s.replace("\ufffd", "-").replace("\x96", "-").replace("\u2013", "-").replace("–", "-")

    if s == "BENIGN":
        return "BENIGN"
    elif s == "PortScan":
        return "PortScan"
    elif s in ("DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowloris", "DoS Slowhttptest"):
        return "DoS_DDoS"
    elif s in ("FTP-Patator", "SSH-Patator"):
        return "BruteForce"
    elif "Web Attack" in s:
        return "WebAttacks"
    elif s == "Bot":
        return "Botnet"
    elif s in ("Heartbleed", "Infiltration"):
        return "EXCLUDED"
    else:
        return None


class MultiAttackDatasetPipeline:
    """
    Leakage-controlled multi-attack benchmark dataset loader and preprocessor.
    """

    def __init__(self, raw_data_dir: str = RAW_DATA_DIR):
        self.raw_data_dir = raw_data_dir
        self.feature_columns: List[str] = []
        self.imputation_medians: Dict[str, float] = {}
        self.imputation_max_finite: Dict[str, float] = {}
        self.scaler: StandardScaler = StandardScaler()
        self.is_fitted: bool = False

    def load_all_raw_data(self) -> pd.DataFrame:
        """
        Loads all authentic CICIDS2017 benchmark CSV files from raw_data_dir,
        cleans headers, normalizes labels, and filters out excluded classes.
        """
        csv_files = sorted(glob.glob(os.path.join(self.raw_data_dir, "*.csv")))
        if not csv_files:
            raise FileNotFoundError(f"No CSV benchmark files found in {self.raw_data_dir}")

        dfs = []
        for fpath in csv_files:
            df = pd.read_csv(fpath, encoding="latin1")
            df.columns = [c.strip() for c in df.columns]

            if "Label" not in df.columns:
                raise ValueError(f"Missing 'Label' column in {fpath}")

            df["NormLabel"] = df["Label"].map(normalize_raw_label)
            # Check for unmapped unknown labels
            unknown_mask = df["NormLabel"].isnull()
            if unknown_mask.any():
                bad_labels = df.loc[unknown_mask, "Label"].unique()
                raise ValueError(f"Unknown labels encountered in {fpath}: {bad_labels}")

            # Filter out explicitly excluded classes (Heartbleed, Infiltration)
            df = df[df["NormLabel"] != "EXCLUDED"].copy()
            dfs.append(df)

        combined_df = pd.concat(dfs, ignore_index=True)
        return combined_df

    def select_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """
        Selects valid 66 behavioral flow features, excluding metadata and constants.
        """
        excluded = set(CONSTANT_COLUMNS + REDUNDANT_COLUMNS + METADATA_EXCLUDED_COLUMNS + ["Label", "NormLabel"])
        self.feature_columns = [c for c in df.columns if c not in excluded]
        return self.feature_columns

    def deduplicate_and_audit(self, df: pd.DataFrame, feature_cols: List[str]) -> Tuple[pd.DataFrame, int]:
        """
        Performs feature-level deduplication on the 66 behavioral features.
        Identifies and removes conflicting feature vectors (identical features with different labels).
        Returns deduplicated clean DataFrame and count of removed conflicting profiles.
        """
        # 1. Unique (feature, label) pairs
        unique_fl = df.drop_duplicates(subset=feature_cols + ["NormLabel"])

        # 2. Conflicting feature vectors appear >1 time across different labels
        conflict_mask = unique_fl.duplicated(subset=feature_cols, keep=False)
        conflicting_profiles = unique_fl[conflict_mask].drop_duplicates(subset=feature_cols)
        n_conflicts = len(conflicting_profiles)

        # 3. Clean deduplicated dataframe: keep=False drops all conflicting profiles entirely
        clean_df = unique_fl.drop_duplicates(subset=feature_cols, keep=False).reset_index(drop=True)

        return clean_df, n_conflicts

    def stratified_zero_leakage_split(
        self,
        dedup_df: pd.DataFrame,
        feature_cols: List[str],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        random_seed: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Splits deduplicated feature profiles into Train (70%), Val (15%), and Test (15%)
        using stratified sampling per class.
        Guarantees strictly 0 feature-vector overlap across partitions.
        """
        labels = dedup_df["NormLabel"].map(CLASS_MAPPING).values.astype(int)
        test_ratio = 1.0 - train_ratio - val_ratio
        val_test_ratio = val_ratio + test_ratio

        # First split train vs (val + test)
        train_idx, val_test_idx = train_test_split(
            np.arange(len(dedup_df)),
            test_size=val_test_ratio,
            stratify=labels,
            random_state=random_seed
        )

        # Second split val vs test (50% of the remaining 30% = 15% each)
        val_test_labels = labels[val_test_idx]
        val_sub_idx, test_sub_idx = train_test_split(
            val_test_idx,
            test_size=0.50,
            stratify=val_test_labels,
            random_state=random_seed
        )

        train_df = dedup_df.iloc[train_idx].reset_index(drop=True)
        val_df = dedup_df.iloc[val_sub_idx].reset_index(drop=True)
        test_df = dedup_df.iloc[test_sub_idx].reset_index(drop=True)

        # Verify strict zero leakage (pandas handles NaNs deterministically: NaN == NaN)
        combined_check = pd.concat([train_df[feature_cols], test_df[feature_cols]], ignore_index=True)
        if combined_check.duplicated().any():
            overlap_count = int(combined_check.duplicated().sum())
            raise RuntimeError(f"Data leakage detected! {overlap_count} feature vectors overlap between Train and Test.")

        return train_df, val_df, test_df

    def fit_preprocessing(self, train_df: pd.DataFrame, feature_cols: List[str]) -> None:
        """
        Fits all preprocessing transformations EXCLUSIVELY on training data:
        1. Computes medians on Train for NaN imputation.
        2. Computes maximum finite bounds on Train for Inf replacement.
        3. Fits StandardScaler on Train features.
        """
        self.feature_columns = list(feature_cols)
        self.imputation_medians = {}
        self.imputation_max_finite = {}

        X_train_clean = pd.DataFrame(index=train_df.index)

        for col in self.feature_columns:
            s = pd.to_numeric(train_df[col], errors="coerce")
            finite = np.isfinite(s)
            med = float(s[finite].median()) if finite.any() else 0.0
            mxf = float(s[finite].max()) if finite.any() else 0.0
            self.imputation_medians[col] = med
            self.imputation_max_finite[col] = mxf

            clean = s.replace([np.inf, -np.inf], mxf).fillna(med)
            X_train_clean[col] = clean

        self.scaler = StandardScaler()
        self.scaler.fit(X_train_clean.values)
        self.is_fitted = True

    def transform_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforms features of any partition using strictly learned training statistics.
        """
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fitted on training data before transforming.")

        X_clean = pd.DataFrame(index=df.index)
        for col in self.feature_columns:
            s = pd.to_numeric(df[col], errors="coerce")
            clean = s.replace([np.inf, -np.inf], self.imputation_max_finite[col]).fillna(self.imputation_medians[col])
            X_clean[col] = clean

        return self.scaler.transform(X_clean.values)

    def extract_labels(self, df: pd.DataFrame) -> np.ndarray:
        """Extracts integer target labels according to CLASS_MAPPING."""
        return df["NormLabel"].map(CLASS_MAPPING).values.astype(int)

    def save_artifacts(
        self,
        out_dir: str = BENCHMARK_MULTIATTACK_DIR
    ) -> None:
        """Persists fitted scaler and preprocessor configuration."""
        os.makedirs(out_dir, exist_ok=True)
        config = {
            "feature_columns": self.feature_columns,
            "feature_count": len(self.feature_columns),
            "class_mapping": CLASS_MAPPING,
            "class_names": CLASS_NAMES,
            "imputation_medians": self.imputation_medians,
            "imputation_max_finite": self.imputation_max_finite,
            "constant_columns_excluded": CONSTANT_COLUMNS,
            "redundant_columns_excluded": REDUNDANT_COLUMNS,
            "metadata_excluded": METADATA_EXCLUDED_COLUMNS,
            "scaler_type": "StandardScaler"
        }
        with open(os.path.join(out_dir, "multiattack_preprocessing_config.json"), "w") as f:
            json.dump(config, f, indent=2)

        with open(os.path.join(out_dir, "multiattack_scaler.pkl"), "wb") as f:
            pickle.dump(self.scaler, f)

    def load_artifacts(
        self,
        config_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        in_dir: Optional[str] = None
    ) -> None:
        """Loads fitted scaler and preprocessor configuration from disk."""
        if in_dir:
            config_path = os.path.join(in_dir, "multiattack_preprocessing_config.json")
            scaler_path = os.path.join(in_dir, "multiattack_scaler.pkl")
        else:
            if config_path is None:
                config_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_preprocessing_config.json")
            if scaler_path is None:
                scaler_path = os.path.join(BENCHMARK_MULTIATTACK_DIR, "multiattack_scaler.pkl")

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")

        with open(config_path, "r") as f:
            config = json.load(f)
        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        self.feature_columns = config["feature_columns"]
        self.imputation_medians = config["imputation_medians"]
        self.imputation_max_finite = config["imputation_max_finite"]
        self.is_fitted = True
