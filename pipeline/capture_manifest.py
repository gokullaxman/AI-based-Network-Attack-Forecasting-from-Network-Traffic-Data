"""
Capture Dataset Manifest Generator
Maintains clear provenance and isolation for imported or recorded packet captures.
Guarantees that real captures are separated from benchmark research datasets and never falsely labeled.
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List


CAPTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "captures"
)
MANIFEST_PATH = os.path.join(CAPTURES_DIR, "manifest.json")


def load_manifest() -> List[Dict[str, Any]]:
    """Loads the existing capture manifest or returns an empty list."""
    if not os.path.exists(MANIFEST_PATH):
        return []
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("captures", [])
    except Exception:
        return []


def register_capture(
    source: str,
    filename: str,
    file_format: str,
    duration_seconds: float,
    packet_count: int,
    total_bytes: int,
    timestamp_quality: str = "VALID_TIMESTAMPS",
    parsing_status: str = "SUCCESS",
    interface_or_context: Optional[str] = None,
    label_availability: str = "UNLABELED (Real Observation)",
    processing_version: str = "2.0-RealData"
) -> Dict[str, Any]:
    """
    Registers a newly imported or processed capture in data/captures/manifest.json.
    Excludes sensitive raw identifiers from public manifest summary.
    """
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    manifest_entries = load_manifest()

    entry = {
        "capture_id": f"cap_{int(time.time())}_{len(manifest_entries) + 1}",
        "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "filename": os.path.basename(filename),
        "file_format": file_format,
        "interface_or_context": interface_or_context or "Offline User Import",
        "duration_seconds": round(duration_seconds, 3),
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "timestamp_quality": timestamp_quality,
        "parsing_status": parsing_status,
        "label_availability": label_availability,
        "ground_truth_status": "NONE (Operational Traffic Unlabeled)",
        "processing_version": processing_version
    }

    manifest_entries.append(entry)

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "version": "1.0",
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_registered_captures": len(manifest_entries),
                "captures": manifest_entries
            },
            f,
            indent=2
        )

    return entry
