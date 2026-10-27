"""
Download authentic multi-attack CICIDS2017 files from official distribution mirror
using HTTP Range streaming (fast, downloads only the requested CSV members from zip).
"""

import os
import io
import time
import zipfile
import hashlib
import urllib.request
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.download_benchmark import HttpRangeReader, URL

TARGET_FILES = [
    "MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv",
    "MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv"
]

OUTPUT_DIR = os.path.join("data", "benchmark", "raw")

def extract_members():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Connecting to {URL}...")
    reader = HttpRangeReader(URL)
    buffered = io.BufferedReader(reader, buffer_size=2 * 1024 * 1024)

    with zipfile.ZipFile(buffered, 'r') as zf:
        namelist = zf.namelist()
        for member in TARGET_FILES:
            base_name = os.path.basename(member)
            out_path = os.path.join(OUTPUT_DIR, base_name)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 10_000_000:
                print(f"[SKIP] Already exists: {out_path} ({os.path.getsize(out_path):,} bytes)")
                continue

            if member not in namelist:
                print(f"[ERROR] Member {member} not found in zip archive!")
                continue

            info = zf.getinfo(member)
            print(f"\n[EXTRACTING] {member}")
            print(f"Compressed: {info.compress_size:,} bytes | Uncompressed: {info.file_size:,} bytes...")
            t0 = time.time()
            with zf.open(member) as src, open(out_path, 'wb') as dst:
                chunk_size = 1024 * 1024
                extracted = 0
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    extracted += len(chunk)
                    pct = (extracted / info.file_size) * 100
                    print(f"Extracted {extracted:,} / {info.file_size:,} bytes ({pct:.1f}%)", end='\r')
            print(f"\nCompleted {base_name} in {time.time() - t0:.2f}s.")

    # Checksums
    print("\n=== LOCAL MULTI-ATTACK BENCHMARK FILES AUDIT ===")
    for fname in os.listdir(OUTPUT_DIR):
        if fname.endswith(".csv"):
            fpath = os.path.join(OUTPUT_DIR, fname)
            fsize = os.path.getsize(fpath)
            sha = hashlib.sha256()
            lines = 0
            with open(fpath, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    sha.update(chunk)
                    lines += chunk.count(b'\n')
            print(f"File: {fname}")
            print(f"  Size: {fsize:,} bytes | Lines: {lines:,}")
            print(f"  SHA-256: {sha.hexdigest()}")

if __name__ == "__main__":
    extract_members()
