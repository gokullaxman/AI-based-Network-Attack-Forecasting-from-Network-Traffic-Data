"""
Selective, reproducible streaming extraction of authentic CICIDS2017 GeneratedLabelledFlows
CSV files with timestamps and IP addresses using robust HTTP Range streaming with retries.
Extracts into data/benchmark/temporal/raw/ while keeping data/benchmark/raw/ completely isolated.
"""

import os
import io
import time
import zipfile
import hashlib
import urllib.request
import urllib.error

TEMPORAL_ARCHIVE_URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/GeneratedLabelledFlows.zip"
TEMPORAL_RAW_DIR = os.path.join("data", "benchmark", "temporal", "raw")

TARGET_MEMBERS = [
    "TrafficLabelling /Monday-WorkingHours.pcap_ISCX.csv",
    "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv",
    "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "TrafficLabelling /Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "TrafficLabelling /Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "TrafficLabelling /Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "TrafficLabelling /Friday-WorkingHours-Morning.pcap_ISCX.csv"
]


class RobustHttpRangeReader(io.RawIOBase):
    """
    HTTP Range-based seekable stream with automatic retry on network drops/timeouts.
    """
    def __init__(self, url: str, max_retries: int = 8):
        self.url = url
        self.max_retries = max_retries
        self.final_url = None
        self.total_size = 0

        # Resolve initial URL and total content length with retries
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self.final_url = resp.geturl()
                    self.total_size = int(resp.headers.get("Content-Length", 0))
                break
            except Exception as e:
                wait_sec = 2 ** attempt
                print(f"[RETRY {attempt+1}/{max_retries}] Connecting to {url} failed: {e}. Retrying in {wait_sec}s...")
                time.sleep(wait_sec)
        else:
            raise ConnectionError(f"Could not connect to {url} after {max_retries} retries.")

        self.pos = 0
        self.buffer = b""
        self.buf_start = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.pos = offset
        elif whence == io.SEEK_CUR:
            self.pos += offset
        elif whence == io.SEEK_END:
            self.pos = self.total_size + offset
        else:
            raise ValueError("Invalid whence parameter in seek.")
        return self.pos

    def tell(self):
        return self.pos

    def readinto(self, b):
        if self.pos >= self.total_size:
            return 0
        req_len = len(b)

        # Serve from local cache if within bounds
        if self.buf_start <= self.pos < self.buf_start + len(self.buffer):
            offset_in_buf = self.pos - self.buf_start
            available = len(self.buffer) - offset_in_buf
            to_copy = min(req_len, available)
            b[:to_copy] = self.buffer[offset_in_buf : offset_in_buf + to_copy]
            self.pos += to_copy
            return to_copy

        # Fetch chunk with retry logic (read 2MB buffer to minimize roundtrips)
        fetch_len = max(req_len, 2 * 1024 * 1024)
        end = min(self.pos + fetch_len - 1, self.total_size - 1)

        data = None
        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(
                    self.final_url,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Range": f"bytes={self.pos}-{end}"
                    }
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                break
            except Exception as e:
                wait_sec = min(30, 2 ** attempt)
                print(f"\n[RETRY {attempt+1}/{self.max_retries}] Fetch range {self.pos}-{end} failed: {e}. Retrying in {wait_sec}s...")
                time.sleep(wait_sec)
        else:
            raise ConnectionError(f"Failed to fetch range bytes={self.pos}-{end} after {self.max_retries} attempts.")

        self.buffer = data
        self.buf_start = self.pos

        to_copy = min(req_len, len(data))
        b[:to_copy] = data[:to_copy]
        self.pos += to_copy
        return to_copy


def extract_temporal_files():
    os.makedirs(TEMPORAL_RAW_DIR, exist_ok=True)
    print(f"Connecting to {TEMPORAL_ARCHIVE_URL}...")
    reader = RobustHttpRangeReader(TEMPORAL_ARCHIVE_URL)
    print(f"Archive Size: {reader.total_size:,} bytes ({reader.total_size / (1024*1024):.2f} MB)")
    buffered = io.BufferedReader(reader, buffer_size=4 * 1024 * 1024)

    with zipfile.ZipFile(buffered, "r") as zf:
        namelist = zf.namelist()
        for member in TARGET_MEMBERS:
            clean_name = os.path.basename(member.strip())
            out_path = os.path.join(TEMPORAL_RAW_DIR, clean_name)

            if os.path.exists(out_path) and os.path.getsize(out_path) > 10_000_000:
                print(f"[SKIP] Already exists: {clean_name} ({os.path.getsize(out_path):,} bytes)")
                continue

            if member not in namelist:
                print(f"[ERROR] Member {member} not found in zip archive!")
                continue

            info = zf.getinfo(member)
            print(f"\n[EXTRACTING] {clean_name}")
            print(f"Compressed: {info.compress_size:,} bytes | Uncompressed: {info.file_size:,} bytes...")
            t0 = time.time()
            with zf.open(member) as src, open(out_path, "wb") as dst:
                chunk_size = 1024 * 1024
                extracted = 0
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    extracted += len(chunk)
                    pct = (extracted / info.file_size) * 100
                    print(f"Extracted {extracted:,} / {info.file_size:,} bytes ({pct:.1f}%)", end="\r")
            print(f"\nCompleted {clean_name} in {time.time() - t0:.2f}s.")

    # Audit SHA-256 Checksums
    print("\n=== EXTRACTED TEMPORAL FILES AUDIT ===")
    for fname in sorted(os.listdir(TEMPORAL_RAW_DIR)):
        if fname.endswith(".csv"):
            fpath = os.path.join(TEMPORAL_RAW_DIR, fname)
            fsize = os.path.getsize(fpath)
            sha = hashlib.sha256()
            lines = 0
            with open(fpath, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    sha.update(chunk)
                    lines += chunk.count(b"\n")
            print(f"File: {fname}")
            print(f"  Size: {fsize:,} bytes | Lines: {lines:,}")
            print(f"  SHA-256: {sha.hexdigest()}")


if __name__ == "__main__":
    extract_temporal_files()
