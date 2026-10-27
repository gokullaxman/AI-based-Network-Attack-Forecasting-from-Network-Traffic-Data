import os
import io
import hashlib
import zipfile
import urllib.request
import time

URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/MachineLearningCSV.zip"
TARGET_FILE = "MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
OUTPUT_DIR = os.path.join("data", "benchmark", "raw")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

class HttpRangeReader(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        # Follow redirects to get final URL and total length
        with urllib.request.urlopen(req) as resp:
            self.final_url = resp.geturl()
            self.total_size = int(resp.headers.get("Content-Length", 0))
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
            raise ValueError("Invalid whence")
        return self.pos

    def tell(self):
        return self.pos

    def readinto(self, b):
        if self.pos >= self.total_size:
            return 0
        req_len = len(b)
        
        # Check if already in cache buffer
        if self.buf_start <= self.pos < self.buf_start + len(self.buffer):
            offset_in_buf = self.pos - self.buf_start
            available = len(self.buffer) - offset_in_buf
            to_copy = min(req_len, available)
            b[:to_copy] = self.buffer[offset_in_buf : offset_in_buf + to_copy]
            self.pos += to_copy
            return to_copy

        # Fetch chunk (read at least 1MB to minimize round trips)
        fetch_len = max(req_len, 1024 * 1024)
        end = min(self.pos + fetch_len - 1, self.total_size - 1)
        req = urllib.request.Request(
            self.final_url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Range": f"bytes={self.pos}-{end}"
            }
        )
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
        
        self.buffer = data
        self.buf_start = self.pos
        
        to_copy = min(req_len, len(data))
        b[:to_copy] = data[:to_copy]
        self.pos += to_copy
        return to_copy

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if os.path.exists(OUTPUT_PATH) and os.path.getsize(OUTPUT_PATH) > 10_000_000:
        print(f"Target file already exists: {OUTPUT_PATH} ({os.path.getsize(OUTPUT_PATH)} bytes)")
    else:
        print(f"Connecting to {URL}...")
        start_time = time.time()
        reader = HttpRangeReader(URL)
        print(f"Remote file size: {reader.total_size:,} bytes. Final URL: {reader.final_url}")
        
        buffered = io.BufferedReader(reader, buffer_size=1024 * 1024)
        print("Reading zip index...")
        with zipfile.ZipFile(buffered, 'r') as zf:
            namelist = zf.namelist()
            print(f"Archive contains {len(namelist)} files.")
            if TARGET_FILE not in namelist:
                print(f"Error: {TARGET_FILE} not in archive! Files: {namelist}")
                return
            
            info = zf.getinfo(TARGET_FILE)
            print(f"Extracting {TARGET_FILE} (compressed: {info.compress_size:,} bytes, uncompressed: {info.file_size:,} bytes)...")
            with zf.open(TARGET_FILE) as src, open(OUTPUT_PATH, 'wb') as dst:
                chunk_size = 512 * 1024
                extracted = 0
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    extracted += len(chunk)
                    print(f"Extracted {extracted:,} / {info.file_size:,} bytes ({extracted / info.file_size * 100:.1f}%)", end='\r')
            print()
        print(f"Extraction completed in {time.time() - start_time:.2f}s.")

    # Calculate SHA-256 and verify
    sha256 = hashlib.sha256()
    line_count = 0
    with open(OUTPUT_PATH, 'rb') as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)
            line_count += chunk.count(b'\n')
    
    file_size = os.path.getsize(OUTPUT_PATH)
    digest = sha256.hexdigest()
    print("=== PROVENANCE SUMMARY ===")
    print(f"Source URL: {URL}")
    print(f"Archive Internal Path: {TARGET_FILE}")
    print(f"Local Path: {OUTPUT_PATH}")
    print(f"File Size: {file_size:,} bytes")
    print(f"Line Count: {line_count:,}")
    print(f"SHA-256: {digest}")

if __name__ == "__main__":
    main()
