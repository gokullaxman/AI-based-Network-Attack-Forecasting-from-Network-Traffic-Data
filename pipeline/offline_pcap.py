"""
Wireshark-Compatible Offline Capture Processing Module
Supports PCAP and PCAPNG file formats via streaming parser.
Strictly processes authentic packets without synthetic fallbacks, payload leakage, or silent zero-filling.
"""

import os
import io
import time
from typing import List, Dict, Any, Optional, Iterator, Tuple
from dataclasses import dataclass, asdict

import scapy.all as scapy
from scapy.utils import PcapReader

from .packet_record import PacketMetadata, parse_scapy_packet


PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4": "PCAP (Standard Microsecond)",
    b"\xd4\xc3\xb2\xa1": "PCAP (Byte-swapped Microsecond)",
    b"\xa1\xb2\x3c\x4d": "PCAP (Nanosecond)",
    b"\x4d\x3c\xb2\xa1": "PCAP (Byte-swapped Nanosecond)",
    b"\x0a\x0d\x0d\x0a": "PCAPNG (Next Generation Format)"
}


@dataclass
class CaptureSummary:
    """Statistical summary of an offline capture file processing run."""
    filepath: str
    file_size_bytes: int
    format_detected: str
    total_packets_read: int
    successfully_parsed: int
    parsing_errors: int
    invalid_timestamps: int
    start_timestamp: Optional[float]
    end_timestamp: Optional[float]
    duration_seconds: float
    total_captured_bytes: int
    timestamp_monotonic: bool
    status: str
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_pcap_file(filepath: str, allowed_base_dirs: Optional[List[str]] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Validates capture file existence, size, magic header, and optional directory containment.
    Returns: (is_valid, format_name_or_error, error_detail)
    """
    if not filepath or not isinstance(filepath, str):
        return False, "INVALID_PATH", "Capture path must be a non-empty string."

    abs_path = os.path.abspath(filepath)
    if not os.path.exists(abs_path):
        return False, "FILE_NOT_FOUND", f"File does not exist: {filepath}"

    if os.path.isdir(abs_path):
        return False, "IS_DIRECTORY", f"Path is a directory, not a capture file: {filepath}"

    # Path confinement check if specified
    if allowed_base_dirs:
        in_allowed = any(os.path.commonpath([abs_path, os.path.abspath(b)]) == os.path.abspath(b) for b in allowed_base_dirs)
        if not in_allowed:
            return False, "FORBIDDEN_PATH", f"Access to path outside allowed directories is restricted: {filepath}"

    file_size = os.path.getsize(abs_path)
    if file_size == 0:
        return False, "EMPTY_FILE", f"Capture file is empty (0 bytes): {filepath}"

    if file_size < 24: # Minimum PCAP global header size
        return False, "TRUNCATED_HEADER", f"Capture file too small for a valid PCAP/PCAPNG header ({file_size} bytes)."

    # Check magic bytes
    try:
        with open(abs_path, "rb") as f:
            magic = f.read(4)
        if magic in PCAP_MAGIC_NUMBERS:
            return True, PCAP_MAGIC_NUMBERS[magic], None
        return False, "UNSUPPORTED_FORMAT", f"Unrecognized capture magic bytes: {magic.hex()}"
    except Exception as e:
        return False, "READ_ERROR", f"Failed to read capture file header: {str(e)}"


class OfflinePcapProcessor:
    """
    Streaming offline PCAP / PCAPNG parser.
    Iterates over packets without buffering the entire capture in memory.
    """

    def __init__(self, allowed_base_dirs: Optional[List[str]] = None):
        self.allowed_base_dirs = allowed_base_dirs

    def stream_packets(self, filepath: str) -> Iterator[PacketMetadata]:
        """
        Yields PacketMetadata records iteratively from a validated PCAP/PCAPNG file.
        Does not load the entire capture into memory.
        """
        is_valid, fmt, err = validate_pcap_file(filepath, self.allowed_base_dirs)
        if not is_valid:
            raise ValueError(f"PCAP validation failed [{fmt}]: {err}")

        abs_path = os.path.abspath(filepath)
        reader = None
        pkt_id = 0
        try:
            reader = PcapReader(abs_path)
            for sc_pkt in reader:
                pkt_id += 1
                try:
                    meta = parse_scapy_packet(
                        sc_pkt=sc_pkt,
                        pkt_id=pkt_id,
                        source=f"Offline PCAP ({os.path.basename(abs_path)})"
                    )
                    yield meta
                except Exception as ex:
                    yield PacketMetadata(
                        pkt_id=pkt_id,
                        timestamp=time.time(),
                        captured_len=len(sc_pkt) if sc_pkt else 0,
                        wire_len=len(sc_pkt) if sc_pkt else 0,
                        parse_status="MALFORMED",
                        error_message=str(ex),
                        observation_source=f"Offline PCAP ({os.path.basename(abs_path)})"
                    )
        except Exception as e:
            raise RuntimeError(f"Error while reading capture packets: {str(e)}")
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass

    def process_file(self, filepath: str, max_packets: Optional[int] = None) -> Tuple[List[PacketMetadata], CaptureSummary]:
        """
        Processes a capture file, extracting packet records and compiling a complete CaptureSummary.
        """
        is_valid, fmt, err = validate_pcap_file(filepath, self.allowed_base_dirs)
        abs_path = os.path.abspath(filepath) if os.path.exists(filepath) else filepath
        file_size = os.path.getsize(abs_path) if os.path.exists(abs_path) and os.path.isfile(abs_path) else 0

        if not is_valid:
            summary = CaptureSummary(
                filepath=filepath,
                file_size_bytes=file_size,
                format_detected=fmt,
                total_packets_read=0,
                successfully_parsed=0,
                parsing_errors=0,
                invalid_timestamps=0,
                start_timestamp=None,
                end_timestamp=None,
                duration_seconds=0.0,
                total_captured_bytes=0,
                timestamp_monotonic=True,
                status="ERROR",
                error_message=err
            )
            return [], summary

        packets: List[PacketMetadata] = []
        total_read = 0
        successful = 0
        errors = 0
        invalid_ts = 0
        total_bytes = 0
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        is_monotonic = True
        last_ts = -1.0

        try:
            for meta in self.stream_packets(abs_path):
                total_read += 1
                if meta.parse_status == "OK":
                    successful += 1
                else:
                    errors += 1

                # Timestamp verification
                ts = meta.timestamp
                if ts <= 0 or ts > 2524608000.0:  # > year 2050 or <= 0
                    invalid_ts += 1
                else:
                    if start_ts is None or ts < start_ts:
                        start_ts = ts
                    if end_ts is None or ts > end_ts:
                        end_ts = ts
                    if last_ts >= 0 and ts < last_ts:
                        is_monotonic = False
                    last_ts = ts

                total_bytes += meta.captured_len
                packets.append(meta)

                if max_packets is not None and total_read >= max_packets:
                    break

            duration = max(0.0, (end_ts - start_ts)) if (start_ts and end_ts) else 0.0

            summary = CaptureSummary(
                filepath=abs_path,
                file_size_bytes=file_size,
                format_detected=fmt,
                total_packets_read=total_read,
                successfully_parsed=successful,
                parsing_errors=errors,
                invalid_timestamps=invalid_ts,
                start_timestamp=start_ts,
                end_timestamp=end_ts,
                duration_seconds=round(duration, 3),
                total_captured_bytes=total_bytes,
                timestamp_monotonic=is_monotonic,
                status="SUCCESS" if errors == 0 else "PARTIAL_SUCCESS"
            )
            return packets, summary

        except Exception as e:
            summary = CaptureSummary(
                filepath=abs_path,
                file_size_bytes=file_size,
                format_detected=fmt,
                total_packets_read=total_read,
                successfully_parsed=successful,
                parsing_errors=errors + 1,
                invalid_timestamps=invalid_ts,
                start_timestamp=start_ts,
                end_timestamp=end_ts,
                duration_seconds=0.0,
                total_captured_bytes=total_bytes,
                timestamp_monotonic=is_monotonic,
                status="ERROR",
                error_message=str(e)
            )
            return packets, summary
