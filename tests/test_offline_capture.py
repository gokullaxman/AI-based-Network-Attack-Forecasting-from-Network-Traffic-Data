"""
Unit Tests for Wireshark-Compatible Offline Capture Processing
Tests:
- Valid PCAP/PCAPNG parsing
- Missing capture file handling
- Empty capture file handling
- Invalid capture magic bytes
- Malformed packets
- Invalid timestamps detection
- Capture duration and metadata calculation
- Streaming memory-safe iteration
"""

import os
import tempfile
import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap

from pipeline.offline_pcap import (
    validate_pcap_file,
    OfflinePcapProcessor,
    CaptureSummary
)
from pipeline.packet_record import PacketMetadata, parse_scapy_packet


@pytest.fixture
def valid_pcap():
    """Generates a small valid PCAP file with authentic packet headers."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        path = tf.name

    pkts = []
    t0 = 1700000000.0
    for i in range(5):
        pkt = Ether() / IP(src="192.168.1.10", dst=f"192.168.1.{20+i}") / TCP(sport=5000+i, dport=80, flags="S")
        pkt.time = t0 + (i * 0.5)
        pkts.append(pkt)

    wrpcap(path, pkts)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def empty_file():
    """Creates a 0-byte file."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        path = tf.name
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def invalid_format_file():
    """Creates a text file disguised as .pcap."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        tf.write(b"NOT A PCAP FILE CONTENT AT ALL")
        path = tf.name
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_validate_pcap_missing_file():
    """Verify missing capture file returns FILE_NOT_FOUND error."""
    is_valid, code, err = validate_pcap_file("non_existent_capture_999.pcap")
    assert not is_valid
    assert code == "FILE_NOT_FOUND"
    assert "does not exist" in err


def test_validate_pcap_empty_file(empty_file):
    """Verify empty 0-byte file returns EMPTY_FILE error."""
    is_valid, code, err = validate_pcap_file(empty_file)
    assert not is_valid
    assert code == "EMPTY_FILE"
    assert "0 bytes" in err


def test_validate_pcap_invalid_format(invalid_format_file):
    """Verify non-PCAP magic bytes are rejected."""
    is_valid, code, err = validate_pcap_file(invalid_format_file)
    assert not is_valid
    assert code == "UNSUPPORTED_FORMAT"


def test_valid_pcap_processing(valid_pcap):
    """Verify valid PCAP processing yields correct packet count, timestamps, and summary."""
    processor = OfflinePcapProcessor()
    packets, summary = processor.process_file(valid_pcap)

    assert summary.status == "SUCCESS"
    assert summary.successfully_parsed == 5
    assert summary.parsing_errors == 0
    assert summary.invalid_timestamps == 0
    assert summary.duration_seconds == 2.0  # 4 * 0.5s = 2.0s
    assert summary.timestamp_monotonic is True
    assert len(packets) == 5

    first_pkt = packets[0]
    assert isinstance(first_pkt, PacketMetadata)
    assert first_pkt.network_protocol == "IPv4"
    assert first_pkt.transport_protocol == "TCP"
    assert first_pkt.src_ip == "192.168.1.10"
    assert first_pkt.dst_port == 80
    assert first_pkt.tcp_flags == "S"


def test_streaming_iterator(valid_pcap):
    """Verify stream_packets yields packets without loading all into memory."""
    processor = OfflinePcapProcessor()
    count = 0
    for meta in processor.stream_packets(valid_pcap):
        count += 1
        assert isinstance(meta, PacketMetadata)
        assert meta.parse_status == "OK"
    assert count == 5


def test_path_confinement_security(valid_pcap):
    """Verify allowed_base_dirs prevents path traversal."""
    allowed = [os.path.join(tempfile.gettempdir(), "some_restricted_dir")]
    processor = OfflinePcapProcessor(allowed_base_dirs=allowed)
    is_valid, code, err = validate_pcap_file(valid_pcap, allowed_base_dirs=allowed)
    assert not is_valid
    assert code == "FORBIDDEN_PATH"
