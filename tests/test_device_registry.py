"""
Unit Tests for Verifiable Device Observation Registry (Rule B)
Tests:
1. Genuine observed IP creates a registry entry.
2. Repeated observations update counts and last-seen timestamps correctly.
3. Missing MAC addresses remain unknown rather than fabricated.
4. Offline PCAP observations remain marked historical.
5. Connection metadata is not represented as captured packets.
6. Simulation observations cannot contaminate live records.
7. Invalid observations are rejected safely.
8. Unobserved devices are never created.
9. Stale observations are marked appropriately without claiming the device is offline.
"""

import time
import pytest
from pipeline.device_registry import DeviceObservationRegistry, DeviceObservation
from pipeline.live_capture import CapturedPacket, ConnectionRecord


def test_genuine_observed_ip_creates_registry_entry():
    """Test 1: A genuine observed IP creates a registry entry with exact provenance."""
    registry = DeviceObservationRegistry()
    assert registry.count(mode="live") == 0

    obs = registry.record_observation(
        ip="192.168.1.50",
        mac="00:11:22:33:44:55",
        source="Scapy Live Sniff (Real Packet)",
        bytes_len=128,
        protocol="TCP",
        port=443,
        timestamp=1700000000.0,
        mode="live"
    )

    assert obs is not None
    assert registry.count(mode="live") == 1

    devices = registry.get_devices(mode="live")
    assert len(devices) == 1
    dev = devices[0]
    assert dev["ip_address"] == "192.168.1.50"
    assert dev["mac_address"] == "00:11:22:33:44:55"
    assert dev["identity_type"] == "Observed L2/L3 Node"
    assert dev["observation_count"] == 1
    assert dev["bytes_observed"] == 128
    assert "TCP" in dev["protocols_observed"]
    assert 443 in dev["ports_observed"]


def test_repeated_observations_update_counts_and_timestamps():
    """Test 2: Repeated observations update counts and last-seen timestamps correctly."""
    registry = DeviceObservationRegistry()
    t1 = 1700000000.0
    t2 = 1700000010.0

    registry.record_observation(ip="10.0.0.5", bytes_len=100, timestamp=t1, mode="live")
    registry.record_observation(ip="10.0.0.5", bytes_len=200, timestamp=t2, mode="live")

    assert registry.count(mode="live") == 1
    dev = registry.get_device_by_ip("10.0.0.5", mode="live")
    assert dev is not None
    assert dev["observation_count"] == 2
    assert dev["first_seen"] == t1
    assert dev["last_seen"] == t2
    assert dev["bytes_observed"] == 300


def test_missing_mac_addresses_remain_unknown():
    """Test 3: Missing MAC addresses remain unknown (None) rather than fabricated."""
    registry = DeviceObservationRegistry()
    registry.record_observation(
        ip="8.8.8.8",
        mac=None,
        source="Real Packet Capture",
        bytes_len=64,
        mode="live"
    )

    dev = registry.get_device_by_ip("8.8.8.8", mode="live")
    assert dev is not None
    assert dev["mac_address"] is None
    assert dev["identity_type"] == "Observed IP Endpoint"
    assert "MAC unavailable across L3 gateway/NAT" in dev["attribution_notes"]


def test_offline_pcap_observations_remain_marked_historical():
    """Test 4: Offline PCAP observations remain marked historical and quarantined."""
    registry = DeviceObservationRegistry()
    hist_time = 1600000000.0

    pkt = CapturedPacket(
        pkt_id=1,
        timestamp=hist_time,
        src_ip="172.16.0.10",
        dst_ip="172.16.0.1",
        sport=5000,
        dport=80,
        proto="TCP",
        length=74,
        observation_source="Offline PCAP File (Historical)"
    )

    registry.record_packet(pkt, mode="pcap")

    # Must be in pcap mode, NEVER in live mode
    assert registry.count(mode="live") == 0
    assert registry.count(mode="pcap") == 2

    pcap_dev = registry.get_device_by_ip("172.16.0.10", mode="pcap")
    assert pcap_dev is not None
    assert pcap_dev["mode"] == "pcap"
    assert pcap_dev["status"] == "Historical record"
    assert pcap_dev["first_seen"] == hist_time


def test_connection_metadata_not_represented_as_packets():
    """Test 5: Connection metadata is not represented as captured packets."""
    registry = DeviceObservationRegistry()
    conn = ConnectionRecord(
        record_id=1,
        timestamp=1700000050.0,
        proto="TCP",
        local_ip="192.168.1.3",
        local_port=54321,
        foreign_ip="142.250.190.46",
        foreign_port=443,
        state="ESTABLISHED",
        pid=1234
    )

    registry.record_connection(conn)

    # Must be quarantined in connection_metadata mode
    assert registry.count(mode="live") == 0
    assert registry.count(mode="connection_metadata") == 2

    conn_dev = registry.get_device_by_ip("142.250.190.46", mode="connection_metadata")
    assert conn_dev is not None
    assert conn_dev["identity_type"] == "Operating-system connection endpoint"
    assert "Operating System Connection Table" in conn_dev["observation_source"]
    # Byte volume must be None because netstat does not measure packet bytes
    assert conn_dev["bytes_observed"] is None
    assert "Byte volume and frame MAC not available" in conn_dev["attribution_notes"]


def test_simulation_cannot_contaminate_live():
    """Test 6: Simulation observations cannot contaminate live records."""
    registry = DeviceObservationRegistry()

    # Record simulation packet
    sim_pkt = CapturedPacket(
        pkt_id=100,
        timestamp=time.time(),
        src_ip="192.168.1.185",
        dst_ip="10.0.0.45",
        sport=44444,
        dport=80,
        proto="TCP",
        length=64,
        observation_source="Simulation Engine (Test Only)"
    )
    registry.record_packet(sim_pkt, mode="simulation")

    # Verify strict quarantine
    assert registry.count(mode="live") == 0
    assert registry.count(mode="simulation") == 2

    live_query = registry.get_device_by_ip("192.168.1.185", mode="live")
    assert live_query is None

    sim_query = registry.get_device_by_ip("192.168.1.185", mode="simulation")
    assert sim_query is not None
    assert sim_query["mode"] == "simulation"
    assert sim_query["status"] == "Simulated endpoint (Testing)"


def test_invalid_observations_rejected_safely():
    """Test 7: Invalid observations (bad IPs, broadcast, wildcard) are rejected safely."""
    registry = DeviceObservationRegistry()

    # Rejection of invalid / wildcard IPs
    assert registry.record_observation(ip="0.0.0.0", mode="live") is None
    assert registry.record_observation(ip="255.255.255.255", mode="live") is None
    assert registry.record_observation(ip="*", mode="live") is None
    assert registry.record_observation(ip="::", mode="live") is None
    assert registry.record_observation(ip="not_an_ip", mode="live") is None
    assert registry.record_observation(ip="", mode="live") is None
    assert registry.record_observation(ip=None, mode="live") is None

    # Registry remains completely empty
    assert registry.count(mode="live") == 0


def test_unobserved_devices_never_created():
    """Test 8: Unobserved devices are never created; no placeholder lists."""
    registry = DeviceObservationRegistry()
    assert registry.get_devices(mode="live") == []
    assert registry.get_device_by_ip("192.168.1.1", mode="live") is None
    assert registry.count(mode="live") == 0


def test_stale_observations_marked_appropriately():
    """Test 9: Stale observations are marked 'No recent observations', never claimed offline."""
    registry = DeviceObservationRegistry(recency_threshold=30.0)
    current_time = time.time()
    
    # 1. Recent observation (10 seconds ago)
    registry.record_observation(
        ip="192.168.1.100",
        timestamp=current_time - 10.0,
        mode="live"
    )
    dev_recent = registry.get_device_by_ip("192.168.1.100", mode="live")
    assert dev_recent["status"] == "Recently observed"

    # 2. Stale observation (45 seconds ago, beyond 30s threshold)
    registry.record_observation(
        ip="192.168.1.200",
        timestamp=current_time - 45.0,
        mode="live"
    )
    dev_stale = registry.get_device_by_ip("192.168.1.200", mode="live")
    assert dev_stale["status"] == "No recent observations"
    # Evidence must NOT be deleted
    assert dev_stale["observation_count"] == 1
    assert dev_stale["ip_address"] == "192.168.1.200"
