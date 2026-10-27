"""
Unit Tests for Real-Data-Only SOC Telemetry & Manager (Phase 3)
Tests:
1. Empty live registry returns no devices.
2. Missing Npcap produces unavailable/error status, not fake traffic.
3. Packet counters reflect actual supplied observations.
4. Byte counters use real packet lengths.
5. No hardcoded baseline counters (605/101/31) remain in live telemetry.
6. No random events or fabricated alerts enter live mode.
7. Simulation data cannot contaminate live telemetry.
8. Historical PCAP data remains explicitly historical.
9. Connection metadata is not counted as captured packets.
10. Empty topology contains no sample devices.
11. Unknown metrics remain unavailable rather than being presented as verified zeros.
12. Existing public API contracts are preserved.
"""

import time
import pytest
from dashboard.soc_manager import SOCTrafficManager
from pipeline.device_registry import DeviceObservationRegistry
from pipeline.live_capture import CapturedPacket, ConnectionRecord


def test_empty_live_registry_returns_empty_topology():
    """Test 1 & 10: Empty live registry returns an empty topology with 0 nodes and 0 edges."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    topo = soc.get_topology(mode="live")
    assert topo["node_count"] == 0
    assert topo["edge_count"] == 0
    assert topo["nodes"] == []
    assert topo["edges"] == []
    assert "Empty state" in topo["layout_metadata"]


def test_missing_npcap_produces_error_status_not_fake_traffic():
    """Test 2: Missing Npcap or capture error produces honest error status, not fake 24.5 pps or fake bytes."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    capture_status = {
        "is_capturing": False,
        "capture_mode": "live",
        "capture_status": "CAPTURE ERROR",
        "last_error": "Npcap packet capture driver is not installed on this system.",
        "recovery_instruction": "Download Npcap from https://npcap.com",
        "actual_packets_captured": 0,
        "total_bytes": 0,
        "packet_rate": 0.0,
        "uptime_seconds": 0
    }

    overview = soc.get_traffic_overview(capture_status=capture_status, mode="live")

    # Packet counts must be strictly 0, not 605/101/31
    assert overview["traffic_counts"]["total"] == 0
    assert overview["traffic_counts"]["normal"] == 0
    assert overview["traffic_counts"]["suspicious"] == 0
    assert overview["traffic_counts"]["malicious"] == 0

    # Network stats must reflect genuine state
    net_stats = overview["network_stats"]
    assert net_stats["packet_rate"] == 0.0
    assert net_stats["total_bytes"] == 0
    assert net_stats["capture_status"] == "CAPTURE ERROR"
    assert "Npcap packet capture driver is not installed" in net_stats["last_error"]
    assert "Unavailable" in net_stats["data_source"]

    # Threat stats must be unavailable
    threat_stats = overview["threat_stats"]
    assert not threat_stats["prediction_available"]
    assert threat_stats["threat_index"] is None
    assert threat_stats["risk_level"] == "UNAVAILABLE"
    assert "insufficient validated real traffic data" in threat_stats["formatted_output"]


def test_packet_and_byte_counters_reflect_actual_observations():
    """Test 3 & 4: Packet and byte counters reflect actual measured values."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    capture_status = {
        "is_capturing": True,
        "capture_mode": "live",
        "capture_status": "CAPTURING REAL PACKETS",
        "selected_interface_name": "Wi-Fi",
        "actual_packets_captured": 42,
        "total_bytes": 26880,
        "packet_rate": 14.5,
        "uptime_seconds": 3.0
    }

    overview = soc.get_traffic_overview(capture_status=capture_status, mode="live")
    assert overview["traffic_counts"]["total"] == 42
    assert overview["network_stats"]["total_bytes"] == 26880
    assert overview["network_stats"]["packet_rate"] == 14.5
    assert overview["network_stats"]["bandwidth_kbps"] > 0


def test_no_hardcoded_baseline_counters_remain():
    """Test 5: Verified that 605, 101, 31 do not exist anywhere in live telemetry."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    assert not hasattr(soc, "base_normal")
    assert not hasattr(soc, "base_suspicious")
    assert not hasattr(soc, "base_malicious")

    status = {"is_capturing": False, "capture_mode": "live", "actual_packets_captured": 0, "total_bytes": 0, "packet_rate": 0.0}
    overview = soc.get_traffic_overview(status, mode="live")
    tc = overview["traffic_counts"]
    assert tc["normal"] != 605
    assert tc["suspicious"] != 101
    assert tc["malicious"] != 31


def test_no_random_events_or_fabricated_alerts_in_live():
    """Test 6: No pre-seeded fake threat logs (SEC-9842, Kali probes, etc.) enter live mode."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    logs = soc.get_threat_logs(mode="live")
    assert len(logs) == 0

    overview = soc.get_traffic_overview({"is_capturing": False, "capture_mode": "live"}, mode="live")
    assert overview["active_alert"] is None


def test_simulation_cannot_contaminate_live():
    """Test 7: Simulation endpoints and data cannot contaminate live topology or telemetry."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    # Insert simulated packet into registry under simulation mode
    sim_pkt = CapturedPacket(
        pkt_id=1,
        timestamp=time.time(),
        src_ip="192.168.1.185",
        dst_ip="10.0.0.45",
        sport=50000,
        dport=80,
        proto="TCP",
        length=64,
        observation_source="Simulation Engine (Test Only)"
    )
    registry.record_packet(sim_pkt, mode="simulation")

    # Live query must remain completely empty!
    live_topo = soc.get_topology(mode="live")
    assert live_topo["node_count"] == 0

    # Simulation query sees the nodes
    sim_topo = soc.get_topology(mode="simulation")
    assert sim_topo["node_count"] == 2


def test_historical_pcap_remains_explicitly_historical():
    """Test 8: Historical PCAP data remains labeled historical and quarantined."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    pcap_status = {
        "is_capturing": True,
        "capture_mode": "pcap",
        "capture_status": "OFFLINE PCAP MODE",
        "actual_packets_captured": 37,
        "total_bytes": 2368,
        "packet_rate": 0.0
    }

    overview = soc.get_traffic_overview(pcap_status, mode="pcap")
    assert overview["network_stats"]["source_type"] == "HISTORICAL"
    assert "Historical PCAP" in overview["network_stats"]["data_source"]


def test_connection_metadata_not_counted_as_captured_packets():
    """Test 9: Connection metadata is labeled as OS connections, not captured packets."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    conn = ConnectionRecord(
        record_id=1,
        timestamp=time.time(),
        proto="TCP",
        local_ip="192.168.1.3",
        local_port=8080,
        foreign_ip="1.1.1.1",
        foreign_port=443,
        state="ESTABLISHED"
    )
    registry.record_connection(conn)

    conn_status = {
        "is_capturing": True,
        "capture_mode": "connection_metadata",
        "capture_status": "CONNECTION METADATA MODE",
        "actual_packets_captured": 0,  # 0 packets captured!
        "total_bytes": 0,
        "packet_rate": 0.0
    }

    overview = soc.get_traffic_overview(conn_status, mode="connection_metadata")
    assert overview["network_stats"]["source_type"] == "CONNECTION_METADATA"
    assert overview["traffic_counts"]["total"] == 0
    assert overview["network_stats"]["active_flows"] == 2


def test_topology_with_real_devices_and_edges():
    """Test 11 & 12: Real observed packets between endpoints build verified topology nodes and edges."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    pkt = CapturedPacket(
        pkt_id=1,
        timestamp=time.time(),
        src_ip="192.168.1.3",
        dst_ip="142.250.190.46",
        sport=54321,
        dport=443,
        proto="TCP",
        length=150,
        observation_source="Scapy Live Sniff (Real Packet)",
        src_mac="20:2b:20:18:b9:45"
    )
    registry.record_packet(pkt, mode="live")

    topo = soc.get_topology(recent_packets=[pkt.to_dict()], mode="live")
    assert topo["node_count"] == 2
    assert topo["edge_count"] == 1

    node_src = next(n for n in topo["nodes"] if n["ip"] == "192.168.1.3")
    assert node_src["mac"] == "20:2b:20:18:b9:45"
    assert node_src["os"] == "Unavailable (Not in raw packet)"
    assert node_src["risk_score"] is None

    edge = topo["edges"][0]
    assert edge["protocol"] == "TCP"
    assert edge["volume"] == 1


def test_authorized_ping_diagnostic_event():
    """Test: Authorized ICMP ping diagnostic creates a verified event log."""
    registry = DeviceObservationRegistry()
    soc = SOCTrafficManager(device_registry=registry)

    soc.inject_live_ping_event(target_ip="8.8.8.8", packet_count=4, local_ip="192.168.1.3")
    logs = soc.get_threat_logs(mode="live")
    assert len(logs) == 1
    log = logs[0]
    assert log["source_ip"] == "192.168.1.3"
    assert log["destination_ip"] == "8.8.8.8"
    assert log["packet_count"] == 4
    assert log["event_type"] == "Authorized Host ICMP Ping Diagnostic"

    # Status update works
    updated = soc.update_log_status(log["id"], "Acknowledged")
    assert updated["status"] == "Acknowledged"
