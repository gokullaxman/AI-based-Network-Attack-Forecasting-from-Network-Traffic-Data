"""
Phase B Verification Test Suite: Connected-Device-Only 3D Visualization & Topology Policy
Tests the explicit, evidence-based connected-device policy:
1. Live device observed recently (within 60s timeout) -> connected (is_connected=True)
2. Live device beyond timeout (>60s) -> disconnected (is_connected=False)
3. Device with no valid timestamp (None, NaN, <=0) -> unknown (is_connected=False)
4. Device with implausible future timestamp (>60s future skew) -> unknown (is_connected=False)
5. PCAP / replay record -> historical (is_connected=False)
6. Simulation record -> unknown / quarantined (is_connected=False)
7. Disconnected device excluded from connected topology view
8. Cleanup of orphaned edges when an endpoint disconnects
9. Accurate connected-node counts and empty state verification
10. Server API contracts for /api/soc/topology and /api/soc/devices
"""

import time
import math
import pytest
from fastapi.testclient import TestClient
from pipeline.device_registry import (
    DeviceObservationRegistry,
    DeviceObservation,
    CONNECTED_DEVICE_TIMEOUT_SECONDS
)
from dashboard.soc_manager import SOCTrafficManager
from dashboard.server import app


@pytest.fixture
def registry():
    return DeviceObservationRegistry(recency_threshold=60.0)


@pytest.fixture
def soc(registry):
    return SOCTrafficManager(device_registry=registry)


@pytest.fixture
def client():
    return TestClient(app)


def test_recently_observed_live_device_is_connected(registry, soc):
    """Case 1: Live device observed recently (e.g. 5s ago) must be connected."""
    now = time.time()
    registry.record_observation(
        ip="192.168.1.50",
        mac="00:11:22:33:44:55",
        timestamp=now - 5.0,
        mode="live"
    )

    devices = registry.get_devices(mode="live", current_time=now)
    assert len(devices) == 1
    dev = devices[0]
    assert dev["is_connected"] is True
    assert dev["connection_status"] == "connected"
    assert dev["connectivity_source"] == "Real Packet Capture"
    assert "within 60.0s timeout" in dev["connectivity_reason"]

    # In topology
    topo = soc.get_topology(registry=registry, mode="live")
    assert topo["connected_device_count"] == 1
    assert topo["nodes"][0]["is_connected"] is True
    assert topo["nodes"][0]["status"] == "connected"


def test_live_device_beyond_timeout_is_disconnected(registry, soc):
    """Case 2: Live device observed 120s ago (> 60s timeout) must be disconnected."""
    now = time.time()
    registry.record_observation(
        ip="192.168.1.60",
        mac="00:11:22:33:44:66",
        timestamp=now - 120.0,
        mode="live"
    )

    devices = registry.get_devices(mode="live", current_time=now)
    assert len(devices) == 1
    dev = devices[0]
    assert dev["is_connected"] is False
    assert dev["connection_status"] == "disconnected"
    assert "exceeded 60.0s timeout" in dev["connectivity_reason"]

    # In connected_only topology view, disconnected node must be excluded
    connected_topo = soc.get_topology(registry=registry, mode="live", connected_only=True)
    assert connected_topo["connected_device_count"] == 0
    assert len(connected_topo["nodes"]) == 0

    # In regular topology query, device has explicit is_connected=False
    all_topo = soc.get_topology(registry=registry, mode="live", connected_only=False)
    assert all_topo["connected_device_count"] == 0
    assert len(all_topo["nodes"]) == 1
    assert all_topo["nodes"][0]["is_connected"] is False
    assert all_topo["nodes"][0]["status"] == "disconnected"


def test_device_with_no_valid_timestamp_is_unknown(registry):
    """Case 3: Device with None, NaN, or non-positive timestamp must be unknown."""
    now = time.time()
    # Create observation directly with invalid timestamps
    obs_none = DeviceObservation(
        ip_address="192.168.1.71",
        mode="live",
        first_seen=0.0,
        last_seen=0.0
    )
    obs_none.last_seen = None
    conn_none = obs_none.get_connectivity(current_time=now)
    assert conn_none["is_connected"] is False
    assert conn_none["connection_status"] == "unknown"

    obs_nan = DeviceObservation(
        ip_address="192.168.1.72",
        mode="live",
        first_seen=now,
        last_seen=float("nan")
    )
    conn_nan = obs_nan.get_connectivity(current_time=now)
    assert conn_nan["is_connected"] is False
    assert conn_nan["connection_status"] == "unknown"


def test_implausibly_future_timestamp_is_unknown(registry):
    """Case 4: Timestamp far in the future (> 60s ahead) indicates clock corruption; must be unknown."""
    now = time.time()
    obs_future = DeviceObservation(
        ip_address="192.168.1.80",
        mode="live",
        first_seen=now,
        last_seen=now + 500.0  # 500s in the future
    )
    conn = obs_future.get_connectivity(current_time=now)
    assert conn["is_connected"] is False
    assert conn["connection_status"] == "unknown"
    assert "Implausible Future Timestamp" in conn["connectivity_source"]


def test_pcap_replay_device_is_historical(registry, soc):
    """Case 5: Offline PCAP trace endpoints must be labeled historical and never live-connected."""
    now = time.time()
    registry.record_observation(
        ip="10.0.0.100",
        timestamp=now,
        mode="pcap"
    )

    devices = registry.get_devices(mode="pcap", current_time=now)
    assert len(devices) == 1
    dev = devices[0]
    assert dev["is_connected"] is False
    assert dev["connection_status"] == "historical"
    assert dev["connectivity_source"] == "Offline PCAP trace"

    # PCAP devices must never appear in live registry
    live_devices = registry.get_devices(mode="live", current_time=now)
    assert len(live_devices) == 0

    # In connected topology, historical device count is 0
    topo = soc.get_topology(registry=registry, mode="pcap", connected_only=True)
    assert topo["connected_device_count"] == 0
    assert len(topo["nodes"]) == 0


def test_simulation_device_is_quarantined_from_connected_live(registry, soc):
    """Case 6: Testing simulation endpoint must not be classified as connected live device."""
    now = time.time()
    registry.record_observation(
        ip="172.16.0.5",
        timestamp=now,
        mode="simulation"
    )

    devices = registry.get_devices(mode="simulation", current_time=now)
    assert len(devices) == 1
    dev = devices[0]
    assert dev["is_connected"] is False
    assert dev["connection_status"] == "unknown"
    assert "Simulation" in dev["connectivity_source"]

    # Simulation nodes must not enter live registry
    live_devices = registry.get_devices(mode="live", current_time=now)
    assert len(live_devices) == 0

    # Connected count for simulation is 0
    topo = soc.get_topology(registry=registry, mode="simulation", connected_only=True)
    assert topo["connected_device_count"] == 0
    assert len(topo["nodes"]) == 0


def test_disconnected_device_excluded_and_orphaned_edges_pruned(registry, soc):
    """Case 7 & 8: When one node disconnects, connected view excludes it and removes orphaned edges."""
    now = time.time()
    # Node A is active (last seen 5s ago)
    registry.record_observation(ip="192.168.1.10", timestamp=now - 5.0, mode="live")
    # Node B was active (last seen 150s ago, timed out)
    registry.record_observation(ip="192.168.1.20", timestamp=now - 150.0, mode="live")

    # Recent traffic packet between A and B
    recent_pkts = [{
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "proto": "TCP"
    }]

    # In connected_only view:
    # Node A is connected, Node B is excluded
    # The edge between A and B MUST be eliminated because B is not in the connected topology
    topo = soc.get_topology(
        recent_packets=recent_pkts,
        registry=registry,
        mode="live",
        connected_only=True
    )

    assert topo["connected_device_count"] == 1
    assert len(topo["nodes"]) == 1
    assert topo["nodes"][0]["ip"] == "192.168.1.10"
    assert topo["nodes"][0]["is_connected"] is True

    # Edge must be pruned (no orphaned edges allowed!)
    assert topo["edge_count"] == 0
    assert len(topo["edges"]) == 0


def test_empty_state_and_counters_match_connected_count(registry, soc):
    """Case 9: When no devices are connected, empty state is truthful and counts are 0."""
    topo = soc.get_topology(registry=registry, mode="live", connected_only=True)
    assert topo["connected_device_count"] == 0
    assert topo["node_count"] == 0
    assert topo["edge_count"] == 0
    assert len(topo["nodes"]) == 0
    assert len(topo["edges"]) == 0
    assert "Empty state" in topo["layout_metadata"]


def test_api_soc_topology_and_devices_expose_connectivity_contracts(client):
    """Case 10: Server endpoints /api/soc/topology and /api/soc/devices expose is_connected."""
    # Reset capture / registry
    client.post("/api/capture/clear")

    res_topo = client.get("/api/soc/topology?connected_only=true")
    assert res_topo.status_code == 200
    json_topo = res_topo.json()
    assert "connected_device_count" in json_topo
    assert "timeout_seconds" in json_topo
    assert json_topo["connected_device_count"] == 0
    assert len(json_topo["nodes"]) == 0

    res_devs = client.get("/api/soc/devices?mode=live")
    assert res_devs.status_code == 200
    json_devs = res_devs.json()
    assert "connected_count" in json_devs
    assert "devices" in json_devs
    assert json_devs["connected_count"] == 0
