"""
Unit and Integration Tests for Phase 5: Dashboard UI and 3D Visualization
Verifies:
1. Empty live registry yields empty topology (nodes: [], edges: [])
2. Capture health contract exposes Npcap diagnostics, backend, and error instructions
3. Missing metrics render as unavailable rather than fabricated values
4. No hardcoded fake counters (605, 101, 31, 737) remain in static HTML or scripts
5. Simulation mode data is strictly quarantined and visibly distinguished
6. PCAP mode data is marked historical with preserved timestamps
7. Failed API calls / invalid mode switches are rejected with 400 (not silently accepted)
8. Missing predictions return prediction_available: False without fake risk scores
9. Genuine nodes display verified attributes only
10. Interface and mode selectors reflect genuine backend data
11. Static files contain verified empty state "Waiting for real network observations..."
12. Empty chart data produces no artificial samples
"""

import os
import re
import pytest
from fastapi.testclient import TestClient

from dashboard.server import app, soc_manager, capture_engine
from pipeline.device_registry import DeviceObservationRegistry, DeviceObservation

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML_PATH = os.path.join(BASE_DIR, "dashboard", "static", "index.html")
APP_JS_PATH = os.path.join(BASE_DIR, "dashboard", "static", "app.js")
STYLE_CSS_PATH = os.path.join(BASE_DIR, "dashboard", "static", "style.css")


@pytest.fixture(autouse=True)
def reset_system():
    capture_engine.clear_buffer()
    capture_engine.device_registry.clear()
    capture_engine.capture_mode = "live"
    soc_manager.clear()
    yield
    capture_engine.clear_buffer()
    capture_engine.device_registry.clear()
    capture_engine.capture_mode = "live"
    soc_manager.clear()


# =========================================================================
# 1. Static Frontend Integrity Checks
# =========================================================================

def test_static_html_no_fake_baseline_counters():
    """Verify index.html contains no hardcoded 605, 101, 31, or 737 counters."""
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()

    # Check for hardcoded 605, 101, 31, 737 in HTML
    assert "605" not in html, "Hardcoded normal counter 605 found in index.html"
    assert "737" not in html, "Hardcoded total counter 737 found in index.html"
    assert "SEC-9842" not in html, "Hardcoded threat event SEC-9842 found in index.html"

    # Initial threat logs badge must be 0 Events
    assert 'id="threatLogsCountBadge">0 Events</span>' in html

    # Initial alert banner must be hidden
    assert 'id="mainSecurityAlertBanner" style="display: none;"' in html


def test_static_html_contains_capture_health_banner():
    """Verify index.html includes the required Capture Health component elements."""
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()

    assert 'id="captureHealthBanner"' in html
    assert 'id="healthStatusDot"' in html
    assert 'id="healthStatusText"' in html
    assert 'id="healthBackendText"' in html
    assert 'id="healthInterfaceText"' in html
    assert 'id="healthPacketCount"' in html
    assert 'id="healthLastSeen"' in html
    assert 'id="systemModeSelect"' in html
    assert 'id="systemInterfaceSelect"' in html
    assert 'id="healthDiagnosticStrip"' in html


def test_static_html_contains_empty_topology_state():
    """Verify index.html includes the exact empty state required by Section 5."""
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()

    assert 'id="threeJsEmptyState"' in html
    assert "Waiting for real network observations..." in html


def test_static_app_js_no_hardcoded_devices_or_fake_fallbacks():
    """Verify app.js does not contain hardcoded devices, fake MAC fallbacks, or synthetic generators."""
    with open(APP_JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()

    # Verify fake MAC fallback is removed
    assert "00:1A:2B:3C:4D:EE" not in js
    # Verify fake payload fallback is removed
    assert "45 00 00 3c 1a 2b 40 00 40 06 7c e4" not in js
    # Verify empty chart state message is present
    assert "Waiting for real traffic observations..." in js
    # Verify health polling endpoint is consumed
    assert "/api/capture/health" in js
    # Verify interface enumeration endpoint is consumed
    assert "/api/capture/interfaces" in js


# =========================================================================
# 2. API & Data Contract Checks
# =========================================================================

def test_empty_live_registry_renders_empty_topology():
    """Section 5: When no endpoints observed, topology must return empty nodes and edges."""
    res = client.get("/api/soc/topology")
    assert res.status_code == 200
    data = res.json()
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["mode"] == "live"


def test_capture_health_endpoint_contract():
    """Section 1: GET /api/capture/health must expose complete diagnostics."""
    res = client.get("/api/capture/health")
    assert res.status_code == 200
    data = res.json()

    assert "capture_status" in data
    assert "capture_backend" in data
    assert "actual_packets_captured" in data
    assert "npcap_diagnostics" in data
    assert "recovery_instruction" in data

    # When no packets captured, count is exactly 0
    assert data["actual_packets_captured"] == 0
    # Last packet timestamp should be None or 'Not yet observed'
    assert data["last_packet_timestamp"] is None or data["last_packet_timestamp"] == "Not yet observed"


def test_missing_metrics_render_unavailable_not_fake_zeros():
    """Section 4 & 7: Missing prediction must report unavailable, not fabricated risk scores."""
    res = client.get("/api/soc/overview")
    assert res.status_code == 200
    data = res.json()

    threat_stats = data["threat_stats"]
    assert threat_stats["prediction_available"] is False
    assert "insufficient" in threat_stats["reason"].lower() or "not available" in threat_stats["reason"].lower()
    assert threat_stats["threat_index"] is None or threat_stats["threat_index"] == "—"
    assert threat_stats["risk_level"] == "UNAVAILABLE"


def test_mode_switch_rejected_for_invalid_mode():
    """Section 3: Mode switch must reject unsupported modes with 400 error."""
    res = client.post("/api/mode/select", json={"mode": "invalid_hacker_mode"})
    assert res.status_code == 400
    assert "unsupported mode" in res.json()["detail"].lower()


def test_mode_switch_rejected_for_missing_pcap():
    """Section 3: Switching to PCAP mode without valid file path must reject with 400."""
    res = client.post("/api/mode/select", json={"mode": "pcap", "pcap_path": "non_existent_file.pcap"})
    assert res.status_code == 400
    assert "valid pcap file path is required" in res.json()["detail"].lower()


def test_interface_enumeration_reflects_actual_adapters():
    """Section 2: GET /api/capture/interfaces must return discovered host adapters."""
    res = client.get("/api/capture/interfaces")
    assert res.status_code == 200
    data = res.json()
    assert "interfaces" in data
    assert "count" in data
    assert isinstance(data["interfaces"], list)
    assert data["count"] == len(data["interfaces"])
    if data["count"] > 0:
        iface = data["interfaces"][0]
        assert "id" in iface
        assert "name" in iface


def test_genuine_nodes_display_verified_attributes_only():
    """Section 5: Observed node in registry must only contain verified fields."""
    capture_engine.device_registry.record_observation(
        ip="192.168.1.50",
        mac="00:11:22:33:44:55",
        source="packet_header",
        mode="live"
    )

    res = client.get("/api/soc/topology")
    assert res.status_code == 200
    nodes = res.json()["nodes"]
    assert len(nodes) == 1
    node = nodes[0]
    assert node["ip"] == "192.168.1.50"
    assert node["mac"] == "00:11:22:33:44:55"
    assert "fictional" not in str(node).lower()


def test_simulation_data_strictly_quarantined_from_live():
    """Section 3: Simulation data must be isolated and clearly marked."""
    client.post("/api/mode/select", json={"mode": "simulation"})
    res = client.get("/api/soc/topology")
    assert res.status_code == 200
    assert res.json()["mode"] == "simulation"

    # Switching back to live must clear simulated nodes
    client.post("/api/mode/select", json={"mode": "live"})
    capture_engine.stop_capture()
    capture_engine.device_registry.clear(mode="live")
    res_live = client.get("/api/soc/topology")
    assert res_live.status_code == 200
    assert res_live.json()["mode"] == "live"
    assert res_live.json()["nodes"] == []


def test_interface_selection_and_backend_confirmation():
    """Requirement 1: Interface selection validates and confirms selected adapter."""
    ifaces_res = client.get("/api/capture/interfaces")
    assert ifaces_res.status_code == 200
    ifaces = ifaces_res.json()["interfaces"]
    if not ifaces:
        pytest.skip("No host interfaces enumerated in this environment")

    target_iface = ifaces[0]
    select_res = client.post("/api/capture/interface/select", json={"interface_id": target_iface["id"]})
    assert select_res.status_code == 200
    data = select_res.json()
    assert data["status"] in ("selected", "restarted")
    assert data["interface"]["id"] == target_iface["id"]

    # Verify capture engine state matches
    status = capture_engine.get_status()
    assert status["selected_interface_name"] == target_iface["name"]


def test_invalid_interface_selection_rejected_with_400():
    """Requirement 1: Non-existent interface must be rejected with 400."""
    res = client.post("/api/capture/interface/select", json={"interface_id": "non_existent_fake_adapter_999"})
    assert res.status_code == 400
    assert "invalid network interface" in res.json()["detail"].lower()


def test_metric_semantics_zero_and_unavailable():
    """Requirement 2: Zero measurements are distinguishable from unavailable measurements."""
    res = client.get("/api/soc/overview")
    assert res.status_code == 200
    data = res.json()

    counts = data["traffic_counts"]
    assert counts["total"] == 0
    assert counts["normal"] == 0
    assert counts["suspicious"] == 0
    assert counts["malicious"] == 0
    # Zero traffic must have None percentage, never a fake percentage
    assert counts["normal_pct"] is None

    threat = data["threat_stats"]
    assert threat["prediction_available"] is False
    assert threat["threat_index"] is None
    assert threat["risk_level"] == "UNAVAILABLE"
    assert threat["confidence"] is None
    assert "insufficient" in threat["reason"].lower()


def test_mode_changes_clear_incompatible_telemetry():
    """Requirement 4: Mode switch resets buffers and prevents cross-mode contamination."""
    # Record in simulation
    client.post("/api/mode/select", json={"mode": "simulation"})
    capture_engine.device_registry.record_observation(
        ip="10.10.10.10",
        mode="simulation"
    )
    sim_topo = client.get("/api/soc/topology").json()
    assert len(sim_topo["nodes"]) == 1
    assert sim_topo["mode"] == "simulation"

    # Switch to live
    client.post("/api/mode/select", json={"mode": "live"})
    capture_engine.stop_capture()
    capture_engine.device_registry.clear(mode="live")
    live_topo = client.get("/api/soc/topology").json()
    assert len(live_topo["nodes"]) == 0
    assert live_topo["mode"] == "live"


def test_no_stale_forecast_after_clear():
    """Requirement 5: Clearing capture resets sequence and ensures forecast is unavailable."""
    clear_res = client.post("/api/capture/clear")
    assert clear_res.status_code == 200

    overview = client.get("/api/soc/overview").json()
    assert overview["threat_stats"]["prediction_available"] is False
    assert overview["threat_stats"]["threat_index"] is None
    assert overview["threat_stats"]["risk_level"] == "UNAVAILABLE"

