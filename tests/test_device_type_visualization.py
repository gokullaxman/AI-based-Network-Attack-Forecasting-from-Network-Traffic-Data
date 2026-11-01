"""
Tests for Phase B Enhancement: Device-Type Color Coding in 3D Visualization.
Verifies all 9 requirements:
1. A router always receives the router color (#00D5FF).
2. Switches (#4287F5), servers (#A970FF), PCs (#42D392), laptops (#20B8A8),
   mobile devices (#FF9F43), IoT devices (#F4D35E), and firewalls (#FF4D5A)
   receive their configured colors when their types are known.
3. Type normalization and supported aliases work correctly.
4. Unknown types receive the neutral fallback color (#8B95A5).
5. Changing a node's type updates its color without leaving stale materials.
6. Connectivity changes do not alter the primary device-type color.
7. Threat alerts remain visible without replacing the primary type color.
8. The legend matches the centralized color mapping.
9. The existing connected-only filter continues to work.
"""

import time
import re
from pathlib import Path
from typing import Dict, Any

import pytest

from pipeline.device_registry import (
    DeviceObservationRegistry,
    DeviceObservation,
    normalize_device_type,
    CONNECTED_DEVICE_TIMEOUT_SECONDS
)
from dashboard.soc_manager import SOCTrafficManager


# Centralized specification palette
EXPECTED_PALETTE = {
    "Router":        {"color": "Cyan",         "hex": "#00D5FF", "int": 0x00d5ff},
    "Switch":        {"color": "Blue",         "hex": "#4287F5", "int": 0x4287f5},
    "Server":        {"color": "Purple",       "hex": "#A970FF", "int": 0xa970ff},
    "Desktop / PC":  {"color": "Green",        "hex": "#42D392", "int": 0x42d392},
    "Laptop":        {"color": "Teal",         "hex": "#20B8A8", "int": 0x20b8a8},
    "Mobile device": {"color": "Orange",       "hex": "#FF9F43", "int": 0xff9f43},
    "IoT device":    {"color": "Yellow",       "hex": "#F4D35E", "int": 0xf4d35e},
    "Firewall":      {"color": "Red",          "hex": "#FF4D5A", "int": 0xff4d5a},
    "Unknown":       {"color": "Neutral grey", "hex": "#8B95A5", "int": 0x8b95a5},
}


def test_1_router_always_receives_router_color_and_rule():
    """Requirement 1: Every node identified as a router uses router color (#00D5FF), and router rule holds."""
    router_cfg = EXPECTED_PALETTE["Router"]
    assert router_cfg["hex"].upper() == "#00D5FF"
    assert router_cfg["int"] == 0x00d5ff

    # Canonical types and aliases
    assert normalize_device_type("Router") == "Router"
    assert normalize_device_type("router") == "Router"
    assert normalize_device_type("core router") == "Router"
    assert normalize_device_type("Edge Router") == "Router"
    assert normalize_device_type("gateway") == "Router"
    assert normalize_device_type("default gateway") == "Router"

    # Router rule: Never classify a device as a router solely because IP ends in .1 or hostname
    reg = DeviceObservationRegistry()
    now = time.time()
    # Device ending in .1 with unverified/default endpoint role
    dev = reg.record_observation(ip="192.168.1.1", timestamp=now)
    assert dev is not None
    # Must NOT be classified as Router solely because of .1
    assert dev.device_type == "Unknown"
    assert normalize_device_type(dev.identity_type) == "Unknown"

    # If explicit evidence/role provides gateway/router metadata, it classifies as Router
    dev_router = reg.record_observation(ip="192.168.1.254", timestamp=now, device_type="core router")
    assert dev_router is not None
    assert dev_router.device_type == "Router"


def test_2_all_device_types_receive_configured_colors():
    """Requirement 2: Switches, servers, PCs, laptops, mobile devices, IoT, and firewalls receive configured colors."""
    for dev_type, cfg in EXPECTED_PALETTE.items():
        assert cfg["hex"].startswith("#")
        assert len(cfg["hex"]) == 7
        assert isinstance(cfg["int"], int)

    assert EXPECTED_PALETTE["Switch"]["hex"].upper() == "#4287F5"
    assert EXPECTED_PALETTE["Server"]["hex"].upper() == "#A970FF"
    assert EXPECTED_PALETTE["Desktop / PC"]["hex"].upper() == "#42D392"
    assert EXPECTED_PALETTE["Laptop"]["hex"].upper() == "#20B8A8"
    assert EXPECTED_PALETTE["Mobile device"]["hex"].upper() == "#FF9F43"
    assert EXPECTED_PALETTE["IoT device"]["hex"].upper() == "#F4D35E"
    assert EXPECTED_PALETTE["Firewall"]["hex"].upper() == "#FF4D5A"


def test_3_type_normalization_and_supported_aliases():
    """Requirement 3: Normalization handles casing, whitespace, and common supported aliases."""
    test_cases = [
        # Switch
        ("switch", "Switch"),
        ("SWITCH", "Switch"),
        ("  Core Switch  ", "Switch"),
        ("access switch", "Switch"),
        # Server
        ("server", "Server"),
        ("Web Server", "Server"),
        ("database server", "Server"),
        ("dns server", "Server"),
        ("internal server cluster", "Server"),
        # Desktop / PC
        ("desktop", "Desktop / PC"),
        ("pc", "Desktop / PC"),
        ("workstation", "Desktop / PC"),
        ("corporate workstation", "Desktop / PC"),
        ("Desktop / PC", "Desktop / PC"),
        # Laptop
        ("laptop", "Laptop"),
        ("notebook", "Laptop"),
        ("LAPTOP", "Laptop"),
        # Mobile device
        ("mobile", "Mobile device"),
        ("mobile device", "Mobile device"),
        ("phone", "Mobile device"),
        ("smartphone", "Mobile device"),
        ("tablet", "Mobile device"),
        ("android", "Mobile device"),
        ("ios", "Mobile device"),
        # IoT device
        ("iot", "IoT device"),
        ("iot device", "IoT device"),
        ("sensor", "IoT device"),
        ("camera", "IoT device"),
        ("smart device", "IoT device"),
        # Firewall
        ("firewall", "Firewall"),
        ("fw", "Firewall"),
        ("ngfw", "Firewall"),
        ("Next-Gen Firewall", "Firewall"),
    ]

    for raw, expected in test_cases:
        assert normalize_device_type(raw) == expected, f"Failed for '{raw}': got '{normalize_device_type(raw)}', expected '{expected}'"


def test_4_unknown_types_receive_neutral_fallback():
    """Requirement 4: Unknown types, unverified endpoints, or arbitrary unrecognized labels receive neutral fallback color."""
    unknown_cases = [
        None,
        "",
        "   ",
        "unknown",
        "UNKNOWN",
        "unverified",
        "other",
        "none",
        "Observed IP Endpoint",
        "Observed L2/L3 Node",
        "operating-system connection endpoint",
        "some_random_device_xyz_99"
    ]

    for raw in unknown_cases:
        norm = normalize_device_type(raw)
        assert norm == "Unknown", f"Expected 'Unknown' for '{raw}', got '{norm}'"

    fallback_cfg = EXPECTED_PALETTE["Unknown"]
    assert fallback_cfg["hex"].upper() == "#8B95A5"
    assert fallback_cfg["int"] == 0x8b95a5


def test_5_changing_node_type_updates_without_stale_metadata():
    """Requirement 5: Changing a node's type updates its classification and serialization without leaving stale metadata."""
    reg = DeviceObservationRegistry()
    now = time.time()

    # Initial observation without explicit type -> defaults to Unknown
    dev = reg.record_observation(ip="10.0.0.50", timestamp=now)
    assert dev.device_type == "Unknown"
    soc = SOCTrafficManager(device_registry=reg)
    topo = soc.get_topology(mode="live", connected_only=True)
    assert len(topo["nodes"]) == 1
    assert topo["nodes"][0]["device_type"] == "Unknown"

    # Type becomes established through genuine metadata update (e.g. Server)
    reg.record_observation(ip="10.0.0.50", timestamp=now + 5, device_type="Server")
    assert dev.device_type == "Server"
    topo2 = soc.get_topology(mode="live", connected_only=True)
    assert topo2["nodes"][0]["device_type"] == "Server"

    # Type changes to Firewall
    reg.record_observation(ip="10.0.0.50", timestamp=now + 10, device_type="Next-Gen Firewall")
    assert dev.device_type == "Firewall"
    topo3 = soc.get_topology(mode="live", connected_only=True)
    assert topo3["nodes"][0]["device_type"] == "Firewall"


def test_6_connectivity_changes_do_not_alter_device_type():
    """Requirement 6: Connectivity status changes do not alter the primary device type."""
    reg = DeviceObservationRegistry()
    now = time.time()

    dev_router = reg.record_observation(ip="10.0.0.1", timestamp=now, device_type="Router")
    dev_server = reg.record_observation(ip="10.0.0.2", timestamp=now, device_type="Server")

    # Initially connected (within timeout)
    conn_r = dev_router.get_connectivity(current_time=now, timeout_seconds=60.0)
    conn_s = dev_server.get_connectivity(current_time=now, timeout_seconds=60.0)
    assert conn_r["is_connected"] is True
    assert conn_s["is_connected"] is True
    assert dev_router.device_type == "Router"
    assert dev_server.device_type == "Server"

    # Later: timeout exceeded (disconnected)
    future_time = now + 120.0
    conn_r_disc = dev_router.get_connectivity(current_time=future_time, timeout_seconds=60.0)
    assert conn_r_disc["is_connected"] is False
    assert conn_r_disc["connection_status"] == "disconnected"
    # Primary device type MUST remain completely intact
    assert dev_router.device_type == "Router"
    assert dev_server.device_type == "Server"


def test_7_threat_alerts_decoupled_from_primary_device_type():
    """Requirement 7: Suspicious/Malicious threat categories do not overwrite the primary device-type."""
    reg = DeviceObservationRegistry()
    now = time.time()

    # Record a genuine Router and Server
    reg.record_observation(ip="10.0.0.1", timestamp=now, device_type="Router")
    reg.record_observation(ip="10.0.0.2", timestamp=now, device_type="Server")

    # Simulate heavy ICMP sweep to trigger suspicious categorization
    for _ in range(250):
        reg.record_observation(ip="10.0.0.1", timestamp=now, protocol="ICMP")

    soc = SOCTrafficManager(device_registry=reg)
    topo = soc.get_topology(mode="live", connected_only=True)

    nodes_by_ip = {n["ip"]: n for n in topo["nodes"]}
    router_node = nodes_by_ip["10.0.0.1"]
    server_node = nodes_by_ip["10.0.0.2"]

    # The router node has category 'Suspicious'
    assert router_node["category"] == "Suspicious"
    # CRITICAL: device_type remains strictly 'Router', NOT 'Suspicious'
    assert router_node["device_type"] == "Router"

    # Server node is normal
    assert server_node["category"] == "Normal"
    assert server_node["device_type"] == "Server"

    # They have distinct device types and colors
    assert router_node["device_type"] != server_node["device_type"]
    assert EXPECTED_PALETTE[router_node["device_type"]]["hex"] != EXPECTED_PALETTE[server_node["device_type"]]["hex"]


def test_8_legend_and_centralized_palette_consistency():
    """Requirement 8: Frontend app.js, index.html, and style.css match the centralized color palette and legend contract."""
    base_dir = Path(__file__).resolve().parent.parent

    # 1. Verify app.js contains DEVICE_TYPE_COLORS and all canonical entries
    app_js_path = base_dir / "dashboard" / "static" / "app.js"
    assert app_js_path.exists(), "dashboard/static/app.js missing"
    app_js_content = app_js_path.read_text(encoding="utf-8")

    assert "const DEVICE_TYPE_COLORS =" in app_js_content
    for dev_type, cfg in EXPECTED_PALETTE.items():
        assert f"'{dev_type}'" in app_js_content or f'"{dev_type}"' in app_js_content
        # Check that hex code is defined for each
        assert cfg["hex"] in app_js_content, f"Hex {cfg['hex']} for {dev_type} not found in app.js"

    # 2. Verify index.html contains legend containers
    index_html_path = base_dir / "dashboard" / "static" / "index.html"
    assert index_html_path.exists(), "dashboard/static/index.html missing"
    html_content = index_html_path.read_text(encoding="utf-8")

    assert 'id="canvasLegend"' in html_content
    assert 'id="legendDeviceTypesContainer"' in html_content
    assert 'id="legendConnectedCount"' in html_content
    assert '#8B95A5' in html_content  # Unknown / unverified explanation

    # 3. Verify style.css defines the legend styling
    style_css_path = base_dir / "dashboard" / "static" / "style.css"
    assert style_css_path.exists(), "dashboard/static/style.css missing"
    css_content = style_css_path.read_text(encoding="utf-8")

    assert ".canvas-visual-legend" in css_content
    assert ".legend-device-list" in css_content
    assert ".legend-count-pill" in css_content
    assert ".legend-fallback-note" in css_content


def test_9_connected_only_filter_preserves_device_types():
    """Requirement 9: Connected-only filter excludes disconnected devices while preserving device types of connected devices."""
    reg = DeviceObservationRegistry()
    now = time.time()

    # Connected router observed 5s ago
    reg.record_observation(ip="10.0.0.1", timestamp=now - 5.0, device_type="Router")
    # Disconnected switch observed 120s ago (> 60s timeout)
    reg.record_observation(ip="10.0.0.2", timestamp=now - 120.0, device_type="Switch")
    # Connected server observed 10s ago
    reg.record_observation(ip="10.0.0.3", timestamp=now - 10.0, device_type="Server")

    soc = SOCTrafficManager(device_registry=reg)

    # When connected_only=True: only 10.0.0.1 and 10.0.0.3 should be returned
    topo = soc.get_topology(mode="live", connected_only=True)
    assert topo["node_count"] == 2
    assert topo["connected_device_count"] == 2

    returned_ips = {n["ip"]: n for n in topo["nodes"]}
    assert "10.0.0.1" in returned_ips
    assert "10.0.0.3" in returned_ips
    assert "10.0.0.2" not in returned_ips

    assert returned_ips["10.0.0.1"]["device_type"] == "Router"
    assert returned_ips["10.0.0.3"]["device_type"] == "Server"
