"""
Unit Tests for Live Packet Capture Engine
Tests:
- Truthful capture state transitions
- Missing / invalid interface handling (INTERFACE NOT AVAILABLE)
- Start / stop capture lifecycle and resource cleanup
- Zero-packet intervals remain NO PACKETS OBSERVED (strictly no synthetic fallback)
- Interface enumeration details
"""

import time
import pytest
from pipeline.live_capture import (
    LiveNetworkCaptureEngine,
    check_npcap_diagnostics,
    get_network_interfaces
)


def test_interface_enumeration():
    """Verify get_network_interfaces returns well-formed interface dictionaries."""
    ifaces = get_network_interfaces()
    assert isinstance(ifaces, list)
    for iface in ifaces:
        assert "id" in iface
        assert "name" in iface
        assert "is_active" in iface
        assert "is_loopback" in iface


def test_invalid_interface_rejected():
    """Verify selecting a non-existent interface triggers INTERFACE NOT AVAILABLE state."""
    engine = LiveNetworkCaptureEngine()
    res = engine.start_capture(mode="live", interface_id="non_existent_adapter_xyz_9999")
    assert res["status"] == "error"
    assert engine.capture_status == "INTERFACE NOT AVAILABLE"
    assert not engine.is_capturing


def test_truthful_state_no_synthetic_fallback():
    """
    Verify that in live capture mode with 0 packets arriving,
    the engine remains in NO PACKETS OBSERVED or INITIALIZING and never fabricates packets.
    """
    engine = LiveNetworkCaptureEngine()
    diag = check_npcap_diagnostics()

    if not diag["installed"]:
        # When Npcap is missing, state must truthfully be MONITOR NOT DETECTED
        res = engine.start_capture(mode="live")
        assert res["status"] == "error"
        assert engine.capture_status == "MONITOR NOT DETECTED"
        assert engine.packet_counter == 0
        assert engine.actual_packets_captured == 0
        return

    # If Npcap is installed, start capture on default interface
    res = engine.start_capture(mode="live")
    if res["status"] == "started":
        time.sleep(0.5)
        status = engine.get_status()
        # If no real packet arrived, must NOT be CAPTURING REAL PACKETS
        if status["actual_packets_captured"] == 0:
            assert status["capture_status"] in ("NO PACKETS OBSERVED", "CAPTURE INITIALIZING")
            assert status["packet_counter"] == 0
        engine.stop_capture()
        assert engine.capture_status == "STOPPED"
        assert not engine.is_capturing


def test_start_stop_resource_cleanup():
    """Verify start and stop lifecycle cleanly sets stop_event and releases thread."""
    engine = LiveNetworkCaptureEngine()
    # Test with connection_metadata mode which requires no raw socket drivers
    res_start = engine.start_capture(mode="connection_metadata")
    assert res_start["status"] == "started"
    assert engine.is_capturing

    time.sleep(0.8)

    res_stop = engine.stop_capture()
    assert res_stop["status"] == "stopped"
    assert engine.capture_status == "STOPPED"
    assert not engine.is_capturing
    assert engine._stop_event.is_set()

    # Calling stop again on stopped engine returns not_running
    res_stop2 = engine.stop_capture()
    assert res_stop2["status"] == "not_running"
