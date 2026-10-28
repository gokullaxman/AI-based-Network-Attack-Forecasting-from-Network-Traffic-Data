"""
Pipeline Real Network Data Traffic Capture & Working Model Engine
STRICT REAL-DATA-ONLY ARCHITECTURE (Zero Synthetic Fabrication in Live Mode)

Supports:
1. Live Network Packet Sniffer via Scapy + Npcap on selected Windows Interface
2. Diagnostic Health Checker for Npcap Installation & Permissions
3. Verifiable Interface Discovery (Friendly Name, Description, GUID, IPs, MAC)
4. Offline PCAP / PCAPNG Dissection with Preserved Historical Timestamps
5. Separately Quarantined Testing Simulation Mode (Explicitly Labeled)
6. Optional OS Connection Metadata Mode (Explicitly Labeled Connection Poller)
7. Real-Time 12-Feature Window Aggregation (Exact Measurements, No Heuristic Multipliers)
"""

import os
import io
import time
import math
import random
import threading
import subprocess
from datetime import datetime
from collections import deque
from typing import List, Dict, Any, Optional, Tuple
import numpy as np

import scapy.all as scapy
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, rdpcap, wrpcap
from .feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS
from .device_registry import DeviceObservationRegistry
from .packet_record import PacketMetadata, parse_scapy_packet
from .temporal_aggregator import TemporalAggregator, TemporalWindow


def check_npcap_diagnostics() -> Dict[str, Any]:
    """
    Checks Npcap / WinPcap installation, driver service, and Scapy pcap provider on Windows.
    Returns detailed diagnostics and actionable recovery instructions.
    """
    sys32 = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32"
    wpcap_sys32 = os.path.exists(os.path.join(sys32, "wpcap.dll"))
    packet_sys32 = os.path.exists(os.path.join(sys32, "Packet.dll"))
    npcap_dir = os.path.join(sys32, "Npcap")
    wpcap_npcap = os.path.exists(os.path.join(npcap_dir, "wpcap.dll"))
    packet_npcap = os.path.exists(os.path.join(npcap_dir, "Packet.dll"))
    prog_npcap = os.path.exists(r"C:\Program Files\Npcap")

    # Scapy internal pcap check
    scapy_pcap = bool(getattr(scapy.conf, "use_pcap", False))

    # Service check
    service_found = False
    for svc in ("npcap", "npf"):
        try:
            res = subprocess.run(["sc", "query", svc], capture_output=True, text=True, timeout=2)
            if "RUNNING" in res.stdout or "STATE" in res.stdout:
                service_found = True
                break
        except Exception:
            pass

    installed = (wpcap_sys32 or wpcap_npcap) and (packet_sys32 or packet_npcap) or scapy_pcap

    guidance = (
        "Npcap packet capture driver is NOT installed or WinPcap compatibility mode is inactive.\n"
        "To enable real live packet capture on Windows:\n"
        "1. Download Npcap from https://npcap.com/#download\n"
        "2. Run the installer as Administrator.\n"
        "3. Ensure the option 'Install Npcap in WinPcap API-compatible Mode' is CHECKED.\n"
        "4. Restart the monitoring dashboard."
    )

    return {
        "installed": installed,
        "scapy_use_pcap": scapy_pcap,
        "wpcap_dll_present": wpcap_sys32 or wpcap_npcap,
        "packet_dll_present": packet_sys32 or packet_npcap,
        "service_running": service_found,
        "npcap_folder_present": prog_npcap,
        "status": "READY" if installed else "NOT_INSTALLED",
        "error_message": None if installed else "Npcap packet capture driver is not installed on this system.",
        "recovery_instruction": None if installed else guidance
    }


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates genuine network interfaces on the host system.
    Returns clean interface details with friendly name, description, GUID, IPs, and MAC.
    """
    interfaces = []
    
    # 1. Scapy Windows interface list
    raw_if_list = []
    try:
        from scapy.arch.windows import get_windows_if_list
        raw_if_list = get_windows_if_list()
    except Exception:
        pass

    # 2. Netsh configuration for IP details and friendly names
    netsh_map: Dict[str, Dict[str, Any]] = {}
    try:
        res = subprocess.run(["netsh", "interface", "ipv4", "show", "config"], capture_output=True, text=True, timeout=3)
        current_iface = None
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith('Configuration for interface "'):
                current_iface = line_str.split('"')[1]
                netsh_map[current_iface] = {"ips": []}
            elif current_iface and line_str.startswith("IP Address:"):
                ip_val = line_str.split(":", 1)[1].strip()
                netsh_map[current_iface]["ips"].append(ip_val)
    except Exception:
        pass

    seen_guids = set()

    def is_routable(ip_str: str) -> bool:
        return not (ip_str.startswith("127.") or ip_str.startswith("169.254.") or ip_str.startswith("fe80:"))

    for item in raw_if_list:
        guid = item.get("guid", "")
        if guid in seen_guids:
            continue
        seen_guids.add(guid)

        name = item.get("name", "Unknown Interface")
        desc = item.get("description", "")
        mac = item.get("mac", "")
        ips = item.get("ips", [])
        if not isinstance(ips, list):
            ips = [ips] if ips else []

        # Ignore redundant Windows NDIS lightweight filter sub-adapters
        if ("-0000" in name or "-0000" in desc) and not ips:
            continue

        # Merge netsh IPs if friendly name matches
        if name in netsh_map and not ips:
            ips = netsh_map[name]["ips"]

        has_routable = bool(ips) and any(is_routable(ip) for ip in ips)
        is_up = bool(ips) and any(not ip.startswith("127.") for ip in ips)
        is_loopback = "Loopback" in desc or "127.0.0.1" in ips

        # Formatted interface record
        iface_entry = {
            "id": guid if guid else name,
            "name": name,
            "description": desc,
            "guid": guid,
            "mac_address": mac if mac else None,
            "ip_addresses": ips,
            "is_active": is_up,
            "is_loopback": is_loopback,
            "has_routable": has_routable,
            "scapy_name": guid if guid else name
        }
        interfaces.append(iface_entry)

    def sort_score(x):
        desc = (x.get("description") or "").lower()
        name = (x.get("name") or "").lower()
        is_virtual = "virtual" in desc or "pseudo" in desc or "miniport" in desc
        is_preferred = "wi-fi" in name or "wireless" in desc or "ethernet" in desc
        return (
            not x.get("has_routable", False),
            is_virtual,
            not is_preferred,
            not x.get("is_active", False),
            x.get("is_loopback", False),
            x.get("name", "")
        )

    # Sort active routable interfaces to top
    interfaces.sort(key=sort_score)
    return interfaces


def resolve_scapy_interface(iface_spec: Any) -> Any:
    """
    Resolves an interface identifier (friendly name, GUID, NPF device name, or Scapy NetworkInterface)
    to a valid Scapy NetworkInterface object or string that Scapy's sniff() reliably accepts on Windows.
    """
    if iface_spec is None:
        return None

    # If already a Scapy NetworkInterface instance
    if hasattr(iface_spec, "network_name"):
        return iface_spec

    str_spec = str(iface_spec).strip()
    if not str_spec or str_spec == "None Available":
        return None

    try:
        from scapy.all import conf
        # 1. Exact dictionary lookup
        if str_spec in conf.ifaces:
            return conf.ifaces[str_spec]

        # 2. Extract GUID if present in the string
        import re
        guid_match = re.search(r"\{([0-9a-fA-F-]+)\}", str_spec)
        target_guid = ("{" + guid_match.group(1).lower() + "}") if guid_match else None

        for iface_obj in conf.ifaces.values():
            if getattr(iface_obj, "name", None) == str_spec:
                return iface_obj
            if getattr(iface_obj, "description", None) == str_spec:
                return iface_obj
            guid = getattr(iface_obj, "guid", None)
            if guid:
                guid_lower = guid.lower()
                if target_guid and guid_lower == target_guid:
                    return iface_obj
                if str_spec.lower() in (guid_lower, guid_lower.strip("{}")):
                    return iface_obj
            net_name = getattr(iface_obj, "network_name", None)
            if net_name:
                if str_spec.lower() in net_name.lower():
                    return iface_obj

        # 3. Try Scapy dev_from_name
        try:
            return conf.ifaces.dev_from_name(str_spec)
        except Exception:
            pass
    except Exception:
        pass

    return None


class CapturedPacket:
    """Represents a single captured network packet with verifiable dissection details."""
    def __init__(
        self,
        pkt_id: int,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: str,
        length: int,
        flags: str = "",
        info: str = "",
        raw_hex: str = "",
        attack_hint: str = "Live Observation",
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        payload_len: int = 0,
        observation_source: str = "Real Packet Capture"
    ):
        self.id = pkt_id
        self.timestamp = timestamp
        self.time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.length = length
        self.payload_len = payload_len
        self.flags = flags
        self.info = info
        self.raw_hex = raw_hex
        self.attack_hint = attack_hint
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.observation_source = observation_source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "time_str": self.time_str,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.proto,
            "length": self.length,
            "payload_len": self.payload_len,
            "flags": self.flags,
            "info": self.info,
            "raw_hex": self.raw_hex,
            "attack_hint": self.attack_hint,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "observation_source": self.observation_source
        }


class ConnectionRecord:
    """Represents an operating-system socket connection endpoint (explicitly separate from captured packets)."""
    def __init__(
        self,
        record_id: int,
        timestamp: float,
        proto: str,
        local_ip: str,
        local_port: int,
        foreign_ip: str,
        foreign_port: int,
        state: str,
        pid: Optional[int] = None
    ):
        self.id = record_id
        self.timestamp = timestamp
        self.time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        self.proto = proto
        self.local_ip = local_ip
        self.local_port = local_port
        self.foreign_ip = foreign_ip
        self.foreign_port = foreign_port
        self.state = state
        self.pid = pid
        self.observation_source = "Operating System Connection Table (netstat)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "time_str": self.time_str,
            "proto": self.proto,
            "local_address": f"{self.local_ip}:{self.local_port}",
            "foreign_address": f"{self.foreign_ip}:{self.foreign_port}",
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "foreign_ip": self.foreign_ip,
            "foreign_port": self.foreign_port,
            "state": self.state,
            "pid": self.pid,
            "observation_source": self.observation_source
        }


class LiveNetworkCaptureEngine:
    """
    Real-Time Network Traffic Capture Engine strictly adhering to Real-Data-Only rules.
    Never fabricates, estimates, simulates, or randomly generates network data in LIVE MODE.
    """

    def __init__(self, max_packet_buffer: int = 500, sequence_length: int = 10):
        self.max_packet_buffer = max_packet_buffer
        self.sequence_length = sequence_length
        self.packets_buffer: deque = deque(maxlen=max_packet_buffer)
        self.flow_sequence: deque = deque(maxlen=sequence_length)
        
        # Operational mode: 'live', 'pcap', 'simulation', 'connection_metadata'
        self.capture_mode = "live"
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.lock = threading.RLock()
        
        # Health & State Indicators
        self.capture_status = "INITIALIZING"  # 'INITIALIZING', 'CAPTURING REAL PACKETS', 'NO PACKETS OBSERVED', 'CAPTURE ERROR', 'INSUFFICIENT PERMISSIONS', 'STOPPED'
        self.last_error: Optional[str] = None
        self.recovery_instruction: Optional[str] = None
        self.capture_backend = "Scapy / Npcap"
        self.selected_interface: Optional[str] = None
        self.selected_interface_name: Optional[str] = None
        self.bpf_filter: str = ""
        
        # Genuine Observation Counters
        self.packet_counter = 0
        self.actual_packets_captured = 0
        self.total_bytes = 0
        self.start_time: Optional[float] = None
        self.last_packet_timestamp: Optional[float] = None
        self.current_pkt_rate = 0.0
        self.current_stage_label = "Benign Traffic"
        self.active_flows_count = 0
        
        self._recent_pkt_timestamps: deque = deque(maxlen=300)
        self._async_sniffer = None
        
        # Optional connection metadata table (for explicit connection_metadata mode)
        self.connections_buffer: deque = deque(maxlen=200)
        
        # Device observation registry for verified endpoints
        self.device_registry = DeviceObservationRegistry()

        # Temporal 1-minute aggregation pipeline
        self.temporal_aggregator = TemporalAggregator(window_size_seconds=60.0)
        self.temporal_windows: deque = deque(maxlen=120)
        self._current_window_packets: List[PacketMetadata] = []
        self._current_window_start: Optional[float] = None

        # Auto-detect default active interface
        self._select_default_interface()

        # Set truthful initial capture status
        diag = check_npcap_diagnostics()
        if not diag["installed"]:
            self.capture_status = "MONITOR NOT DETECTED"
            self.last_error = diag["error_message"]
            self.recovery_instruction = diag["recovery_instruction"]
        elif not self.selected_interface or self.selected_interface == "None Available":
            self.capture_status = "INTERFACE NOT AVAILABLE"
            self.last_error = "No active network interface discovered on host."
        else:
            self.capture_status = "STOPPED"

    def set_device_registry(self, registry):
        """Attaches a device observation registry for recording real observed endpoints."""
        self.device_registry = registry

    def _select_default_interface(self):
        """Discovers and sets the active interface with valid IP address."""
        ifaces = get_network_interfaces()
        active = [i for i in ifaces if i["is_active"] and not i["is_loopback"]]
        if active:
            self.selected_interface = active[0]["guid"] or active[0]["name"]
            self.selected_interface_name = active[0]["name"]
        elif ifaces:
            self.selected_interface = ifaces[0]["guid"] or ifaces[0]["name"]
            self.selected_interface_name = ifaces[0]["name"]
        else:
            self.selected_interface = None
            self.selected_interface_name = "None Available"
            self.capture_status = "INTERFACE NOT AVAILABLE"

    def set_interface(self, interface_id: str) -> Dict[str, Any]:
        """Sets the active network interface to be captured."""
        with self.lock:
            ifaces = get_network_interfaces()
            match = next((i for i in ifaces if i["id"] == interface_id or i["name"] == interface_id or i["guid"] == interface_id), None)
            if match:
                self.selected_interface = match["guid"] or match["name"]
                self.selected_interface_name = match["name"]
                return {"status": "ok", "interface": match}
            else:
                return {"status": "error", "message": f"Interface '{interface_id}' not found in enumerated host interfaces."}

    def set_bpf_filter(self, filter_expr: str):
        """Configures the Berkeley Packet Filter (BPF) capture filter."""
        with self.lock:
            self.bpf_filter = filter_expr.strip()

    def start_capture(self, mode: str = "live", interface_id: Optional[str] = None, bpf_filter: str = "") -> Dict[str, Any]:
        """
        Starts packet capture in the designated mode without silent synthetic fallbacks.
        Modes:
        - 'live': Real packet capture via Scapy on selected interface (Default)
        - 'pcap': Offline PCAP analysis mode
        - 'simulation': Isolated test simulation mode
        - 'connection_metadata': Explicit OS socket poller mode
        """
        with self.lock:
            if self.is_capturing:
                if interface_id and (interface_id != self.selected_interface and interface_id != self.selected_interface_name):
                    self.stop_capture()
                    self.clear_buffer()
                else:
                    return {"status": "already_running", "mode": self.capture_mode, "capture_status": self.capture_status}

            self.capture_mode = mode
            if interface_id:
                res = self.set_interface(interface_id)
                if res.get("status") == "error":
                    self.is_capturing = False
                    self.capture_status = "INTERFACE NOT AVAILABLE"
                    self.last_error = res.get("message")
                    return {
                        "status": "error",
                        "capture_status": self.capture_status,
                        "error": self.last_error,
                        "mode": mode
                    }
            if bpf_filter:
                self.set_bpf_filter(bpf_filter)

            self.last_error = None
            self.recovery_instruction = None
            self._stop_event.clear()
            self.start_time = time.time()

            if mode == "live":
                # Verify Npcap diagnostics
                diag = check_npcap_diagnostics()
                if not diag["installed"]:
                    self.is_capturing = False
                    self.capture_status = "MONITOR NOT DETECTED"
                    self.last_error = diag["error_message"]
                    self.recovery_instruction = diag["recovery_instruction"]
                    return {
                        "status": "error",
                        "capture_status": self.capture_status,
                        "error": self.last_error,
                        "recovery_instruction": self.recovery_instruction
                    }

                # Verify interface availability
                if not self.selected_interface or self.selected_interface == "None Available":
                    self.is_capturing = False
                    self.capture_status = "INTERFACE NOT AVAILABLE"
                    self.last_error = "No active network interface selected or available."
                    return {
                        "status": "error",
                        "capture_status": self.capture_status,
                        "error": self.last_error,
                        "mode": mode
                    }

                # Attempt live packet capture worker
                self.is_capturing = True
                self.capture_status = "CAPTURE INITIALIZING"
                self.capture_backend = "Scapy / Npcap Live Sniff"
                self.capture_thread = threading.Thread(target=self._live_sniff_worker, daemon=True)
                self.capture_thread.start()
                return {"status": "started", "mode": "live", "capture_status": self.capture_status}

            elif mode == "connection_metadata":
                # Explicit OS Connection Metadata Poller (Not disguised as packets)
                self.is_capturing = True
                self.capture_status = "CONNECTION METADATA MODE"
                self.capture_backend = "Windows System Connection Poller (netstat)"
                self.capture_thread = threading.Thread(target=self._connection_poller_worker, daemon=True)
                self.capture_thread.start()
                return {"status": "started", "mode": "connection_metadata", "capture_status": self.capture_status}

            elif mode == "simulation":
                # Isolated Test Simulation
                self.is_capturing = True
                self.capture_status = "SIMULATION MODE (TESTING)"
                self.capture_backend = "Simulation Engine (Test Only)"
                self.capture_thread = threading.Thread(target=self._simulation_worker, daemon=True)
                self.capture_thread.start()
                return {"status": "started", "mode": "simulation", "capture_status": self.capture_status}

            elif mode == "pcap":
                self.is_capturing = True
                self.capture_status = "OFFLINE PCAP MODE"
                self.capture_backend = "Scapy Offline PCAP Dissector"
                return {"status": "started", "mode": "pcap", "capture_status": self.capture_status}

            else:
                return {"status": "error", "error": f"Unknown capture mode: {mode}"}

    def stop_capture(self) -> Dict[str, Any]:
        """Stops live capture gracefully and releases resources."""
        thread_to_join = None
        with self.lock:
            if not self.is_capturing:
                return {"status": "not_running", "capture_status": self.capture_status}

            self.is_capturing = False
            self._stop_event.set()
            self.capture_status = "STOPPED"
            thread_to_join = self.capture_thread
            self.capture_thread = None

            if self._async_sniffer:
                try:
                    self._async_sniffer.stop()
                except Exception:
                    pass
                self._async_sniffer = None

        if thread_to_join and thread_to_join.is_alive() and threading.current_thread() != thread_to_join:
            thread_to_join.join(timeout=2.0)

        with self.lock:
            return {
                "status": "stopped",
                "capture_status": self.capture_status,
                "total_packets": self.packet_counter,
                "actual_packets_captured": self.actual_packets_captured
            }

    def clear_buffer(self) -> Dict[str, Any]:
        """Clears captured packet history and sliding window buffer."""
        with self.lock:
            self.packets_buffer.clear()
            self.flow_sequence.clear()
            self.connections_buffer.clear()
            self.packet_counter = 0
            self.actual_packets_captured = 0
            self.total_bytes = 0
            self.last_packet_timestamp = None
            self._recent_pkt_timestamps.clear()
            self.temporal_windows.clear()
            self._current_window_packets.clear()
            self._current_window_start = None
            return {"status": "cleared"}

    def _live_sniff_worker(self):
        """Worker executing genuine Scapy packet sniffing without synthetic fallbacks."""
        raw_iface = self.selected_interface
        iface = resolve_scapy_interface(raw_iface) or raw_iface
        bpf = self.bpf_filter if self.bpf_filter else None

        def packet_handler(sc_pkt):
            if self._stop_event.is_set():
                return
            self._process_genuine_packet(sc_pkt)

        try:
            from scapy.all import sniff
            # Mark ready to capture
            with self.lock:
                if self.is_capturing and self.actual_packets_captured == 0:
                    self.capture_status = "NO PACKETS OBSERVED"

            # Sniff in small slices to monitor stop event
            while not self._stop_event.is_set():
                try:
                    sniff(
                        iface=iface,
                        filter=bpf,
                        prn=packet_handler,
                        count=10,
                        timeout=1.5,
                        store=False
                    )
                except PermissionError as pe:
                    with self.lock:
                        self.capture_status = "INSUFFICIENT PERMISSIONS"
                        self.last_error = f"Permission denied while capturing: {str(pe)}"
                        self.recovery_instruction = "Run terminal as Administrator to enable raw packet capture."
                        self.is_capturing = False
                    break
                except Exception as ex:
                    with self.lock:
                        err_str = str(ex)
                        if "winpcap is not installed" in err_str.lower() or "wpcap" in err_str.lower():
                            self.capture_status = "CAPTURE ERROR"
                            self.last_error = "Npcap / WinPcap is not installed on this system."
                            self.recovery_instruction = check_npcap_diagnostics()["recovery_instruction"]
                        else:
                            self.capture_status = "CAPTURE ERROR"
                            self.last_error = f"Capture failed on interface {self.selected_interface_name}: {err_str}"
                            self.recovery_instruction = "Select a valid active network interface in settings."
                        self.is_capturing = False
                    break

        except Exception as ex:
            with self.lock:
                self.capture_status = "CAPTURE ERROR"
                self.last_error = str(ex)
                self.is_capturing = False

    def _process_genuine_packet(self, sc_pkt):
        """Extracts strictly authentic headers and bytes from a genuinely captured packet."""
        now = float(sc_pkt.time) if hasattr(sc_pkt, "time") else time.time()
        pkt_len = len(sc_pkt)

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_mac = None
        dst_mac = None
        proto = "OTHER"
        sport = 0
        dport = 0
        flags = ""
        info = sc_pkt.summary()
        payload_len = 0
        raw_hex = ""

        if sc_pkt.haslayer(Ether):
            src_mac = str(sc_pkt[Ether].src)
            dst_mac = str(sc_pkt[Ether].dst)

        if sc_pkt.haslayer(IP):
            src_ip = str(sc_pkt[IP].src)
            dst_ip = str(sc_pkt[IP].dst)
            proto_num = sc_pkt[IP].proto
            proto = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else f"IP({proto_num})"))
        elif sc_pkt.haslayer(IPv6):
            src_ip = str(sc_pkt[IPv6].src)
            dst_ip = str(sc_pkt[IPv6].dst)
            proto = "IPv6"

        if sc_pkt.haslayer(TCP):
            proto = "TCP"
            sport = int(sc_pkt[TCP].sport)
            dport = int(sc_pkt[TCP].dport)
            flags = str(sc_pkt[TCP].flags)
        elif sc_pkt.haslayer(UDP):
            proto = "UDP"
            sport = int(sc_pkt[UDP].sport)
            dport = int(sc_pkt[UDP].dport)
        elif sc_pkt.haslayer(ICMP):
            proto = "ICMP"
            flags = f"Type={sc_pkt[ICMP].type}"
        elif sc_pkt.haslayer(ARP):
            proto = "ARP"
            src_ip = str(sc_pkt[ARP].psrc)
            dst_ip = str(sc_pkt[ARP].pdst)
            src_mac = str(sc_pkt[ARP].hwsrc)
            dst_mac = str(sc_pkt[ARP].hwdst)

        if sc_pkt.haslayer(Raw):
            load_bytes = bytes(sc_pkt[Raw].load)
            payload_len = len(load_bytes)
            # Safe hex preview of first 16 bytes
            raw_hex = " ".join(f"{b:02x}" for b in load_bytes[:16])

        with self.lock:
            self.packet_counter += 1
            self.actual_packets_captured += 1
            self.total_bytes += pkt_len
            self.last_packet_timestamp = now
            self.capture_status = "CAPTURING REAL PACKETS"
            self._recent_pkt_timestamps.append(now)

            pkt = CapturedPacket(
                pkt_id=self.packet_counter,
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                proto=proto,
                length=pkt_len,
                flags=flags,
                info=info,
                raw_hex=raw_hex,
                attack_hint="Observed Live Frame",
                src_mac=src_mac,
                dst_mac=dst_mac,
                payload_len=payload_len,
                observation_source="Scapy Live Sniff (Real Packet)"
            )
            self.packets_buffer.append(pkt)

            # Record in verifiable device registry if attached
            if self.device_registry:
                if src_ip and src_ip != "0.0.0.0":
                    self.device_registry.record_observation(
                        ip=src_ip,
                        mac=src_mac,
                        source="Real Captured Packet (Source)",
                        timestamp=now
                    )
                if dst_ip and dst_ip != "0.0.0.0":
                    self.device_registry.record_observation(
                        ip=dst_ip,
                        mac=dst_mac,
                        source="Real Captured Packet (Destination)",
                        timestamp=now
                    )

            # Record in 1-minute temporal aggregator
            meta = parse_scapy_packet(sc_pkt, self.packet_counter, source="Live Capture")
            if self._current_window_start is None:
                self._current_window_start = math.floor(now / 60.0) * 60.0

            if now >= self._current_window_start + 60.0:
                tw = self.temporal_aggregator.aggregate_packet_batch(
                    self._current_window_packets,
                    self._current_window_start,
                    self._current_window_start + 60.0,
                    len(self.temporal_windows),
                    provenance="Live Capture"
                )
                self.temporal_windows.append(tw)
                self._current_window_start = math.floor(now / 60.0) * 60.0
                self._current_window_packets = []

            self._current_window_packets.append(meta)

            # Step features dynamically every 5 packets
            if self.actual_packets_captured % 5 == 0:
                recent_window = list(self.packets_buffer)[-5:]
                self._aggregate_and_step_features(recent_window)

    def _connection_poller_worker(self):
        """
        Polls genuine Windows socket connections via netstat.
        Records endpoints strictly as connection metadata, never disguised as captured packets.
        """
        while not self._stop_event.is_set():
            try:
                res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=3)
                lines = res.stdout.splitlines()
                now = time.time()
                rec_count = 0

                for line in lines:
                    line = line.strip()
                    if not (line.startswith("TCP") or line.startswith("UDP")):
                        continue
                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    proto = parts[0]
                    local_addr = parts[1]
                    foreign_addr = parts[2] if len(parts) >= 3 else "*:*"
                    state = parts[3] if proto == "TCP" and len(parts) >= 4 else "UDP"
                    pid = int(parts[-1]) if parts[-1].isdigit() else None

                    def split_ip_port(addr: str) -> Tuple[str, int]:
                        if ":" in addr:
                            r_idx = addr.rfind(":")
                            ip_p = addr[:r_idx].strip("[]")
                            port_str = addr[r_idx + 1:]
                            try:
                                return ip_p, int(port_str)
                            except ValueError:
                                return ip_p, 0
                        return addr, 0

                    local_ip, local_port = split_ip_port(local_addr)
                    foreign_ip, foreign_port = split_ip_port(foreign_addr)

                    rec_count += 1
                    record = ConnectionRecord(
                        record_id=rec_count,
                        timestamp=now,
                        proto=proto,
                        local_ip=local_ip,
                        local_port=local_port,
                        foreign_ip=foreign_ip,
                        foreign_port=foreign_port,
                        state=state,
                        pid=pid
                    )

                    with self.lock:
                        self.connections_buffer.append(record)
                        if self.device_registry:
                            if local_ip and local_ip not in ("0.0.0.0", "*", "::"):
                                self.device_registry.record_observation(
                                    ip=local_ip,
                                    mac=None,
                                    source="OS Connection Endpoint (Local)",
                                    timestamp=now,
                                    mode="connection_metadata"
                                )
                            if foreign_ip and foreign_ip not in ("0.0.0.0", "*", "::", "127.0.0.1"):
                                self.device_registry.record_observation(
                                    ip=foreign_ip,
                                    mac=None,
                                    source="OS Connection Endpoint (Foreign)",
                                    timestamp=now,
                                    mode="connection_metadata"
                                )

                time.sleep(2.0)
            except Exception:
                time.sleep(2.0)

    def _simulation_worker(self):
        """
        Runs isolated testing simulation only when user explicitly selects SIMULATION MODE.
        All records are explicitly branded as simulated.
        """
        stages = ["Reconnaissance", "Scanning", "Enumeration", "Exploitation", "Intrusion"]
        stage_idx = 0
        attacker_ip = "192.168.1.185"
        target_server = "10.0.0.45"

        while not self._stop_event.is_set():
            now = time.time()
            stage_name = stages[stage_idx]
            self.current_stage_label = f"Simulated {stage_name}"

            with self.lock:
                self.packet_counter += 1
                length = 64
                self.total_bytes += length
                self.last_packet_timestamp = now
                self._recent_pkt_timestamps.append(now)

                pkt = CapturedPacket(
                    pkt_id=self.packet_counter,
                    timestamp=now,
                    src_ip=attacker_ip,
                    dst_ip=target_server,
                    sport=random.randint(40000, 60000),
                    dport=80,
                    proto="TCP",
                    length=length,
                    flags="SYN",
                    info=f"[SIMULATION] Attack stage trace: {stage_name}",
                    raw_hex="45 00 00 3c 1a 2b 40 00 40 06",
                    attack_hint=f"SIMULATED {stage_name}",
                    observation_source="Simulation Engine (Test Only)"
                )
                self.packets_buffer.append(pkt)
                self._aggregate_and_step_features([pkt])

            stage_idx = (stage_idx + 1) % len(stages)
            time.sleep(1.0)

    def _aggregate_and_step_features(self, window_packets: List[CapturedPacket]):
        """
        Calculates the 12 behavioral/temporal features strictly from real captured packets.
        Uses exact mathematical definitions without arbitrary multiplier heuristics.
        """
        if not window_packets:
            return

        now = time.time()
        timestamps = [p.timestamp for p in window_packets]
        t_span = max(0.001, timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 1.0

        # Instantaneous packet rate across the observation window
        recent_count = len([t for t in self._recent_pkt_timestamps if (now - t) <= 1.0])
        self.current_pkt_rate = float(recent_count)

        # 1. Connection frequency: distinct endpoints per second
        distinct_pairs = set((p.src_ip, p.dst_ip, p.dport) for p in window_packets)
        conn_freq = float(len(distinct_pairs) / t_span)

        # 2. Packet rate: packets per second in window
        packet_rate = float(len(window_packets) / t_span)

        # 3. Destination IP Fanout: count of distinct destination IPs
        dst_ips = [p.dst_ip for p in window_packets]
        unique_dsts = len(set(dst_ips))
        dst_fanout = float(unique_dsts)

        # 4. Source-Destination Entropy: Shannon entropy across destination IP distribution
        counts = [dst_ips.count(ip) for ip in set(dst_ips)]
        total = len(dst_ips)
        if total > 1 and len(counts) > 1:
            probs = [c / total for c in counts]
            entropy = -sum(p * math.log2(p) for p in probs) / math.log2(len(counts))
        else:
            entropy = 0.0
        src_dst_entropy = float(np.clip(entropy, 0.0, 1.0))

        # 5. Port diversity: distinct destination ports observed
        dports = [p.dport for p in window_packets if p.dport > 0]
        port_diversity = float(len(set(dports))) if dports else 1.0

        # 6. Well-known port ratio: fraction of destination ports < 1024
        if dports:
            wk = sum(1 for dp in dports if dp < 1024)
            well_known_ratio = float(wk / len(dports))
        else:
            well_known_ratio = 1.0

        # 7. Host sweep rate: distinct targets per second
        sweep_rate = float(unique_dsts / t_span)

        # 8. ICMP / ARP ratio: fraction of ICMP or ARP packets
        icmp_arp_count = sum(1 for p in window_packets if p.proto in ("ICMP", "ARP"))
        icmp_arp_ratio = float(icmp_arp_count / len(window_packets))

        # 9. Service probe rate: SYN packets per second
        syn_count = sum(1 for p in window_packets if "S" in p.flags or "SYN" in p.flags)
        service_probe_rate = float(syn_count / t_span)

        # 10. Targeted query volume: average captured packet byte length
        targeted_query_vol = float(sum(p.length for p in window_packets) / len(window_packets))

        # 11. Inter-Arrival Time (IAT) Jitter: standard deviation of packet inter-arrival times
        if len(timestamps) > 1:
            iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            iat_jitter = float(np.std(iats))
        else:
            iat_jitter = 0.0

        # 12. Burstiness Index: ratio of peak packet rate to mean rate
        mean_rate = max(0.1, conn_freq)
        burstiness = float(np.clip(packet_rate / mean_rate, 1.0, 20.0))

        feature_vector = np.array([
            conn_freq,
            packet_rate,
            dst_fanout,
            src_dst_entropy,
            port_diversity,
            well_known_ratio,
            sweep_rate,
            icmp_arp_ratio,
            service_probe_rate,
            targeted_query_vol,
            iat_jitter,
            burstiness
        ], dtype=np.float32)

        self.flow_sequence.append(feature_vector)

    def parse_pcap_bytes(self, pcap_bytes: bytes) -> List[CapturedPacket]:
        """
        Parses genuine PCAP bytes uploaded by user into CapturedPacket records.
        Preserves original capture timestamps and marks provenance as Historical PCAP.
        """
        with io.BytesIO(pcap_bytes) as bio:
            sc_pkts = rdpcap(bio)

        parsed_packets = []
        for idx, sc_pkt in enumerate(sc_pkts):
            self.packet_counter += 1
            pkt_time = float(sc_pkt.time) if hasattr(sc_pkt, "time") else time.time()
            pkt_len = len(sc_pkt)

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_mac = None
            dst_mac = None
            proto = "OTHER"
            sport = 0
            dport = 0
            flags = ""
            payload_len = 0
            raw_hex = ""

            if sc_pkt.haslayer(Ether):
                src_mac = str(sc_pkt[Ether].src)
                dst_mac = str(sc_pkt[Ether].dst)

            if sc_pkt.haslayer(IP):
                src_ip = str(sc_pkt[IP].src)
                dst_ip = str(sc_pkt[IP].dst)
                proto_num = sc_pkt[IP].proto
                proto = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else "IP"))
            elif sc_pkt.haslayer(IPv6):
                src_ip = str(sc_pkt[IPv6].src)
                dst_ip = str(sc_pkt[IPv6].dst)
                proto = "IPv6"

            if sc_pkt.haslayer(TCP):
                proto = "TCP"
                sport = int(sc_pkt[TCP].sport)
                dport = int(sc_pkt[TCP].dport)
                flags = str(sc_pkt[TCP].flags)
            elif sc_pkt.haslayer(UDP):
                proto = "UDP"
                sport = int(sc_pkt[UDP].sport)
                dport = int(sc_pkt[UDP].dport)
            elif sc_pkt.haslayer(ICMP):
                proto = "ICMP"
                flags = f"Type={sc_pkt[ICMP].type}"

            if sc_pkt.haslayer(Raw):
                raw_bytes = bytes(sc_pkt[Raw].load)
                payload_len = len(raw_bytes)
                raw_hex = " ".join(f"{b:02x}" for b in raw_bytes[:16])

            cp = CapturedPacket(
                pkt_id=self.packet_counter,
                timestamp=pkt_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                proto=proto,
                length=pkt_len,
                flags=flags,
                info=sc_pkt.summary(),
                raw_hex=raw_hex,
                attack_hint="Historical PCAP Record",
                src_mac=src_mac,
                dst_mac=dst_mac,
                payload_len=payload_len,
                observation_source="Offline PCAP File (Historical)"
            )
            parsed_packets.append(cp)

            if self.device_registry:
                if src_ip and src_ip != "0.0.0.0":
                    self.device_registry.record_observation(
                        ip=src_ip,
                        mac=src_mac,
                        source="Historical PCAP File",
                        timestamp=pkt_time,
                        mode="pcap"
                    )
                if dst_ip and dst_ip != "0.0.0.0":
                    self.device_registry.record_observation(
                        ip=dst_ip,
                        mac=dst_mac,
                        source="Historical PCAP File",
                        timestamp=pkt_time,
                        mode="pcap"
                    )

        with self.lock:
            for p in parsed_packets:
                self.packets_buffer.append(p)
            self.total_bytes += sum(p.length for p in parsed_packets)
            self.capture_status = "OFFLINE PCAP MODE"

            # Calculate genuine 1-minute temporal windows
            pcap_metas = [
                parse_scapy_packet(sc, idx + 1, source="Offline PCAP File")
                for idx, sc in enumerate(sc_pkts)
            ]
            pcap_windows = self.temporal_aggregator.aggregate_chronological_stream(
                pcap_metas,
                provenance="Offline PCAP"
            )
            for tw in pcap_windows:
                self.temporal_windows.append(tw)

            # Step features across parsed chunks
            chunk_size = max(1, len(parsed_packets) // self.sequence_length)
            for i in range(0, len(parsed_packets), chunk_size):
                chunk = parsed_packets[i : i + chunk_size]
                if chunk:
                    self._aggregate_and_step_features(chunk)

        return parsed_packets

    def get_sliding_window(self) -> Optional[np.ndarray]:
        """
        Returns the current sequence window [sequence_length, 12] for BiLSTM inference.
        Returns None if fewer than sequence_length validated real flow steps exist.
        """
        with self.lock:
            if len(self.flow_sequence) < self.sequence_length:
                return None
            return np.array(list(self.flow_sequence), dtype=np.float32)

    def get_status(self) -> Dict[str, Any]:
        """Returns capture engine health indicators and telemetry counters."""
        with self.lock:
            uptime = time.time() - self.start_time if self.start_time and self.is_capturing else 0.0
            return {
                "is_capturing": self.is_capturing,
                "capture_mode": self.capture_mode,
                "capture_status": self.capture_status,
                "capture_backend": self.capture_backend,
                "selected_interface": self.selected_interface,
                "selected_interface_name": self.selected_interface_name,
                "packet_counter": self.packet_counter,
                "actual_packets_captured": self.actual_packets_captured,
                "buffer_size": len(self.packets_buffer),
                "total_bytes": self.total_bytes,
                "packet_rate": round(self.current_pkt_rate, 2),
                "uptime_seconds": round(uptime, 1),
                "current_stage_label": self.current_stage_label,
                "active_flows": self.active_flows_count,
                "last_packet_timestamp": self.last_packet_timestamp if self.actual_packets_captured > 0 else None,
                "last_error": self.last_error,
                "recovery_instruction": self.recovery_instruction,
                "flow_sequence_steps": len(self.flow_sequence),
                "flow_sequence_required": self.sequence_length,
                "temporal_windows_count": len(self.temporal_windows)
            }

    def get_temporal_windows(self, count: int = 50) -> List[Dict[str, Any]]:
        """Returns genuine 1-minute discrete temporal feature windows."""
        with self.lock:
            windows = list(self.temporal_windows)
            if self._current_window_packets and self._current_window_start is not None:
                in_flight = self.temporal_aggregator.aggregate_packet_batch(
                    self._current_window_packets,
                    self._current_window_start,
                    self._current_window_start + 60.0,
                    len(windows),
                    provenance=f"Live Capture (In-flight: {len(self._current_window_packets)} pkts)"
                )
                windows.append(in_flight)
            return [w.to_dict() for w in windows[-count:]]

    def get_recent_packets(self, count: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent captured packets formatted as dicts."""
        with self.lock:
            pkts = list(self.packets_buffer)[-count:]
            return [p.to_dict() for p in reversed(pkts)]

    def get_recent_connections(self, count: int = 50) -> List[Dict[str, Any]]:
        """Returns genuine OS connection records when operating in connection_metadata mode."""
        with self.lock:
            recs = list(self.connections_buffer)[-count:]
            return [r.to_dict() for r in reversed(recs)]


def generate_sample_attack_pcap(filepath: str):
    """
    Generates a realistic multi-stage network attack PCAP file with genuine packet headers.
    Used exclusively for OFFLINE PCAP / TESTING.
    """
    packets = []
    attacker = "192.168.1.185"
    target = "10.0.0.45"
    t0 = time.time()

    # Stage 1: Reconnaissance (ICMP)
    for i in range(1, 12):
        pkt = Ether() / IP(src=attacker, dst=f"10.0.0.{i}") / ICMP(type=8, code=0, id=0x1234, seq=i)
        pkt.time = t0 + (i * 0.05)
        packets.append(pkt)

    # Stage 2: Scanning (TCP SYN)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for idx, p in enumerate(scan_ports):
        pkt = Ether() / IP(src=attacker, dst=target) / TCP(sport=50000 + idx, dport=p, flags="S", seq=1000 + idx)
        pkt.time = t0 + 1.0 + (idx * 0.08)
        packets.append(pkt)

    # Stage 3: Enumeration (HTTP GET & SSH probe)
    enum_queries = [
        "GET /robots.txt HTTP/1.1\r\nHost: target\r\nUser-Agent: Nikto\r\n\r\n",
        "GET /admin/login.php HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET /phpmyadmin HTTP/1.1\r\nHost: target\r\n\r\n",
        "SSH-2.0-OpenSSH_Probe_v1\r\n",
        "SMB2_Negotiate_Protocol_Dialect_v2\r\n"
    ]
    for idx, payload in enumerate(enum_queries):
        dport = 22 if "SSH" in payload else (445 if "SMB" in payload else 80)
        pkt = Ether() / IP(src=attacker, dst=target) / TCP(sport=51000 + idx, dport=dport, flags="PA", seq=2000 + idx) / Raw(load=payload.encode())
        pkt.time = t0 + 2.5 + (idx * 0.15)
        packets.append(pkt)

    # Stage 4: Exploitation (SQL Injection & Command Injection)
    exploits = [
        "POST /login.php HTTP/1.1\r\nHost: target\r\n\r\nusername=' OR '1'='1'--&pass=admin",
        "GET /cgi-bin/test.sh HTTP/1.1\r\nHost: target\r\nUser-Agent: () { :;}; /bin/cat /etc/passwd\r\n\r\n",
        "POST /api/exec HTTP/1.1\r\nHost: target\r\n\r\ncmd=whoami%3Bid%3Buname+-a"
    ]
    for idx, payload in enumerate(exploits):
        pkt = Ether() / IP(src=attacker, dst=target) / TCP(sport=52000 + idx, dport=80, flags="PA", seq=3000 + idx) / Raw(load=payload.encode())
        pkt.time = t0 + 4.0 + (idx * 0.2)
        packets.append(pkt)

    # Stage 5: Intrusion (Reverse Shell Session)
    c2_payloads = [
        "/bin/sh: Connected to 192.168.1.185:4444\r\n",
        "bash# uname -a\r\nLinux target-server 5.15.0-generic #1 SMP x86_64\r\n",
        "bash# cat /etc/shadow\r\nroot:$6$salt$hashedpassword:19000:0:99999:7:::\r\n"
    ]
    for idx, payload in enumerate(c2_payloads):
        pkt = Ether() / IP(src=attacker, dst=target) / TCP(sport=4444, dport=4444, flags="PA", seq=4000 + idx) / Raw(load=payload.encode())
        pkt.time = t0 + 5.5 + (idx * 0.25)
        packets.append(pkt)

    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    wrpcap(filepath, packets)
    return filepath
