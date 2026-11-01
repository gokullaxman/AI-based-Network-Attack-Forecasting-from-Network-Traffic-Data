"""
Verifiable Device Observation Registry
STRICT REAL-DATA-ONLY ARCHITECTURE (Rule B)

Maintains a device and network endpoint inventory derived exclusively from genuine observations.
Never fabricates, estimates, simulates, or hallucinates device identities, hostnames,
MAC addresses, manufacturers, or operating systems.

Key Identity Categories:
- 'Observed L2/L3 Node': IP and MAC observed in actual layer-2/layer-3 frame
- 'Observed IP Endpoint': IP observed without verifiable local MAC (e.g. routed remote host)
- 'Operating-system connection endpoint': Connection endpoint reported by OS kernel (netstat)
- 'Historical Observation': Endpoint parsed from offline PCAP trace
- 'Simulated Endpoint (Testing)': Isolated testing simulation node
"""

import time
import math
import ipaddress
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Set

# Configurable live-device recency timeout (default 60.0s)
CONNECTED_DEVICE_TIMEOUT_SECONDS: float = 60.0
# Maximum plausible future clock skew before timestamp is treated as unknown/corrupt
MAX_FUTURE_TIMESTAMP_SKEW_SECONDS: float = 60.0


def normalize_device_type(raw_type: Optional[str]) -> str:
    """
    Normalizes arbitrary device type / role strings into canonical categories.
    Returns 'Unknown' when the type cannot be reliably established.
    
    Canonical categories:
      - 'Router': Routers and verified gateways ('router', 'gateway', 'core router', 'edge router', 'default gateway')
      - 'Switch': Network switches ('switch', 'core switch', 'access switch')
      - 'Server': Servers ('server', 'web server', 'dns server', 'database server', 'file server')
      - 'Desktop / PC': Desktop PCs ('desktop', 'pc', 'workstation', 'desktop / pc', 'desktop/pc')
      - 'Laptop': Laptops ('laptop', 'notebook')
      - 'Mobile device': Mobile devices ('mobile', 'mobile device', 'phone', 'smartphone', 'tablet', 'android', 'ios')
      - 'IoT device': IoT devices ('iot', 'iot device', 'smart device', 'sensor', 'camera')
      - 'Firewall': Firewalls ('firewall', 'fw', 'ngfw', 'next-gen firewall')
      - 'Unknown': Anything unverified or unrecognized
    """
    if not raw_type or not isinstance(raw_type, str):
        return "Unknown"

    cleaned = raw_type.strip().lower()

    if not cleaned or cleaned in ("unknown", "unverified", "other", "none", ""):
        return "Unknown"

    if cleaned in ("observed ip endpoint", "observed l2/l3 node", "operating-system connection endpoint"):
        return "Unknown"

    # Router rule: Gateway and Core Router normalize strictly to Router
    if any(k in cleaned for k in ("router", "gateway")):
        return "Router"

    if "switch" in cleaned:
        return "Switch"

    if "server" in cleaned:
        return "Server"

    if any(k in cleaned for k in ("desktop", "workstation", "pc")):
        return "Desktop / PC"

    if any(k in cleaned for k in ("laptop", "notebook")):
        return "Laptop"

    if any(k in cleaned for k in ("mobile", "phone", "tablet", "android", "ios")):
        return "Mobile device"

    if any(k in cleaned for k in ("iot", "sensor", "camera", "smart device")):
        return "IoT device"

    if any(k in cleaned for k in ("firewall", "fw", "ngfw")):
        return "Firewall"

    return "Unknown"


class DeviceObservation:
    """
    Represents an endpoint supported exclusively by genuine network observations.
    Never invents attributes not present in the observation.
    """
    def __init__(
        self,
        ip_address: str,
        mac_address: Optional[str] = None,
        identity_type: str = "Observed IP Endpoint",
        observation_source: str = "Real Packet Capture",
        mode: str = "live",
        first_seen: Optional[float] = None,
        last_seen: Optional[float] = None,
        bytes_len: Optional[int] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        attribution_notes: Optional[str] = None,
        device_type: Optional[str] = None
    ):
        now = time.time()
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.identity_type = identity_type
        self.observation_source = observation_source
        self.mode = mode
        self.device_type = normalize_device_type(device_type or identity_type)
        
        self.first_seen = first_seen if first_seen is not None else now
        self.last_seen = last_seen if last_seen is not None else now
        self.observation_count = 1
        self.total_bytes = bytes_len if bytes_len is not None else 0
        self.bytes_measured = bytes_len is not None
        
        self.protocols_seen: Set[str] = set()
        if protocol:
            self.protocols_seen.add(protocol.upper())

        self.ports_seen: Set[int] = set()
        if port and port > 0:
            self.ports_seen.add(port)

        self.attribution_notes = attribution_notes or self._default_attribution_note(mac_address, mode)

    def _default_attribution_note(self, mac: Optional[str], mode: str) -> str:
        if mode == "pcap":
            return "Historical PCAP record. Observation reflects timestamped traffic from saved trace."
        if mode == "simulation":
            return "Test simulation node. Quarantined from live telemetry."
        if mode == "connection_metadata":
            return "Operating-system connection endpoint (netstat). Byte volume and frame MAC not available."
        if mac:
            return "Direct local layer-2 observation with observed hardware MAC."
        return "Routed IP endpoint. Frame MAC unavailable across L3 gateway/NAT. IP may represent multiple hosts or NAT pool."

    def update_observation(
        self,
        timestamp: float,
        mac_address: Optional[str] = None,
        bytes_len: Optional[int] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        source: Optional[str] = None,
        device_type: Optional[str] = None
    ):
        """Updates cumulative observations strictly incrementing evidence counters."""
        self.observation_count += 1
        if timestamp > self.last_seen:
            self.last_seen = timestamp

        if device_type:
            norm_type = normalize_device_type(device_type)
            if norm_type != "Unknown":
                self.device_type = norm_type

        # Update MAC only if a genuine MAC is observed and wasn't known before
        if mac_address and not self.mac_address:
            self.mac_address = mac_address
            self.identity_type = "Observed L2/L3 Node"
            self.attribution_notes = "Direct local layer-2 observation with observed hardware MAC."

        if bytes_len is not None:
            self.total_bytes += bytes_len
            self.bytes_measured = True

        if protocol:
            self.protocols_seen.add(protocol.upper())

        if port and port > 0:
            self.ports_seen.add(port)

        if source and source not in self.observation_source:
            self.observation_source = f"{self.observation_source}, {source}"

    def get_connectivity(
        self,
        current_time: Optional[float] = None,
        timeout_seconds: float = CONNECTED_DEVICE_TIMEOUT_SECONDS
    ) -> Dict[str, Any]:
        """
        Derives connection status strictly from genuine observations and timestamps.
        Canonical connection states:
          - 'connected': Live observation with valid timestamp within timeout_seconds.
          - 'disconnected': Live observation with valid timestamp exceeding timeout_seconds.
          - 'historical': Offline PCAP trace observation (never connected live).
          - 'unknown': Simulation, missing/malformed timestamp, or implausible future timestamp.
        """
        now = current_time if current_time is not None else time.time()

        # Offline PCAP is historical, never connected
        if self.mode == "pcap":
            return {
                "connection_status": "historical",
                "legacy_status": "Historical record",
                "is_connected": False,
                "connectivity_source": "Offline PCAP trace",
                "reason": "Historical PCAP observation; not an active live device."
            }

        # Simulation is testing only, never live connected
        if self.mode == "simulation":
            return {
                "connection_status": "unknown",
                "legacy_status": "Simulated endpoint (Testing)",
                "is_connected": False,
                "connectivity_source": "Quarantined Simulation",
                "reason": "Simulation record excluded from live network connectivity."
            }

        # Check timestamp validity
        if self.last_seen is None or math.isnan(self.last_seen) or math.isinf(self.last_seen) or self.last_seen <= 0:
            return {
                "connection_status": "unknown",
                "legacy_status": "Unknown",
                "is_connected": False,
                "connectivity_source": "Unverified Timestamp",
                "reason": "Missing or invalid observation timestamp."
            }

        # Conservative check for future timestamps (clock skew / corruption)
        if self.last_seen > (now + MAX_FUTURE_TIMESTAMP_SKEW_SECONDS):
            return {
                "connection_status": "unknown",
                "legacy_status": "Unknown",
                "is_connected": False,
                "connectivity_source": "Implausible Future Timestamp",
                "reason": f"Observation timestamp is {round(self.last_seen - now, 1)}s in the future."
            }

        # Live observation evaluation
        time_since_last = now - self.last_seen
        if time_since_last < 0:
            time_since_last = 0.0

        if time_since_last <= timeout_seconds:
            return {
                "connection_status": "connected",
                "legacy_status": "Recently observed",
                "is_connected": True,
                "connectivity_source": self.observation_source,
                "reason": f"Observed {round(time_since_last, 1)}s ago (within {timeout_seconds}s timeout)."
            }
        else:
            return {
                "connection_status": "disconnected",
                "legacy_status": "No recent observations",
                "is_connected": False,
                "connectivity_source": self.observation_source,
                "reason": f"Last observed {round(time_since_last, 1)}s ago (exceeded {timeout_seconds}s timeout)."
            }

    def get_status(self, current_time: Optional[float] = None, recency_threshold: float = CONNECTED_DEVICE_TIMEOUT_SECONDS) -> str:
        """
        Calculates status strictly based on observation recency and validity.
        Preserves legacy API contract ('Recently observed', 'No recent observations', etc.).
        """
        conn = self.get_connectivity(current_time=current_time, timeout_seconds=recency_threshold)
        return conn["legacy_status"]

    def to_dict(self, recency_threshold: float = CONNECTED_DEVICE_TIMEOUT_SECONDS, current_time: Optional[float] = None) -> Dict[str, Any]:
        """Serializes endpoint record with full data provenance, connectivity state, and explicit caveats."""
        now = current_time if current_time is not None else time.time()
        conn_info = self.get_connectivity(current_time=now, timeout_seconds=recency_threshold)

        first_seen_str = datetime.fromtimestamp(self.first_seen).strftime("%Y-%m-%d %H:%M:%S") if (self.first_seen and self.first_seen > 0) else "Unavailable"
        last_seen_str = datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S") if (self.last_seen and self.last_seen > 0) else "Unavailable"
        
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "identity_type": self.identity_type,
            "device_type": self.device_type,
            "observation_source": self.observation_source,
            "mode": self.mode,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_seen_str": first_seen_str,
            "last_seen_str": last_seen_str,
            "seconds_since_last_seen": round(now - self.last_seen, 1) if (self.mode == "live" and self.last_seen and self.last_seen > 0) else None,
            "observation_count": self.observation_count,
            "bytes_observed": self.total_bytes if self.bytes_measured else None,
            "status": conn_info["legacy_status"],
            "connection_status": conn_info["connection_status"],
            "is_connected": conn_info["is_connected"],
            "connectivity_source": conn_info["connectivity_source"],
            "connectivity_reason": conn_info["reason"],
            "protocols_observed": sorted(list(self.protocols_seen)),
            "ports_observed": sorted(list(self.ports_seen)),
            "attribution_notes": self.attribution_notes
        }


class DeviceObservationRegistry:
    """
    Registry for network endpoints verified by real observations.
    Maintains strict quarantine between LIVE, PCAP, SIMULATION, and CONNECTION METADATA.
    """

    def __init__(self, recency_threshold: float = CONNECTED_DEVICE_TIMEOUT_SECONDS):
        self.recency_threshold = float(recency_threshold)
        self.connected_timeout = float(recency_threshold)
        self._lock = threading.RLock()
        
        # Quarantined mode storage
        self._live_registry: Dict[str, DeviceObservation] = {}
        self._pcap_registry: Dict[str, DeviceObservation] = {}
        self._sim_registry: Dict[str, DeviceObservation] = {}
        self._conn_registry: Dict[str, DeviceObservation] = {}

    def _validate_ip(self, ip: Optional[str]) -> Optional[str]:
        """Validates that IP is a well-formed IPv4 or IPv6 address and not an empty or wild card."""
        if not ip or not isinstance(ip, str):
            return None
        ip_clean = ip.strip("[] \t\r\n")
        if ip_clean in ("0.0.0.0", "*", "::", "broadcast", "255.255.255.255"):
            return None
        try:
            parsed = ipaddress.ip_address(ip_clean)
            return str(parsed)
        except ValueError:
            return None

    def _validate_mac(self, mac: Optional[str]) -> Optional[str]:
        """Validates MAC address string format; returns None if missing, malformed, or broadcast."""
        if not mac or not isinstance(mac, str):
            return None
        mac_clean = mac.strip().lower()
        if mac_clean in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "unknown", "none", ""):
            return None
        parts = mac_clean.replace("-", ":").split(":")
        if len(parts) == 6 and all(len(p) <= 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
            return ":".join(f"{int(p, 16):02x}" for p in parts)
        return None

    def _get_target_map(self, mode: str) -> Dict[str, DeviceObservation]:
        """Returns the specific quarantined storage map for the given mode."""
        if mode == "live":
            return self._live_registry
        elif mode == "pcap":
            return self._pcap_registry
        elif mode == "simulation":
            return self._sim_registry
        elif mode == "connection_metadata":
            return self._conn_registry
        else:
            return self._live_registry

    def record_observation(
        self,
        ip: str,
        mac: Optional[str] = None,
        source: str = "Real Packet Capture",
        bytes_len: Optional[int] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        timestamp: Optional[float] = None,
        mode: str = "live",
        device_type: Optional[str] = None
    ) -> Optional[DeviceObservation]:
        """
        Records an endpoint observation.
        Validates IP and MAC; returns None if observation is invalid.
        """
        valid_ip = self._validate_ip(ip)
        if not valid_ip:
            return None

        valid_mac = self._validate_mac(mac)
        ts = timestamp if timestamp is not None else time.time()

        identity_type = "Observed L2/L3 Node" if valid_mac else "Observed IP Endpoint"
        if mode == "connection_metadata":
            identity_type = "Operating-system connection endpoint"

        with self._lock:
            registry_map = self._get_target_map(mode)
            if valid_ip in registry_map:
                entry = registry_map[valid_ip]
                entry.update_observation(
                    timestamp=ts,
                    mac_address=valid_mac,
                    bytes_len=bytes_len,
                    protocol=protocol,
                    port=port,
                    source=source,
                    device_type=device_type
                )
                return entry
            else:
                entry = DeviceObservation(
                    ip_address=valid_ip,
                    mac_address=valid_mac,
                    identity_type=identity_type,
                    observation_source=source,
                    mode=mode,
                    first_seen=ts,
                    last_seen=ts,
                    bytes_len=bytes_len,
                    protocol=protocol,
                    port=port,
                    device_type=device_type
                )
                registry_map[valid_ip] = entry
                return entry

    def record_packet(self, pkt, mode: str = "live"):
        """Records source and destination endpoints from a genuine CapturedPacket object."""
        if not pkt:
            return
        src_ip = getattr(pkt, "src_ip", None)
        dst_ip = getattr(pkt, "dst_ip", None)
        src_mac = getattr(pkt, "src_mac", None)
        dst_mac = getattr(pkt, "dst_mac", None)
        proto = getattr(pkt, "proto", None)
        sport = getattr(pkt, "sport", 0)
        dport = getattr(pkt, "dport", 0)
        length = getattr(pkt, "length", None)
        ts = getattr(pkt, "timestamp", time.time())
        source = getattr(pkt, "observation_source", "Real Packet Capture")

        if src_ip:
            self.record_observation(
                ip=src_ip,
                mac=src_mac,
                source=f"{source} (Source)",
                bytes_len=length,
                protocol=proto,
                port=sport,
                timestamp=ts,
                mode=mode
            )
        if dst_ip:
            self.record_observation(
                ip=dst_ip,
                mac=dst_mac,
                source=f"{source} (Destination)",
                bytes_len=length,
                protocol=proto,
                port=dport,
                timestamp=ts,
                mode=mode
            )

    def record_connection(self, conn):
        """Records endpoints from an OS ConnectionRecord (netstat)."""
        if not conn:
            return
        local_ip = getattr(conn, "local_ip", None)
        foreign_ip = getattr(conn, "foreign_ip", None)
        proto = getattr(conn, "proto", None)
        local_port = getattr(conn, "local_port", 0)
        foreign_port = getattr(conn, "foreign_port", 0)
        ts = getattr(conn, "timestamp", time.time())
        source = getattr(conn, "observation_source", "Operating System Connection Table (netstat)")

        if local_ip:
            self.record_observation(
                ip=local_ip,
                mac=None,
                source=f"{source} (Local)",
                bytes_len=None,
                protocol=proto,
                port=local_port,
                timestamp=ts,
                mode="connection_metadata"
            )
        if foreign_ip:
            self.record_observation(
                ip=foreign_ip,
                mac=None,
                source=f"{source} (Foreign)",
                bytes_len=None,
                protocol=proto,
                port=foreign_port,
                timestamp=ts,
                mode="connection_metadata"
            )

    def get_devices(
        self,
        mode: str = "live",
        connected_only: bool = False,
        timeout_seconds: Optional[float] = None,
        current_time: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Returns verified endpoint observations for the specified mode.
        Strictly prevents simulation or PCAP data from leaking into live queries.
        
        Args:
            mode: Registry mode ('live', 'pcap', 'simulation', 'connection_metadata')
            connected_only: When True, filters to endpoints with is_connected == True
            timeout_seconds: Optional custom timeout in seconds (defaults to self.connected_timeout)
            current_time: Optional reference timestamp for testing
        """
        threshold = timeout_seconds if timeout_seconds is not None else self.connected_timeout
        now = current_time if current_time is not None else time.time()
        with self._lock:
            registry_map = self._get_target_map(mode)
            devices = [
                d.to_dict(recency_threshold=threshold, current_time=now)
                for d in registry_map.values()
            ]
            if connected_only:
                devices = [d for d in devices if d.get("is_connected", False) is True]
            # Sort by last seen descending
            devices.sort(key=lambda x: (x["last_seen"] or 0), reverse=True)
            return devices

    def get_connected_devices(
        self,
        timeout_seconds: Optional[float] = None,
        current_time: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Convenience method returning strictly verified live connected devices."""
        return self.get_devices(
            mode="live",
            connected_only=True,
            timeout_seconds=timeout_seconds,
            current_time=current_time
        )

    def get_device_by_ip(self, ip: str, mode: str = "live") -> Optional[Dict[str, Any]]:
        """Finds an endpoint by IP address in the specified operating mode."""
        valid_ip = self._validate_ip(ip)
        if not valid_ip:
            return None
        with self._lock:
            registry_map = self._get_target_map(mode)
            entry = registry_map.get(valid_ip)
            return entry.to_dict(recency_threshold=self.recency_threshold) if entry else None

    def count(self, mode: str = "live") -> int:
        """Returns the number of verified observed endpoints for a mode."""
        with self._lock:
            return len(self._get_target_map(mode))

    def cleanup_stale(self, max_age_seconds: float, mode: Optional[str] = None) -> int:
        """
        Thread-safely removes observations whose last_seen is older than max_age_seconds.
        If mode is specified, prunes only that mode's storage. Otherwise, prunes all modes.
        Returns the total number of pruned records.
        """
        if max_age_seconds <= 0:
            return 0
        now = time.time()
        cutoff = now - max_age_seconds
        pruned_count = 0
        with self._lock:
            maps_to_clean = [self._get_target_map(mode)] if mode else [
                self._live_registry,
                self._pcap_registry,
                self._sim_registry,
                self._conn_registry
            ]
            for reg in maps_to_clean:
                stale_keys = [ip for ip, entry in reg.items() if entry.last_seen < cutoff]
                for k in stale_keys:
                    del reg[k]
                    pruned_count += 1
        return pruned_count

    def clear(self, mode: Optional[str] = None):
        """Clears registry records for the specified mode, or all modes if None."""
        with self._lock:
            if mode:
                self._get_target_map(mode).clear()
            else:
                self._live_registry.clear()
                self._pcap_registry.clear()
                self._sim_registry.clear()
                self._conn_registry.clear()

