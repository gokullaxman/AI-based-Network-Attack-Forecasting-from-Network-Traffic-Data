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
import ipaddress
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Set


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
        attribution_notes: Optional[str] = None
    ):
        now = time.time()
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.identity_type = identity_type
        self.observation_source = observation_source
        self.mode = mode
        
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
        source: Optional[str] = None
    ):
        """Updates cumulative observations strictly incrementing evidence counters."""
        self.observation_count += 1
        if timestamp > self.last_seen:
            self.last_seen = timestamp

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

    def get_status(self, current_time: Optional[float] = None, recency_threshold: float = 60.0) -> str:
        """
        Calculates status strictly based on observation recency.
        Never asserts a device is definitely 'online' or 'offline'.
        """
        if self.mode == "pcap":
            return "Historical record"
        if self.mode == "simulation":
            return "Simulated endpoint (Testing)"

        now = current_time if current_time is not None else time.time()
        time_since_last = now - self.last_seen
        if time_since_last <= recency_threshold:
            return "Recently observed"
        else:
            return "No recent observations"

    def to_dict(self, recency_threshold: float = 60.0) -> Dict[str, Any]:
        """Serializes endpoint record with full data provenance and explicit caveats."""
        now = time.time()
        first_seen_str = datetime.fromtimestamp(self.first_seen).strftime("%Y-%m-%d %H:%M:%S")
        last_seen_str = datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "identity_type": self.identity_type,
            "observation_source": self.observation_source,
            "mode": self.mode,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_seen_str": first_seen_str,
            "last_seen_str": last_seen_str,
            "seconds_since_last_seen": round(now - self.last_seen, 1) if self.mode == "live" else None,
            "observation_count": self.observation_count,
            "bytes_observed": self.total_bytes if self.bytes_measured else None,
            "status": self.get_status(recency_threshold=recency_threshold),
            "protocols_observed": sorted(list(self.protocols_seen)),
            "ports_observed": sorted(list(self.ports_seen)),
            "attribution_notes": self.attribution_notes
        }


class DeviceObservationRegistry:
    """
    Registry for network endpoints verified by real observations.
    Maintains strict quarantine between LIVE, PCAP, SIMULATION, and CONNECTION METADATA.
    """

    def __init__(self, recency_threshold: float = 60.0):
        self.recency_threshold = recency_threshold
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
        mode: str = "live"
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
                    source=source
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
                    port=port
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

    def get_devices(self, mode: str = "live") -> List[Dict[str, Any]]:
        """
        Returns all verified endpoint observations for the specified mode.
        Strictly prevents simulation or PCAP data from leaking into live queries.
        """
        with self._lock:
            registry_map = self._get_target_map(mode)
            devices = [
                d.to_dict(recency_threshold=self.recency_threshold)
                for d in registry_map.values()
            ]
            # Sort by last seen descending
            devices.sort(key=lambda x: x["last_seen"], reverse=True)
            return devices

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

