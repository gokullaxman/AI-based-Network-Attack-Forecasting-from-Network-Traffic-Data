"""
Shared Packet Record Schema and Unified Packet Parser
Defines an evidence-backed packet metadata representation for both offline PCAPs and live capture.
Excludes synthetic fields, fictional application protocols, or decrypted payload claims.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import time

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    Ether = IP = IPv6 = TCP = UDP = ICMP = ARP = Raw = None


@dataclass
class PacketMetadata:
    """
    Structured metadata representing a single genuinely observed network packet.
    Distinguishes captured frame length from wire length, and tracks parse status.
    """
    pkt_id: int
    timestamp: float                       # UNIX timestamp (seconds, floating point)
    captured_len: int                      # Captured frame byte length (in buffer/trace)
    wire_len: int                          # Original on-the-wire frame length (if available)
    network_protocol: Optional[str] = None # e.g. "IPv4", "IPv6", "ARP", "OTHER"
    transport_protocol: Optional[str] = None # e.g. "TCP", "UDP", "ICMP", "OTHER"
    src_ip: Optional[str] = None           # Source IP address or L2 identifier
    dst_ip: Optional[str] = None           # Destination IP address or L2 identifier
    src_port: Optional[int] = None         # Source port (TCP/UDP)
    dst_port: Optional[int] = None         # Destination port (TCP/UDP)
    tcp_flags: Optional[str] = None        # TCP flag summary string (e.g. "S", "PA")
    src_mac: Optional[str] = None          # Source MAC address (if L2 present)
    dst_mac: Optional[str] = None          # Destination MAC address (if L2 present)
    has_payload: bool = False              # Whether transport payload was present
    payload_len: int = 0                   # Length of payload in bytes
    parse_status: str = "OK"               # "OK", "MALFORMED", "UNSUPPORTED"
    error_message: Optional[str] = None    # Error details if parse failed
    observation_source: str = "Unknown"    # Provenance source label

    def to_dict(self) -> Dict[str, Any]:
        """Serializes metadata to dictionary format."""
        return asdict(self)


def parse_scapy_packet(
    sc_pkt,
    pkt_id: int,
    source: str = "Real Packet Capture",
    default_timestamp: Optional[float] = None
) -> PacketMetadata:
    """
    Extracts strictly authentic headers and metadata from a Scapy packet object.
    Never infers application payload content or invents unverified attributes.
    """
    now = default_timestamp if default_timestamp is not None else time.time()
    
    # 1. Timestamp extraction
    pkt_time = now
    if hasattr(sc_pkt, "time") and sc_pkt.time is not None:
        try:
            pkt_time = float(sc_pkt.time)
        except (ValueError, TypeError):
            pkt_time = now

    # 2. Lengths: captured frame length vs on-the-wire length
    captured_len = len(sc_pkt) if sc_pkt is not None else 0
    wire_len = getattr(sc_pkt, "wirelen", captured_len)
    if wire_len is None or wire_len < captured_len:
        wire_len = captured_len

    if sc_pkt is None:
        return PacketMetadata(
            pkt_id=pkt_id,
            timestamp=pkt_time,
            captured_len=0,
            wire_len=0,
            parse_status="MALFORMED",
            error_message="Null packet object",
            observation_source=source
        )

    try:
        src_ip = None
        dst_ip = None
        src_mac = None
        dst_mac = None
        net_proto = "OTHER"
        trans_proto = "OTHER"
        sport = None
        dport = None
        flags = None
        payload_len = 0
        has_payload = False

        # Layer 2: Ethernet
        if Ether is not None and sc_pkt.haslayer(Ether):
            src_mac = str(sc_pkt[Ether].src)
            dst_mac = str(sc_pkt[Ether].dst)

        # Layer 3: IPv4, IPv6, ARP
        if IP is not None and sc_pkt.haslayer(IP):
            net_proto = "IPv4"
            src_ip = str(sc_pkt[IP].src)
            dst_ip = str(sc_pkt[IP].dst)
            proto_num = sc_pkt[IP].proto
            if proto_num == 6:
                trans_proto = "TCP"
            elif proto_num == 17:
                trans_proto = "UDP"
            elif proto_num == 1:
                trans_proto = "ICMP"
            else:
                trans_proto = f"IP({proto_num})"
        elif IPv6 is not None and sc_pkt.haslayer(IPv6):
            net_proto = "IPv6"
            src_ip = str(sc_pkt[IPv6].src)
            dst_ip = str(sc_pkt[IPv6].dst)
            trans_proto = "IPv6"
        elif ARP is not None and sc_pkt.haslayer(ARP):
            net_proto = "ARP"
            trans_proto = "ARP"
            src_ip = str(sc_pkt[ARP].psrc)
            dst_ip = str(sc_pkt[ARP].pdst)
            if not src_mac:
                src_mac = str(sc_pkt[ARP].hwsrc)
            if not dst_mac:
                dst_mac = str(sc_pkt[ARP].hwdst)

        # Layer 4: TCP, UDP, ICMP
        if TCP is not None and sc_pkt.haslayer(TCP):
            trans_proto = "TCP"
            sport = int(sc_pkt[TCP].sport)
            dport = int(sc_pkt[TCP].dport)
            flags = str(sc_pkt[TCP].flags)
        elif UDP is not None and sc_pkt.haslayer(UDP):
            trans_proto = "UDP"
            sport = int(sc_pkt[UDP].sport)
            dport = int(sc_pkt[UDP].dport)
        elif ICMP is not None and sc_pkt.haslayer(ICMP):
            trans_proto = "ICMP"
            flags = f"Type={sc_pkt[ICMP].type}"

        # Payload measurement (without storing sensitive data)
        if Raw is not None and sc_pkt.haslayer(Raw):
            load_bytes = bytes(sc_pkt[Raw].load)
            payload_len = len(load_bytes)
            has_payload = payload_len > 0

        return PacketMetadata(
            pkt_id=pkt_id,
            timestamp=pkt_time,
            captured_len=captured_len,
            wire_len=wire_len,
            network_protocol=net_proto,
            transport_protocol=trans_proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            tcp_flags=flags,
            src_mac=src_mac,
            dst_mac=dst_mac,
            has_payload=has_payload,
            payload_len=payload_len,
            parse_status="OK",
            observation_source=source
        )
    except Exception as e:
        return PacketMetadata(
            pkt_id=pkt_id,
            timestamp=pkt_time,
            captured_len=captured_len,
            wire_len=wire_len,
            parse_status="MALFORMED",
            error_message=str(e),
            observation_source=source
        )
