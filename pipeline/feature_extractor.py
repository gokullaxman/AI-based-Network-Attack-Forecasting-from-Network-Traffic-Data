"""
Pipeline Step 1: Behavioural & Temporal Feature Extraction
Extracts features across the 6 mandatory categories benchmarked on CICIDS2017/2018 flow distributions:
1. Connection frequency
2. Source–destination relationships
3. Port-access patterns
4. Host discovery
5. Service enumeration
6. Timing irregularities
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any


# 12 specific engineered features mapping directly to the 6 behavioural categories
FEATURE_NAMES = [
    # 1. Connection frequency
    "conn_frequency",         # flows / sec
    "packet_rate",            # total packets / flow duration
    # 2. Source-destination relationships
    "dst_ip_fanout",          # unique destination IPs contacted
    "src_dst_entropy",        # normalized entropy of target IP distribution
    # 3. Port-access patterns
    "port_diversity",         # unique destination ports accessed
    "well_known_port_ratio",  # fraction of packets targeting ports < 1024
    # 4. Host discovery
    "host_sweep_rate",        # rapid sequential target IP discovery attempts/sec
    "icmp_arp_ratio",         # ping / probe protocol ratio
    # 5. Service enumeration
    "service_probe_rate",     # service/version identification probe rate
    "targeted_query_volume",  # high-density queries on open services (HTTP/SSH/SMB)
    # 6. Timing irregularities
    "iat_jitter",             # variance / standard deviation of packet inter-arrival times
    "burstiness_index"        # peak-to-average transmission ratio
]

FEATURE_DESCRIPTIONS = {
    "conn_frequency": "Rate of network connection initiations per second",
    "packet_rate": "Mean packet transmission frequency",
    "dst_ip_fanout": "Volume of distinct target endpoints probed",
    "src_dst_entropy": "Dispersion entropy across target host addresses",
    "port_diversity": "Distinct destination port probe breadth",
    "well_known_port_ratio": "Proportion of requests targeting standard system ports (<1024)",
    "host_sweep_rate": "Frequency of horizontal host discovery attempts",
    "icmp_arp_ratio": "Ratio of diagnostic discovery frames (ICMP/ARP) to data frames",
    "service_probe_rate": "Rate of application-layer handshake/version probes",
    "targeted_query_volume": "Specific service inspection burst density (HTTP/SMB/SSH)",
    "iat_jitter": "Irregularity and jitter in packet inter-arrival intervals",
    "burstiness_index": "Peak-to-average flow burst irregularity ratio"
}


class FlowFeatureExtractor:
    """Extracts the 6 behavioral/temporal feature categories from network flow records."""

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def extract_from_raw_flow(self, flow: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical feature vector from a single flow or aggregate flow summary.
        Ensures all 12 behavioural features are present and non-negative.
        """
        feats = np.zeros(len(self.feature_names), dtype=np.float32)
        for i, name in enumerate(self.feature_names):
            val = float(flow.get(name, 0.0))
            feats[i] = max(0.0, val)
        return feats

    def extract_batch(self, flows: List[Dict[str, Any]]) -> np.ndarray:
        """Extract a batch of flow vectors (shape: [N, num_features])."""
        return np.array([self.extract_from_raw_flow(f) for f in flows], dtype=np.float32)
