"""
Pipeline Step 2: Temporal Sequence Construction
Generates and structures temporal sequences of network flow behavior benchmarked
on CICIDS2017/2018 multi-stage cyber attack distributions.

Stages modeled:
1. Reconnaissance: passive/active network probing, host discovery, ping sweeps
2. Scanning: SYN scans, aggressive port discovery across diverse ports
3. Enumeration: service/version detection, web application and protocol enumeration
4. Exploitation: vulnerability weaponization, anomalous payload bursts, high packet rate
5. Intrusion: successful breach, lateral movement, beaconing, command-and-control

BALANCED DISTRIBUTION:
Each of the 5 attack stages receives EQUAL representation across generated windows
and live stream sequences to prevent model/demo bias toward later stages.
Tolerates pauses (Benign traffic), repetitions, and behavioural variations.
"""

import numpy as np
from typing import Tuple, List, Dict, Any
from .feature_extractor import FEATURE_NAMES

STAGE_NAMES = [
    "Reconnaissance",
    "Scanning",
    "Enumeration",
    "Exploitation",
    "Intrusion"
]
STAGE_TO_IDX = {name: i for i, name in enumerate(STAGE_NAMES)}
NUM_STAGES = len(STAGE_NAMES)

# CICIDS2017/2018 feature profile prototypes (means and variances per stage)
STAGE_PROFILES = {
    # Benign / Background traffic
    "Benign": {
        "mean": [1.5, 12.0, 1.2, 0.15, 2.0, 0.85, 0.05, 0.02, 0.1, 5.0, 0.2, 1.1],
        "std":  [0.5, 4.0, 0.4, 0.05, 1.0, 0.10, 0.02, 0.01, 0.05, 2.0, 0.08, 0.2]
    },
    # 1. Reconnaissance: host discovery, sweeps, ICMP bursts
    "Reconnaissance": {
        "mean": [4.0, 18.0, 15.0, 0.82, 3.0, 0.40, 12.5, 0.65, 0.3, 8.0, 0.45, 2.2],
        "std":  [1.0, 5.0, 3.5, 0.10, 1.2, 0.12, 3.0, 0.15, 0.1, 3.0, 0.12, 0.5]
    },
    # 2. Scanning: high port diversity, rapid connection attempts
    "Scanning": {
        "mean": [18.5, 95.0, 4.0, 0.35, 48.0, 0.70, 2.0, 0.05, 1.5, 14.0, 0.85, 4.8],
        "std":  [4.0, 20.0, 1.2, 0.08, 12.0, 0.15, 0.8, 0.03, 0.4, 4.0, 0.18, 0.9]
    },
    # 3. Enumeration: targeted query volume, service banner probes
    "Enumeration": {
        "mean": [8.0, 45.0, 2.0, 0.20, 6.0, 0.95, 0.5, 0.01, 8.5, 62.0, 0.60, 3.2],
        "std":  [2.0, 12.0, 0.5, 0.05, 1.8, 0.04, 0.2, 0.01, 2.0, 15.0, 0.14, 0.6]
    },
    # 4. Exploitation: high packet rate, payload burstiness, timing anomalies
    "Exploitation": {
        "mean": [35.0, 320.0, 1.5, 0.18, 2.0, 0.88, 0.2, 0.00, 3.0, 140.0, 1.45, 8.5],
        "std":  [8.0, 60.0, 0.4, 0.04, 0.8, 0.08, 0.1, 0.00, 0.8, 30.0, 0.30, 1.8]
    },
    # 5. Intrusion: lateral movement, beaconing jitter, high fanout
    "Intrusion": {
        "mean": [12.0, 75.0, 8.5, 0.68, 5.0, 0.60, 1.8, 0.02, 4.2, 85.0, 1.10, 5.4],
        "std":  [3.0, 18.0, 2.0, 0.12, 1.5, 0.14, 0.5, 0.01, 1.1, 22.0, 0.25, 1.2]
    }
}


def sample_flow_feature(stage: str) -> np.ndarray:
    """Sample a single flow record feature vector matching the stage profile."""
    profile = STAGE_PROFILES[stage]
    vec = np.random.normal(profile["mean"], profile["std"])
    return np.maximum(0.01, vec).astype(np.float32)


def generate_balanced_attack_timeline(
    steps_per_stage: int = 10,
    pause_prob: float = 0.15,
    warmup_steps: int = 9
) -> List[Dict[str, Any]]:
    """
    Generates a balanced multi-stage attack timeline where each of the 5 stages
    receives approximately EQUAL duration and window representation.
    
    Progression order:
      Reconnaissance -> Scanning -> Enumeration -> Exploitation -> Intrusion
    """
    events = []
    progression_order = STAGE_NAMES
    global_step = 0
    
    for stage_idx, stage_name in enumerate(progression_order):
        # Forecasted next stage along progression
        if stage_idx < len(progression_order) - 1:
            next_stage_name = progression_order[stage_idx + 1]
        else:
            next_stage_name = progression_order[-1] # Intrusion persists
            
        num_steps = steps_per_stage + (warmup_steps if stage_idx == 0 else 0)
        for s in range(num_steps):
            # Interspersed benign pauses (tolerating variation without losing stage label)
            is_pause = np.random.rand() < pause_prob and s > 1
            effective_stage = "Benign" if is_pause else stage_name
            
            feature_vector = sample_flow_feature(effective_stage)
            
            events.append({
                "step": global_step,
                "stage": stage_name,
                "stage_idx": stage_idx,
                "effective_stage": effective_stage,
                "next_stage": next_stage_name,
                "next_stage_idx": STAGE_TO_IDX[next_stage_name],
                "features": feature_vector
            })
            global_step += 1
            
    return events


# For backward compatibility
generate_multi_stage_sequence = generate_balanced_attack_timeline


def build_temporal_dataset(
    num_timelines: int = 150,
    sequence_length: int = 10,
    steps_per_stage: int = 14
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Construct sliding temporal sequences from balanced attack timelines.
    Ensures approximately EQUAL representation across all 5 stage labels.
    
    Returns:
      X: [N, sequence_length, num_features]
      y_current: [N] current stage index (0 to 4)
      y_next: [N] next stage index (0 to 4)
    """
    # Group windows by current stage to guarantee equal balancing
    stage_windows = {i: [] for i in range(NUM_STAGES)}
    stage_nexts = {i: [] for i in range(NUM_STAGES)}
    
    for _ in range(num_timelines):
        timeline = generate_balanced_attack_timeline(
            steps_per_stage=steps_per_stage,
            warmup_steps=sequence_length - 1
        )
        
        for i in range(len(timeline) - sequence_length + 1):
            window = timeline[i : i + sequence_length]
            target_event = window[-1]
            
            curr_idx = target_event["stage_idx"]
            next_idx = target_event["next_stage_idx"]
            
            window_feats = np.array([ev["features"] for ev in window], dtype=np.float32)
            stage_windows[curr_idx].append(window_feats)
            stage_nexts[curr_idx].append(next_idx)
            
    # Equalize count across all 5 stages to the minimum available count
    min_count = min(len(stage_windows[i]) for i in range(NUM_STAGES))
    
    X_list = []
    y_curr_list = []
    y_next_list = []
    
    for stage_idx in range(NUM_STAGES):
        # Sample min_count items per stage
        selected_indices = np.random.choice(len(stage_windows[stage_idx]), size=min_count, replace=False)
        for idx in selected_indices:
            X_list.append(stage_windows[stage_idx][idx])
            y_curr_list.append(stage_idx)
            y_next_list.append(stage_nexts[stage_idx][idx])
            
    # Shuffle together
    perm = np.random.permutation(len(X_list))
    X_arr = np.array(X_list, dtype=np.float32)[perm]
    y_curr_arr = np.array(y_curr_list, dtype=np.int64)[perm]
    y_next_arr = np.array(y_next_list, dtype=np.int64)[perm]
    
    return X_arr, y_curr_arr, y_next_arr
