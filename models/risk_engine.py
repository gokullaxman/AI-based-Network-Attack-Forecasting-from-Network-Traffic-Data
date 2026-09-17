"""
Pipeline Step 5 & 6: Dynamic Risk Engine & Preventive Response Recommender
- Dynamic Risk Score (0 - 100): Calculated from current stage severity, predicted next stage severity,
  transition confidence, and traffic behavioural anomaly intensity.
- Risk Classification: LOW (<40), MEDIUM (40-75), HIGH (>=75).
- Multiple Defending Methods: Ranked list of 2-4 concrete, non-blocking defensive options,
  each tied directly to the predicted next stage and the SHAP-flagged top contributing features
  with an explicit feature-based rationale string for security analyst review.
"""

from typing import Dict, Any, Tuple, List, Optional


STAGE_SEVERITY = {
    "Reconnaissance": 20,
    "Scanning": 35,
    "Enumeration": 55,
    "Exploitation": 82,
    "Intrusion": 95
}


class DynamicRiskEngine:
    """Computes dynamic risk score and generates ranked preventive defense options with SHAP-based rationales."""

    def __init__(self):
        self.severity_weights = STAGE_SEVERITY

    def compute_risk(
        self,
        current_stage: str,
        predicted_next_stage: str,
        confidence: float,
        anomaly_intensity: float = 0.5
    ) -> Tuple[int, str]:
        """
        Calculate dynamic risk score (0-100) and risk category (LOW / MEDIUM / HIGH).
        """
        curr_sev = self.severity_weights.get(current_stage, 25)
        next_sev = self.severity_weights.get(predicted_next_stage, 35)
        
        score_val = (0.35 * curr_sev) + (0.45 * next_sev * confidence) + (0.20 * anomaly_intensity * 100.0)
        risk_score = int(min(100, max(5, round(score_val))))
        
        if risk_score < 40:
            risk_level = "LOW"
        elif risk_score < 75:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"
            
        return risk_score, risk_level

    def get_recommendation(
        self,
        predicted_next_stage: str,
        top_features: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generates a ranked list of 2-4 concrete, non-blocking defensive options,
        each tied to the predicted next stage and the SHAP-flagged top contributing feature(s).
        Returns a dict with `title`, `description`, and `options` list.
        """
        # Extract top 2 feature names and values from SHAP ranking for the rationale string
        feat1_name = "conn_frequency"
        feat1_val = "0.45"
        feat2_name = "dst_ip_fanout"
        feat2_val = "0.38"

        if top_features and len(top_features) > 0:
            f1 = top_features[0]
            feat1_name = f1.get("feature", "conn_frequency")
            val1 = f1.get("attribution", f1.get("value", 0.45))
            feat1_val = f"{abs(float(val1)):.2f}"
            
            if len(top_features) > 1:
                f2 = top_features[1]
                feat2_name = f2.get("feature", "dst_ip_fanout")
                val2 = f2.get("attribution", f2.get("value", 0.38))
                feat2_val = f"{abs(float(val2)):.2f}"
            else:
                feat2_name = "iat_jitter"
                feat2_val = "0.22"

        options = []

        if predicted_next_stage == "Reconnaissance":
            options = [
                {
                    "priority": 1,
                    "action": "Inspect ingress edge telemetry and rate-limit discovery probes",
                    "rationale": f"Rate-limit perimeter probes — driven by elevated {feat1_name} ({feat1_val}) and {feat2_name} ({feat2_val})."
                },
                {
                    "priority": 2,
                    "action": "Tighten ICMP/ARP gateway broadcast ACLs and verify DMZ host isolation",
                    "rationale": f"Filter discovery sweeps — driven by abnormal {feat1_name} ({feat1_val})."
                },
                {
                    "priority": 3,
                    "action": "Arm decoy darknet addresses and monitor boundary honeypot tripwires",
                    "rationale": f"Honeypot activation — indicated by early target mapping in {feat2_name} ({feat2_val})."
                }
            ]
            title = "Ingress Filtering & Probe Threshold Tuning"
            description = "Inspect perimeter firewall and IDS logs for sequential sweep patterns. Review ICMP/ARP rate-limiting policies on external gateways."

        elif predicted_next_stage == "Scanning":
            options = [
                {
                    "priority": 1,
                    "action": "Rate-limit suspicious source IPs and drop half-open connections",
                    "rationale": f"Throttle scanning sources — driven by elevated {feat1_name} ({feat1_val}) and {feat2_name} ({feat2_val})."
                },
                {
                    "priority": 2,
                    "action": "Tighten firewall ACLs on probed port ranges and cloaked service ports",
                    "rationale": f"Filter target ports — driven by high {feat1_name} ({feat1_val})."
                },
                {
                    "priority": 3,
                    "action": "Enable stateful port-scan detection alerting and SYN-cookie thresholds",
                    "rationale": f"Alert SOC analysts — driven by sweep intensity in {feat2_name} ({feat2_val})."
                }
            ]
            title = "Port Cloaking & Adaptive Rate Limiting"
            description = "Validate perimeter ACLs against unmapped high-port sweeps. Increase SYN-cookie thresholds, flag anomalous source IPs for analyst inspection."

        elif predicted_next_stage == "Enumeration":
            options = [
                {
                    "priority": 1,
                    "action": "Disable unnecessary service banners and suppress HTTP/SSH version headers",
                    "rationale": f"Mask service versions — driven by elevated {feat1_name} ({feat1_val}) and {feat2_name} ({feat2_val})."
                },
                {
                    "priority": 2,
                    "action": "Restrict SMB, RPC, and SSH exposure to authorized bastion management subnets",
                    "rationale": f"Limit service access — driven by targeted probe concentration in {feat1_name} ({feat1_val})."
                },
                {
                    "priority": 3,
                    "action": "Stage credential rotation for queried service accounts and verify WAF inspect rules",
                    "rationale": f"Rotate vulnerable credentials — driven by anomalous query bursts in {feat2_name} ({feat2_val})."
                }
            ]
            title = "Service Banner Suppression & Access Restraint"
            description = "Enforce strict HTTP/SSH/SMB header masking to suppress version enumeration. Review web application firewall (WAF) inspect rules and verify endpoint service exposure."

        elif predicted_next_stage == "Exploitation":
            options = [
                {
                    "priority": 1,
                    "action": "Apply virtual patching and emergency WAF inspection rules for targeted services",
                    "rationale": f"Deploy virtual patch — driven by elevated {feat1_name} ({feat1_val}) and payload burstiness in {feat2_name} ({feat2_val})."
                },
                {
                    "priority": 2,
                    "action": "Stage rapid network micro-segmentation and prepare candidate host isolation",
                    "rationale": f"Isolate affected endpoint — driven by critical {feat1_name} ({feat1_val})."
                },
                {
                    "priority": 3,
                    "action": "Enforce mandatory MFA step-up verification on exposed application endpoints",
                    "rationale": f"Enforce step-up authentication — driven by timing irregularities in {feat2_name} ({feat2_val})."
                }
            ]
            title = "Targeted Host Isolation & Patch Validation"
            description = "Alert Tier-2 SOC analysts to prioritize candidate vulnerable service endpoints. Prepare rapid network micro-segmentation and stage emergency virtual patching rules."

        else: # Intrusion
            options = [
                {
                    "priority": 1,
                    "action": "Segment and quarantine the affected subnet to prevent lateral movement",
                    "rationale": f"Segment subnet — driven by elevated {feat1_name} ({feat1_val}) and {feat2_name} ({feat2_val})."
                },
                {
                    "priority": 2,
                    "action": "Force enterprise-wide credential rotation and invalidate active Kerberos/OAuth sessions",
                    "rationale": f"Revoke compromised tokens — driven by breach escalation in {feat1_name} ({feat1_val})."
                },
                {
                    "priority": 3,
                    "action": "Escalate to Tier-3 Incident Response (IR) war room and initiate memory forensics capture",
                    "rationale": f"Trigger forensic acquisition — driven by sustained beaconing in {feat2_name} ({feat2_val})."
                }
            ]
            title = "Privilege Audit & East-West Flow Containment"
            description = "Review lateral Kerberos/SMB traffic anomalies. Stage credential invalidation for exposed service accounts, verify honeypot tripwires, and ready endpoint containment."

        return {
            "title": title,
            "description": description,
            "options": options
        }
