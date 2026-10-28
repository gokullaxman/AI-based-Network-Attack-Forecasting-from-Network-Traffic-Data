"""
Pipeline Step 5 & 6: Dynamic Risk Engine & Preventive Response Recommender
- Dynamic Risk Score (0 - 100): Calculated from current stage severity, predicted next stage severity,
  transition confidence, and traffic behavioural anomaly intensity.
- Risk Classification: LOW (<40), MEDIUM (40-75), HIGH (>=75).
- Multiple Defending Methods: Ranked list of 2-4 concrete, non-blocking defensive options,
  each tied directly to the predicted next stage and the SHAP-flagged top contributing features
  with an explicit feature-based rationale string for security analyst review.
"""

import math
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
        Strictly validates numeric types, finite ranges, and bounded probabilities.
        """
        if confidence is None or not isinstance(confidence, (int, float)) or math.isnan(confidence) or math.isinf(confidence):
            raise ValueError(f"Invalid confidence value: {confidence}. Expected finite float in [0.0, 1.0].")
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Confidence {confidence} out of supported range [0.0, 1.0].")

        if anomaly_intensity is None or not isinstance(anomaly_intensity, (int, float)) or math.isnan(anomaly_intensity) or math.isinf(anomaly_intensity):
            raise ValueError(f"Invalid anomaly_intensity value: {anomaly_intensity}. Expected finite float in [0.0, 1.0].")
        if not (0.0 <= anomaly_intensity <= 1.0):
            raise ValueError(f"Anomaly intensity {anomaly_intensity} out of supported range [0.0, 1.0].")

        curr_sev = self.severity_weights.get(current_stage, 25)
        next_sev = self.severity_weights.get(predicted_next_stage, 35)

        score_val = (0.35 * curr_sev) + (0.45 * next_sev * float(confidence)) + (0.20 * float(anomaly_intensity) * 100.0)
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
        Generates a ranked list of 2-4 concrete, non-blocking defensive options.
        If real SHAP top_features are provided, the rationale directly references the
        genuine contributing features and attributions.
        If SHAP is unavailable or empty, standard defensive rationales are provided
        without fabricating attribution values or false feature names.
        """
        has_shap = bool(top_features and len(top_features) > 0)
        feat1_name: Optional[str] = None
        feat1_val: Optional[str] = None
        feat2_name: Optional[str] = None
        feat2_val: Optional[str] = None

        if has_shap and top_features:
            f1 = top_features[0]
            feat1_name = str(f1.get("feature", "unknown_feature"))
            val1 = f1.get("attribution", f1.get("value", 0.0))
            try:
                feat1_val = f"{abs(float(val1)):.2f}"
            except (ValueError, TypeError):
                feat1_val = "0.00"

            if len(top_features) > 1:
                f2 = top_features[1]
                feat2_name = str(f2.get("feature", "secondary_feature"))
                val2 = f2.get("attribution", f2.get("value", 0.0))
                try:
                    feat2_val = f"{abs(float(val2)):.2f}"
                except (ValueError, TypeError):
                    feat2_val = "0.00"

        options = []

        if predicted_next_stage == "Reconnaissance":
            r1 = f"Rate-limit perimeter probes — driven by elevated {feat1_name} ({feat1_val})" + (f" and {feat2_name} ({feat2_val})." if feat2_name else ".") if has_shap else "Rate-limit perimeter probes — standard defensive policy (SHAP attribution unavailable)."
            r2 = f"Filter discovery sweeps — driven by abnormal {feat1_name} ({feat1_val})." if has_shap else "Filter discovery sweeps — baseline ingress protection policy."
            r3 = f"Honeypot activation — indicated by early target mapping in {feat2_name or feat1_name} ({feat2_val or feat1_val})." if has_shap else "Honeypot activation — defensive boundary tripwire."

            options = [
                {
                    "priority": 1,
                    "action": "Inspect ingress edge telemetry and rate-limit discovery probes",
                    "rationale": r1
                },
                {
                    "priority": 2,
                    "action": "Tighten ICMP/ARP gateway broadcast ACLs and verify DMZ host isolation",
                    "rationale": r2
                },
                {
                    "priority": 3,
                    "action": "Arm decoy darknet addresses and monitor boundary honeypot tripwires",
                    "rationale": r3
                }
            ]
            title = "Ingress Filtering & Probe Threshold Tuning"
            description = "Inspect perimeter firewall and IDS logs for sequential sweep patterns. Review ICMP/ARP rate-limiting policies on external gateways."

        elif predicted_next_stage == "Scanning":
            r1 = f"Throttle scanning sources — driven by elevated {feat1_name} ({feat1_val})" + (f" and {feat2_name} ({feat2_val})." if feat2_name else ".") if has_shap else "Throttle scanning sources — standard defensive policy (SHAP attribution unavailable)."
            r2 = f"Filter target ports — driven by high {feat1_name} ({feat1_val})." if has_shap else "Filter target ports — standard adaptive ACL protection policy."
            r3 = f"Alert SOC analysts — driven by sweep intensity in {feat2_name or feat1_name} ({feat2_val or feat1_val})." if has_shap else "Alert SOC analysts — stateful port-scan tripwire policy."

            options = [
                {
                    "priority": 1,
                    "action": "Rate-limit suspicious source IPs and drop half-open connections",
                    "rationale": r1
                },
                {
                    "priority": 2,
                    "action": "Tighten firewall ACLs on probed port ranges and cloaked service ports",
                    "rationale": r2
                },
                {
                    "priority": 3,
                    "action": "Enable stateful port-scan detection alerting and SYN-cookie thresholds",
                    "rationale": r3
                }
            ]
            title = "Port Cloaking & Adaptive Rate Limiting"
            description = "Validate perimeter ACLs against unmapped high-port sweeps. Increase SYN-cookie thresholds, flag anomalous source IPs for analyst inspection."

        elif predicted_next_stage == "Enumeration":
            r1 = f"Mask service versions — driven by elevated {feat1_name} ({feat1_val})" + (f" and {feat2_name} ({feat2_val})." if feat2_name else ".") if has_shap else "Mask service versions — standard service hardening policy (SHAP attribution unavailable)."
            r2 = f"Limit service access — driven by targeted probe concentration in {feat1_name} ({feat1_val})." if has_shap else "Limit service access — defensive subnet isolation policy."
            r3 = f"Rotate vulnerable credentials — driven by anomalous query bursts in {feat2_name or feat1_name} ({feat2_val or feat1_val})." if has_shap else "Stage credential rotation — proactive credential hygiene policy."

            options = [
                {
                    "priority": 1,
                    "action": "Disable unnecessary service banners and suppress HTTP/SSH version headers",
                    "rationale": r1
                },
                {
                    "priority": 2,
                    "action": "Restrict SMB, RPC, and SSH exposure to authorized bastion management subnets",
                    "rationale": r2
                },
                {
                    "priority": 3,
                    "action": "Stage credential rotation for queried service accounts and verify WAF inspect rules",
                    "rationale": r3
                }
            ]
            title = "Service Banner Suppression & Access Restraint"
            description = "Enforce strict HTTP/SSH/SMB header masking to suppress version enumeration. Review web application firewall (WAF) inspect rules and verify endpoint service exposure."

        elif predicted_next_stage == "Exploitation":
            r1 = f"Deploy virtual patch — driven by elevated {feat1_name} ({feat1_val})" + (f" and payload burstiness in {feat2_name} ({feat2_val})." if feat2_name else ".") if has_shap else "Deploy virtual patch — emergency WAF defense rule (SHAP attribution unavailable)."
            r2 = f"Isolate affected endpoint — driven by critical {feat1_name} ({feat1_val})." if has_shap else "Isolate affected endpoint — rapid micro-segmentation policy."
            r3 = f"Enforce step-up authentication — driven by timing irregularities in {feat2_name or feat1_name} ({feat2_val or feat1_val})." if has_shap else "Enforce step-up authentication — defensive access step-up rule."

            options = [
                {
                    "priority": 1,
                    "action": "Apply virtual patching and emergency WAF inspection rules for targeted services",
                    "rationale": r1
                },
                {
                    "priority": 2,
                    "action": "Stage rapid network micro-segmentation and prepare candidate host isolation",
                    "rationale": r2
                },
                {
                    "priority": 3,
                    "action": "Enforce mandatory MFA step-up verification on exposed application endpoints",
                    "rationale": r3
                }
            ]
            title = "Targeted Host Isolation & Patch Validation"
            description = "Alert Tier-2 SOC analysts to prioritize candidate vulnerable service endpoints. Prepare rapid network micro-segmentation and stage emergency virtual patching rules."

        else: # Intrusion
            r1 = f"Segment subnet — driven by elevated {feat1_name} ({feat1_val})" + (f" and {feat2_name} ({feat2_val})." if feat2_name else ".") if has_shap else "Segment subnet — immediate containment policy (SHAP attribution unavailable)."
            r2 = f"Revoke compromised tokens — driven by breach escalation in {feat1_name} ({feat1_val})." if has_shap else "Revoke compromised tokens — defensive identity protection rule."
            r3 = f"Trigger forensic acquisition — driven by sustained beaconing in {feat2_name or feat1_name} ({feat2_val or feat1_val})." if has_shap else "Trigger forensic acquisition — incident response escalation policy."

            options = [
                {
                    "priority": 1,
                    "action": "Segment and quarantine the affected subnet to prevent lateral movement",
                    "rationale": r1
                },
                {
                    "priority": 2,
                    "action": "Force enterprise-wide credential rotation and invalidate active Kerberos/OAuth sessions",
                    "rationale": r2
                },
                {
                    "priority": 3,
                    "action": "Escalate to Tier-3 Incident Response (IR) war room and initiate memory forensics capture",
                    "rationale": r3
                }
            ]
            title = "Privilege Audit & East-West Flow Containment"
            description = "Review lateral Kerberos/SMB traffic anomalies. Stage credential invalidation for exposed service accounts, verify honeypot tripwires, and ready endpoint containment."

        return {
            "title": title,
            "description": description,
            "options": options,
            "attribution_available": has_shap
        }
