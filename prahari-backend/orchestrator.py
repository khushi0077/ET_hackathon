import audit
import uuid
import datetime
import time
from collections import deque

def send_soc_alert(title, details):
    # Stub: In production, this pushes to a Kafka topic, Slack webhook, or PagerDuty API
    print(f"\n[!] SOC ALERT: {title}")
    print(f"    TIME: {datetime.datetime.now().isoformat()}")
    print(f"    DETAILS: {details}\n")

# Mock CMDB for Vulnerability Prioritization
KNOWN_VULNERABLE_ASSETS = {
    80: {"cve": "CVE-2021-23017", "service": "Nginx 1.18"},
    443: {"cve": "CVE-2021-23017", "service": "Nginx 1.18"},
    22: {"cve": "CVE-2020-15778", "service": "OpenSSH 8.2"}
}

def check_cve_exposure(flow):
    port = flow["dst_port"]
    return KNOWN_VULNERABLE_ASSETS.get(port)

class ResponseOrchestrator:
    def __init__(self):
        self.pending_approvals = {}
        self.event_timestamps = deque(maxlen=100)
        self.stats = {
            "total_events": 0,
            "anomalies_flagged": 0,
            "auto_resolved": 0,
            "gated_approvals": 0,
            "throughput_eps": 0,
            "detection_latency_ms": 0.0,
            "llm_latency_s": 0.0,
            "fp_rate": 0.0
        }
        
    def process_event(self, flow, anomaly_score, explanation):
        self.stats["total_events"] += 1
        
        # Calculate rolling EPS (Events Per Second)
        current_time = time.time()
        self.event_timestamps.append(current_time)
        if len(self.event_timestamps) > 1:
            time_diff = current_time - self.event_timestamps[0]
            if time_diff > 0:
                self.stats["throughput_eps"] = int(len(self.event_timestamps) / time_diff)
                
        # Estimate FP Rate (heuristic for demo: ~ 0.1% base + auto-resolved as potential FPs)
        self.stats["fp_rate"] = 0.12 + (self.stats["auto_resolved"] / max(self.stats["total_events"], 1)) * 0.5
        
        
        if anomaly_score > 0.6:
            self.stats["anomalies_flagged"] += 1
            
            # Check external CVE CMDB
            cve_info = check_cve_exposure(flow)
            cve_warning = ""
            if cve_info:
                cve_warning = f" | ⚠️ VULNERABLE: {cve_info['service']} ({cve_info['cve']})"
                if explanation:
                    explanation += f"\n\nCRITICAL CONTEXT: The target asset is running {cve_info['service']} which is known to be vulnerable to {cve_info['cve']}."
            
            # Mock criticality check
            is_critical = flow["dst_ip"].endswith(".1") or flow["dst_port"] in [22, 3389] or cve_info is not None
            
            if not is_critical:
                action = f"AUTO-CONTAIN: Blocked {flow['src_ip']} to {flow['dst_ip']}"
                audit.log_action(flow["timestamp"], flow, action)
                self.stats["auto_resolved"] += 1
                return {"status": "auto_resolved", "action": action}
            else:
                approval_id = str(uuid.uuid4())
                action = f"PENDING APPROVAL: Isolate {flow['dst_ip']}?{cve_warning}"
                self.pending_approvals[approval_id] = {
                    "flow": flow,
                    "action": action,
                    "explanation": explanation
                }
                self.stats["gated_approvals"] += 1
                
                # Trigger external SOC alert (stub)
                send_soc_alert(
                    title="High-Risk Anomaly Detected & Gated", 
                    details=f"Target: {flow['dst_ip']}. AI Confidence: {anomaly_score:.2f}.{cve_warning} Waiting for analyst approval."
                )
                
                return {"status": "pending_approval", "approval_id": approval_id, "action": action, "explanation": explanation}
                
        return {"status": "benign"}
        
    def approve_action(self, approval_id):
        if approval_id in self.pending_approvals:
            req = self.pending_approvals.pop(approval_id)
            action = f"MANUAL-APPROVE: {req['action']}"
            audit.log_action(req["flow"]["timestamp"], req["flow"], action)
            return {"success": True, "action": action}
        return {"success": False, "error": "Approval ID not found"}
        
    def deny_action(self, approval_id):
        if approval_id in self.pending_approvals:
            req = self.pending_approvals.pop(approval_id)
            action = f"MANUAL-DENY: {req['action']}"
            audit.log_action(req["flow"]["timestamp"], req["flow"], action)
            return {"success": True, "action": action}
        return {"success": False, "error": "Approval ID not found"}

orchestrator = ResponseOrchestrator()
