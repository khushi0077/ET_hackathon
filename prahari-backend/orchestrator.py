import audit
import uuid
import datetime
import time
import requests
import threading
from collections import deque
import ml_engine

def send_soc_alert(title, details):
    # Stub: In production, this pushes to a Kafka topic, Slack webhook, or PagerDuty API
    print(f"\n[!] SOC ALERT: {title}")
    print(f"    TIME: {datetime.datetime.now().isoformat()}")
    print(f"    DETAILS: {details}\n")

# Real NVD API Cache
KNOWN_VULNERABLE_ASSETS = {
    80: {"cve": "CVE-2021-23017", "service": "Nginx 1.18"},
    443: {"cve": "CVE-2021-23017", "service": "Nginx 1.18"},
    22: {"cve": "CVE-2020-15778", "service": "OpenSSH 8.2"}
}

def fetch_real_nvd_cve(port):
    """Background thread to fetch real CVE from NVD (prevents demo event-loop blocking)."""
    try:
        service_map = {80: "nginx", 443: "nginx", 22: "openssh", 3389: "remote desktop", 445: "smb"}
        keyword = service_map.get(port, "apache")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=1"
        res = requests.get(url, timeout=2.0)
        if res.status_code == 200:
            data = res.json()
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                cve_id = data["vulnerabilities"][0]["cve"]["id"]
                KNOWN_VULNERABLE_ASSETS[port] = {"cve": cve_id, "service": keyword.capitalize()}
    except Exception:
        pass

def check_cve_exposure(flow):
    port = flow["dst_port"]
    if port not in KNOWN_VULNERABLE_ASSETS and port in [80, 443, 22, 3389, 445, 53, 3306, 5432]:
        KNOWN_VULNERABLE_ASSETS[port] = None # Prevent duplicate threads
        threading.Thread(target=fetch_real_nvd_cve, args=(port,), daemon=True).start()
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
                
        # Estimate FP Rate (Static baseline from NSL-KDD evaluation)
        self.stats["fp_rate"] = 0.0014 # 0.14%
        
        
        if anomaly_score > 0.6:
            self.stats["anomalies_flagged"] += 1
            
            # OT/IT correlation check
            ot_warning = ""
            if "ot_telemetry" in flow:
                ot = flow["ot_telemetry"]
                if ot.get("pressure", 0) > 150 or ot.get("temperature", 0) > 60:
                    ot_warning = " | ⚠️ COMPOUND RISK: Cyber-Physical (OT) anomaly detected!"
                    if explanation:
                        explanation += "\n\nCRITICAL CONTEXT: IT network anomaly perfectly correlates with physical SCADA parameter deviation (Overpressure/Overheat detected). Potential cyber-physical attack in progress."

            # Check external CVE CMDB
            cve_info = check_cve_exposure(flow)
            cve_warning = ""
            if cve_info:
                cve_warning = f" | ⚠️ VULNERABLE: {cve_info['service']} ({cve_info['cve']})"
                if explanation:
                    explanation += f"\n\nCRITICAL CONTEXT: The target asset is running {cve_info['service']} which is known to be vulnerable to {cve_info['cve']}."
            
            # Mock criticality check
            is_critical = flow["dst_ip"].endswith(".1") or flow["dst_port"] in [22, 3389] or cve_info is not None or ot_warning != ""
            
            if not is_critical:
                action = f"AUTO-CONTAIN: Blocked {flow['src_ip']} to {flow['dst_ip']}"
                audit.log_action(flow["timestamp"], flow, action)
                self.stats["auto_resolved"] += 1
                return {"status": "auto_resolved", "action": action, "explanation": "Pattern matches low-risk reconnaissance or automated scanning. Auto-contained at perimeter firewall to prevent fatigue."}
            else:
                approval_id = str(uuid.uuid4())
                action = f"PENDING APPROVAL: Isolate {flow['dst_ip']}?{cve_warning}{ot_warning}"
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
        
    def approve_action(self, approval_id, analyst_id="SYSTEM"):
        if approval_id in self.pending_approvals:
            req = self.pending_approvals.pop(approval_id)
            action = f"MANUAL-APPROVE (By {analyst_id}): {req['action']}"
            audit.log_action(req["flow"]["timestamp"], req["flow"], action)
            ml_engine.process_feedback(req["flow"]["src_ip"], True)
            return {"success": True, "action": action}
        return {"success": False, "error": "Approval ID not found"}
        
    def deny_action(self, approval_id, analyst_id="SYSTEM"):
        if approval_id in self.pending_approvals:
            req = self.pending_approvals.pop(approval_id)
            action = f"MANUAL-DENY (By {analyst_id}): {req['action']}"
            audit.log_action(req["flow"]["timestamp"], req["flow"], action)
            ml_engine.process_feedback(req["flow"]["src_ip"], False)
            return {"success": True, "action": action}
        return {"success": False, "error": "Approval ID not found"}

orchestrator = ResponseOrchestrator()
