import os
from dotenv import load_dotenv
load_dotenv()

import json
import chromadb
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import IsolationForest
import numpy as np
import google.generativeai as genai
import uuid
import sim
from collections import OrderedDict
import requests
import xml.etree.ElementTree as ET

# Behavioral Baselining State
entity_profiles = OrderedDict()

# Isolation Forest Setup
feature_keys = ["dst_port", "bytes_sent", "bytes_recv", "duration", "byte_deviation", "duration_deviation"]

def get_behavioral_features(flow):
    src_ip = flow["src_ip"]
    if src_ip not in entity_profiles:
        if len(entity_profiles) >= 10000:
            entity_profiles.popitem(last=False)
        entity_profiles[src_ip] = {"count": 0, "total_bytes": 0, "total_duration": 0}
    else:
        entity_profiles.move_to_end(src_ip)
    
    prof = entity_profiles[src_ip]
    avg_bytes = prof["total_bytes"] / max(1, prof["count"])
    avg_dur = prof["total_duration"] / max(1, prof["count"])
    
    byte_dev = abs(flow["bytes_sent"] - avg_bytes)
    dur_dev = abs(flow["duration"] - avg_dur)
    
    prof["count"] += 1
    prof["total_bytes"] += flow["bytes_sent"]
    prof["total_duration"] += flow["duration"]
    
    return [
        flow["dst_port"], flow["bytes_sent"], flow["bytes_recv"], flow["duration"],
        byte_dev, dur_dev
    ]

model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
print("Pre-training IsolationForest on 2000 synthetic baseline (normal) traffic flows...")
batch_data = sim.generate_batch(size=2000, anomaly_ratio=0.01)
X_train = [get_behavioral_features(f) for f in batch_data]
model.fit(X_train)
print("IsolationForest ready.")

# ChromaDB Setup
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="incident_memory")
sentence_model = SentenceTransformer('all-MiniLM-L6-v2')

def embed_text(text):
    return sentence_model.encode(text).tolist()

seed_incidents = [
    {"id": "inc-1", "desc": "Port scan detected from unknown internal IP", "outcome": "Blocked at firewall", "date": "2026-05-12", "analyst": "Alice"},
    {"id": "inc-2", "desc": "High volume data exfiltration over HTTPS to external IP", "outcome": "Host isolated", "date": "2026-06-01", "analyst": "Bob"},
    {"id": "inc-3", "desc": "Repeated failed RDP logins followed by success", "outcome": "Account suspended", "date": "2026-06-15", "analyst": "Charlie"},
    {"id": "inc-4", "desc": "Lateral movement attempt via SMB from compromised host", "outcome": "Subnet segmented", "date": "2026-06-20", "analyst": "Alice"},
    {"id": "inc-5", "desc": "Massive UDP traffic burst causing local denial of service", "outcome": "Rate limited applied", "date": "2026-07-02", "analyst": "Dave"}
]

def fetch_cisa_alerts():
    alerts = []
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/national-cyber-awareness-system/ncas-alerts.xml", timeout=3)
        if resp.status_code == 200:
            root = ET.fromstring(resp.content)
            for item in root.findall(".//item")[:5]:
                title = item.find("title").text if item.find("title") is not None else "Unknown Alert"
                alerts.append({"id": f"cisa-{uuid.uuid4().hex[:6]}", "desc": f"CISA Alert: {title}", "outcome": "External Threat Intel", "date": "Live", "analyst": "CISA RSS"})
    except Exception as e:
        print(f"Failed to fetch CISA RSS: {e}")
    return alerts

seed_incidents.extend(fetch_cisa_alerts())

print("Seeding vector memory...")
for inc in seed_incidents:
    collection.add(
        embeddings=[embed_text(inc["desc"])],
        documents=[inc["desc"]],
        metadatas=[{"outcome": inc["outcome"], "date": inc["date"], "analyst": inc["analyst"]}],
        ids=[inc["id"]]
    )
print("Vector memory ready.")

# Gemini LLM Setup
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "mock_key"))
gemini_model = genai.GenerativeModel("gemini-1.5-flash")

def extract_features(flow):
    return [get_behavioral_features(flow)]

def score_event(flow):
    X = extract_features(flow)
    raw_score = model.decision_function(X)[0]
    
    import math
    # Platt scaling (Logistic Sigmoid) to map raw distance to probability
    # raw_score < 0 means anomaly. We want it to approach 1.0
    try:
        anomaly_score = 1.0 / (1.0 + math.exp(raw_score * 20))
    except OverflowError:
        anomaly_score = 0.0 if raw_score > 0 else 1.0
        
    return float(anomaly_score)

def redact_payload(flow):
    # Mask PII (like IPs) for data privacy before sending to LLM
    redacted = flow.copy()
    redacted["src_ip"] = "[REDACTED_IP]"
    redacted["dst_ip"] = "[REDACTED_IP]"
    if "payload" in redacted:
        redacted["payload"] = "[REDACTED_PAYLOAD]"
    return redacted

async def get_llm_explanation(flow):
    if os.environ.get("GEMINI_API_KEY") is None:
        return {"technique": "Unknown", "explanation": "MOCK EXPLANATION: Anomalous behavior detected (Missing API Key). Privacy preserved."}
        
    safe_flow = redact_payload(flow)
    
    # Agent 1: Attribution Agent (identifies technique)
    prompt_1 = f"You are the Attribution Agent. Analyze this network event and return ONLY a single MITRE ATT&CK technique ID (e.g., T1046). Event details: {json.dumps(safe_flow)}"
    
    try:
        resp_1 = await gemini_model.generate_content_async(prompt_1)
        technique = resp_1.text.strip().replace("```", "").split()[0]
        
        # Agent 2: Response Agent (explains and acts)
        prompt_2 = f"You are the Response Agent. Agent 1 identified this flow as {technique}. Event details: {json.dumps(safe_flow)}. Provide a one-paragraph plain-language explanation of the threat and a recommended defensive action. Do not include markdown."
        resp_2 = await gemini_model.generate_content_async(prompt_2)
        explanation = resp_2.text.strip()
        
        return {
            "technique": technique,
            "explanation": explanation
        }
    except Exception as e:
        print("CRITICAL LLM ERROR: Live Gemini inference failed (API key suspended or invalid).")
        return {
            "technique": "T1190", 
            "explanation": "MOCK AI INFERENCE (Fallback): Statistically significant deviation in outbound traffic volume and frequency detected. This behavioral signature strongly aligns with automated exploitation or lateral movement attempts. (Note: Live Gemini inference unavailable - check server logs)."
        }

def get_similar_incidents(description, n=3):
    query_embedding = embed_text(description)
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n
    )
    matches = []
    if results['documents'] and len(results['documents']) > 0:
        for i in range(len(results['documents'][0])):
            matches.append({
                "description": results['documents'][0][i],
                "metadata": results['metadatas'][0][i]
            })
    return matches
