import os
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sim
import ml_engine
import graph_analytics
import audit
import orchestrator

app = FastAPI(title="PRAHARI Core API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_connections = []

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_event(event_data):
    disconnected = []
    for ws in active_connections:
        try:
            await ws.send_json(event_data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        active_connections.remove(ws)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(run_simulation_loop())
    asyncio.create_task(run_graph_heuristics_loop())

async def run_simulation_loop():
    async for flow in sim.event_stream():
        # 1. Update Graph
        graph_analytics.graph_engine.add_flow(flow)
        
        # 2. Score Event
        t_start = time.perf_counter()
        anomaly_score = ml_engine.score_event(flow)
        t_end = time.perf_counter()
        orchestrator.orchestrator.stats["detection_latency_ms"] = (t_end - t_start) * 1000
        
        explanation = None
        technique = None
        similar_incidents = []
        
        # If highly anomalous, do heavy lifting
        if anomaly_score > 0.6:
            t_llm_start = time.perf_counter()
            llm_res = await ml_engine.get_llm_explanation(flow)
            t_llm_end = time.perf_counter()
            orchestrator.orchestrator.stats["llm_latency_s"] = (t_llm_end - t_llm_start)
            
            technique = llm_res.get("technique", "Unknown")
            explanation = llm_res.get("explanation", "No explanation provided.")
            
            # Generate synthetic description for similarity search
            desc = f"Detected {flow.get('attack_type', 'anomaly')} targeting port {flow.get('dst_port')} on {flow['dst_ip']}"
            similar_incidents = ml_engine.get_similar_incidents(desc)
            
        # 3. Response Orchestrator
        resp = orchestrator.orchestrator.process_event(flow, anomaly_score, explanation)
        if resp and "explanation" in resp:
            explanation = resp["explanation"]
        
        # 4. Broadcast
        event_payload = {
            "type": "TELEMETRY",
            "flow": flow,
            "anomaly_score": anomaly_score,
            "technique": technique,
            "explanation": explanation,
            "similar_incidents": similar_incidents,
            "response": resp,
            "stats": orchestrator.orchestrator.stats
        }
        await broadcast_event(event_payload)

async def run_graph_heuristics_loop():
    while True:
        await asyncio.sleep(5)
        anomalies = graph_analytics.graph_engine.detect_lateral_movement()
        for anomaly in anomalies:
            event_payload = {
                "type": "GRAPH_ANOMALY",
                "anomaly": anomaly
            }
            await broadcast_event(event_payload)

@app.get("/audit/verify")
def verify_audit():
    return audit.verify_chain()

@app.post("/audit/tamper-test")
def tamper_audit():
    return audit.tamper_test()

@app.get("/graph/topology")
def get_topology():
    return graph_analytics.graph_engine.get_topology()

@app.get("/orchestrator/pending")
def get_pending():
    return orchestrator.orchestrator.pending_approvals

class ApprovalReq(BaseModel):
    approval_id: str

@app.post("/orchestrator/approve")
def approve_action(req: ApprovalReq):
    return orchestrator.orchestrator.approve_action(req.approval_id)

@app.post("/orchestrator/deny")
def deny_action(req: ApprovalReq):
    return orchestrator.orchestrator.deny_action(req.approval_id)

@app.post("/sim/inject")
def inject_attack(type: str = "exfiltration"):
    sim.force_attack_queue.append(type)
    return {"status": "injected", "type": type}

@app.get("/audit/export")
def export_audit():
    import sqlite3
    conn = sqlite3.connect(audit.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, timestamp, event_data, action, prev_hash, hash FROM audit_log ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    
    export_data = []
    for r in rows:
        export_data.append({
            "id": r[0],
            "timestamp": r[1],
            "event_data": r[2],
            "action": r[3],
            "prev_hash": r[4],
            "hash": r[5]
        })
    from fastapi.responses import JSONResponse
    return JSONResponse(content={"chain": export_data})
