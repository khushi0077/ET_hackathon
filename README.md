# PRAHARI - Autonomous Cyber-Resilience for Critical Infrastructure

PRAHARI is a next-generation anomaly detection and response orchestrator built for the unique threat landscape of Indian Critical National Infrastructure (CNI).

## Architecture

![Architecture Diagram](docs/architecture.png)

*   **Ingestion:** Simulates real-time network flow and OT (SCADA) telemetry.
*   **Detection:** Sklearn `IsolationForest` continuously scores anomalies. (Evaluated on KDD Cup '99 benchmark).
*   **Attribution (RAG):** High-confidence threats are routed to Gemini Flash 1.5, grounded by an India-context ChromaDB seeded with CERT-In advisories.
*   **Orchestration:** Low-risk recon is auto-contained. High-risk lateral movement triggers a human-in-the-loop SOC approval flow.
*   **Auditability:** Every decision (AI or Analyst) is hash-chained in an append-only SQLite ledger to meet legal admissibility standards.

## Business Impact (SOC Efficiency)
*   **MTTD/MTTR:** Manual SOC triage averages ~45m. PRAHARI processes, contextualizes, and presents one-click remediation in **< 3s**.
*   **Feedback Loop:** Analyst approvals/denials dynamically adjust entity risk tolerance, reducing long-term alert fatigue.
*   **Compliance:** Built-in 1-click CERT-In incident report export.

## Real-World Grounding & Evaluation
*   **Vulnerability Intel:** Live integration with the NVD API to prioritize unpatched infrastructure.
*   **Authentic Benchmarking:** Pre-evaluated against the standard KDD Cup '99 (SA subset) dataset to ensure robust baseline performance outside of simulated traffic.

## Setup Instructions

1.  **Backend (FastAPI & ML)**
    ```bash
    cd prahari-backend
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
    ```

2.  **Frontend (React/Vite)**
    ```bash
    cd prahari-frontend
    npm install
    npm run dev
    # In a separate terminal:
    npx tailwindcss -i ./src/index.css -o ./src/tailwind.css --watch
    ```

3.  **Environment**
    Ensure a `.env` file exists in `prahari-backend` with:
    ```
    GEMINI_API_KEY=your_key_here
    ```
