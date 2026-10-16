"""
SENTINEL AI // FASTAPI WEB APPLICATION SERVER
Enterprise SOC Anomaly Detection & Threat Intelligence REST API
"""

from pathlib import Path
import random
import time
from typing import Optional
from fastapi import FastAPI, Request, Query, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pandas as pd

from webapp.ml_engine import engine, FEATURES

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="Sentinel AI Network Defense",
    description="Enterprise Network Anomaly Detection Platform & Threat Intelligence API",
    version="3.0.0"
)

# Mount static and templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class FlowSimulationPayload(BaseModel):
    duration: float
    packets: int
    bytes: float
    failed_connections: int
    unique_ports: int
    threshold: Optional[float] = 0.50


class TrainModelPayload(BaseModel):
    model_type: str = "Random Forest"
    n_estimators: int = 150
    test_size: float = 0.25
    threshold: float = 0.50


class GenerateDataPayload(BaseModel):
    n_samples: int = 2000
    anomaly_ratio: float = 0.5
    seed: int = 42


@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serve the flagship Sentinel AI Single Page Application."""
    return templates.TemplateResponse(request=request, name="index.html", context={"app_version": "3.0.0"})


@app.get("/healthz")
async def health_check():
    """Liveness probe for cloud deployments (Kubernetes, Render, AWS)."""
    return {
        "status": "healthy",
        "service": "sentinel-ai-engine",
        "uptime": time.time(),
        "active_model": engine.model_type
    }


@app.get("/api/overview")
async def get_overview(threshold: Optional[float] = None):
    """Retrieve top-level KPI metrics, active threat ratios, and latest incident feed."""
    return engine.get_overview_stats(threshold=threshold)


@app.get("/api/diagnostics")
async def get_diagnostics(threshold: Optional[float] = None):
    """Retrieve ROC curve, Precision-Recall curve, Confusion Matrix, and Feature Importance."""
    return engine.get_diagnostics(threshold=threshold)


@app.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None, description="Comma-separated severities: Critical,High,Medium,Low"),
    search: Optional[str] = Query(None, description="Search by flow ID or keyword"),
    min_risk: Optional[int] = Query(0, description="Minimum risk score filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=5, le=100)
):
    """Filtered, searchable, paginated forensic queue of flagged threat flows."""
    overview = engine.get_overview_stats()
    all_alerts = overview.get("recent_alerts", [])

    # Filter by severity
    if severity:
        allowed_sev = [s.strip().capitalize() for s in severity.split(",")]
        all_alerts = [a for a in all_alerts if a["severity"] in allowed_sev]

    # Filter by min risk
    if min_risk > 0:
        all_alerts = [a for a in all_alerts if a["risk_score"] >= min_risk]

    # Filter by search
    if search:
        q = search.lower().strip()
        all_alerts = [
            a for a in all_alerts
            if q in a["id"].lower() or q in a["reason"].lower() or q in a["severity"].lower()
        ]

    total = len(all_alerts)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    items = all_alerts[start_idx:end_idx]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "items": items
    }


@app.get("/api/alert/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Deep forensic inspection for a specific network flow ID."""
    try:
        raw_idx = int(alert_id.replace("FLW-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Flow ID format")

    if raw_idx not in engine.df.index:
        raise HTTPException(status_code=404, detail="Flow record not found in telemetry database")

    row = engine.df.loc[raw_idx].to_dict()
    inference = engine.predict_single(row)
    inference["id"] = alert_id
    inference["row_index"] = raw_idx
    inference["actual_label"] = int(row.get("label", 0))
    return inference


@app.post("/api/simulate")
async def simulate_flow(payload: FlowSimulationPayload):
    """Live inference for custom or preset adversary network flows."""
    result = engine.predict_single(payload.model_dump(), threshold=payload.threshold)
    return result


@app.post("/api/model/train")
async def train_model(payload: TrainModelPayload):
    """Reconfigure and retrain the classifier ensemble."""
    diag = engine.train_model(
        model_type=payload.model_type,
        n_estimators=payload.n_estimators,
        test_size=payload.test_size,
        threshold=payload.threshold
    )
    return {
        "message": f"Successfully retrained {payload.model_type} with {payload.n_estimators} trees.",
        "diagnostics": diag
    }


@app.post("/api/generate-data")
async def generate_dataset(payload: GenerateDataPayload):
    """Regenerate synthetic network flow dataset with custom anomaly balance."""
    new_df = engine.generate_synthetic_data(
        n_samples=payload.n_samples,
        anomaly_ratio=payload.anomaly_ratio,
        seed=payload.seed
    )
    if engine.csv_path:
        new_df.to_csv(engine.csv_path, index=False)
    engine._find_and_load_data()
    engine.train_model()
    return {
        "message": f"Generated {len(new_df)} synthetic records.",
        "total_records": len(new_df),
        "anomaly_ratio": payload.anomaly_ratio
    }


@app.get("/api/stream/packets")
async def get_packet_stream():
    """Generates a batch of simulated live packets for the interactive network canvas."""
    packets = []
    types = ["HTTP", "HTTPS", "DNS", "SSH", "TLS", "TCP_SYN", "SMB", "NTP"]
    ips = [
        "192.168.1.104", "192.168.1.112", "192.168.1.205", "10.0.4.15",
        "10.0.8.22", "172.16.0.45", "198.51.100.14", "203.0.113.88"
    ]

    for _ in range(8):
        is_attack = random.random() < 0.25
        if is_attack:
            flow_data = {
                "duration": random.uniform(15, 60),
                "packets": random.randint(60, 140),
                "bytes": random.uniform(8000, 45000),
                "failed_connections": random.randint(4, 12),
                "unique_ports": random.randint(7, 24)
            }
            pred = engine.predict_single(flow_data)
            packets.append({
                "id": f"PKT-{random.randint(1000, 9999)}",
                "source": random.choice(ips),
                "dest": "10.0.0.1 (Gateway)",
                "protocol": random.choice(["TCP_SYN", "SSH", "SMB"]),
                "is_anomaly": True,
                "threat_score": pred["composite_risk_score"],
                "reason": pred["flags"][0]["title"] if pred["flags"] else "Anomaly Alert"
            })
        else:
            packets.append({
                "id": f"PKT-{random.randint(1000, 9999)}",
                "source": random.choice(ips[:4]),
                "dest": "10.0.0.5 (App Server)",
                "protocol": random.choice(["HTTPS", "DNS", "TLS"]),
                "is_anomaly": False,
                "threat_score": random.randint(2, 25),
                "reason": "Normal Traffic"
            })

    return {"packets": packets, "timestamp": time.time()}
