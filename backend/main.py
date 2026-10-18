"""FastAPI service that runs the Sentinel event pipeline and persists results."""  
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from anomaly_detection.score import InvalidEventError
from backend.db import init_db, list_incidents, list_metric_history, save_event
from genai_explanation.explain import explain_incident
from pipeline.orchestrator import create_detector, process_event, MemoryTrendTracker
from src.anomaly_detection import METRICS


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Sentinel Anomaly Detection API",
    description=(
        "Accepts raw system events, scores and classifies them, optionally "
        "generates an advisory explanation, and stores the result."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/events", status_code=201)
def create_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Process and persist one raw event from the Part 1 event stream."""
    event = dict(raw_event)

    system_id = event.get("system_id")
    if not isinstance(system_id, str) or not system_id.strip():
        raise HTTPException(
            status_code=422,
            detail="system_id must be a non-empty string",
        )
    event["system_id"] = system_id.strip()

    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        event["event_id"] = f"evt_{uuid4().hex}"
    else:
        event["event_id"] = event_id.strip()

    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        event["timestamp"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    else:
        event["timestamp"] = timestamp.strip()

    # Ground-truth labels are for evaluation only and must not affect processing.
    event.pop("injected_anomaly", None)
    event.pop("anomaly_type", None)

    
    try:
        processed_event = process_event(event, DETECTOR, TREND_TRACKER)
    except (InvalidEventError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    if processed_event["is_anomaly"]:
        processed_event["explanation"] = explain_incident(processed_event)
    else:
        processed_event["explanation"] = None

    try:
        return save_event(processed_event)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"Event contains a value that cannot be stored as JSON: {error}",
        ) from error


@app.get("/incidents")
def get_incidents(
    severity: str | None = Query(default=None, min_length=1),
    system_id: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List anomalous events, newest first, with optional filters."""
    total, items = list_incidents(severity, system_id, limit, offset)
    return {
        "count": len(items),
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@app.get("/metrics/{system_id}")
def get_metrics(
    system_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Return recent raw metric samples in chronological order for charting."""
    items = list_metric_history(system_id, limit)
    return {"system_id": system_id, "count": len(items), "items": items}
