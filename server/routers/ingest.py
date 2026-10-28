"""Ingest API router handling event ingestion, deduplication, and detection triggering."""

from collections import deque
import time
from fastapi import APIRouter, Depends, HTTPException, Request, status

from server.auth import verify_api_key
from server.bus import bus
from server.db import Database
from server.detections.engine import engine
from server.models import Alert, IngestRequest, IngestResponse

router = APIRouter(prefix="/api", tags=["ingest"])

# Simple in-memory sliding rate limiter (20 requests per second per key)
RATE_LIMIT_RPS = 20
_rate_limit_records: deque = deque()


def check_rate_limit() -> None:
    now = time.time()
    while _rate_limit_records and _rate_limit_records[0] < now - 1.0:
        _rate_limit_records.popleft()
    if len(_rate_limit_records) >= RATE_LIMIT_RPS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded (max 20 requests/second)",
        )
    _rate_limit_records.append(now)


@router.post(
    "/ingest",
    response_model=IngestResponse,
    dependencies=[Depends(verify_api_key)],
)
async def ingest_events(req: IngestRequest, request: Request) -> IngestResponse:
    check_rate_limit()
    db: Database = request.app.state.db

    new_events, duplicates = await db.insert_events(req.events)

    alerts_created: list[Alert] = []
    if new_events:
        # Sort new events in timestamp order for detection evaluation
        sorted_new = sorted(new_events, key=lambda x: x.timestamp)
        for ev in sorted_new:
            fired_alerts = engine.evaluate(ev)
            for a in fired_alerts:
                alert_id = await db.insert_alert(a)
                a.id = alert_id
                alerts_created.append(a)
                # Broadcast alert immediately on bus
                bus.publish("alert", a.model_dump())

        # Publish new events on bus (coalesced by websocket handler)
        bus.publish("events", [e.model_dump() for e in new_events])

    return IngestResponse(
        accepted=len(new_events),
        duplicates=duplicates,
        alerts_created=len(alerts_created),
    )
