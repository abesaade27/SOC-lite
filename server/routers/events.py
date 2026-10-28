"""Events query API router."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

from server.db import Database

router = APIRouter(prefix="/api/events", tags=["events"])


class UIDListRequest(BaseModel):
    uids: List[str]


@router.get("")
async def list_events(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    before_id: Optional[int] = Query(None),
    host: Optional[str] = Query(None),
    channel: Optional[str] = Query(None),
    event_id: Optional[int] = Query(None),
    category: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    db: Database = request.app.state.db
    return await db.get_events(
        limit=limit,
        before_id=before_id,
        host=host,
        channel=channel,
        event_id=event_id,
        category=category,
        query_str=q,
        since_iso=since,
    )


@router.post("/by-uids")
async def get_events_by_uids(req: UIDListRequest, request: Request) -> List[Dict[str, Any]]:
    db: Database = request.app.state.db
    return await db.get_events_by_uids(req.uids)


@router.get("/{event_id}")
async def get_event_detail(event_id: int, request: Request) -> Dict[str, Any]:
    db: Database = request.app.state.db
    ev = await db.get_event_by_id(event_id)
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return ev
