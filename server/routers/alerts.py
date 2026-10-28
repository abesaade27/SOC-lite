"""Alerts management API router."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request, status

from server.db import Database
from server.models import AlertPatchRequest

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

VALID_STATUSES = {"new", "ack", "closed", "false_positive"}


@router.get("")
async def list_alerts(
    request: Request,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    before_id: Optional[int] = Query(None),
) -> List[Dict[str, Any]]:
    db: Database = request.app.state.db
    return await db.get_alerts(
        status=status_filter,
        severity=severity,
        limit=limit,
        before_id=before_id,
    )


@router.patch("/{alert_id}")
async def update_alert_status(
    alert_id: int,
    patch: AlertPatchRequest,
    request: Request,
) -> Dict[str, Any]:
    if patch.status and patch.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{patch.status}'. Allowed: {sorted(list(VALID_STATUSES))}",
        )

    db: Database = request.app.state.db
    updated = await db.update_alert(alert_id, status=patch.status, note=patch.note)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return updated
