"""Statistics overview and rules catalog router."""

from typing import List
from fastapi import APIRouter, Query, Request

from server.db import Database
from server.detections.engine import engine
from server.models import RuleModel, StatsOverview

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats/overview", response_model=StatsOverview)
async def get_overview_stats(
    request: Request,
    minutes: int = Query(60, ge=1, le=1440),
) -> StatsOverview:
    db: Database = request.app.state.db
    return await db.get_stats_overview(minutes=minutes)


@router.get("/rules", response_model=List[RuleModel])
async def get_rule_catalog() -> List[RuleModel]:
    result = []
    for r in engine.rules:
        result.append(
            RuleModel(
                id=r.id,
                name=r.name,
                severity=r.severity.value,
                mitre_tactic=r.mitre_tactic,
                mitre_technique=r.mitre_technique,
                description=r.description,
                enabled=r.enabled,
            )
        )
    return result
