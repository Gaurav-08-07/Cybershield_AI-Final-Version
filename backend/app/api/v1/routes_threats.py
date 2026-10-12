from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from typing import Optional
import math

from app.db.database import get_db
from app.models.models import ThreatIndicator
from app.schemas.schemas import ThreatIndicatorOut, PaginatedThreats

router = APIRouter()

@router.get("/threats", response_model=PaginatedThreats)
async def list_threats(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(ThreatIndicator).where(ThreatIndicator.active == True)
    if verdict: query = query.where(ThreatIndicator.verdict == verdict)
    if severity: query = query.where(ThreatIndicator.severity == severity)
    if search: query = query.where(or_(
        ThreatIndicator.indicator.ilike(f"%{search}%"),
        ThreatIndicator.category.ilike(f"%{search}%"),
    ))
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0
    query = query.order_by(desc(ThreatIndicator.last_seen)).offset((page - 1) * per_page).limit(per_page)
    items = (await db.execute(query)).scalars().all()
    return PaginatedThreats(items=items, total=total, page=page, per_page=per_page, pages=math.ceil(total / per_page) if total else 1)

@router.get("/threats/{threat_id}", response_model=ThreatIndicatorOut)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ThreatIndicator).where(ThreatIndicator.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat indicator not found")
    return threat
