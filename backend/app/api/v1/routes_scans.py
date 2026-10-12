from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text
from typing import Optional
import math

from app.db.database import get_db
from app.models.models import UrlScan, SecurityEvent
from app.schemas.schemas import ScanRequest, ScanOut, ScanListOut, PaginatedScans, DashboardStats, SecurityEventOut
from app.services.scan_service import perform_scan, get_scans, get_scan_by_id
import datetime

router = APIRouter()

@router.post("/scans", response_model=ScanOut, status_code=201)
async def create_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    scan = await perform_scan(request.url, db)
    await db.refresh(scan, ["evidence"])
    return scan

@router.get("/scans", response_model=PaginatedScans)
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    verdict: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    items, total = await get_scans(db, page=page, per_page=per_page, verdict=verdict, search=search)
    pages = math.ceil(total / per_page) if total > 0 else 1
    return PaginatedScans(items=items, total=total, page=page, per_page=per_page, pages=pages)

@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await get_scan_by_id(scan_id, db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    stats_q = await db.execute(
        select(UrlScan.verdict, func.count(UrlScan.id)).group_by(UrlScan.verdict)
    )
    verdict_counts = {row[0]: row[1] for row in stats_q}
    total = sum(verdict_counts.values())

    from app.models.models import ThreatIndicator
    active_threats_q = await db.execute(
        select(func.count(ThreatIndicator.id)).where(ThreatIndicator.active == True)
    )
    active_threats = active_threats_q.scalar() or 0

    events_q = await db.execute(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(5)
    )
    recent_events = events_q.scalars().all()

    db_healthy = False
    try:
        await db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        pass

    from app.core.config import settings
    return DashboardStats(
        total_scans=total,
        malicious_count=verdict_counts.get("malicious", 0),
        suspicious_count=verdict_counts.get("suspicious", 0),
        inconclusive_count=verdict_counts.get("inconclusive", 0),
        no_threat_count=verdict_counts.get("no_threat", 0),
        active_threats=active_threats,
        recent_events=recent_events,
        db_healthy=db_healthy,
        backend_version=settings.APP_VERSION,
    )
