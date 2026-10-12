from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
import datetime

from app.db.database import get_db
from app.models.models import UrlScan, ThreatIndicator
from app.schemas.schemas import ReportSummary

router = APIRouter()

@router.get("/reports/summary", response_model=ReportSummary)
async def get_report_summary(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db)
):
    since = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    
    # Verdict counts
    vc_result = await db.execute(
        select(UrlScan.verdict, func.count(UrlScan.id))
        .where(UrlScan.created_at >= since)
        .group_by(UrlScan.verdict)
    )
    verdict_counts = {row[0]: row[1] for row in vc_result}
    total = sum(verdict_counts.values())
    
    # Categories
    cat_result = await db.execute(
        select(UrlScan.category, func.count(UrlScan.id))
        .where(UrlScan.created_at >= since, UrlScan.category != None)
        .group_by(UrlScan.category)
        .order_by(desc(func.count(UrlScan.id)))
        .limit(10)
    )
    top_categories = [{"category": row[0], "count": row[1]} for row in cat_result]
    
    # Average risk score
    avg_result = await db.execute(
        select(func.avg(UrlScan.risk_score)).where(UrlScan.created_at >= since, UrlScan.risk_score != None)
    )
    avg_score = avg_result.scalar()
    
    # Daily activity (last 7 days)
    daily = []
    for i in range(7):
        day = datetime.datetime.utcnow() - datetime.timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + datetime.timedelta(days=1)
        day_result = await db.execute(
            select(func.count(UrlScan.id)).where(
                UrlScan.created_at >= day_start,
                UrlScan.created_at < day_end
            )
        )
        count = day_result.scalar() or 0
        daily.append({"date": day_start.strftime("%Y-%m-%d"), "count": count})
    
    # Threat severity distribution
    sev_result = await db.execute(
        select(ThreatIndicator.severity, func.count(ThreatIndicator.id))
        .where(ThreatIndicator.active == True)
        .group_by(ThreatIndicator.severity)
    )
    sev_dist = {row[0]: row[1] for row in sev_result}
    
    return ReportSummary(
        total_scans=total,
        malicious_count=verdict_counts.get("malicious", 0),
        suspicious_count=verdict_counts.get("suspicious", 0),
        no_threat_count=verdict_counts.get("no_threat", 0),
        inconclusive_count=verdict_counts.get("inconclusive", 0),
        top_categories=top_categories,
        daily_activity=list(reversed(daily)),
        threat_severity_distribution=sev_dist,
        average_risk_score=round(avg_score, 1) if avg_score else None,
        period_days=days,
    )
