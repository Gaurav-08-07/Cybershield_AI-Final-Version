from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
import json, datetime, math

from app.db.database import get_db
from app.models.models import LogAnalysisJob, LogEntry
from app.schemas.schemas import LogAnalyzeRequest, LogJobOut, LogEntryOut
from app.services.log_analyzer import analyze_logs

router = APIRouter()

@router.post("/logs/analyze", response_model=LogJobOut, status_code=201)
async def analyze_log(request: LogAnalyzeRequest, db: AsyncSession = Depends(get_db)):
    if len(request.content) > 5_000_000:  # 5MB limit
        raise HTTPException(status_code=413, detail="Log content too large (max 5MB)")
    
    job = LogAnalysisJob(filename=request.filename, status="processing")
    db.add(job)
    await db.commit()
    await db.refresh(job)
    
    try:
        result = analyze_logs(request.content)
        events = result["events"]
        
        entries = []
        for evt in events[:5000]:  # cap stored entries at 5000
            ts = None
            if evt.timestamp:
                try:
                    ts = datetime.datetime.fromisoformat(evt.timestamp)
                except Exception:
                    pass
            entries.append(LogEntry(
                job_id=job.id,
                timestamp=ts,
                level=evt.level,
                severity=evt.severity,
                source_ip=evt.source_ip,
                message=evt.message[:1000],
                event_type=evt.event_type,
                raw_line=evt.raw_line[:500],
                flags=json.dumps(evt.flags),
            ))
        
        for entry in entries:
            db.add(entry)
        
        sev_counts = result["severity_counts"]
        job.status = "completed"
        job.total_entries = result["total_entries"]
        job.processed_entries = len(events)
        job.critical_count = sev_counts.get("critical", 0)
        job.high_count = sev_counts.get("high", 0)
        job.medium_count = sev_counts.get("medium", 0)
        job.low_count = sev_counts.get("low", 0)
        job.summary_json = json.dumps({
            "severity_counts": sev_counts,
            "flag_counts": result["flag_counts"],
            "brute_force_ips": result["brute_force_ips"],
            "data_structure_stats": result["data_structure_stats"],
        })
        job.completed_at = datetime.datetime.utcnow()
    except Exception as e:
        job.status = "failed"
        job.error_message = str(e)[:500]
    
    await db.commit()
    await db.refresh(job)
    return job

@router.get("/logs", response_model=list[LogJobOut])
async def list_jobs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(LogAnalysisJob).order_by(desc(LogAnalysisJob.created_at))
        .offset((page - 1) * per_page).limit(per_page)
    )
    return result.scalars().all()

@router.get("/logs/{job_id}", response_model=LogJobOut)
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LogAnalysisJob).where(LogAnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Log job not found")
    return job

@router.get("/logs/{job_id}/entries", response_model=list[LogEntryOut])
async def get_entries(
    job_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = select(LogEntry).where(LogEntry.job_id == job_id)
    if severity: q = q.where(LogEntry.severity == severity)
    q = q.order_by(LogEntry.created_at).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    return result.scalars().all()
