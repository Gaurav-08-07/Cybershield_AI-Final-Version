from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
import datetime

from app.db.database import get_db
from app.models.models import ThreatIndicator, ExtensionEvent, SecurityEvent
from app.schemas.schemas import ExtensionRulesResponse, ExtensionRule
from app.core.config import settings

router = APIRouter()

class ExtensionEventIn(BaseModel):
    event_type: str
    url: Optional[str] = None
    domain: Optional[str] = None
    extension_version: Optional[str] = "1.0.0"

@router.get("/extension/rules", response_model=ExtensionRulesResponse)
async def get_extension_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.active == True,
            ThreatIndicator.verdict == "malicious",
            ThreatIndicator.indicator_type.in_(["domain", "host"]),
        ).limit(settings.RULE_SYNC_MAX_RULES)
    )
    indicators = result.scalars().all()
    
    rules = []
    domains = []
    for idx, ind in enumerate(indicators, start=1):
        domain = ind.indicator.lstrip("www.") if ind.indicator else None
        if not domain:
            continue
        domains.append(domain)
        rule = ExtensionRule(
            id=idx,
            priority=1,
            action={
                "type": "redirect",
                "redirect": {"extensionPath": f"/blocked.html?domain={domain}&category={ind.category or 'malware'}&source={ind.source}"}
            },
            condition={
                "urlFilter": f"||{domain}^",
                "resourceTypes": ["main_frame"],
            }
        )
        rules.append(rule)
        ind.rule_id = idx
    
    await db.commit()
    
    return ExtensionRulesResponse(
        rules=rules,
        domains=domains,
        version=len(rules),
        generated_at=datetime.datetime.utcnow(),
        total=len(rules),
    )

@router.post("/extension/event", status_code=201)
async def log_extension_event(payload: ExtensionEventIn, db: AsyncSession = Depends(get_db)):
    event = ExtensionEvent(
        event_type=payload.event_type,
        url_hostname=payload.domain,
        verdict="malicious",
        blocked=True,
        extension_version=payload.extension_version
    )
    db.add(event)
    sec_event = SecurityEvent(
        event_type="navigation_blocked",
        severity="high",
        source="SafeBrowse-Extension",
        description=f"Extension blocked user navigation to malicious destination: {payload.domain or payload.url}",
    )
    db.add(sec_event)
    await db.commit()
    return {"status": "recorded"}

@router.get("/extension/status")
async def extension_status(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    count_result = await db.execute(
        select(func.count(ThreatIndicator.id)).where(
            ThreatIndicator.active == True,
            ThreatIndicator.verdict == "malicious",
        )
    )
    count = count_result.scalar() or 0
    return {
        "status": "operational",
        "active_rules": count,
        "last_updated": datetime.datetime.utcnow().isoformat(),
        "providers_active": ["urlhaus"],
        "coverage_note": "Only confirmed malicious domains are blocked. New URLs may not be blocked before local rules are updated.",
    }
