from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.database import get_db
from app.core.config import settings
from app.schemas.schemas import HealthOut
import datetime

router = APIRouter()

@router.get("/health", response_model=HealthOut)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_healthy = False
    try:
        await db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        pass
    providers = {
        "urlhaus": {"enabled": True, "type": "free"},
        "virustotal": {"enabled": bool(settings.VIRUSTOTAL_API_KEY), "type": "api_key"},
    }
    return HealthOut(
        status="healthy" if db_healthy else "degraded",
        version=settings.APP_VERSION,
        db_healthy=db_healthy,
        providers=providers,
    )
