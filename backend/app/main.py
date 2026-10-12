from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.core.config import settings
from app.db.database import init_db
from app.api.v1 import routes_health, routes_scans, routes_threats, routes_extension, routes_logs, routes_reports

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="CyberShield-AI — Cybersecurity threat detection platform",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

PREFIX = settings.API_V1_PREFIX

app.include_router(routes_health.router, prefix=PREFIX, tags=["Health"])
app.include_router(routes_scans.router, prefix=PREFIX, tags=["Scans"])
app.include_router(routes_threats.router, prefix=PREFIX, tags=["Threats"])
app.include_router(routes_extension.router, prefix=PREFIX, tags=["Extension"])
app.include_router(routes_logs.router, prefix=PREFIX, tags=["Logs"])
app.include_router(routes_reports.router, prefix=PREFIX, tags=["Reports"])

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."}  # Never expose raw stacktrace
    )

@app.get("/")
async def root():
    return {"name": settings.APP_NAME, "version": settings.APP_VERSION, "docs": "/api/docs"}
