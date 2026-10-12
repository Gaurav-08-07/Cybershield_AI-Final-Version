
from __future__ import annotations
import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, HttpUrl, Field, field_validator
import re

class ScanRequest(BaseModel):
    url: str = Field(..., min_length=10, max_length=2048, description="URL to scan")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not re.match(r"^https?://", v, re.I):
            raise ValueError("URL must start with http:// or https://")
        return v

class EvidenceOut(BaseModel):
    id: str
    source: str
    evidence_type: str
    detail: Optional[str]
    severity: Optional[str]
    created_at: datetime.datetime
    model_config = {"from_attributes": True}

class ScanOut(BaseModel):
    id: str
    url: str
    hostname: str
    verdict: str
    risk_score: Optional[float]
    confidence: Optional[float]
    scan_status: str
    provider_status: Optional[str]
    error_message: Optional[str]
    category: Optional[str]
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime]
    evidence: List[EvidenceOut] = []
    model_config = {"from_attributes": True}

class ScanListOut(BaseModel):
    id: str
    url: str
    hostname: str
    verdict: str
    risk_score: Optional[float]
    category: Optional[str]
    scan_status: str
    created_at: datetime.datetime
    model_config = {"from_attributes": True}

class PaginatedScans(BaseModel):
    items: List[ScanListOut]
    total: int
    page: int
    per_page: int
    pages: int

class ThreatIndicatorOut(BaseModel):
    id: str
    indicator: str
    indicator_type: str
    verdict: str
    severity: str
    category: Optional[str]
    source: str
    confidence: float
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    active: bool
    model_config = {"from_attributes": True}

class PaginatedThreats(BaseModel):
    items: List[ThreatIndicatorOut]
    total: int
    page: int
    per_page: int
    pages: int

class SecurityEventOut(BaseModel):
    id: str
    event_type: str
    severity: str
    source: Optional[str]
    description: str
    created_at: datetime.datetime
    acknowledged: bool
    model_config = {"from_attributes": True}

class LogAnalyzeRequest(BaseModel):
    content: str = Field(..., description="Log content to analyze (plain text or JSON lines)")
    filename: Optional[str] = None

class LogJobOut(BaseModel):
    id: str
    filename: Optional[str]
    status: str
    total_entries: Optional[int]
    processed_entries: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    summary_json: Optional[str]
    error_message: Optional[str]
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime]
    model_config = {"from_attributes": True}

class LogEntryOut(BaseModel):
    id: str
    timestamp: Optional[datetime.datetime]
    level: Optional[str]
    severity: str
    source_ip: Optional[str]
    message: str
    event_type: Optional[str]
    flags: Optional[str]
    created_at: datetime.datetime
    model_config = {"from_attributes": True}

class DashboardStats(BaseModel):
    total_scans: int
    malicious_count: int
    suspicious_count: int
    inconclusive_count: int
    no_threat_count: int
    active_threats: int
    recent_events: List[SecurityEventOut]
    db_healthy: bool
    backend_version: str

class HealthOut(BaseModel):
    status: str
    version: str
    db_healthy: bool
    providers: dict

class ExtensionRule(BaseModel):
    id: int
    priority: int
    action: dict
    condition: dict

class ExtensionRulesResponse(BaseModel):
    rules: List[ExtensionRule]
    domains: Optional[List[str]] = None
    version: int
    generated_at: datetime.datetime
    total: int

class ReportSummary(BaseModel):
    total_scans: int
    malicious_count: int
    suspicious_count: int
    no_threat_count: int
    inconclusive_count: int
    top_categories: List[dict]
    daily_activity: List[dict]
    threat_severity_distribution: dict
    average_risk_score: Optional[float]
    period_days: int
