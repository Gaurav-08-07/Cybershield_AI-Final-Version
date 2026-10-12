import uuid, datetime, enum
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def utcnow(): return datetime.datetime.utcnow()
def new_uuid(): return str(uuid.uuid4())

class UrlScan(Base):
    __tablename__ = "url_scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False, default="inconclusive")
    risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    scan_status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    provider_status: Mapped[str] = mapped_column(String(20), nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    tags: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    completed_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=True)
    evidence: Mapped[list["ThreatEvidence"]] = relationship("ThreatEvidence", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    __table_args__ = (Index("ix_url_scans_verdict_created", "verdict", "created_at"),)

class ThreatEvidence(Base):
    __tablename__ = "threat_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True)
    raw_data: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow)
    scan: Mapped["UrlScan"] = relationship("UrlScan", back_populates="evidence", lazy="selectin")

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False, default="malicious")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="high")
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)
    first_seen: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_id: Mapped[int] = mapped_column(Integer, nullable=True)
    tags: Mapped[str] = mapped_column(Text, nullable=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

class LogAnalysisJob(Base):
    __tablename__ = "log_analysis_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    filename: Mapped[str] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    total_entries: Mapped[int] = mapped_column(Integer, nullable=True)
    processed_entries: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=True)
    log_entries: Mapped[list["LogEntry"]] = relationship("LogEntry", back_populates="job", cascade="all, delete-orphan", lazy="selectin")

class LogEntry(Base):
    __tablename__ = "log_entries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    job_id: Mapped[str] = mapped_column(String(36), ForeignKey("log_analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=True)
    level: Mapped[str] = mapped_column(String(20), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    source_ip: Mapped[str] = mapped_column(String(50), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=True)
    raw_line: Mapped[str] = mapped_column(Text, nullable=True)
    flags: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow)
    job: Mapped["LogAnalysisJob"] = relationship("LogAnalysisJob", back_populates="log_entries", lazy="selectin")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, index=True)

class ExtensionEvent(Base):
    __tablename__ = "extension_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    url_hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    extension_version: Mapped[str] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, index=True)
