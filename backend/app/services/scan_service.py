import datetime
import json
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional

from app.models.models import UrlScan, ThreatEvidence, ThreatIndicator
from app.services.url_validator import validate_url
from app.services.risk_scorer import RiskComponents, compute_risk_score, score_url_patterns
from app.services.providers import urlhaus, virustotal
from app.core.config import settings


async def perform_scan(url: str, db: AsyncSession) -> UrlScan:
    """
    Full scan workflow:
    1. Validate and normalize URL
    2. Check local threat indicators
    3. Query external providers (URLhaus, VirusTotal if configured)
    4. Compute risk score
    5. Persist scan and evidence
    """
    # 1. Validate
    validation = validate_url(url)
    if not validation["valid"]:
        scan = UrlScan(
            url=url,
            url_normalized=url,
            hostname=_extract_hostname_safe(url),
            verdict="inconclusive",
            scan_status="failed",
            error_message=validation["error"],
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        return scan

    normalized = validation["normalized"]
    hostname = validation["hostname"]
    suspicious_patterns = validation.get("suspicious_patterns", [])

    scan = UrlScan(
        url=url,
        url_normalized=normalized,
        hostname=hostname,
        verdict="inconclusive",
        scan_status="scanning",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    evidence_list = []
    components = RiskComponents()

    # 2. Check local threat indicator DB
    local_result = await _check_local_indicators(normalized, hostname, db)
    if local_result:
        components.confirmed_malicious = True
        components.threat_intel_score = 90.0
        components.evidence_count += 1
        components.evidence_sources.append("local_db")
        evidence_list.append(ThreatEvidence(
            scan_id=scan.id, source="CyberShield-DB",
            evidence_type="threat_indicator_match",
            detail=f"Matched local threat indicator: {local_result.indicator}",
            severity=local_result.severity,
            raw_data=json.dumps({"indicator_id": local_result.id, "category": local_result.category}),
        ))

    # 3. Query URLhaus
    uh_result = await urlhaus.lookup_url(normalized)
    if uh_result.get("status") == "found" and uh_result.get("found"):
        components.confirmed_malicious = True
        components.threat_intel_score = max(components.threat_intel_score or 0, 88.0)
        components.evidence_count += 1
        components.evidence_sources.append("urlhaus")
        evidence_list.append(ThreatEvidence(
            scan_id=scan.id, source="URLhaus",
            evidence_type="threat_feed_match",
            detail=f"URLhaus threat: {uh_result.get('threat', 'unknown')} | Status: {uh_result.get('url_status', 'unknown')}",
            severity="high",
            raw_data=json.dumps({k: v for k, v in uh_result.items() if k != "raw"}),
        ))
        # Also store as local indicator for future lookups
        await _upsert_indicator(normalized, hostname, "malicious", "high", "malware", "urlhaus", db)
    elif uh_result.get("status") in ("timeout", "error"):
        evidence_list.append(ThreatEvidence(
            scan_id=scan.id, source="URLhaus",
            evidence_type="provider_error",
            detail=uh_result.get("error", "URLhaus unavailable"),
            severity="info",
        ))

    # Also check URLhaus host lookup
    uh_host = await urlhaus.lookup_host(hostname)
    if uh_host.get("status") == "found" and uh_host.get("found"):
        if not components.confirmed_malicious:
            components.domain_rep_score = 75.0
        components.evidence_count += 1
        evidence_list.append(ThreatEvidence(
            scan_id=scan.id, source="URLhaus",
            evidence_type="malicious_host",
            detail=f"Host {hostname} is listed in URLhaus with {uh_host.get('urls_count', 0)} malicious URLs",
            severity="high",
            raw_data=json.dumps({k: v for k, v in uh_host.items() if k != "raw"}),
        ))

    # 4. Query VirusTotal if configured
    if settings.VIRUSTOTAL_API_KEY:
        vt_result = await virustotal.lookup_url(normalized, settings.VIRUSTOTAL_API_KEY)
        if vt_result.get("status") == "found" and vt_result.get("found"):
            malicious = vt_result.get("malicious_count", 0)
            total = vt_result.get("total_engines", 0)
            if malicious > 0:
                vt_score = min(100.0, (malicious / max(total, 1)) * 100 * 2)
                components.threat_intel_score = max(components.threat_intel_score or 0, vt_score)
                if malicious >= 3:
                    components.confirmed_malicious = True
                components.evidence_count += 1
                evidence_list.append(ThreatEvidence(
                    scan_id=scan.id, source="VirusTotal",
                    evidence_type="av_detection",
                    detail=f"{malicious}/{total} engines flagged as malicious",
                    severity="high" if malicious >= 5 else "medium",
                    raw_data=json.dumps(vt_result.get("raw_stats", {})),
                ))

    # 5. URL pattern heuristics
    pattern_score = score_url_patterns(normalized, hostname)
    components.url_pattern_score = pattern_score
    if suspicious_patterns:
        for p in suspicious_patterns:
            evidence_list.append(ThreatEvidence(
                scan_id=scan.id, source="Heuristics",
                evidence_type="url_pattern",
                detail=p["detail"],
                severity="medium",
            ))

    # 6. Compute final score
    result = compute_risk_score(components)
    verdict = result["verdict"]
    risk_score = result["risk_score"]
    confidence = result["confidence"]

    # Determine category
    category = _determine_category(evidence_list)

    # 7. Update scan record
    scan.verdict = verdict
    scan.risk_score = risk_score
    scan.confidence = confidence
    scan.scan_status = "completed"
    scan.provider_status = "ok"
    scan.category = category
    scan.completed_at = datetime.datetime.utcnow()
    for ev in evidence_list:
        db.add(ev)

    await db.commit()
    await db.refresh(scan, ["evidence"])
    return scan


async def _check_local_indicators(url: str, hostname: str, db: AsyncSession) -> Optional[ThreatIndicator]:
    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.active == True,
            ThreatIndicator.indicator.in_([url, hostname])
        ).limit(1)
    )
    return result.scalar_one_or_none()


async def _upsert_indicator(url: str, hostname: str, verdict: str, severity: str, category: str, source: str, db: AsyncSession):
    existing = await db.execute(
        select(ThreatIndicator).where(ThreatIndicator.indicator == hostname).limit(1)
    )
    ind = existing.scalar_one_or_none()
    if ind:
        ind.last_seen = datetime.datetime.utcnow()
        ind.active = True
    else:
        ind = ThreatIndicator(
            indicator=hostname, indicator_type="domain",
            verdict=verdict, severity=severity,
            category=category, source=source,
            confidence=0.85,
        )
        db.add(ind)
    await db.commit()


def _extract_hostname_safe(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or "unknown"
    except Exception:
        return "unknown"


def _determine_category(evidence_list: list) -> Optional[str]:
    for ev in evidence_list:
        if ev.evidence_type == "threat_feed_match":
            raw = ev.raw_data
            if raw:
                import json
                try:
                    data = json.loads(raw)
                    threat = data.get("threat", "")
                    if threat:
                        return threat
                except Exception:
                    pass
    return None


async def get_scans(db: AsyncSession, page: int = 1, per_page: int = 20,
                    verdict: Optional[str] = None, search: Optional[str] = None):
    query = select(UrlScan)
    if verdict:
        query = query.where(UrlScan.verdict == verdict)
    if search:
        query = query.where(UrlScan.hostname.ilike(f"%{search}%"))
    count_q = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0
    query = query.order_by(desc(UrlScan.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    items = result.scalars().all()
    return items, total


async def get_scan_by_id(scan_id: str, db: AsyncSession) -> Optional[UrlScan]:
    result = await db.execute(
        select(UrlScan).where(UrlScan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan:
        # eagerly load evidence
        await db.refresh(scan, ["evidence"])
    return scan
