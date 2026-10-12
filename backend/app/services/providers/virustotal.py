import httpx
import base64
from typing import Optional

VT_BASE = "https://www.virustotal.com/api/v3"

def _encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

async def lookup_url(url: str, api_key: str, timeout: int = 30) -> dict:
    """Query VirusTotal v3 for URL analysis. Requires a valid API key."""
    if not api_key:
        return {"provider": "virustotal", "status": "unconfigured", "error": "No VirusTotal API key configured"}
    url_id = _encode_url(url)
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
            if resp.status_code == 404:
                return {"provider": "virustotal", "status": "not_found", "found": False}
            if resp.status_code == 429:
                return {"provider": "virustotal", "status": "rate_limited", "error": "VirusTotal rate limit reached"}
            if resp.status_code == 401:
                return {"provider": "virustotal", "status": "auth_error", "error": "Invalid VirusTotal API key"}
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return {"provider": "virustotal", "status": "timeout", "error": "VirusTotal request timed out"}
    except Exception as e:
        return {"provider": "virustotal", "status": "error", "error": str(e)}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    return {
        "provider": "virustotal",
        "status": "found",
        "found": True,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "total_engines": total,
        "categories": attrs.get("categories", {}),
        "reputation": attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "raw_stats": stats,
    }
