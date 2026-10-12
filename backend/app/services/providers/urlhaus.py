import httpx
import datetime
from typing import Optional

URLHAUS_LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"

async def lookup_url(url: str, timeout: int = 20) -> dict:
    """Query URLhaus for a specific URL. Returns parsed result or error dict."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(URLHAUS_LOOKUP_URL, data={"url": url})
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return {"provider": "urlhaus", "status": "timeout", "error": "URLhaus lookup timed out"}
    except Exception as e:
        return {"provider": "urlhaus", "status": "error", "error": str(e)}

    query_status = data.get("query_status", "")
    if query_status == "no_results":
        return {"provider": "urlhaus", "status": "no_results", "found": False}
    if query_status == "is_listed":
        threat = data.get("threat", "unknown")
        url_status = data.get("url_status", "unknown")
        tags = data.get("tags") or []
        return {
            "provider": "urlhaus",
            "status": "found",
            "found": True,
            "threat": threat,
            "url_status": url_status,
            "tags": tags,
            "date_added": data.get("date_added"),
            "payloads": [p.get("file_type") for p in (data.get("payloads") or []) if p.get("file_type")],
            "raw": data,
        }
    return {"provider": "urlhaus", "status": query_status, "found": False, "raw": data}

async def lookup_host(hostname: str, timeout: int = 20) -> dict:
    """Query URLhaus for a hostname/domain."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(URLHAUS_HOST_URL, data={"host": hostname})
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return {"provider": "urlhaus", "status": "timeout", "error": "URLhaus host lookup timed out"}
    except Exception as e:
        return {"provider": "urlhaus", "status": "error", "error": str(e)}

    query_status = data.get("query_status", "")
    if query_status == "no_results":
        return {"provider": "urlhaus", "status": "no_results", "found": False}
    if query_status == "is_listed":
        return {
            "provider": "urlhaus",
            "status": "found",
            "found": True,
            "blacklists": data.get("blacklists", {}),
            "urls_count": len(data.get("urls", [])),
            "raw": data,
        }
    return {"provider": "urlhaus", "status": query_status, "found": False}
