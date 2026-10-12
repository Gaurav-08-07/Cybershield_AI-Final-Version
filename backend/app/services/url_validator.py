import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Optional

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

LOOKALIKE_BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook"]
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "pw", "top", "click", "download"}

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.params, parsed.query, ""))

def extract_hostname(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None

def is_private_ip(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def check_suspicious_patterns(url: str, hostname: str) -> list:
    findings = []
    if "@" in url:
        findings.append({"type": "credential_harvesting", "detail": "URL contains @ sign"})
    if re.search(r"\.(exe|bat|cmd|scr|msi|ps1|vbs)(\?|$)", url, re.I):
        findings.append({"type": "executable_extension", "detail": "URL points to executable file"})
    if re.search(r"(base64|eval|decode)=", url, re.I):
        findings.append({"type": "encoded_payload", "detail": "Encoded payload in query"})
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        for brand in LOOKALIKE_BRANDS:
            if brand in hostname:
                findings.append({"type": "phishing_lookalike", "detail": f"Brand name '{brand}' with suspicious TLD '.{tld}'"})
                break
    return findings

def validate_url(url: str) -> dict:
    if not url or not url.strip():
        return {"valid": False, "error": "Empty URL"}
    url = url.strip()
    if len(url) > 2048:
        return {"valid": False, "error": "URL too long"}
    if not re.match(r"^https?://", url, re.I):
        return {"valid": False, "error": "Only http:// and https:// URLs are accepted"}
    try:
        normalized = normalize_url(url)
        hostname = extract_hostname(normalized)
    except Exception as exc:
        return {"valid": False, "error": f"URL parse error: {exc}"}
    if not hostname:
        return {"valid": False, "error": "Could not extract hostname"}
    if hostname in ("localhost",):
        return {"valid": False, "error": "Loopback hostnames not permitted"}
    if is_private_ip(hostname):
        return {"valid": False, "error": "Private/internal IP addresses not permitted"}
    return {"valid": True, "normalized": normalized, "hostname": hostname, "suspicious_patterns": check_suspicious_patterns(normalized, hostname)}
