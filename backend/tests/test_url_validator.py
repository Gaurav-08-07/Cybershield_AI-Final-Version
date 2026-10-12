import pytest
from app.services.url_validator import validate_url, normalize_url, extract_hostname, is_private_ip

def test_valid_http_url():
    result = validate_url("http://example.com/path")
    assert result["valid"] is True
    assert result["hostname"] == "example.com"

def test_valid_https_url():
    result = validate_url("https://www.google.com/search?q=test")
    assert result["valid"] is True
    assert result["hostname"] == "www.google.com"

def test_empty_url():
    result = validate_url("")
    assert result["valid"] is False
    assert "Empty" in result["error"]

def test_no_scheme():
    result = validate_url("malware.example.com")
    assert result["valid"] is False
    assert "http" in result["error"].lower()

def test_private_ip_blocked():
    result = validate_url("http://192.168.1.1/admin")
    assert result["valid"] is False
    assert "private" in result["error"].lower() or "internal" in result["error"].lower()

def test_loopback_blocked():
    result = validate_url("http://localhost/")
    assert result["valid"] is False

def test_url_too_long():
    result = validate_url("https://example.com/" + "a" * 2040)
    assert result["valid"] is False
    assert "long" in result["error"].lower() or "length" in result["error"].lower()

def test_private_ip_check():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False

def test_normalize_strips_fragment():
    url = normalize_url("https://Example.COM/path#section")
    assert "#" not in url
    assert url.startswith("https://example.com")

def test_suspicious_at_sign():
    result = validate_url("https://legit.com@evil.com/")
    assert result["valid"] is True  # URL is syntactically valid...
    patterns = result.get("suspicious_patterns", [])
    assert any(p["type"] == "credential_harvesting" for p in patterns)
