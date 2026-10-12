import pytest
from app.services.risk_scorer import RiskComponents, compute_risk_score, score_url_patterns

def test_confirmed_malicious_always_malicious():
    c = RiskComponents(confirmed_malicious=True, threat_intel_score=90.0)
    result = compute_risk_score(c)
    assert result["verdict"] == "malicious"
    assert result["risk_score"] >= 80

def test_no_signals_is_inconclusive():
    c = RiskComponents()
    result = compute_risk_score(c)
    assert result["verdict"] == "inconclusive"
    assert result["risk_score"] is None

def test_high_threat_intel_score():
    c = RiskComponents(threat_intel_score=90.0, domain_rep_score=70.0)
    result = compute_risk_score(c)
    assert result["verdict"] in ("malicious", "suspicious")
    assert result["risk_score"] >= 70

def test_low_score_is_no_threat():
    c = RiskComponents(threat_intel_score=5.0, domain_rep_score=5.0, url_pattern_score=5.0, signal_score=5.0)
    result = compute_risk_score(c)
    assert result["verdict"] in ("no_threat", "suspicious")
    assert result["risk_score"] < 30

def test_single_signal_low_confidence():
    c = RiskComponents(url_pattern_score=30.0)
    result = compute_risk_score(c)
    assert result["confidence"] <= 0.25
    assert result["verdict"] == "inconclusive"

def test_phishing_url_pattern_score():
    score = score_url_patterns("https://paypal-secure.tk/verify", "paypal-secure.tk")
    assert score > 50

def test_clean_url_low_pattern_score():
    score = score_url_patterns("https://wikipedia.org/wiki/Python", "wikipedia.org")
    assert score < 20

def test_confirmed_overrides_low_pattern():
    c = RiskComponents(
        confirmed_malicious=True,
        threat_intel_score=90.0,
        url_pattern_score=5.0,  # low heuristic score
    )
    result = compute_risk_score(c)
    assert result["verdict"] == "malicious"
    assert result["risk_score"] >= 85
