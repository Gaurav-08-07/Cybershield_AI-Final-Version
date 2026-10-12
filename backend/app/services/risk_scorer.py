from dataclasses import dataclass, field
from typing import Optional
import re

@dataclass
class RiskComponents:
    threat_intel_score: Optional[float] = None
    domain_rep_score: Optional[float] = None
    url_pattern_score: Optional[float] = None
    signal_score: Optional[float] = None
    confirmed_malicious: bool = False
    evidence_count: int = 0
    evidence_sources: list = field(default_factory=list)

WEIGHTS = {"threat_intel": 0.50, "domain_rep": 0.20, "url_pattern": 0.15, "signal": 0.15}

def compute_risk_score(components: RiskComponents) -> dict:
    if components.confirmed_malicious:
        base_score = max(85.0, components.threat_intel_score or 85.0)
        return {"risk_score": round(min(100.0, base_score), 1), "verdict": "malicious",
                "confidence": 0.9, "explanation": "Confirmed match in threat intelligence feed.",
                "components": _cdict(components)}
    available = {}
    if components.threat_intel_score is not None: available["threat_intel"] = components.threat_intel_score
    if components.domain_rep_score is not None: available["domain_rep"] = components.domain_rep_score
    if components.url_pattern_score is not None: available["url_pattern"] = components.url_pattern_score
    if components.signal_score is not None: available["signal"] = components.signal_score
    if not available:
        return {"risk_score": None, "verdict": "inconclusive", "confidence": 0.0,
                "explanation": "Insufficient evidence. No threat signals available.",
                "components": _cdict(components)}
    total_weight = sum(WEIGHTS[k] for k in available)
    weighted_sum = sum(WEIGHTS[k] * v for k, v in available.items())
    score = (weighted_sum / total_weight) if total_weight > 0 else 0
    confidence = len(available) / len(WEIGHTS)
    if score >= 80: verdict = "malicious"
    elif score >= 50: verdict = "suspicious"
    elif score >= 20: verdict = "suspicious" if confidence < 0.5 else "no_threat"
    else: verdict = "no_threat"
    if confidence <= 0.25 and score < 80: verdict = "inconclusive"
    explanation = f"Score {score:.1f}/100 from {len(available)}/{len(WEIGHTS)} signals. Confidence {confidence*100:.0f}%. Note: absence of threat-feed match does not guarantee safety."
    return {"risk_score": round(score, 1), "verdict": verdict, "confidence": round(confidence, 2),
            "explanation": explanation, "components": _cdict(components)}

def _cdict(c):
    return {"threat_intel_score": c.threat_intel_score, "domain_rep_score": c.domain_rep_score,
            "url_pattern_score": c.url_pattern_score, "signal_score": c.signal_score,
            "confirmed_malicious": c.confirmed_malicious, "evidence_count": c.evidence_count}

def score_url_patterns(url: str, hostname: str) -> float:
    score = 0.0
    if len(url) > 100: score += 10
    if url.count(".") > 5: score += 15
    if "@" in url: score += 40
    if re.search(r"\.(exe|bat|scr|ps1|msi)(\?|$)", url, re.I): score += 35
    if re.search(r"\d{4,}", hostname): score += 10
    if re.search(r"(paypal|amazon|google|microsoft|apple).*\.(tk|ml|ga|cf|pw|top)", hostname, re.I): score += 60
    if re.search(r"(base64|decode|eval)=", url, re.I): score += 30
    if len(hostname.split(".")) > 4: score += 10
    return min(100.0, score)
