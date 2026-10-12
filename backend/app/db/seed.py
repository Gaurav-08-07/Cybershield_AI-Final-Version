import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select, func
from app.db.database import AsyncSessionLocal
from app.models.models import ThreatIndicator, SecurityEvent

SAMPLE_THREATS = [
    {
        "indicator": "malware-test-site.example.com",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "critical",
        "category": "trojan_downloader",
        "source": "CyberShield-Intel",
        "confidence": 0.98,
        "tags": "test,trojan,c2"
    },
    {
        "indicator": "phishing-bank-portal.fake.net",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "high",
        "category": "phishing",
        "source": "CyberShield-Intel",
        "confidence": 0.95,
        "tags": "phishing,finance,credential_harvesting"
    },
    {
        "indicator": "cryptominer-pool.crypto-evil.org",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "medium",
        "category": "cryptominer",
        "source": "URLhaus-Feed",
        "confidence": 0.88,
        "tags": "coinminer,unauthorized_compute"
    },
    {
        "indicator": "c2-command-hub.threat-actor.io",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "critical",
        "category": "command_and_control",
        "source": "ThreatStream-Sync",
        "confidence": 0.99,
        "tags": "c2,apt,beaconing"
    },
    {
        "indicator": "ransomware-dist.evilpayload.cc",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "critical",
        "category": "ransomware",
        "source": "CyberShield-Intel",
        "confidence": 0.97,
        "tags": "ransomware,payload_drop,extortion"
    },
    {
        "indicator": "credential-harvester.verify-account-security.xyz",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "high",
        "category": "credential_theft",
        "source": "PhishTank-Mirror",
        "confidence": 0.92,
        "tags": "credential_theft,oauth_phish"
    },
    {
        "indicator": "trojan-dropper.update-flash-player.com",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "high",
        "category": "dropper",
        "source": "CyberShield-Intel",
        "confidence": 0.91,
        "tags": "drive_by,fake_installer"
    },
    {
        "indicator": "exploit-kit-delivery.vulnerability-scan.cc",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "critical",
        "category": "exploit_kit",
        "source": "URLhaus-Feed",
        "confidence": 0.96,
        "tags": "browser_exploit,zero_day"
    },
    {
        "indicator": "stealer-logs.darkweb-drop.onion.pet",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "high",
        "category": "infostealer",
        "source": "CyberShield-Intel",
        "confidence": 0.94,
        "tags": "redline,raccoon,exfiltration"
    },
    {
        "indicator": "fake-update-service.browser-patch.online",
        "indicator_type": "domain",
        "verdict": "malicious",
        "severity": "medium",
        "category": "social_engineering",
        "source": "PhishTank-Mirror",
        "confidence": 0.85,
        "tags": "malvertising,clickjacking"
    }
]

SAMPLE_EVENTS = [
    {
        "event_type": "rule_sync",
        "severity": "info",
        "source": "ExtensionEngine",
        "description": "Chrome SafeBrowse synchronized 10 dynamic blocklist rules with warning page redirect.",
    },
    {
        "event_type": "threat_intel_ingest",
        "severity": "info",
        "source": "ThreatIntelService",
        "description": "Baseline threat indicator feeds ingested and indexed into high-speed SQLite lookup.",
    },
    {
        "event_type": "engine_initialized",
        "severity": "info",
        "source": "CyberShieldCore",
        "description": "Real-time hybrid risk scoring engine initialized with URLhaus feed integration and heuristic analyzers.",
    }
]

async def seed_data():
    async with AsyncSessionLocal() as session:
        q = await session.execute(select(func.count(ThreatIndicator.id)))
        count = q.scalar() or 0
        if count == 0:
            for item in SAMPLE_THREATS:
                ti = ThreatIndicator(
                    indicator=item["indicator"],
                    indicator_type=item["indicator_type"],
                    verdict=item["verdict"],
                    severity=item["severity"],
                    category=item["category"],
                    source=item["source"],
                    confidence=item["confidence"],
                    tags=item["tags"],
                    first_seen=datetime.utcnow() - timedelta(days=2),
                    last_seen=datetime.utcnow() - timedelta(hours=1),
                    active=True
                )
                session.add(ti)
            
            for evt in SAMPLE_EVENTS:
                se = SecurityEvent(
                    event_type=evt["event_type"],
                    severity=evt["severity"],
                    source=evt["source"],
                    description=evt["description"],
                )
                session.add(se)
                
            await session.commit()
            print("Successfully seeded threat indicators and security events.")
        else:
            print(f"Database already has {count} threat indicators.")

if __name__ == "__main__":
    asyncio.run(seed_data())
