# CyberShield-AI Backend Configuration
import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "CyberShield-AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./cybershield.db"
    
    # API
    API_V1_PREFIX: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING"
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    
    # Threat Intelligence Providers
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLHAUS_ENABLED: bool = True
    
    # Rate Limiting
    RATE_LIMIT_SCANS_PER_MINUTE: int = 10
    RATE_LIMIT_GLOBAL_PER_MINUTE: int = 100
    
    # Extension
    EXTENSION_SECRET: Optional[str] = None
    RULE_SYNC_MAX_RULES: int = 5000
    
    # Scanning
    SCAN_TIMEOUT_SECONDS: int = 30
    MAX_URL_LENGTH: int = 2048
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
