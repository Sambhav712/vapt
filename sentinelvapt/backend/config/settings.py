"""
SentinelVAPT — Centralized Settings Module
Loads all config from environment variables / .env file.
"""

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
logger = logging.getLogger("sentinelvapt.config")


class Settings(BaseSettings):
    """Application-wide settings, loaded from environment / .env."""

    # ── Database ──────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://sentinelvapt:sentinelvapt@localhost:5432/sentinelvapt"
    database_url_sync: str = "postgresql://sentinelvapt:sentinelvapt@localhost:5432/sentinelvapt"

    # ── Redis ─────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── LLM ───────────────────────────────────────────────────
    llm_provider: str = "groq"  # groq | ollama
    groq_api_key: Optional[str] = None
    groq_model: str = "llama-3.3-70b-versatile"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # ── OWASP ZAP ────────────────────────────────────────────
    zap_api_key: str = ""
    zap_base_url: str = "http://localhost:8080"

    # ── Metasploit RPC ────────────────────────────────────────
    msfrpc_host: str = "localhost"
    msfrpc_port: int = 55553
    msfrpc_user: str = "msf"
    msfrpc_password: str = "msf_password"

    # ── External API Keys (all have FREE tiers) ───────────────
    nvd_api_key: Optional[str] = None          # NVD — free key for higher rate limits
    shodan_api_key: Optional[str] = None       # Shodan — InternetDB is free, full API is freemium
    virustotal_api_key: Optional[str] = None   # VirusTotal — free: 4 req/min, 500/day
    abuseipdb_api_key: Optional[str] = None    # AbuseIPDB — free: 1000/day
    censys_api_id: Optional[str] = None        # Censys — free: 250 queries/month
    censys_api_secret: Optional[str] = None
    securitytrails_api_key: Optional[str] = None  # SecurityTrails — free: 50 queries/month
    greynoise_api_key: Optional[str] = None    # GreyNoise Community — free
    github_token: Optional[str] = None         # GitHub — free: 5000 req/hr with token
    hibp_api_key: Optional[str] = None         # Have I Been Pwned — breach list is free

    # ── Privilege Management ──────────────────────────────────
    auto_elevate: bool = True  # Auto-prefix sudo for tools that need root

    # ── Server ────────────────────────────────────────────────
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # ── Safety ────────────────────────────────────────────────
    exploit_allowlist: str = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    # ── Reports ───────────────────────────────────────────────
    report_output_dir: str = "reports"

    # ── Logging ───────────────────────────────────────────────
    log_level: str = "INFO"

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    # ── Derived helpers ───────────────────────────────────────

    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT

    @property
    def reports_path(self) -> Path:
        p = PROJECT_ROOT / self.report_output_dir
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def tools_bin_dir(self) -> Path:
        """Local directory for downloaded tool binaries."""
        p = PROJECT_ROOT / "tools_bin"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def allowlisted_networks(self) -> List[ipaddress.IPv4Network]:
        """Parse the exploit_allowlist into a list of IPv4Network objects."""
        networks = []
        for entry in self.exploit_allowlist.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning("Invalid network in EXPLOIT_ALLOWLIST: %s", entry)
        return networks

    def is_target_allowlisted(self, target_ip: str) -> bool:
        """Check whether a target IP falls within the exploitation allowlist."""
        try:
            addr = ipaddress.ip_address(target_ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlisted_networks)


@lru_cache()
def get_settings() -> Settings:
    """Singleton access to application settings."""
    return Settings()
