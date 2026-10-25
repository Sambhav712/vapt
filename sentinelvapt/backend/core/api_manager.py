"""
SentinelVAPT — External API Manager
Manages all external API integrations with free-tier detection,
rate-limit tracking, health checks, and automatic fallback.

All APIs used by SentinelVAPT are FREE or have generous free tiers:
  - Groq: Free tier (limited RPM/RPD)
  - Ollama: Completely free (local LLM)
  - OWASP ZAP: Free & open source (local daemon)
  - NVD (NIST): Free, no key required (rate-limited)
  - Shodan InternetDB: Free, no key required
  - CVE.circl.lu: Free, no key required
  - ExploitDB / Searchsploit: Free & offline
  - GitHub API: Free (60 req/hour unauthenticated, 5000/hour with token)
  - VirusTotal: Free tier (4 req/min, 500/day)
  - AbuseIPDB: Free tier (1000 checks/day)
  - SecurityTrails: Free tier (50 queries/month)
  - Censys: Free tier (250 queries/month)
  - GreyNoise: Free Community tier (unlimited basic lookups)
  - Have I Been Pwned: Free API for breach lookups
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.api_manager")


class ApiTier(str, Enum):
    FREE = "free"               # Completely free, no key needed
    FREE_WITH_KEY = "free_key"  # Free tier exists but needs API key
    FREEMIUM = "freemium"       # Free tier with limits, paid for more
    LOCAL = "local"             # Runs locally, no external API
    PAID = "paid"               # Requires paid subscription


class ApiHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"       # Working but slow/rate-limited
    DOWN = "down"
    UNCHECKED = "unchecked"
    NO_KEY = "no_key"           # Needs API key but none configured


@dataclass
class RateLimitState:
    """Track rate limit state for an API."""
    requests_made: int = 0
    requests_limit: int = 0         # 0 = unlimited
    window_seconds: int = 3600      # rate limit window
    window_start: float = 0.0       # timestamp of window start
    daily_made: int = 0
    daily_limit: int = 0            # 0 = unlimited
    daily_start: float = 0.0
    last_request_time: float = 0.0
    last_429_time: float = 0.0      # last time we got rate-limited
    backoff_until: float = 0.0      # don't send requests until this time

    def can_request(self) -> bool:
        now = time.time()

        # Respect backoff
        if now < self.backoff_until:
            return False

        # Reset window if expired
        if self.window_seconds > 0 and (now - self.window_start) > self.window_seconds:
            self.requests_made = 0
            self.window_start = now

        # Reset daily if 24h passed
        if (now - self.daily_start) > 86400:
            self.daily_made = 0
            self.daily_start = now

        # Check window limit
        if self.requests_limit > 0 and self.requests_made >= self.requests_limit:
            return False

        # Check daily limit
        if self.daily_limit > 0 and self.daily_made >= self.daily_limit:
            return False

        return True

    def record_request(self):
        now = time.time()
        self.requests_made += 1
        self.daily_made += 1
        self.last_request_time = now

    def record_rate_limit(self, retry_after: int = 60):
        now = time.time()
        self.last_429_time = now
        self.backoff_until = now + retry_after

    def remaining_in_window(self) -> int:
        if self.requests_limit <= 0:
            return -1  # unlimited
        return max(0, self.requests_limit - self.requests_made)

    def remaining_daily(self) -> int:
        if self.daily_limit <= 0:
            return -1  # unlimited
        return max(0, self.daily_limit - self.daily_made)


@dataclass
class ApiEndpoint:
    """Definition of an external API used by SentinelVAPT."""
    name: str
    description: str
    tier: ApiTier
    base_url: str
    health_endpoint: str            # URL to ping for health check
    requires_key: bool
    key_env_var: str                 # env var name for API key
    free_tier_limits: str            # human-readable limits
    rate_limit: RateLimitState = field(default_factory=RateLimitState)
    health: ApiHealth = ApiHealth.UNCHECKED
    last_health_check: float = 0.0
    enabled: bool = True
    fallback_to: Optional[str] = None  # name of fallback API
    notes: str = ""


# ── API Catalog ─────────────────────────────────────────────────
# Every external API SentinelVAPT uses, with free-tier info

def _build_api_catalog() -> Dict[str, ApiEndpoint]:
    """Build the complete API catalog with free-tier information."""
    return {
        # ── LLM Providers ──────────────────────────────────────
        "groq": ApiEndpoint(
            name="Groq",
            description="Cloud LLM inference (Llama 3.3, Mixtral, etc.)",
            tier=ApiTier.FREE_WITH_KEY,
            base_url="https://api.groq.com/openai/v1",
            health_endpoint="https://api.groq.com/openai/v1/models",
            requires_key=True,
            key_env_var="GROQ_API_KEY",
            free_tier_limits="Free: 30 RPM, 14,400 RPD, 6000 tokens/min (Llama 3.3 70B)",
            rate_limit=RateLimitState(
                requests_limit=30, window_seconds=60,
                daily_limit=14400, daily_start=time.time()
            ),
            fallback_to="ollama",
            notes="100% FREE tier. Get key at https://console.groq.com — no credit card needed.",
        ),
        "ollama": ApiEndpoint(
            name="Ollama",
            description="Local LLM inference engine (Llama 3.1, Mistral, etc.)",
            tier=ApiTier.LOCAL,
            base_url="http://localhost:11434",
            health_endpoint="http://localhost:11434/api/tags",
            requires_key=False,
            key_env_var="",
            free_tier_limits="Unlimited — runs 100% locally on your hardware",
            notes="Completely FREE. Install from https://ollama.ai. Needs 8GB+ RAM.",
        ),

        # ── Vulnerability / CVE Databases ──────────────────────
        "nvd": ApiEndpoint(
            name="NVD (NIST)",
            description="National Vulnerability Database — CVE details and CVSS scores",
            tier=ApiTier.FREE,
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            health_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
            requires_key=False,
            key_env_var="NVD_API_KEY",
            free_tier_limits="Free: 5 req/30s without key, 50 req/30s with free key",
            rate_limit=RateLimitState(
                requests_limit=5, window_seconds=30,
            ),
            notes="100% FREE. Optional key from https://nvd.nist.gov/developers/request-an-api-key for higher limits.",
        ),
        "cve_circl": ApiEndpoint(
            name="CVE.circl.lu",
            description="CIRCL CVE search and lookup API",
            tier=ApiTier.FREE,
            base_url="https://cve.circl.lu/api",
            health_endpoint="https://cve.circl.lu/api/last",
            requires_key=False,
            key_env_var="",
            free_tier_limits="Free & unlimited — community service",
            fallback_to="nvd",
            notes="100% FREE, no key needed. Good fallback for NVD.",
        ),
        "exploitdb": ApiEndpoint(
            name="ExploitDB / Searchsploit",
            description="Exploit database — local offline search via searchsploit",
            tier=ApiTier.LOCAL,
            base_url="",
            health_endpoint="",
            requires_key=False,
            key_env_var="",
            free_tier_limits="Unlimited — offline local database (Kali default)",
            notes="100% FREE. Pre-installed on Kali. Update with: searchsploit -u",
        ),

        # ── Recon / OSINT APIs ──────────────────────────────────
        "shodan_internetdb": ApiEndpoint(
            name="Shodan InternetDB",
            description="Free IP enrichment — open ports, vulns, hostnames",
            tier=ApiTier.FREE,
            base_url="https://internetdb.shodan.io",
            health_endpoint="https://internetdb.shodan.io/8.8.8.8",
            requires_key=False,
            key_env_var="",
            free_tier_limits="Free & unlimited — no key needed",
            notes="100% FREE. No API key required. Provides port/vuln/hostname data.",
        ),
        "shodan_api": ApiEndpoint(
            name="Shodan API (Full)",
            description="Full Shodan search, banners, and host details",
            tier=ApiTier.FREEMIUM,
            base_url="https://api.shodan.io",
            health_endpoint="https://api.shodan.io/api-info",
            requires_key=True,
            key_env_var="SHODAN_API_KEY",
            free_tier_limits="Free: 1 query credit/month, 100 scan credits. Paid: $49/month",
            rate_limit=RateLimitState(requests_limit=1, window_seconds=1),
            fallback_to="shodan_internetdb",
            notes="Free tier is VERY limited. Use InternetDB instead for most tasks.",
        ),
        "censys": ApiEndpoint(
            name="Censys",
            description="Internet-wide host and certificate search",
            tier=ApiTier.FREEMIUM,
            base_url="https://search.censys.io/api",
            health_endpoint="https://search.censys.io/api/v1/account",
            requires_key=True,
            key_env_var="CENSYS_API_ID",
            free_tier_limits="Free: 250 queries/month",
            rate_limit=RateLimitState(daily_limit=8, daily_start=time.time()),
            fallback_to="shodan_internetdb",
            notes="Free tier available. Sign up at https://search.censys.io/register",
        ),
        "securitytrails": ApiEndpoint(
            name="SecurityTrails",
            description="DNS history, subdomains, associated domains",
            tier=ApiTier.FREEMIUM,
            base_url="https://api.securitytrails.com/v1",
            health_endpoint="https://api.securitytrails.com/v1/ping",
            requires_key=True,
            key_env_var="SECURITYTRAILS_API_KEY",
            free_tier_limits="Free: 50 queries/month",
            rate_limit=RateLimitState(daily_limit=2, daily_start=time.time()),
            fallback_to=None,
            notes="Free tier at https://securitytrails.com/app/signup. Good for DNS recon.",
        ),
        "greynoise": ApiEndpoint(
            name="GreyNoise Community",
            description="IP reputation — is this IP scanning/attacking the internet?",
            tier=ApiTier.FREE_WITH_KEY,
            base_url="https://api.greynoise.io/v3/community",
            health_endpoint="https://api.greynoise.io/v3/community/8.8.8.8",
            requires_key=True,
            key_env_var="GREYNOISE_API_KEY",
            free_tier_limits="Free Community: unlimited basic IP lookups",
            notes="Free Community API. Sign up at https://viz.greynoise.io/signup",
        ),

        # ── Threat Intelligence ─────────────────────────────────
        "virustotal": ApiEndpoint(
            name="VirusTotal",
            description="File/URL/IP reputation scanning with 70+ AV engines",
            tier=ApiTier.FREE_WITH_KEY,
            base_url="https://www.virustotal.com/api/v3",
            health_endpoint="https://www.virustotal.com/api/v3/users/current",
            requires_key=True,
            key_env_var="VIRUSTOTAL_API_KEY",
            free_tier_limits="Free: 4 lookups/min, 500/day, 15.5K/month",
            rate_limit=RateLimitState(
                requests_limit=4, window_seconds=60,
                daily_limit=500, daily_start=time.time()
            ),
            notes="Free tier at https://www.virustotal.com/gui/join-us — no credit card.",
        ),
        "abuseipdb": ApiEndpoint(
            name="AbuseIPDB",
            description="IP abuse/reputation checking database",
            tier=ApiTier.FREE_WITH_KEY,
            base_url="https://api.abuseipdb.com/api/v2",
            health_endpoint="https://api.abuseipdb.com/api/v2/check",
            requires_key=True,
            key_env_var="ABUSEIPDB_API_KEY",
            free_tier_limits="Free: 1000 checks/day",
            rate_limit=RateLimitState(daily_limit=1000, daily_start=time.time()),
            notes="Free tier at https://www.abuseipdb.com/register — no credit card.",
        ),
        "haveibeenpwned": ApiEndpoint(
            name="Have I Been Pwned",
            description="Check if emails/passwords have appeared in data breaches",
            tier=ApiTier.FREE,
            base_url="https://haveibeenpwned.com/api/v3",
            health_endpoint="https://haveibeenpwned.com/api/v3/breaches",
            requires_key=False,
            key_env_var="HIBP_API_KEY",
            free_tier_limits="Free for breach search. Paid ($3.50/mo) for full API",
            rate_limit=RateLimitState(requests_limit=10, window_seconds=60),
            notes="Breach list is free. Full search needs key from https://haveibeenpwned.com/API/Key",
        ),

        # ── GitHub ──────────────────────────────────────────────
        "github": ApiEndpoint(
            name="GitHub API",
            description="Used for tool updates, release downloads, and advisory lookups",
            tier=ApiTier.FREE,
            base_url="https://api.github.com",
            health_endpoint="https://api.github.com/rate_limit",
            requires_key=False,
            key_env_var="GITHUB_TOKEN",
            free_tier_limits="Free: 60 req/hour (unauthenticated), 5000/hour (with free token)",
            rate_limit=RateLimitState(requests_limit=60, window_seconds=3600),
            notes="100% FREE. Optional token from https://github.com/settings/tokens for 5000/hr.",
        ),

        # ── Local Tools (always free) ──────────────────────────
        "zap": ApiEndpoint(
            name="OWASP ZAP",
            description="OWASP Zed Attack Proxy — local web app scanner",
            tier=ApiTier.LOCAL,
            base_url="http://localhost:8080",
            health_endpoint="http://localhost:8080/JSON/core/view/version/",
            requires_key=False,
            key_env_var="ZAP_API_KEY",
            free_tier_limits="Unlimited — runs 100% locally, open source",
            notes="100% FREE & open source. Runs as local daemon.",
        ),
        "metasploit_rpc": ApiEndpoint(
            name="Metasploit RPC",
            description="Metasploit Framework msfrpcd for exploit verification",
            tier=ApiTier.LOCAL,
            base_url="https://localhost:55553",
            health_endpoint="",
            requires_key=False,
            key_env_var="MSFRPC_PASSWORD",
            free_tier_limits="Unlimited — runs 100% locally, open source",
            notes="100% FREE (Community Edition). Included in Kali. Paid Pro is optional.",
        ),
    }


class ApiManager:
    """
    Manages all external API integrations:
    - Tracks which APIs are free vs. paid
    - Monitors rate limits per API
    - Health-checks all endpoints
    - Auto-falls back to free alternatives
    - Reports usage and remaining quota
    """

    def __init__(self):
        self.settings = get_settings()
        self.apis = _build_api_catalog()
        self._apply_env_keys()

    def _apply_env_keys(self):
        """Check env for API keys and update availability."""
        import os
        for name, api in self.apis.items():
            if api.requires_key and api.key_env_var:
                key = os.environ.get(api.key_env_var, "")
                if not key:
                    # Also check settings for known keys
                    key = self._get_key_from_settings(api.key_env_var)
                if key and key not in ("", "your_groq_api_key_here", "your_zap_api_key"):
                    api.health = ApiHealth.UNCHECKED  # has key, can check
                else:
                    api.health = ApiHealth.NO_KEY

            # NVD: boost rate limit if key is configured
            if name == "nvd":
                key = os.environ.get("NVD_API_KEY", "")
                if key:
                    api.rate_limit.requests_limit = 50
                    api.rate_limit.window_seconds = 30

            # GitHub: boost rate limit if token is configured
            if name == "github":
                key = os.environ.get("GITHUB_TOKEN", "")
                if key:
                    api.rate_limit.requests_limit = 5000

    def _get_key_from_settings(self, env_var: str) -> str:
        """Try to get a key from settings object."""
        mapping = {
            "GROQ_API_KEY": "groq_api_key",
            "ZAP_API_KEY": "zap_api_key",
            "MSFRPC_PASSWORD": "msfrpc_password",
        }
        attr = mapping.get(env_var, "")
        if attr and hasattr(self.settings, attr):
            return getattr(self.settings, attr, "") or ""
        return ""

    # ── Health Checks ──────────────────────────────────────────

    def check_health(self, api_name: str, timeout: int = 10) -> ApiHealth:
        """Check health of a specific API endpoint."""
        api = self.apis.get(api_name)
        if not api:
            return ApiHealth.DOWN

        if not api.health_endpoint:
            api.health = ApiHealth.HEALTHY if api.tier == ApiTier.LOCAL else ApiHealth.UNCHECKED
            return api.health

        if api.health == ApiHealth.NO_KEY and api.requires_key:
            return ApiHealth.NO_KEY

        try:
            headers = {"User-Agent": "SentinelVAPT/1.0"}

            # Add auth headers where needed
            if api_name == "groq":
                key = self._get_key_from_settings("GROQ_API_KEY")
                if key:
                    headers["Authorization"] = f"Bearer {key}"
            elif api_name == "virustotal":
                import os
                key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if key:
                    headers["x-apikey"] = key
            elif api_name == "github":
                import os
                key = os.environ.get("GITHUB_TOKEN", "")
                if key:
                    headers["Authorization"] = f"token {key}"

            resp = requests.get(api.health_endpoint, headers=headers, timeout=timeout)

            if resp.status_code == 429:
                api.health = ApiHealth.DEGRADED
                api.rate_limit.record_rate_limit()
            elif resp.status_code < 400:
                api.health = ApiHealth.HEALTHY
            elif resp.status_code in (401, 403):
                api.health = ApiHealth.NO_KEY
            else:
                api.health = ApiHealth.DEGRADED

        except requests.exceptions.ConnectionError:
            api.health = ApiHealth.DOWN
        except requests.exceptions.Timeout:
            api.health = ApiHealth.DEGRADED
        except Exception as e:
            logger.warning("Health check failed for %s: %s", api_name, e)
            api.health = ApiHealth.DOWN

        api.last_health_check = time.time()
        return api.health

    def check_all_health(self) -> Dict[str, str]:
        """Check health of all APIs. Returns name → health status."""
        results = {}
        for name in self.apis:
            results[name] = self.check_health(name).value
        return results

    # ── Rate Limiting ──────────────────────────────────────────

    def can_request(self, api_name: str) -> bool:
        """Check if we can make a request to this API within rate limits."""
        api = self.apis.get(api_name)
        if not api:
            return False
        if api.health == ApiHealth.NO_KEY and api.requires_key:
            return False
        return api.rate_limit.can_request()

    def record_request(self, api_name: str):
        """Record that we made a request to this API."""
        api = self.apis.get(api_name)
        if api:
            api.rate_limit.record_request()

    def record_rate_limit(self, api_name: str, retry_after: int = 60):
        """Record that we got rate-limited (429) by this API."""
        api = self.apis.get(api_name)
        if api:
            api.rate_limit.record_rate_limit(retry_after)
            logger.warning("Rate limited by %s, backing off for %ds", api_name, retry_after)

    def get_best_api(self, api_name: str) -> Optional[str]:
        """
        Get the best API to use — the primary if available/within limits,
        otherwise the fallback.
        """
        api = self.apis.get(api_name)
        if not api:
            return None

        # Check if primary is usable
        if api.enabled and api.health not in (ApiHealth.DOWN, ApiHealth.NO_KEY):
            if api.rate_limit.can_request():
                return api_name

        # Try fallback
        if api.fallback_to:
            fallback = self.apis.get(api.fallback_to)
            if fallback and fallback.enabled:
                if fallback.health not in (ApiHealth.DOWN, ApiHealth.NO_KEY):
                    if fallback.rate_limit.can_request():
                        logger.info(
                            "Falling back from %s to %s",
                            api_name, api.fallback_to
                        )
                        return api.fallback_to

        return api_name  # return primary anyway, let caller handle errors

    # ── Summaries ──────────────────────────────────────────────

    def get_free_apis(self) -> List[Dict]:
        """Get all APIs that are completely free or have free tiers."""
        result = []
        for name, api in self.apis.items():
            if api.tier in (ApiTier.FREE, ApiTier.FREE_WITH_KEY, ApiTier.LOCAL):
                result.append({
                    "name": api.name,
                    "key": name,
                    "tier": api.tier.value,
                    "description": api.description,
                    "free_tier_limits": api.free_tier_limits,
                    "requires_key": api.requires_key,
                    "has_key": api.health != ApiHealth.NO_KEY,
                    "notes": api.notes,
                })
        return result

    def get_paid_apis(self) -> List[Dict]:
        """Get APIs that require payment for full functionality."""
        result = []
        for name, api in self.apis.items():
            if api.tier in (ApiTier.FREEMIUM, ApiTier.PAID):
                result.append({
                    "name": api.name,
                    "key": name,
                    "tier": api.tier.value,
                    "description": api.description,
                    "free_tier_limits": api.free_tier_limits,
                    "requires_key": api.requires_key,
                    "has_key": api.health != ApiHealth.NO_KEY,
                    "notes": api.notes,
                })
        return result

    def get_usage_summary(self) -> Dict:
        """Get usage/quota summary for all APIs."""
        usage = {}
        for name, api in self.apis.items():
            rl = api.rate_limit
            usage[name] = {
                "name": api.name,
                "tier": api.tier.value,
                "health": api.health.value,
                "enabled": api.enabled,
                "remaining_in_window": rl.remaining_in_window(),
                "remaining_daily": rl.remaining_daily(),
                "requests_made": rl.requests_made,
                "daily_made": rl.daily_made,
                "is_rate_limited": not rl.can_request(),
                "free_tier_limits": api.free_tier_limits,
            }
        return usage

    def to_dict(self) -> Dict:
        """Full serialization for API responses."""
        return {
            "total_apis": len(self.apis),
            "free_apis": len(self.get_free_apis()),
            "paid_apis": len(self.get_paid_apis()),
            "apis": {
                name: {
                    "name": api.name,
                    "description": api.description,
                    "tier": api.tier.value,
                    "health": api.health.value,
                    "requires_key": api.requires_key,
                    "has_key": api.health != ApiHealth.NO_KEY,
                    "free_tier_limits": api.free_tier_limits,
                    "remaining_in_window": api.rate_limit.remaining_in_window(),
                    "remaining_daily": api.rate_limit.remaining_daily(),
                    "enabled": api.enabled,
                    "notes": api.notes,
                    "fallback_to": api.fallback_to,
                }
                for name, api in self.apis.items()
            },
            "usage": self.get_usage_summary(),
        }


# ── Module-level singleton ──────────────────────────────────────

_api_manager: Optional[ApiManager] = None


def get_api_manager() -> ApiManager:
    """Get the global ApiManager singleton."""
    global _api_manager
    if _api_manager is None:
        _api_manager = ApiManager()
    return _api_manager
