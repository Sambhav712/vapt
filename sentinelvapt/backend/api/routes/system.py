"""
SentinelVAPT — System Health, Privileges & API Status Router
"""

import asyncio
import logging
import platform
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.core.privilege_manager import get_privilege_manager
from backend.core.api_manager import get_api_manager
from backend.db.session import get_async_session

logger = logging.getLogger("sentinelvapt.api.system")
router = APIRouter(prefix="/api/system", tags=["System"])


@router.get(
    "/health",
    summary="Application health check and runtime metrics",
)
async def health_check(session: AsyncSession = Depends(get_async_session)):
    settings = get_settings()
    priv_mgr = get_privilege_manager()
    priv_status = priv_mgr.detect()

    db_ok = False
    try:
        await session.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.warning("Database health probe failed: %s", e)

    return {
        "status": "online" if db_ok else "degraded",
        "database_connected": db_ok,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
            "machine": platform.machine(),
        },
        "privilege": {
            "level": priv_status.level.value,
            "username": priv_status.username,
            "is_admin": priv_status.is_admin,
            "has_sudo": priv_status.has_sudo,
            "can_raw_socket": priv_status.can_raw_socket,
        },
        "llm_provider": settings.llm_provider,
        "exploit_allowlist": settings.exploit_allowlist,
    }


@router.get(
    "/config",
    summary="Safe application configuration parameters",
)
async def get_config():
    settings = get_settings()
    return {
        "llm_provider": settings.llm_provider,
        "groq_model": settings.groq_model,
        "ollama_base_url": settings.ollama_base_url,
        "ollama_model": settings.ollama_model,
        "exploit_allowlist": settings.exploit_allowlist,
        "report_output_dir": settings.report_output_dir,
        "zap_base_url": settings.zap_base_url,
        "msfrpc_host": settings.msfrpc_host,
        "msfrpc_port": settings.msfrpc_port,
        "auto_elevate": settings.auto_elevate,
    }


# ─── Privilege Management Endpoints ────────────────────────

@router.get(
    "/privileges",
    summary="Get current privilege level, sudo status, and tool elevation requirements",
)
async def get_privileges():
    priv_mgr = get_privilege_manager()
    return priv_mgr.to_dict()


@router.get(
    "/privileges/tools",
    summary="Get which tools require root and whether they can be elevated",
)
async def get_tool_privileges():
    priv_mgr = get_privilege_manager()
    return priv_mgr.get_tool_privilege_map()


# ─── API Management Endpoints ──────────────────────────────

@router.get(
    "/apis",
    summary="Get all external APIs with free/paid tier info, health, and rate limits",
)
async def get_apis():
    api_mgr = get_api_manager()
    return api_mgr.to_dict()


@router.get(
    "/apis/free",
    summary="Get all APIs that are 100% free or have free tiers",
)
async def get_free_apis():
    api_mgr = get_api_manager()
    return {
        "free_apis": api_mgr.get_free_apis(),
        "message": "All these APIs are FREE to use. Some need a free API key (no credit card required).",
    }


@router.get(
    "/apis/paid",
    summary="Get APIs that are freemium or paid — with free-tier limits",
)
async def get_paid_apis():
    api_mgr = get_api_manager()
    return {
        "paid_apis": api_mgr.get_paid_apis(),
        "message": "These APIs have limited free tiers. SentinelVAPT auto-falls back to free alternatives.",
    }


@router.get(
    "/apis/usage",
    summary="Get current API usage and remaining quotas",
)
async def get_api_usage():
    api_mgr = get_api_manager()
    return api_mgr.get_usage_summary()


@router.post(
    "/apis/health-check",
    summary="Run health checks on all external APIs",
)
async def run_api_health_check():
    api_mgr = get_api_manager()
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, api_mgr.check_all_health)
    return {
        "results": results,
        "message": "Health check completed for all APIs.",
    }


@router.post(
    "/apis/health-check/{api_name}",
    summary="Run health check on a specific API",
)
async def run_single_api_health_check(api_name: str):
    api_mgr = get_api_manager()
    loop = asyncio.get_running_loop()
    health = await loop.run_in_executor(None, api_mgr.check_health, api_name)
    api = api_mgr.apis.get(api_name)
    if not api:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"API '{api_name}' not found")
    return {
        "name": api.name,
        "key": api_name,
        "health": health.value,
        "tier": api.tier.value,
        "free_tier_limits": api.free_tier_limits,
    }
