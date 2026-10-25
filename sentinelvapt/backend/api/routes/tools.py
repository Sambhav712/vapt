"""
SentinelVAPT — Tools Status & Management API Router
Allows diagnostic inspection, catalog querying, and on-demand installation of security tools.
"""

import asyncio
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.tools.installer import ToolInstaller
from backend.tools.registry import ToolRegistry

logger = logging.getLogger("sentinelvapt.api.tools")
router = APIRouter(prefix="/api/tools", tags=["Tools"])


class ToolStatus(BaseModel):
    name: str
    installed: bool
    path: str
    version: str
    description: str


class ToolToggleRequest(BaseModel):
    enabled: bool


@router.get(
    "",
    response_model=List[ToolStatus],
    summary="Check status and versions of all required security tools",
)
async def get_tools_status():
    installer = ToolInstaller()
    loop = asyncio.get_running_loop()
    status_map = await loop.run_in_executor(None, installer.check_all)

    tool_descriptions = {
        "nmap": "Network mapper, port scanner, and OS fingerprinting engine",
        "nuclei": "Fast, template-based vulnerability scanner by ProjectDiscovery",
        "zap": "OWASP Zed Attack Proxy web app scanner daemon / API",
        "sqlmap": "Automatic SQL injection and database takeover tool",
        "subfinder": "Passive DNS subdomain discovery tool",
        "httpx": "Fast multi-purpose HTTP probe and technology detector",
        "nikto": "Web server configuration and outdated software scanner",
        "amass": "In-depth attack surface mapping and asset discovery",
        "metasploit": "Metasploit Framework RPC console for verified checks",
        "api_security": "Native OpenAPI/REST API security fuzzer and validator",
    }

    out = []
    for name, info in status_map.items():
        is_inst = getattr(info, "installed", False)
        tool_path = getattr(info, "path", None) or "Not found"
        tool_ver = getattr(info, "version", None) or "Unknown"
        out.append(
            ToolStatus(
                name=name,
                installed=bool(is_inst),
                path=str(tool_path),
                version=str(tool_ver),
                description=tool_descriptions.get(
                    name, "Security assessment tool"
                ),
            )
        )

    return out


@router.get(
    "/catalog",
    response_model=List[Dict[str, Any]],
    summary="List all tools supported in the extensible catalog with tiers and status",
)
async def get_tools_catalog():
    registry = ToolRegistry()
    loop = asyncio.get_running_loop()
    # Refresh discovery
    await loop.run_in_executor(None, registry.scan_system)
    return [t.to_dict() for t in registry.get_all()]


@router.get(
    "/detected",
    response_model=Dict[str, Any],
    summary="Get all detected host tools grouped by category and risk tier",
)
async def get_detected_tools():
    registry = ToolRegistry()
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, registry.scan_system)

    detected = registry.get_detected()

    by_category: Dict[str, List[Dict[str, Any]]] = {}
    by_tier: Dict[str, List[Dict[str, Any]]] = {"1": [], "2": [], "3": []}

    for t in detected:
        d = t.to_dict()
        cat = t.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(d)

        tier_str = str(t.tier)
        if tier_str in by_tier:
            by_tier[tier_str].append(d)

    return {
        "total_detected": len(detected),
        "total_catalog": len(registry.get_all()),
        "by_category": by_category,
        "by_tier": by_tier,
        "tools": [t.to_dict() for t in detected],
    }


@router.post(
    "/toggle/{tool_name}",
    summary="Toggle enabled/disabled state of a catalog tool",
)
async def toggle_tool(tool_name: str, payload: ToolToggleRequest):
    registry = ToolRegistry()
    tool = registry.tools.get(tool_name.lower().strip())
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not in catalog")

    tool.enabled = payload.enabled
    return {"name": tool.name, "enabled": tool.enabled}


@router.get(
    "/missing-packages",
    summary="Get missing Kali/Debian apt packages from catalog",
)
async def get_missing_packages():
    registry = ToolRegistry()
    missing = registry.get_missing_apt_packages()
    return {
        "missing_count": len(missing),
        "packages": missing,
        "apt_command": f"sudo apt-get update && sudo apt-get install -y {' '.join(missing)}" if missing else "",
    }


@router.post(
    "/install/{tool_name}",
    summary="Trigger automatic download/installation of a specific tool",
)
async def install_tool(tool_name: str):
    installer = ToolInstaller()
    tool_clean = tool_name.lower().strip()

    supported = [
        "nmap",
        "nuclei",
        "zap",
        "sqlmap",
        "subfinder",
        "httpx",
        "nikto",
        "amass",
        "metasploit",
    ]
    if tool_clean not in supported:
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{tool_clean}' not in auto-installable list: {supported}",
        )

    try:
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(
            None, installer._install_tool, tool_clean
        )
        is_inst = getattr(res, "installed", False)
        return {
            "name": tool_clean,
            "installed": bool(is_inst),
            "path": getattr(res, "path", None),
            "version": getattr(res, "version", None),
            "error": getattr(res, "error", None),
        }
    except Exception as e:
        logger.error(
            "Installation failed for %s: %s", tool_clean, e, exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Installation failed: {e}",
        )


@router.post(
    "/install-all",
    summary="Trigger batch installation of all missing tools",
)
async def install_all_tools():
    installer = ToolInstaller()
    loop = asyncio.get_running_loop()

    def _bg():
        try:
            installer.install_all()
        except Exception as e:
            logger.error("Batch tool installation error: %s", e)

    asyncio.create_task(loop.run_in_executor(None, _bg))
    return {
        "message": "Batch tool installation initiated in background. Poll /api/tools for progress."
    }
