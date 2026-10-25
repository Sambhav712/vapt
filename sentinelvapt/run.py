"""
SentinelVAPT — Main Command Line Interface & Server Runner
Cross-platform CLI supporting server mode, headless scans, and tool diagnostics.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
import uvicorn

# Configure UTF-8 output if possible on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config.settings import get_settings
from backend.db.session import init_db, AsyncSessionLocal
from backend.db.models import Job, ScopeType, PipelineStage
from backend.core.orchestrator import PipelineOrchestrator
from backend.core.privilege_manager import get_privilege_manager
from backend.core.api_manager import get_api_manager
from backend.tools.installer import ToolInstaller

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinelvapt")


def run_server(host: str = None, port: int = None, reload: bool = False):
    settings = get_settings()
    host = host or settings.backend_host
    port = port or settings.backend_port
    logger.info("Starting SentinelVAPT backend on http://%s:%d", host, port)
    uvicorn.run("backend.api.app:app", host=host, port=port, reload=reload)


def check_tools():
    installer = ToolInstaller()
    print("\n[+] Checking SentinelVAPT Tool Ecosystem:\n" + "=" * 55)
    results = installer.check_all()
    for name, info in results.items():
        is_inst = getattr(info, "installed", False)
        status_tag = "[OK]     " if is_inst else "[MISSING]"
        ver = getattr(info, "version", "N/A") or "N/A"
        path = getattr(info, "path", None) or "Not found"
        print(f" {status_tag} {name:<12} | Ver: {ver:<15} | Path: {path}")
    print("=" * 55 + "\n")


def check_privileges():
    """Display current privilege level and sudo/admin status."""
    priv_mgr = get_privilege_manager()
    status = priv_mgr.detect()

    print("\n[+] SentinelVAPT Privilege Status:")
    print("=" * 55)
    print(f"  OS:           {status.os_type}")
    print(f"  User:         {status.username}")
    print(f"  UID:          {status.uid if status.uid is not None else 'N/A (Windows)'}")
    print(f"  Level:        {status.level.value.upper()}")
    print(f"  Is Admin:     {status.is_admin}")
    print(f"  Has sudo:     {status.has_sudo}")
    print(f"  Passwordless: {status.sudo_passwordless}")
    print(f"  Raw sockets:  {status.can_raw_socket}")

    if status.warnings:
        print("\n  ⚠ Warnings:")
        for w in status.warnings:
            print(f"    - {w}")

    print("\n  Tools requiring root:")
    tool_privs = priv_mgr.get_tool_privilege_map()
    for name, info in tool_privs.items():
        installed = "✓" if info["installed"] else "✗"
        can_run = "✓ CAN RUN" if info["can_run_elevated"] else "✗ NEEDS ROOT"
        print(f"    [{installed}] {name:<14} {can_run:<16} ({info['reason']})")
    print("=" * 55 + "\n")


def check_apis():
    """Display external API health and free-tier info."""
    api_mgr = get_api_manager()

    print("\n[+] SentinelVAPT External API Status:")
    print("=" * 75)
    print(f"  {'API':<22} {'Tier':<12} {'Health':<10} {'Limits'}")
    print("  " + "-" * 73)

    for name, api in api_mgr.apis.items():
        health = api_mgr.check_health(name)
        tier_display = api.tier.value.upper()
        health_display = health.value.upper()

        # Color indicators
        if health.value == "healthy":
            health_icon = "✓"
        elif health.value == "no_key":
            health_icon = "🔑"
        elif health.value == "degraded":
            health_icon = "⚠"
        else:
            health_icon = "✗"

        print(f"  {health_icon} {api.name:<20} {tier_display:<12} {health_display:<10} {api.free_tier_limits}")

    free_count = len(api_mgr.get_free_apis())
    paid_count = len(api_mgr.get_paid_apis())
    print(f"\n  Summary: {free_count} FREE APIs | {paid_count} freemium/paid APIs")
    print("  All APIs used by SentinelVAPT have free tiers — no payment required!")
    print("=" * 75 + "\n")


def install_tools():
    installer = ToolInstaller()
    print("\n[*] Installing missing tools into SentinelVAPT environment...\n")
    results = installer.install_all()
    for name, info in results.items():
        p = getattr(info, "path", "Failed")
        print(f"  -> {name}: {p}")
    print("\n[*] Tool installation process concluded.")


async def run_headless_scan(target: str, scope: str, exploit: bool):
    await init_db()
    settings = get_settings()

    scope_type = ScopeType(scope.lower())

    if exploit and not settings.is_target_allowlisted(target):
        logger.error(
            "Exploitation denied: Target '%s' is not in EXPLOIT_ALLOWLIST (%s)",
            target, settings.exploit_allowlist
        )
        sys.exit(1)

    print(f"\n[+] Launching Headless Scan on Target: {target}")
    print(f"    Scope: {scope_type.value.upper()} | Authorized Exploitation: {exploit}\n")

    async with AsyncSessionLocal() as session:
        job = Job(
            target=target,
            scope_type=scope_type,
            authorized_exploitation=exploit,
            current_stage=PipelineStage.TOOL_CHECK,
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)

        async def log_callback(job_id: str, stage: str, message: str):
            print(f"    [{stage.upper()}] {message}")

        orchestrator = PipelineOrchestrator(session=session, job_id=job.id, log_callback=log_callback)
        await orchestrator.run()

        # Reload job for summary
        await session.refresh(job)
        print("\n" + "=" * 60)
        print(f"[+] Scan {job.id} Completed!")
        print(f"    Reports generated:")
        if job.report_pdf_path:
            print(f"    - PDF:      {job.report_pdf_path}")
        if job.report_md_path:
            print(f"    - Markdown: {job.report_md_path}")
        if job.report_json_path:
            print(f"    - JSON:     {job.report_json_path}")
        print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelVAPT — Production-Grade AI Penetration Testing Framework"
    )
    parser.add_argument("--server", action="store_true", help="Start FastAPI Web API server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Server host binding")
    parser.add_argument("--port", type=int, default=8000, help="Server port binding")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn auto-reload")
    parser.add_argument("--check-tools", action="store_true", help="Check status of all security tools")
    parser.add_argument("--check-privs", action="store_true", help="Check privilege level and root/admin status")
    parser.add_argument("--check-apis", action="store_true", help="Check external API health and free-tier status")
    parser.add_argument("--install-tools", action="store_true", help="Automatically install missing tools")
    parser.add_argument("--scan", type=str, help="Target for headless CLI scan")
    parser.add_argument("--scope", type=str, default="web", choices=["web", "api", "network"], help="Scan scope")
    parser.add_argument("--exploit", action="store_true", help="Authorize safe verification (must be allowlisted)")

    args = parser.parse_args()

    # Always show privilege status at startup
    priv_mgr = get_privilege_manager()
    status = priv_mgr.detect()
    level_tag = "ROOT" if status.level.value == "root" else "USER"
    print(f"\n[SentinelVAPT] Running as: {status.username} ({level_tag}) on {status.os_type}")
    if status.warnings:
        for w in status.warnings:
            print(f"  ⚠ {w}")

    if args.check_tools:
        check_tools()
    elif args.check_privs:
        check_privileges()
    elif args.check_apis:
        check_apis()
    elif args.install_tools:
        install_tools()
    elif args.scan:
        asyncio.run(run_headless_scan(args.scan, args.scope, args.exploit))
    else:
        # Default action is running the server
        run_server(host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
