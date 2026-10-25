"""
SentinelVAPT — FastAPI Application Entrypoint
Integrates CORS, database lifespan, route registration, and static report serving.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes.defensive import router as defensive_router
from backend.api.routes.findings import router as findings_router
from backend.api.routes.reports import router as reports_router
from backend.api.routes.scans import router as scans_router
from backend.api.routes.system import router as system_router
from backend.api.routes.tools import router as tools_router
from backend.config.settings import get_settings
from backend.db.session import init_db

logger = logging.getLogger("sentinelvapt.api")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing SentinelVAPT database...")
    try:
        await init_db()
        logger.info("SentinelVAPT database ready.")
    except Exception as e:
        logger.error("Failed to initialize database: %s", e, exc_info=True)

    # Ensure reports dir exists
    settings.reports_path.mkdir(parents=True, exist_ok=True)
    yield
    # Shutdown actions
    logger.info("SentinelVAPT server shutting down.")


app = FastAPI(
    title="SentinelVAPT API",
    description=(
        "Production-Grade AI-Powered Vulnerability Assessment & Penetration Testing Automation Framework. "
        "Strictly for authorized security testing on consented lab environments."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount reports directory as static file path
reports_dir = settings.reports_path
reports_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static/reports", StaticFiles(directory=str(reports_dir)), name="reports")

# Register API Routers
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(defensive_router)
app.include_router(reports_router)
app.include_router(tools_router)
app.include_router(system_router)


# Mount built frontend dist if available
frontend_dist = settings.project_root / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "framework": "SentinelVAPT",
            "version": "1.0.0",
            "status": "ready",
            "docs_url": "/docs",
            "redoc_url": "/redoc",
        }

