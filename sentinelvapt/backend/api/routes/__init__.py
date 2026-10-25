from backend.api.routes.scans import router as scans_router
from backend.api.routes.findings import router as findings_router
from backend.api.routes.defensive import router as defensive_router
from backend.api.routes.reports import router as reports_router
from backend.api.routes.tools import router as tools_router
from backend.api.routes.system import router as system_router

__all__ = [
    "scans_router",
    "findings_router",
    "defensive_router",
    "reports_router",
    "tools_router",
    "system_router",
]
