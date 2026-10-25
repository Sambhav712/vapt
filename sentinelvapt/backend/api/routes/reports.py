"""
SentinelVAPT — Reports API Router
Serves audit-ready PDF, JSON, and Markdown reports and handles on-demand regeneration.
"""

import logging
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Finding, Job, ToolOutput
from backend.db.session import get_async_session
from backend.reporting.report_builder import ReportBuilder

logger = logging.getLogger("sentinelvapt.api.reports")
router = APIRouter(prefix="/api/scans", tags=["Reports"])


@router.get(
    "/{job_id}/reports",
    response_model=Dict[str, Any],
    summary="Get status and URLs of generated reports for a scan",
)
async def get_report_info(
    job_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job UUID")

    result = await session.execute(select(Job).where(Job.id == jid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    def exists(path_str):
        return bool(path_str and Path(path_str).exists())

    return {
        "job_id": job_id,
        "available_formats": {
            "pdf": exists(job.report_pdf_path),
            "json": exists(job.report_json_path),
            "markdown": exists(job.report_md_path),
        },
        "downloads": {
            "pdf": f"/api/scans/{job_id}/reports/download/pdf",
            "json": f"/api/scans/{job_id}/reports/download/json",
            "markdown": f"/api/scans/{job_id}/reports/download/markdown",
        },
    }


@router.get(
    "/{job_id}/reports/download/{fmt}",
    summary="Download report in specified format: pdf | json | markdown",
)
async def download_report(
    job_id: str,
    fmt: str,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job UUID")

    fmt_clean = fmt.lower().strip()
    if fmt_clean not in ("pdf", "json", "markdown", "md"):
        raise HTTPException(
            status_code=400, detail="Format must be pdf, json, or markdown"
        )

    result = await session.execute(select(Job).where(Job.id == jid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    target_path = None
    media_type = "application/octet-stream"
    ext = fmt_clean

    if fmt_clean == "pdf":
        target_path = job.report_pdf_path
        media_type = "application/pdf"
        ext = "pdf"
    elif fmt_clean == "json":
        target_path = job.report_json_path
        media_type = "application/json"
        ext = "json"
    elif fmt_clean in ("markdown", "md"):
        target_path = job.report_md_path
        media_type = "text/markdown"
        ext = "md"

    if not target_path or not Path(target_path).exists():
        # Attempt on-the-fly generation if not yet generated
        builder = ReportBuilder()
        f_res = await session.execute(
            select(Finding).where(
                Finding.job_id == jid, Finding.is_false_positive == False
            )
        )
        findings = f_res.scalars().all()
        t_res = await session.execute(
            select(ToolOutput).where(ToolOutput.job_id == jid)
        )
        tools = t_res.scalars().all()

        paths = await builder.generate_all(job, findings, tools)
        job.report_pdf_path = paths.get("pdf")
        job.report_json_path = paths.get("json")
        job.report_md_path = paths.get("markdown")
        await session.commit()

        target_path = paths.get(
            "markdown" if fmt_clean in ("markdown", "md") else fmt_clean
        )

    if not target_path or not Path(target_path).exists():
        raise HTTPException(
            status_code=404,
            detail=f"Report file for format '{fmt_clean}' is not available",
        )

    safe_target = (
        job.target.replace("http://", "")
        .replace("https://", "")
        .replace(":", "_")
        .replace("/", "_")
    )
    filename = f"SentinelVAPT_{safe_target}_{job_id[:8]}.{ext}"

    return FileResponse(
        path=target_path,
        media_type=media_type,
        filename=filename,
    )
