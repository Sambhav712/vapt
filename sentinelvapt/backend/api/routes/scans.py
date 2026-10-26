"""
SentinelVAPT — Scans API Router
Handles scan creation, execution lifecycle, real-time log streaming (SSE), and management.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.core.orchestrator import PipelineOrchestrator
from backend.db.models import (
    Finding,
    Job,
    AIDecisionLog,
    PipelineStage,
    ScopeType,
    StageStatus,
)
from backend.db.session import AsyncSessionLocal, get_async_session

logger = logging.getLogger("sentinelvapt.api.scans")
router = APIRouter(prefix="/api/scans", tags=["Scans"])

# Active SSE listeners: job_id -> list of asyncio.Queue
_log_queues: Dict[str, List[asyncio.Queue]] = {}
# Active running pipeline tasks: job_id -> asyncio.Task
_running_tasks: Dict[str, asyncio.Task] = {}


class CreateScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="Target IP, hostname, or URL (e.g. 192.168.1.50 or http://10.0.0.5:3000)",
    )
    scope_type: ScopeType = Field(
        default=ScopeType.WEB, description="Scope type: web | api | network"
    )
    authorized_exploitation: bool = Field(
        default=False,
        description="Enable safe authorized verification (requires target to be in allowlist)",
    )
    max_iterations: Optional[int] = Field(
        default=20,
        description="Maximum AI decision iterations for tool discovery",
    )
    enabled_tools: Optional[List[str]] = Field(
        default=None,
        description="Optional list of specific tool names to explicitly enable for this scan",
    )
    disabled_tools: Optional[List[str]] = Field(
        default=None,
        description="Optional list of specific tool names to explicitly disable for this scan",
    )


class ScanSummary(BaseModel):
    id: str
    target: str
    scope_type: str
    authorized_exploitation: bool
    current_stage: str
    stage_statuses: Dict[str, str]
    created_at: str
    completed_at: Optional[str] = None
    finding_counts: Dict[str, int]
    has_pdf_report: bool
    has_json_report: bool
    has_md_report: bool


async def _broadcast_log(job_id: str, stage: str, message: str):
    """Deliver a log event to all connected SSE clients for this job."""
    queues = _log_queues.get(job_id, [])
    event_data = {
        "job_id": job_id,
        "stage": stage,
        "msg": message,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    payload = f"data: {json.dumps(event_data)}\n\n"
    for q in list(queues):
        try:
            q.put_nowait(payload)
        except Exception:
            pass


async def _run_scan_background(job_id: uuid.UUID):
    """Background task driving the pipeline orchestrator."""
    job_id_str = str(job_id)
    async with AsyncSessionLocal() as session:
        try:

            async def log_cb(jid: str, stage: str, msg: str):
                await _broadcast_log(jid, stage, msg)

            orchestrator = PipelineOrchestrator(
                session=session, job_id=job_id, log_callback=log_cb
            )
            await orchestrator.run()
        except Exception as e:
            logger.error(
                "Background scan error on job %s: %s",
                job_id_str,
                e,
                exc_info=True,
            )
            await _broadcast_log(job_id_str, "error", f"Pipeline failed: {e}")
        finally:
            _running_tasks.pop(job_id_str, None)
            # Signal end of stream
            await _broadcast_log(job_id_str, "done", "Scan lifecycle completed")


@router.post(
    "",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Create and start a new scan job",
)
async def create_scan(
    payload: CreateScanRequest,
    session: AsyncSession = Depends(get_async_session),
):
    settings = get_settings()
    target_clean = payload.target.strip()

    if not target_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target cannot be empty",
        )

    # Safety validation: if authorized exploitation is requested, target must be allowlisted
    if payload.authorized_exploitation:
        # Extract IP or hostname
        import socket
        from urllib.parse import urlparse

        host = (
            urlparse(target_clean).hostname
            if "://" in target_clean
            else target_clean.split(":")[0].split("/")[0]
        )
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception:
            resolved_ip = host

        if not settings.is_target_allowlisted(resolved_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Exploitation denied: Target '{resolved_ip}' is not in the authorized EXPLOIT_ALLOWLIST "
                    f"({settings.exploit_allowlist}). Exploitation is restricted to lab / consented targets only."
                ),
            )

    job = Job(
        target=target_clean,
        scope_type=payload.scope_type,
        authorized_exploitation=payload.authorized_exploitation,
        max_iterations=payload.max_iterations or 20,
        ai_orchestration_mode="ai_driven",
        current_iteration=0,
        enabled_tools=payload.enabled_tools or [],
        disabled_tools=payload.disabled_tools or [],
        current_stage=PipelineStage.TOOL_CHECK,
        stage_statuses={
            PipelineStage.TOOL_CHECK.value: StageStatus.PENDING.value
        },
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    # Launch pipeline in background task
    task = asyncio.create_task(_run_scan_background(job.id))
    _running_tasks[str(job.id)] = task

    return {
        "message": "Scan job initialized and pipeline launched",
        "job_id": str(job.id),
        "target": job.target,
        "scope_type": job.scope_type.value,
        "authorized_exploitation": job.authorized_exploitation,
        "created_at": (
            job.created_at.isoformat() if job.created_at else None
        ),
    }


@router.get(
    "",
    response_model=List[ScanSummary],
    summary="List all scan jobs with summary metrics",
)
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(get_async_session),
):
    result = await session.execute(
        select(Job).order_by(desc(Job.created_at)).limit(limit)
    )
    jobs = result.scalars().all()

    summaries = []
    for j in jobs:
        # Count findings by severity
        f_res = await session.execute(
            select(Finding.severity).where(Finding.job_id == j.id)
        )
        sevs = f_res.scalars().all()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for s in sevs:
            val = s.value if hasattr(s, "value") else str(s).lower()
            if val in counts:
                counts[val] += 1
            else:
                counts["info"] += 1

        summaries.append(
            ScanSummary(
                id=str(j.id),
                target=j.target,
                scope_type=(
                    j.scope_type.value
                    if hasattr(j.scope_type, "value")
                    else str(j.scope_type)
                ),
                authorized_exploitation=j.authorized_exploitation or False,
                current_stage=(
                    j.current_stage.value
                    if hasattr(j.current_stage, "value")
                    else str(j.current_stage)
                ),
                stage_statuses=j.stage_statuses or {},
                created_at=(
                    j.created_at.isoformat()
                    if j.created_at
                    else datetime.now(timezone.utc).isoformat()
                ),
                completed_at=(
                    j.completed_at.isoformat() if j.completed_at else None
                ),
                finding_counts=counts,
                has_pdf_report=bool(j.report_pdf_path),
                has_json_report=bool(j.report_json_path),
                has_md_report=bool(j.report_md_path),
            )
        )

    return summaries


@router.get(
    "/{job_id}",
    response_model=Dict[str, Any],
    summary="Get detailed information about a specific scan job",
)
async def get_scan(
    job_id: str, session: AsyncSession = Depends(get_async_session)
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    result = await session.execute(select(Job).where(Job.id == jid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Counts
    f_res = await session.execute(
        select(Finding.severity).where(Finding.job_id == jid)
    )
    sevs = f_res.scalars().all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in sevs:
        val = s.value if hasattr(s, "value") else str(s).lower()
        if val in counts:
            counts[val] += 1
        else:
            counts["info"] += 1

    return {
        "id": str(job.id),
        "target": job.target,
        "scope_type": (
            job.scope_type.value
            if hasattr(job.scope_type, "value")
            else str(job.scope_type)
        ),
        "authorized_exploitation": job.authorized_exploitation,
        "current_stage": (
            job.current_stage.value
            if hasattr(job.current_stage, "value")
            else str(job.current_stage)
        ),
        "stage_statuses": job.stage_statuses or {},
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
        "completed_at": (
            job.completed_at.isoformat() if job.completed_at else None
        ),
        "executive_summary": job.executive_summary,
        "logs": job.logs or [],
        "finding_counts": counts,
        "is_running": str(job.id) in _running_tasks,
        "ai_orchestration_mode": getattr(job, "ai_orchestration_mode", "ai_driven") or "ai_driven",
        "current_iteration": getattr(job, "current_iteration", 0) or 0,
        "max_iterations": getattr(job, "max_iterations", 20) or 20,
        "reports": {
            "pdf": bool(job.report_pdf_path),
            "json": bool(job.report_json_path),
            "markdown": bool(job.report_md_path),
        },
    }


@router.get(
    "/{job_id}/ai-decisions",
    summary="Get all AI decision records and live reasoning timeline for a scan job",
)
async def get_ai_decisions(
    job_id: str, session: AsyncSession = Depends(get_async_session)
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    result = await session.execute(
        select(AIDecisionLog)
        .where(AIDecisionLog.job_id == jid)
        .order_by(AIDecisionLog.iteration.asc())
    )
    decisions = result.scalars().all()
    return [
        {
            "id": str(d.id),
            "iteration": d.iteration,
            "chosen_tool": d.chosen_tool,
            "action": d.action,
            "reasoning": d.reasoning,
            "expected_outcome": d.expected_outcome,
            "confidence": d.confidence,
            "tool_args": d.tool_args or {},
            "tool_execution_result": d.tool_execution_result or {},
            "prompt_tokens": d.prompt_tokens,
            "completion_tokens": d.completion_tokens,
            "latency": d.latency,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        }
        for d in decisions
    ]


@router.delete(
    "/{job_id}",
    summary="Delete a scan job and associated records",
)
async def delete_scan(
    job_id: str, session: AsyncSession = Depends(get_async_session)
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Cancel if running
    task = _running_tasks.pop(str(jid), None)
    if task and not task.done():
        task.cancel()

    result = await session.execute(select(Job).where(Job.id == jid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    await session.delete(job)
    await session.commit()
    return {"message": f"Job {job_id} deleted successfully"}


@router.post(
    "/{job_id}/cancel",
    summary="Cancel a currently running scan",
)
async def cancel_scan(
    job_id: str, session: AsyncSession = Depends(get_async_session)
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    task = _running_tasks.get(str(jid))
    if not task or task.done():
        return {"message": "Job is not actively running"}

    task.cancel()
    _running_tasks.pop(str(jid), None)

    result = await session.execute(select(Job).where(Job.id == jid))
    job = result.scalar_one_or_none()
    if job:
        job.current_stage = PipelineStage.FAILED
        job.add_log("system", "Scan cancelled by user request")
        await session.commit()

    await _broadcast_log(str(jid), "system", "Scan cancelled by user")
    return {"message": f"Scan {job_id} cancelled"}


@router.get(
    "/{job_id}/stream",
    summary="Real-time Server-Sent Events (SSE) log stream for scan progression",
)
async def stream_scan_events(job_id: str):
    """
    Subscribes the client to live log events and stage updates via SSE.
    """
    queue: asyncio.Queue = asyncio.Queue()
    if job_id not in _log_queues:
        _log_queues[job_id] = []
    _log_queues[job_id].append(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        # Initial greeting event
        yield f"data: {json.dumps({'job_id': job_id, 'stage': 'stream', 'msg': 'Connected to live scan stream'})}\n\n"
        try:
            while True:
                msg = await queue.get()
                yield msg
        except asyncio.CancelledError:
            pass
        finally:
            if job_id in _log_queues and queue in _log_queues[job_id]:
                _log_queues[job_id].remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
