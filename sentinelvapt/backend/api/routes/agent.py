"""
SentinelVAPT — Agent API Router
Handles launching, monitoring, and managing autonomous AI agent sessions.
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
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.core.agent_core import AgentCore
from backend.db.models import Job, AgentSession, AgentStepLog, Finding, Severity, Confidence
from backend.db.session import AsyncSessionLocal, get_async_session

logger = logging.getLogger("sentinelvapt.api.agent")
router = APIRouter(prefix="/api/agent", tags=["Agent"])

# Active agent instances: session_id -> AgentCore
_active_agents: Dict[str, AgentCore] = {}
# Active asyncio tasks: session_id -> asyncio.Task
_agent_tasks: Dict[str, asyncio.Task] = {}
# SSE queues: session_id -> list of asyncio.Queue
_agent_log_queues: Dict[str, List[asyncio.Queue]] = {}


# ── Request / Response Models ─────────────────────────────────

class LaunchAgentRequest(BaseModel):
    target: str = Field(..., description="Target IP, hostname, or URL")
    scope_type: str = Field(default="web", description="Scope: web | api | network")
    authorized_exploitation: bool = Field(default=False, description="Enable Tier 3 exploitation tools")
    goal: Optional[str] = Field(default=None, description="Custom assessment goal/objective")
    max_steps: int = Field(default=50, ge=5, le=200, description="Maximum agent steps")
    max_time_seconds: int = Field(default=2400, ge=60, le=7200, description="Maximum session time in seconds")
    job_id: Optional[str] = Field(default=None, description="Link to an existing scan job (optional)")


class AgentSessionSummary(BaseModel):
    session_id: str
    job_id: str
    target: str
    scope_type: str
    status: str
    step_count: int
    finding_count: int
    commands_executed: int
    commands_blocked: int
    started_at: str
    completed_at: Optional[str] = None


# ── Helper Functions ──────────────────────────────────────────

async def _broadcast_agent_log(session_id: str, stage: str, message: str):
    """Deliver a log event to all connected SSE clients for this agent session."""
    queues = _agent_log_queues.get(session_id, [])
    event_data = {
        "session_id": session_id,
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


async def _persist_agent_results(agent: AgentCore):
    """Persist agent session results and findings to the database."""
    state = agent.state
    async with AsyncSessionLocal() as session:
        try:
            # Create or update AgentSession record
            agent_session = AgentSession(
                session_id=state.session_id,
                job_id=uuid.UUID(state.job_id),
                target=state.target,
                scope_type=state.scope_type,
                authorized_exploitation=state.authorized_exploitation,
                goal=state.goal,
                status=state.status,
                final_summary=state.final_summary,
                step_count=len(state.steps),
                finding_count=len(state.findings),
                total_commands_executed=state.total_commands_executed,
                total_commands_blocked=state.total_commands_blocked,
                total_llm_calls=state.total_llm_calls,
                total_llm_latency=state.total_llm_latency,
                installed_tools=state.installed_tools,
                findings_data=[f.to_dict() for f in state.findings],
                completed_at=datetime.fromtimestamp(state.completed_at, tz=timezone.utc) if state.completed_at else None,
            )
            session.add(agent_session)
            await session.flush()

            # Persist step logs
            for step in state.steps:
                step_log = AgentStepLog(
                    session_id=agent_session.id,
                    step_number=step.step_number,
                    thought=step.thought,
                    action=step.action,
                    command=step.command,
                    tool_name=step.tool_name,
                    confidence=step.confidence,
                    result_exit_code=step.result_exit_code,
                    result_stdout=(step.result_stdout[:50000] if step.result_stdout else None),
                    result_stderr=(step.result_stderr[:10000] if step.result_stderr else None),
                    result_success=step.result_success,
                    result_blocked=step.result_blocked,
                    result_block_reason=step.result_block_reason or None,
                    result_duration=step.result_duration,
                    result_message=step.result_message or None,
                    finding_data=step.finding.to_dict() if step.finding else None,
                    llm_latency=step.llm_latency,
                )
                session.add(step_log)

            # Also persist findings to the main Finding table for the job
            for finding in state.findings:
                sev = finding.severity.lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "info"

                job_finding = Finding(
                    job_id=uuid.UUID(state.job_id),
                    title=finding.title,
                    description=finding.description,
                    severity=Severity(sev),
                    confidence=Confidence.HIGH if finding.verified else Confidence.MEDIUM,
                    cvss_score=finding.cvss_score,
                    cve_ids=finding.cve_ids,
                    cwe_ids=finding.cwe_ids,
                    affected_asset=finding.affected_asset,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                    source_tool="agent_core",
                )
                session.add(job_finding)

            await session.commit()
            logger.info("Agent session %s persisted: %d steps, %d findings",
                        state.session_id, len(state.steps), len(state.findings))

        except Exception as e:
            logger.error("Failed to persist agent session: %s", e, exc_info=True)
            await session.rollback()


async def _run_agent_background(agent: AgentCore):
    """Background task that runs the agent and persists results on completion."""
    session_id = agent.session_id
    try:
        await agent.run()
    except Exception as e:
        logger.error("Agent background error [%s]: %s", session_id, e, exc_info=True)
        await _broadcast_agent_log(session_id, "error", f"Agent failed: {e}")
    finally:
        # Persist results
        await _persist_agent_results(agent)
        # Cleanup
        _active_agents.pop(session_id, None)
        _agent_tasks.pop(session_id, None)
        # Signal completion
        await _broadcast_agent_log(session_id, "done", "Agent session completed")


# ── API Endpoints ─────────────────────────────────────────────

@router.post(
    "/launch",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Launch an autonomous AI agent session",
)
async def launch_agent(
    payload: LaunchAgentRequest,
    db: AsyncSession = Depends(get_async_session),
):
    """
    Launch an autonomous AI agent that directly controls the terminal
    to assess the target's security posture using the ReAct pattern.
    """
    settings = get_settings()
    target = payload.target.strip()

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    # Safety validation for exploitation
    if payload.authorized_exploitation:
        import socket
        from urllib.parse import urlparse

        host = (
            urlparse(target).hostname
            if "://" in target
            else target.split(":")[0].split("/")[0]
        )
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception:
            resolved_ip = host

        if not settings.is_target_allowlisted(resolved_ip):
            raise HTTPException(
                status_code=403,
                detail=f"Exploitation denied: Target '{resolved_ip}' is not in the EXPLOIT_ALLOWLIST",
            )

    # Create or link a Job
    if payload.job_id:
        try:
            job_id = uuid.UUID(payload.job_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid job_id UUID format")

        result = await db.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
    else:
        from backend.db.models import ScopeType, PipelineStage, StageStatus
        job = Job(
            target=target,
            scope_type=ScopeType(payload.scope_type) if payload.scope_type in ("web", "api", "network") else ScopeType.WEB,
            authorized_exploitation=payload.authorized_exploitation,
            ai_orchestration_mode="agent_core",
            current_stage=PipelineStage.AI_ORCHESTRATION,
            stage_statuses={PipelineStage.AI_ORCHESTRATION.value: StageStatus.RUNNING.value},
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = job.id

    # Create the agent
    agent = AgentCore(
        job_id=str(job_id),
        target=target,
        scope_type=payload.scope_type,
        authorized_exploitation=payload.authorized_exploitation,
        goal=payload.goal,
        max_steps=payload.max_steps,
        max_time_seconds=payload.max_time_seconds,
        log_callback=_broadcast_agent_log,
    )

    session_id = agent.session_id
    _active_agents[session_id] = agent

    # Launch in background
    task = asyncio.create_task(_run_agent_background(agent))
    _agent_tasks[session_id] = task

    return {
        "message": "Agent session launched",
        "session_id": session_id,
        "job_id": str(job_id),
        "target": target,
        "scope_type": payload.scope_type,
        "goal": agent.state.goal,
        "max_steps": payload.max_steps,
        "max_time_seconds": payload.max_time_seconds,
    }


@router.get(
    "/sessions",
    response_model=List[Dict[str, Any]],
    summary="List all agent sessions (active and historical)",
)
async def list_agent_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_async_session),
):
    """List all agent sessions with summary metrics."""
    # Active sessions
    active = []
    for sid, agent in _active_agents.items():
        active.append({
            "session_id": sid,
            "job_id": agent.state.job_id,
            "target": agent.state.target,
            "scope_type": agent.state.scope_type,
            "status": agent.state.status,
            "step_count": len(agent.state.steps),
            "finding_count": len(agent.state.findings),
            "commands_executed": agent.state.total_commands_executed,
            "commands_blocked": agent.state.total_commands_blocked,
            "elapsed_seconds": round(agent.state.started_at and (
                __import__('time').time() - agent.state.started_at) or 0, 1),
            "is_active": True,
        })

    # Historical sessions from DB
    result = await db.execute(
        select(AgentSession).order_by(desc(AgentSession.created_at)).limit(limit)
    )
    historical = result.scalars().all()
    for s in historical:
        # Skip if already in active list
        if s.session_id in _active_agents:
            continue
        active.append({
            "session_id": s.session_id,
            "job_id": str(s.job_id),
            "target": s.target,
            "scope_type": s.scope_type,
            "status": s.status,
            "step_count": s.step_count or 0,
            "finding_count": s.finding_count or 0,
            "commands_executed": s.total_commands_executed or 0,
            "commands_blocked": s.total_commands_blocked or 0,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "is_active": False,
        })

    return active


@router.get(
    "/{session_id}",
    response_model=Dict[str, Any],
    summary="Get detailed information about an agent session",
)
async def get_agent_session(
    session_id: str,
    db: AsyncSession = Depends(get_async_session),
):
    """Get full details of an agent session including steps and findings."""
    # Check active sessions first
    if session_id in _active_agents:
        return _active_agents[session_id].state.to_dict()

    # Fall back to DB
    result = await db.execute(
        select(AgentSession).where(AgentSession.session_id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if not agent_session:
        raise HTTPException(status_code=404, detail="Agent session not found")

    # Load steps
    steps_result = await db.execute(
        select(AgentStepLog)
        .where(AgentStepLog.session_id == agent_session.id)
        .order_by(AgentStepLog.step_number.asc())
    )
    steps = steps_result.scalars().all()

    return {
        "session_id": agent_session.session_id,
        "job_id": str(agent_session.job_id),
        "target": agent_session.target,
        "scope_type": agent_session.scope_type,
        "authorized_exploitation": agent_session.authorized_exploitation,
        "goal": agent_session.goal,
        "status": agent_session.status,
        "final_summary": agent_session.final_summary,
        "step_count": agent_session.step_count,
        "finding_count": agent_session.finding_count,
        "installed_tools": agent_session.installed_tools or [],
        "findings": agent_session.findings_data or [],
        "metrics": {
            "total_commands_executed": agent_session.total_commands_executed,
            "total_commands_blocked": agent_session.total_commands_blocked,
            "total_llm_calls": agent_session.total_llm_calls,
            "total_llm_latency": agent_session.total_llm_latency,
        },
        "started_at": agent_session.started_at.isoformat() if agent_session.started_at else None,
        "completed_at": agent_session.completed_at.isoformat() if agent_session.completed_at else None,
        "steps": [
            {
                "step_number": s.step_number,
                "thought": s.thought,
                "action": s.action,
                "command": s.command,
                "tool_name": s.tool_name,
                "confidence": s.confidence,
                "result_exit_code": s.result_exit_code,
                "result_stdout": s.result_stdout[:3000] if s.result_stdout else None,
                "result_stderr": s.result_stderr[:1000] if s.result_stderr else None,
                "result_success": s.result_success,
                "result_blocked": s.result_blocked,
                "result_block_reason": s.result_block_reason,
                "result_duration": s.result_duration,
                "result_message": s.result_message,
                "finding_data": s.finding_data,
                "llm_latency": s.llm_latency,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in steps
        ],
    }


@router.get(
    "/{session_id}/steps",
    summary="Get paginated step log for an agent session",
)
async def get_agent_steps(
    session_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_async_session),
):
    """Get paginated step log for an agent session."""
    # Check active sessions first
    if session_id in _active_agents:
        steps = _active_agents[session_id].state.steps
        page = steps[offset:offset + limit]
        return {
            "total": len(steps),
            "offset": offset,
            "limit": limit,
            "steps": [s.to_dict() for s in page],
        }

    # Fall back to DB
    result = await db.execute(
        select(AgentSession).where(AgentSession.session_id == session_id)
    )
    agent_session = result.scalar_one_or_none()
    if not agent_session:
        raise HTTPException(status_code=404, detail="Agent session not found")

    steps_result = await db.execute(
        select(AgentStepLog)
        .where(AgentStepLog.session_id == agent_session.id)
        .order_by(AgentStepLog.step_number.asc())
        .offset(offset)
        .limit(limit)
    )
    steps = steps_result.scalars().all()

    return {
        "total": agent_session.step_count or 0,
        "offset": offset,
        "limit": limit,
        "steps": [
            {
                "step_number": s.step_number,
                "thought": s.thought,
                "action": s.action,
                "command": s.command,
                "result_exit_code": s.result_exit_code,
                "result_success": s.result_success,
                "result_blocked": s.result_blocked,
                "result_duration": s.result_duration,
                "result_message": s.result_message,
                "finding_data": s.finding_data,
                "llm_latency": s.llm_latency,
            }
            for s in steps
        ],
    }


@router.post(
    "/{session_id}/cancel",
    summary="Cancel a running agent session",
)
async def cancel_agent_session(session_id: str):
    """Cancel an active agent session."""
    agent = _active_agents.get(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No active agent session with that ID")

    agent.cancel()

    task = _agent_tasks.get(session_id)
    if task and not task.done():
        task.cancel()

    _active_agents.pop(session_id, None)
    _agent_tasks.pop(session_id, None)

    await _broadcast_agent_log(session_id, "system", "Agent session cancelled by user")
    return {"message": f"Agent session {session_id} cancelled"}


@router.get(
    "/{session_id}/stream",
    summary="Real-time SSE log stream for agent session",
)
async def stream_agent_events(session_id: str):
    """Subscribe to live agent log events via Server-Sent Events."""
    queue: asyncio.Queue = asyncio.Queue()
    if session_id not in _agent_log_queues:
        _agent_log_queues[session_id] = []
    _agent_log_queues[session_id].append(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        yield f"data: {json.dumps({'session_id': session_id, 'stage': 'stream', 'msg': 'Connected to agent live stream'})}\n\n"
        try:
            while True:
                msg = await queue.get()
                yield msg
        except asyncio.CancelledError:
            pass
        finally:
            if session_id in _agent_log_queues and queue in _agent_log_queues[session_id]:
                _agent_log_queues[session_id].remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/{session_id}/stats",
    summary="Get real-time statistics for an active agent session",
)
async def get_agent_stats(session_id: str):
    """Get real-time statistics for a running agent."""
    agent = _active_agents.get(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No active agent session with that ID")
    return agent.stats
