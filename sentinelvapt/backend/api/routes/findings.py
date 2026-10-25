"""
SentinelVAPT — Findings API Router
Provides comprehensive vulnerability finding exploration, AI analysis results, and triaging.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.db.models import DefensiveRule, Finding, Severity
from backend.db.session import get_async_session

logger = logging.getLogger("sentinelvapt.api.findings")
router = APIRouter(prefix="/api", tags=["Findings"])


class FindingUpdate(BaseModel):
    is_false_positive: Optional[bool] = None
    remediation: Optional[str] = None
    ai_reasoning: Optional[str] = None


@router.get(
    "/scans/{job_id}/findings",
    response_model=List[Dict[str, Any]],
    summary="List all findings for a scan job with optional filtering",
)
async def list_findings(
    job_id: str,
    severity: Optional[str] = Query(
        default=None, description="Filter by severity: critical|high|medium|low|info"
    ),
    source_tool: Optional[str] = Query(
        default=None, description="Filter by source tool (nmap, nuclei, zap, etc.)"
    ),
    include_false_positives: bool = Query(
        default=False, description="Whether to include false positives"
    ),
    session: AsyncSession = Depends(get_async_session),
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job UUID")

    query = select(Finding).where(Finding.job_id == jid)

    if not include_false_positives:
        query = query.where(Finding.is_false_positive == False)

    if severity:
        try:
            sev_enum = Severity(severity.lower())
            query = query.where(Finding.severity == sev_enum)
        except ValueError:
            pass

    if source_tool:
        query = query.where(Finding.source_tool == source_tool)

    result = await session.execute(query)
    findings = result.scalars().all()

    # Sort in python by severity rank
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_rank.get(
            (
                f.severity.value
                if hasattr(f.severity, "value")
                else str(f.severity)
            ).lower(),
            9,
        ),
    )

    out = []
    for f in sorted_findings:
        out.append(
            {
                "id": str(f.id),
                "job_id": str(f.job_id),
                "title": f.title,
                "description": f.description,
                "severity": (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                ),
                "confidence": (
                    f.confidence.value
                    if hasattr(f.confidence, "value")
                    else str(f.confidence)
                ),
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cve_ids": f.cve_ids or [],
                "cwe_ids": f.cwe_ids or [],
                "affected_asset": f.affected_asset,
                "affected_component": f.affected_component,
                "source_tool": f.source_tool,
                "is_false_positive": f.is_false_positive,
                "ai_reasoning": f.ai_reasoning,
                "attack_chain": f.attack_chain,
                "mitre_tactic": f.mitre_tactic,
                "mitre_technique_id": f.mitre_technique_id,
                "mitre_technique_name": f.mitre_technique_name,
                "remediation": f.remediation,
                "created_at": (
                    f.created_at.isoformat() if f.created_at else None
                ),
            }
        )

    return out


@router.get(
    "/findings/{finding_id}",
    response_model=Dict[str, Any],
    summary="Get full technical details of a single finding",
)
async def get_finding(
    finding_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding UUID")

    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.defensive_rules))
        .where(Finding.id == fid)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    rules_out = []
    for r in finding.defensive_rules or []:
        rules_out.append(
            {
                "id": str(r.id),
                "sigma_rule": r.sigma_rule,
                "sigma_valid": r.sigma_valid,
                "wazuh_rule": r.wazuh_rule,
                "suricata_rule": r.suricata_rule,
                "firewall_rule": r.firewall_rule,
            }
        )

    return {
        "id": str(finding.id),
        "job_id": str(finding.job_id),
        "title": finding.title,
        "description": finding.description,
        "severity": (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        ),
        "confidence": (
            finding.confidence.value
            if hasattr(finding.confidence, "value")
            else str(finding.confidence)
        ),
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cve_ids": finding.cve_ids or [],
        "cwe_ids": finding.cwe_ids or [],
        "affected_asset": finding.affected_asset,
        "affected_component": finding.affected_component,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "source_tool": finding.source_tool,
        "is_false_positive": finding.is_false_positive,
        "ai_reasoning": finding.ai_reasoning,
        "attack_chain": finding.attack_chain,
        "mitre_tactic": finding.mitre_tactic,
        "mitre_technique_id": finding.mitre_technique_id,
        "mitre_technique_name": finding.mitre_technique_name,
        "raw_data": finding.raw_data,
        "created_at": (
            finding.created_at.isoformat() if finding.created_at else None
        ),
        "defensive_rules": rules_out,
    }


@router.patch(
    "/findings/{finding_id}",
    summary="Update finding status (e.g. mark as false positive)",
)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding UUID")

    result = await session.execute(select(Finding).where(Finding.id == fid))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.is_false_positive is not None:
        finding.is_false_positive = payload.is_false_positive
    if payload.remediation is not None:
        finding.remediation = payload.remediation
    if payload.ai_reasoning is not None:
        finding.ai_reasoning = payload.ai_reasoning

    await session.commit()
    return {
        "message": "Finding updated",
        "id": str(finding.id),
        "is_false_positive": finding.is_false_positive,
    }
