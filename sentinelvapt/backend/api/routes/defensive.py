"""
SentinelVAPT — Defensive & Purple Team API Router
Serves auto-generated Sigma rules, Wazuh detection XML, Suricata signatures, and firewall rules.
"""

import io
import logging
import uuid
import zipfile
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.db.models import DefensiveRule, Finding
from backend.db.session import get_async_session

logger = logging.getLogger("sentinelvapt.api.defensive")
router = APIRouter(prefix="/api", tags=["Defensive Rules"])


@router.get(
    "/scans/{job_id}/defensive-rules",
    response_model=List[Dict[str, Any]],
    summary="List all defensive detection rules generated for a scan",
)
async def list_defensive_rules(
    job_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job UUID")

    result = await session.execute(
        select(DefensiveRule)
        .options(selectinload(DefensiveRule.finding))
        .where(DefensiveRule.job_id == jid)
    )
    rules = result.scalars().all()

    out = []
    for r in rules:
        finding_title = r.finding.title if r.finding else "General Vulnerability"
        finding_sev = (
            r.finding.severity.value
            if r.finding and hasattr(r.finding.severity, "value")
            else "info"
        )

        out.append(
            {
                "id": str(r.id),
                "finding_id": str(r.finding_id),
                "finding_title": finding_title,
                "finding_severity": finding_sev,
                "sigma_rule": r.sigma_rule,
                "sigma_valid": r.sigma_valid,
                "wazuh_rule": r.wazuh_rule,
                "suricata_rule": r.suricata_rule,
                "firewall_rule": r.firewall_rule,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique_id": r.mitre_technique_id,
                "mitre_technique_name": r.mitre_technique_name,
                "created_at": (
                    r.created_at.isoformat() if r.created_at else None
                ),
            }
        )

    return out


@router.get(
    "/scans/{job_id}/defensive-rules/export",
    summary="Export all generated detection rules as a packaged ZIP archive",
)
async def export_rules_zip(
    job_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job UUID")

    result = await session.execute(
        select(DefensiveRule)
        .options(selectinload(DefensiveRule.finding))
        .where(DefensiveRule.job_id == jid)
    )
    rules = result.scalars().all()

    if not rules:
        raise HTTPException(
            status_code=404, detail="No defensive rules found for this job"
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(
        zip_buffer, "w", zipfile.ZIP_DEFLATED, False
    ) as zip_file:
        for idx, r in enumerate(rules, start=1):
            f_title_slug = (
                r.finding.title.lower()
                .replace(" ", "_")
                .replace("/", "_")[:30]
                if r.finding
                else f"rule_{idx}"
            )

            # Sigma YAML
            if r.sigma_rule:
                zip_file.writestr(
                    f"sigma/{idx}_{f_title_slug}.yml", r.sigma_rule
                )

            # Wazuh XML
            if r.wazuh_rule:
                zip_file.writestr(
                    f"wazuh/{idx}_{f_title_slug}.xml", r.wazuh_rule
                )

            # Suricata rules
            if r.suricata_rule:
                zip_file.writestr(
                    f"suricata/{idx}_{f_title_slug}.rules", r.suricata_rule
                )

            # Host firewall scripts
            if r.firewall_rule:
                zip_file.writestr(
                    f"firewall/{idx}_{f_title_slug}.sh", r.firewall_rule
                )

    zip_buffer.seek(0)
    filename = f"sentinelvapt_rules_{job_id[:8]}.zip"

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
