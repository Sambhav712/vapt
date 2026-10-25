"""
SentinelVAPT — Executive & Technical Report Generator
Produces comprehensive, audit-ready security assessment reports in:
- Markdown (.md)
- JSON (.json)
- Professional PDF (.pdf) via ReportLab
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.reporting")


class ReportBuilder:
    """
    Constructs multi-format penetration testing and vulnerability assessment reports.
    """

    def __init__(self):
        self.settings = get_settings()
        self.reports_dir = self.settings.reports_path

    async def generate_all(
        self, job: Any, findings: List[Any], tool_outputs: List[Any]
    ) -> Dict[str, str]:
        """
        Generate Markdown, JSON, and PDF reports for a completed scan job.
        Returns a dictionary mapping format names ('markdown', 'json', 'pdf') to file paths.
        """
        job_id_str = str(job.id)
        results: Dict[str, str] = {}

        try:
            md_path = self.generate_markdown(job, findings, tool_outputs)
            results["markdown"] = str(md_path)
        except Exception as e:
            logger.error("Failed to generate Markdown report: %s", e, exc_info=True)

        try:
            json_path = self.generate_json(job, findings, tool_outputs)
            results["json"] = str(json_path)
        except Exception as e:
            logger.error("Failed to generate JSON report: %s", e, exc_info=True)

        try:
            pdf_path = self.generate_pdf(job, findings, tool_outputs)
            results["pdf"] = str(pdf_path)
        except Exception as e:
            logger.error("Failed to generate PDF report: %s", e, exc_info=True)

        return results

    def _calculate_metrics(self, findings: List[Any]) -> Dict[str, Any]:
        """Calculate severity metrics and breakdown."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total = len(findings)
        max_cvss = 0.0

        for f in findings:
            sev = (
                f.severity.value
                if hasattr(f.severity, "value")
                else str(f.severity or "info").lower()
            )
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

            cvss = getattr(f, "cvss_score", None) or 0.0
            if cvss > max_cvss:
                max_cvss = cvss

        # Overall risk level
        if counts["critical"] > 0:
            risk_level = "CRITICAL"
        elif counts["high"] > 0:
            risk_level = "HIGH"
        elif counts["medium"] > 0:
            risk_level = "MEDIUM"
        elif counts["low"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIONAL"

        return {
            "counts": counts,
            "total": total,
            "max_cvss": max_cvss,
            "risk_level": risk_level,
        }

    # ─────────────────────────────────────────────────────────────
    # MARKDOWN REPORT GENERATOR
    # ─────────────────────────────────────────────────────────────

    def generate_markdown(
        self, job: Any, findings: List[Any], tool_outputs: List[Any]
    ) -> Path:
        metrics = self._calculate_metrics(findings)
        job_id = str(job.id)
        out_path = self.reports_dir / f"sentinelvapt_report_{job_id}.md"

        target = getattr(job, "target", "Unknown Target")
        scope = getattr(job, "scope_type", "web")
        scope_str = scope.value if hasattr(scope, "value") else str(scope)
        created_at = getattr(job, "created_at", datetime.now(timezone.utc))
        created_str = (
            created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if hasattr(created_at, "strftime")
            else str(created_at)
        )
        completed_at = getattr(job, "completed_at", None)
        completed_str = (
            completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if completed_at and hasattr(completed_at, "strftime")
            else "In Progress / Concluded"
        )
        exec_summary = getattr(
            job,
            "executive_summary",
            "Automated vulnerability assessment executed by SentinelVAPT framework.",
        )

        lines = [
            f"# SentinelVAPT Security Assessment Report",
            f"**Target:** `{target}`  ",
            f"**Scope:** `{scope_str.upper()}`  ",
            f"**Job ID:** `{job_id}`  ",
            f"**Assessment Date:** {created_str}  ",
            f"**Completion Date:** {completed_str}  ",
            f"**Overall Risk Rating:** **{metrics['risk_level']}** (Max CVSS: {metrics['max_cvss']:.1f})  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            exec_summary
            or "Security assessment completed. Detailed technical analysis follows.",
            "",
            "### Vulnerability Severity Distribution",
            "| Severity | Finding Count |",
            "| :--- | :--- |",
            f"| **CRITICAL** | {metrics['counts']['critical']} |",
            f"| **HIGH** | {metrics['counts']['high']} |",
            f"| **MEDIUM** | {metrics['counts']['medium']} |",
            f"| **LOW** | {metrics['counts']['low']} |",
            f"| **INFORMATIONAL** | {metrics['counts']['info']} |",
            f"| **Total Findings** | **{metrics['total']}** |",
            "",
            "---",
            "",
            "## 2. Methodology & Scope",
            "",
            "SentinelVAPT combines automated multi-stage reconnaissance, static and dynamic vulnerability scanning, "
            "safe controlled verification, AI-driven correlation and false-positive elimination, followed by defensive detection engineering (Sigma, Wazuh, Suricata).",
            "",
            f"- **Target Asset:** `{target}`",
            f"- **Scope Discipline:** `{scope_str.upper()}`",
            f"- **Authorized Exploitation Flag:** `{getattr(job, 'authorized_exploitation', False)}`",
            "",
            "### Active Tools Executed",
        ]

        # Tool summary table
        if tool_outputs:
            lines.extend(
                [
                    "| Tool Name | Stage | Exit Code | Duration (s) |",
                    "| :--- | :--- | :--- | :--- |",
                ]
            )
            for t in tool_outputs:
                t_name = getattr(t, "tool_name", "tool")
                t_stage = (
                    t.stage.value
                    if hasattr(t.stage, "value")
                    else str(t.stage or "")
                )
                t_code = getattr(t, "exit_code", 0)
                t_dur = getattr(t, "duration_seconds", 0.0) or 0.0
                lines.append(
                    f"| `{t_name}` | {t_stage} | {t_code} | {t_dur:.2f}s |"
                )
        else:
            lines.append("*(No external tool outputs recorded)*")

        lines.extend(["", "---", "", "## 3. Detailed Technical Findings", ""])

        if not findings:
            lines.append(
                "> **Notice:** No security vulnerabilities were detected on this target under the configured scope."
            )
        else:
            # Sort findings by severity
            sev_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            sorted_findings = sorted(
                findings,
                key=lambda f: sev_order.get(
                    (
                        f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity)
                    ).lower(),
                    9,
                ),
            )

            for idx, f in enumerate(sorted_findings, start=1):
                f_title = getattr(f, "title", "Vulnerability Finding")
                f_sev = (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity or "info")
                ).upper()
                f_cvss = getattr(f, "cvss_score", None)
                f_cvss_str = f"{f_cvss:.1f}" if f_cvss is not None else "N/A"
                f_cves = getattr(f, "cve_ids", []) or []
                f_cwes = getattr(f, "cwe_ids", []) or []
                f_asset = getattr(f, "affected_asset", "Target Asset")
                f_comp = getattr(f, "affected_component", "Endpoint/Service")
                f_tool = getattr(f, "source_tool", "Automated Scanner")
                f_desc = (
                    getattr(f, "description", "") or "No description provided."
                )
                f_remed = (
                    getattr(f, "remediation", "")
                    or "Follow standard patching and secure configuration practices."
                )
                f_evid = getattr(f, "evidence", "")
                f_chain = getattr(f, "attack_chain", "")
                f_reason = getattr(f, "ai_reasoning", "")
                f_tactic = getattr(f, "mitre_tactic", "")
                f_tech_id = getattr(f, "mitre_technique_id", "")
                f_tech_name = getattr(f, "mitre_technique_name", "")

                lines.extend(
                    [
                        f"### 3.{idx}. [{f_sev}] {f_title}",
                        f"- **Severity:** `{f_sev}` | **CVSS v3.1:** `{f_cvss_str}` | **Discovered By:** `{f_tool}`",
                        f"- **Target Asset:** `{f_asset}`",
                        f"- **Vulnerable Component:** `{f_comp}`",
                    ]
                )

                if f_cves:
                    lines.append(f"- **CVE Identifiers:** {', '.join(f_cves)}")
                if f_cwes:
                    lines.append(f"- **CWE Weaknesses:** {', '.join(f_cwes)}")
                if f_tech_id:
                    lines.append(
                        f"- **MITRE ATT&CK:** {f_tech_id} ({f_tech_name}) - Tactic: {f_tactic}"
                    )

                lines.extend(
                    [
                        "",
                        "#### Description",
                        f_desc,
                        "",
                        "#### Remediation Guidance",
                        f_remed,
                    ]
                )

                if f_chain:
                    lines.extend(["", "#### Potential Attack Chain", f_chain])

                if f_reason:
                    lines.extend(
                        [
                            "",
                            "#### AI Validation & Analysis",
                            f"> {f_reason}",
                        ]
                    )

                if f_evid:
                    lines.extend(
                        [
                            "",
                            "#### Evidence & Technical Verification",
                            "```text",
                            f_evid[:2000],
                            "```",
                        ]
                    )

                lines.append("")

        lines.extend(
            [
                "---",
                "",
                "## 4. Remediation Prioritization Roadmap",
                "",
                "1. **Immediate (0-24 Hours):** Address all **CRITICAL** findings to mitigate potential direct exposure.",
                "2. **High Priority (1-7 Days):** Remediate **HIGH** severity findings, applying available vendor security patches and hardening configs.",
                "3. **Medium Priority (30 Days):** Address **MEDIUM** severity items during the standard development release cycle.",
                "4. **Low / Hardening (Ongoing):** Implement security headers, tighten cipher suites, and enforce least privilege.",
                "",
                "---",
                "",
                "## 5. Tool Output Appendix (Execution Telemetry)",
                "",
                "This appendix contains raw execution telemetry from all automated security tools deployed during this assessment.",
                "",
            ]
        )

        if tool_outputs:
            for idx, t in enumerate(tool_outputs, start=1):
                t_name = getattr(t, "tool_name", "tool")
                t_stage = t.stage.value if hasattr(t.stage, "value") else str(t.stage or "")
                t_cmd = getattr(t, "command", "") or "Subprocess Call"
                t_exit = getattr(t, "exit_code", 0)
                t_dur = getattr(t, "duration_seconds", 0.0) or 0.0
                t_out = getattr(t, "stdout", "") or "(No standard output)"

                lines.extend([
                    f"### 5.{idx}. Tool: `{t_name}` (Stage: `{t_stage}`)",
                    f"- **Invocation Command:** `{t_cmd}`",
                    f"- **Exit Code:** `{t_exit}` | **Execution Duration:** `{t_dur:.2f} seconds`",
                    "",
                    "```text",
                    t_out[:1500].strip(),
                    "```",
                    "",
                ])
        else:
            lines.append("*(No tool execution outputs logged for this assessment)*\n")

        lines.extend([
            "---",
            "",
            "*(Generated automatically by SentinelVAPT Production Security Suite)*",
        ])

        out_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report written to %s", out_path)
        return out_path

    # ─────────────────────────────────────────────────────────────
    # JSON REPORT GENERATOR
    # ─────────────────────────────────────────────────────────────

    def generate_json(
        self, job: Any, findings: List[Any], tool_outputs: List[Any]
    ) -> Path:
        metrics = self._calculate_metrics(findings)
        job_id = str(job.id)
        out_path = self.reports_dir / f"sentinelvapt_report_{job_id}.json"

        findings_data = []
        for f in findings:
            findings_data.append(
                {
                    "id": str(getattr(f, "id", "")),
                    "title": getattr(f, "title", ""),
                    "severity": (
                        f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity or "info")
                    ),
                    "confidence": (
                        f.confidence.value
                        if hasattr(f.confidence, "value")
                        else str(f.confidence or "medium")
                    ),
                    "cvss_score": getattr(f, "cvss_score", None),
                    "cvss_vector": getattr(f, "cvss_vector", None),
                    "cve_ids": getattr(f, "cve_ids", []) or [],
                    "cwe_ids": getattr(f, "cwe_ids", []) or [],
                    "affected_asset": getattr(f, "affected_asset", ""),
                    "affected_component": getattr(
                        f, "affected_component", ""
                    ),
                    "description": getattr(f, "description", ""),
                    "evidence": getattr(f, "evidence", ""),
                    "remediation": getattr(f, "remediation", ""),
                    "source_tool": getattr(f, "source_tool", ""),
                    "is_false_positive": getattr(f, "is_false_positive", False),
                    "ai_reasoning": getattr(f, "ai_reasoning", ""),
                    "attack_chain": getattr(f, "attack_chain", ""),
                    "mitre_tactic": getattr(f, "mitre_tactic", ""),
                    "mitre_technique_id": getattr(f, "mitre_technique_id", ""),
                    "mitre_technique_name": getattr(
                        f, "mitre_technique_name", ""
                    ),
                }
            )

        tools_data = []
        for t in tool_outputs:
            tools_data.append(
                {
                    "tool_name": getattr(t, "tool_name", ""),
                    "stage": (
                        t.stage.value
                        if hasattr(t.stage, "value")
                        else str(t.stage or "")
                    ),
                    "command": getattr(t, "command", ""),
                    "exit_code": getattr(t, "exit_code", 0),
                    "duration_seconds": getattr(t, "duration_seconds", 0.0),
                    "parsed_summary": (
                        list(t.parsed_output.keys())
                        if isinstance(t.parsed_output, dict)
                        else None
                    ),
                }
            )

        report_dict = {
            "meta": {
                "generator": "SentinelVAPT",
                "version": "1.0.0",
                "schema_version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "job": {
                "id": job_id,
                "target": getattr(job, "target", ""),
                "scope_type": (
                    job.scope_type.value
                    if hasattr(job.scope_type, "value")
                    else str(job.scope_type or "")
                ),
                "authorized_exploitation": getattr(
                    job, "authorized_exploitation", False
                ),
                "created_at": (
                    job.created_at.isoformat()
                    if hasattr(job.created_at, "isoformat")
                    else str(job.created_at or "")
                ),
                "completed_at": (
                    job.completed_at.isoformat()
                    if getattr(job, "completed_at", None)
                    and hasattr(job.completed_at, "isoformat")
                    else None
                ),
                "executive_summary": getattr(job, "executive_summary", ""),
            },
            "metrics": metrics,
            "findings": findings_data,
            "tool_executions": tools_data,
        }

        out_path.write_text(
            json.dumps(report_dict, indent=2, default=str), encoding="utf-8"
        )
        logger.info("JSON report written to %s", out_path)
        return out_path

    # ─────────────────────────────────────────────────────────────
    # PDF REPORT GENERATOR (via ReportLab)
    # ─────────────────────────────────────────────────────────────

    def generate_pdf(
        self, job: Any, findings: List[Any], tool_outputs: List[Any]
    ) -> Path:
        """
        Generate a multi-page PDF security assessment report with styling,
        risk matrices, tables, and remediation blueprints.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        job_id = str(job.id)
        out_path = self.reports_dir / f"sentinelvapt_report_{job_id}.pdf"
        metrics = self._calculate_metrics(findings)

        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        # Custom Palette: Deep Navy, Cyan, Crimson, Slate
        c_navy = colors.HexColor("#0B132B")
        c_blue = colors.HexColor("#1C2541")
        c_cyan = colors.HexColor("#48CAE4")
        c_crimson = colors.HexColor("#E63946")
        c_orange = colors.HexColor("#F77F00")
        c_amber = colors.HexColor("#FCBF49")
        c_green = colors.HexColor("#06D6A0")
        c_gray_bg = colors.HexColor("#F8F9FA")
        c_border = colors.HexColor("#DEE2E6")

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=24,
            leading=28,
            textColor=c_navy,
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=15,
        )

        h1_style = ParagraphStyle(
            "H1",
            parent=styles["Heading2"],
            fontSize=16,
            leading=20,
            textColor=c_navy,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        )

        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading3"],
            fontSize=12,
            leading=16,
            textColor=c_blue,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=6,
        )

        meta_label_style = ParagraphStyle(
            "MetaLabel",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            fontName="Helvetica-Bold",
            textColor=c_navy,
        )

        meta_val_style = ParagraphStyle(
            "MetaVal",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748"),
        )

        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#1A202C"),
            backColor=c_gray_bg,
            borderPadding=4,
            spaceAfter=6,
        )

        story = []

        # ── HEADER & COVER BANNER ─────────────────────────────────
        target_name = getattr(job, "target", "Target System")
        scope_val = getattr(job, "scope_type", "web")
        scope_str = (
            scope_val.value
            if hasattr(scope_val, "value")
            else str(scope_val)
        ).upper()
        date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

        story.append(Paragraph("SENTINEL<b>VAPT</b>", title_style))
        story.append(
            Paragraph(
                f"Automated Vulnerability Assessment & Penetration Testing Report<br/>"
                f"<b>Target:</b> {target_name} &nbsp;|&nbsp; <b>Scope:</b> {scope_str} &nbsp;|&nbsp; <b>Date:</b> {date_str}",
                subtitle_style,
            )
        )
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=c_cyan,
                spaceBefore=0,
                spaceAfter=15,
            )
        )

        # ── METADATA & EXECUTIVE SUMMARY ──────────────────────────
        story.append(Paragraph("1. Executive Summary", h1_style))

        exec_text = (
            getattr(job, "executive_summary", "")
            or f"SentinelVAPT completed an authorized security assessment against target {target_name}. "
            f"The assessment evaluated network services, web endpoints, API interfaces, and defensive posture. "
            f"A total of {metrics['total']} findings were cataloged with an overall risk rating of {metrics['risk_level']}."
        )
        story.append(Paragraph(exec_text, body_style))
        story.append(Spacer(1, 10))

        # ── RISK SCORECARD TABLE ──────────────────────────────────
        sev_counts = metrics["counts"]
        scorecard_data = [
            [
                Paragraph("<b>Overall Risk</b>", meta_label_style),
                Paragraph(
                    f"<b>{metrics['risk_level']}</b>",
                    ParagraphStyle(
                        "RiskBadge",
                        parent=meta_label_style,
                        textColor=(
                            c_crimson
                            if metrics["risk_level"] in ("CRITICAL", "HIGH")
                            else c_navy
                        ),
                    ),
                ),
                Paragraph("<b>Max CVSS Score</b>", meta_label_style),
                Paragraph(f"{metrics['max_cvss']:.1f} / 10.0", meta_val_style),
            ],
            [
                Paragraph("<b>Target Asset</b>", meta_label_style),
                Paragraph(target_name, meta_val_style),
                Paragraph("<b>Authorized Exploitation</b>", meta_label_style),
                Paragraph(
                    (
                        "Enabled"
                        if getattr(job, "authorized_exploitation", False)
                        else "Disabled (Assessment Only)"
                    ),
                    meta_val_style,
                ),
            ],
            [
                Paragraph("<b>Critical Issues</b>", meta_label_style),
                Paragraph(
                    f"<font color='{c_crimson.hexval()}'><b>{sev_counts['critical']}</b></font>",
                    meta_val_style,
                ),
                Paragraph("<b>High Issues</b>", meta_label_style),
                Paragraph(
                    f"<font color='{c_orange.hexval()}'><b>{sev_counts['high']}</b></font>",
                    meta_val_style,
                ),
            ],
            [
                Paragraph("<b>Medium Issues</b>", meta_label_style),
                Paragraph(
                    f"<font color='{c_amber.hexval()}'><b>{sev_counts['medium']}</b></font>",
                    meta_val_style,
                ),
                Paragraph("<b>Low & Info Issues</b>", meta_label_style),
                Paragraph(
                    f"{sev_counts['low'] + sev_counts['info']}", meta_val_style
                ),
            ],
        ]

        scorecard_table = Table(
            scorecard_data, colWidths=[130, 135, 130, 135]
        )
        scorecard_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), c_gray_bg),
                    ("BOX", (0, 0), (-1, -1), 1, c_border),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(scorecard_table)
        story.append(Spacer(1, 15))

        # ── METHODOLOGY & TOOLS EXECUTED ─────────────────────────
        story.append(Paragraph("2. Scope & Execution Telemetry", h1_style))
        story.append(
            Paragraph(
                "Automated scans were orchestrated through specialized tools covering port discovery, "
                "service identification, web application crawling, automated API endpoint auditing, and vulnerability matching.",
                body_style,
            )
        )

        if tool_outputs:
            tool_rows = [
                [
                    Paragraph("<b>Tool</b>", meta_label_style),
                    Paragraph("<b>Stage</b>", meta_label_style),
                    Paragraph("<b>Exit Status</b>", meta_label_style),
                    Paragraph("<b>Runtime</b>", meta_label_style),
                ]
            ]
            for t in tool_outputs[:15]:  # limit top 15
                t_name = getattr(t, "tool_name", "tool")
                t_stage = (
                    t.stage.value
                    if hasattr(t.stage, "value")
                    else str(t.stage or "")
                )
                t_exit = getattr(t, "exit_code", 0)
                t_dur = getattr(t, "duration_seconds", 0.0) or 0.0
                tool_rows.append(
                    [
                        Paragraph(f"<code>{t_name}</code>", meta_val_style),
                        Paragraph(t_stage, meta_val_style),
                        Paragraph(
                            "Success" if t_exit == 0 else f"Code {t_exit}",
                            meta_val_style,
                        ),
                        Paragraph(f"{t_dur:.2f}s", meta_val_style),
                    ]
                )

            tool_table = Table(tool_rows, colWidths=[120, 160, 120, 130])
            tool_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                        ("BOX", (0, 0), (-1, -1), 0.5, c_border),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(tool_table)

        story.append(Spacer(1, 15))

        # ── FINDINGS SECTION ─────────────────────────────────────
        story.append(Paragraph("3. Technical Findings & Vulnerabilities", h1_style))

        if not findings:
            story.append(
                Paragraph(
                    "<b>No vulnerabilities identified</b> for this target under current testing parameters.",
                    body_style,
                )
            )
        else:
            sev_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            sorted_findings = sorted(
                findings,
                key=lambda f: sev_order.get(
                    (
                        f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity)
                    ).lower(),
                    9,
                ),
            )

            for idx, f in enumerate(sorted_findings, start=1):
                f_title = getattr(f, "title", "Vulnerability Finding")
                f_sev = (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity or "info")
                ).upper()
                f_cvss = getattr(f, "cvss_score", None)
                f_cvss_str = f"{f_cvss:.1f}" if f_cvss is not None else "N/A"
                f_cves = getattr(f, "cve_ids", []) or []
                f_cwes = getattr(f, "cwe_ids", []) or []
                f_asset = getattr(f, "affected_asset", "Target Asset")
                f_comp = getattr(f, "affected_component", "Endpoint/Service")
                f_tool = getattr(f, "source_tool", "Scanner")
                f_desc = (
                    getattr(f, "description", "") or "No description provided."
                )
                f_remed = (
                    getattr(f, "remediation", "")
                    or "Apply software patch and restrict public network exposure."
                )
                f_evid = getattr(f, "evidence", "")
                f_chain = getattr(f, "attack_chain", "")
                f_tactic = getattr(f, "mitre_tactic", "")
                f_tech_id = getattr(f, "mitre_technique_id", "")

                # Color badge based on severity
                sev_color = (
                    c_crimson
                    if f_sev == "CRITICAL"
                    else (
                        c_orange
                        if f_sev == "HIGH"
                        else (
                            c_amber
                            if f_sev == "MEDIUM"
                            else (c_blue if f_sev == "LOW" else colors.gray)
                        )
                    )
                )

                finding_elements = [
                    Paragraph(
                        f"<b>3.{idx} [{f_sev}] {f_title}</b>",
                        ParagraphStyle(
                            f"FTitle_{idx}",
                            parent=h2_style,
                            textColor=sev_color,
                        ),
                    ),
                    Paragraph(
                        f"<b>Affected Asset:</b> {f_asset} &nbsp;|&nbsp; "
                        f"<b>Component:</b> {f_comp} &nbsp;|&nbsp; "
                        f"<b>CVSS:</b> {f_cvss_str} &nbsp;|&nbsp; "
                        f"<b>Tool:</b> {f_tool}",
                        meta_val_style,
                    ),
                ]

                if f_cves or f_cwes or f_tech_id:
                    ref_text = []
                    if f_cves:
                        ref_text.append(f"<b>CVEs:</b> {', '.join(f_cves)}")
                    if f_cwes:
                        ref_text.append(f"<b>CWEs:</b> {', '.join(f_cwes)}")
                    if f_tech_id:
                        ref_text.append(
                            f"<b>MITRE:</b> {f_tech_id} ({f_tactic})"
                        )
                    finding_elements.append(
                        Paragraph(" &nbsp;|&nbsp; ".join(ref_text), meta_val_style)
                    )

                finding_elements.append(
                    Paragraph(f"<b>Description:</b> {f_desc}", body_style)
                )
                finding_elements.append(
                    Paragraph(
                        f"<b>Remediation Guidance:</b> {f_remed}", body_style
                    )
                )

                if f_chain:
                    finding_elements.append(
                        Paragraph(
                            f"<b>Attack Chain Impact:</b> {f_chain}",
                            body_style,
                        )
                    )

                if f_evid:
                    clean_evid = f_evid[:1200].replace("<", "&lt;").replace(">", "&gt;")
                    finding_elements.append(
                        Paragraph(
                            f"<b>Proof of Verification:</b><br/>{clean_evid}",
                            code_style,
                        )
                    )

                finding_elements.append(Spacer(1, 8))
                story.append(KeepTogether(finding_elements))

        # ── DEFENSIVE & PURPLE TEAM GUIDANCE ─────────────────────
        story.append(Spacer(1, 10))
        story.append(Paragraph("4. Defensive Detection Recommendations", h1_style))
        story.append(
            Paragraph(
                "SentinelVAPT automatically synthesizes purple-team detection artifacts for identified findings. "
                "Security teams should deploy generated Sigma rules to their SIEM, update Wazuh agent rulesets, "
                "and deploy Suricata NIDS signatures to ingress choke points.",
                body_style,
            )
        )

        # ── TOOL EXECUTION APPENDIX ──────────────────────────────
        if tool_outputs:
            story.append(Spacer(1, 10))
            story.append(Paragraph("5. Tool Execution Appendix", h1_style))
            story.append(
                Paragraph(
                    "Detailed execution telemetry for all automated tools deployed during this scan.",
                    body_style,
                )
            )

            appendix_rows = [
                [
                    Paragraph("<b>Tool Name</b>", meta_label_style),
                    Paragraph("<b>Execution Command</b>", meta_label_style),
                    Paragraph("<b>Exit</b>", meta_label_style),
                    Paragraph("<b>Runtime</b>", meta_label_style),
                ]
            ]
            for t in tool_outputs:
                t_name = getattr(t, "tool_name", "tool")
                t_cmd = getattr(t, "command", "") or t_name
                t_exit = getattr(t, "exit_code", 0)
                t_dur = getattr(t, "duration_seconds", 0.0) or 0.0

                clean_cmd = t_cmd[:65].replace("<", "&lt;").replace(">", "&gt;")
                appendix_rows.append(
                    [
                        Paragraph(f"<code>{t_name}</code>", meta_val_style),
                        Paragraph(f"<code>{clean_cmd}</code>", meta_val_style),
                        Paragraph("0 (OK)" if t_exit == 0 else str(t_exit), meta_val_style),
                        Paragraph(f"{t_dur:.2f}s", meta_val_style),
                    ]
                )

            appendix_table = Table(appendix_rows, colWidths=[90, 270, 70, 100])
            appendix_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                        ("BOX", (0, 0), (-1, -1), 0.5, c_border),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(appendix_table)

        doc.build(story)
        logger.info("PDF report generated successfully at %s", out_path)
        return out_path
