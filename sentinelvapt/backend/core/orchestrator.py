"""
SentinelVAPT — Pipeline Orchestrator
State machine that drives the entire scan lifecycle:
TOOL_CHECK -> RECON -> VULN_SCAN -> EXPLOITATION -> AI_ANALYSIS -> REPORT_GEN -> DEFENSIVE_RULES -> DONE
"""

import asyncio
import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.db.models import (
    Job, Finding, ToolOutput, DefensiveRule, AIDecisionLog,
    PipelineStage, StageStatus, ScopeType, Severity, Confidence,
)
from backend.tools.installer import ToolInstaller
from backend.tools.nmap_tool import NmapTool
from backend.tools.nuclei_tool import NucleiTool
from backend.tools.zap_tool import ZapTool
from backend.tools.sqlmap_tool import SqlmapTool
from backend.tools.subfinder_tool import SubfinderTool
from backend.tools.httpx_tool import HttpxTool
from backend.tools.nikto_tool import NiktoTool
from backend.tools.amass_tool import AmassTool
from backend.tools.metasploit_tool import MetasploitTool
from backend.tools.api_security_tool import ApiSecurityTool
from backend.tools.base import ParsedResult
from backend.tools.registry import ToolRegistry
from backend.core.privilege_manager import get_privilege_manager
from backend.core.api_manager import get_api_manager
from backend.ai.decision_engine import AIDecisionEngine, AIDecision

logger = logging.getLogger("sentinelvapt.orchestrator")


class PipelineOrchestrator:
    """
    Orchestrates the VAPT pipeline using an autonomous AI Decision Loop.
    The AI dynamically inspects accumulated results and determines the optimal tool sequence.
    """

    STAGE_ORDER = [
        PipelineStage.TOOL_CHECK,
        PipelineStage.AI_ORCHESTRATION,
        PipelineStage.AI_ANALYSIS,
        PipelineStage.REPORT_GENERATION,
        PipelineStage.DEFENSIVE_RULE_GENERATION,
        PipelineStage.DONE,
    ]

    def __init__(self, session: AsyncSession, job_id: uuid.UUID,
                 log_callback: Optional[Callable] = None):
        self.session = session
        self.job_id = job_id
        self.settings = get_settings()
        self._log_callback = log_callback

        # Initialize AI Decision Engine
        self.decision_engine = AIDecisionEngine()

        # Initialize tools
        self.installer = ToolInstaller()
        self.nmap = NmapTool()
        self.nuclei = NucleiTool()
        self.zap = ZapTool()
        self.sqlmap = SqlmapTool()
        self.subfinder = SubfinderTool()
        self.httpx = HttpxTool()
        self.nikto = NiktoTool()
        self.amass = AmassTool()
        self.metasploit = MetasploitTool()
        self.api_security = ApiSecurityTool()
        self.registry = ToolRegistry()
        self.privilege_mgr = get_privilege_manager()
        self.api_mgr = get_api_manager()

    async def _get_job(self) -> Job:
        result = await self.session.execute(select(Job).where(Job.id == self.job_id))
        job = result.scalar_one_or_none()
        if not job:
            raise ValueError(f"Job {self.job_id} not found")
        return job

    async def _log(self, stage: str, message: str):
        """Log a message and persist it to the job record."""
        logger.info("[%s] %s: %s", self.job_id, stage, message)
        job = await self._get_job()
        job.add_log(stage, message)
        await self.session.commit()
        if self._log_callback:
            try:
                await self._log_callback(str(self.job_id), stage, message)
            except Exception:
                pass

    async def _update_stage(self, stage: PipelineStage, status: StageStatus):
        """Update the job's current stage and its status."""
        job = await self._get_job()
        job.current_stage = stage
        statuses = dict(job.stage_statuses) if job.stage_statuses else {}
        statuses[stage.value] = status.value
        job.stage_statuses = statuses
        job.updated_at = datetime.now(timezone.utc)
        await self.session.commit()

    async def _save_tool_output(self, tool_name: str, stage: PipelineStage,
                                result: ParsedResult):
        """Persist raw tool output to the database."""
        output = ToolOutput(
            job_id=self.job_id,
            tool_name=tool_name,
            stage=stage,
            command=result.command,
            stdout=result.raw_stdout[:50000] if result.raw_stdout else "",
            stderr=result.raw_stderr[:10000] if result.raw_stderr else "",
            parsed_output=result.parsed_data,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
        )
        self.session.add(output)
        await self.session.commit()

    async def _save_findings(self, findings_data: List[Dict]):
        """Convert raw finding dicts to Finding ORM objects and persist."""
        for fd in findings_data:
            finding = Finding(
                job_id=self.job_id,
                title=fd.get("title", "Unknown Finding"),
                description=fd.get("description", ""),
                severity=Severity(fd.get("severity", "info")),
                confidence=Confidence(fd.get("confidence", "medium")),
                cvss_score=fd.get("cvss_score"),
                cvss_vector=fd.get("cvss_vector"),
                cve_ids=fd.get("cve_ids", []),
                cwe_ids=fd.get("cwe_ids", []),
                affected_asset=fd.get("affected_asset", ""),
                affected_component=fd.get("affected_component", ""),
                evidence=fd.get("evidence", ""),
                remediation=fd.get("remediation", ""),
                source_tool=fd.get("source_tool", ""),
                raw_data=fd.get("raw_data", {}),
            )
            self.session.add(finding)
        await self.session.commit()

    # ─── Main Pipeline Entry Point ─────────────────────

    async def run(self):
        """Alias for run_pipeline."""
        return await self.run_pipeline()

    async def run_pipeline(self):
        """
        Execute the AI-driven pipeline:
        TOOL_CHECK -> AI_ORCHESTRATION (Dynamic Loop) -> AI_ANALYSIS -> REPORT_GENERATION -> DEFENSIVE_RULES -> DONE
        """
        try:
            # Stage 1: Tool Check & Health Verification
            await self._run_tool_check()

            # Stage 2: Autonomous AI Decision Loop (Replaces fixed RECON -> VULN_SCAN -> EXPLOITATION)
            await self._run_ai_orchestration_loop()

            # Stage 3: AI Correlation, Impact Synthesis & False-Positive Pruning
            await self._run_ai_analysis()

            # Stage 4: Technical & Executive Report Generation
            await self._run_report_generation()

            # Stage 5: Defensive SIEM / Firewall Rule Generation
            await self._run_defensive_rules()

            # Complete
            await self._update_stage(PipelineStage.DONE, StageStatus.COMPLETED)
            await self._log("done", "Autonomous AI assessment completed successfully.")

            job = await self._get_job()
            job.completed_at = datetime.now(timezone.utc)
            await self.session.commit()

        except Exception as e:
            logger.error("Pipeline failed: %s\n%s", e, traceback.format_exc())
            await self._update_stage(PipelineStage.FAILED, StageStatus.FAILED)
            await self._log("error", f"Pipeline failed: {e}")

    # ─── Stage 1: Tool Check ──────────────────────────

    async def _run_tool_check(self):
        await self._update_stage(PipelineStage.TOOL_CHECK, StageStatus.RUNNING)
        await self._log("tool_check", "Checking required tool installations...")

        loop = asyncio.get_event_loop()
        statuses = await loop.run_in_executor(None, self.installer.check_all)

        missing = [name for name, s in statuses.items() if not s.installed]
        if missing:
            await self._log("tool_check", f"Missing core tools: {', '.join(missing)}. Dynamic tools will be used where available.")
        else:
            await self._log("tool_check", "Core tools verified.")

        # ── Privilege Detection ────────────────────────────────
        priv_status = self.privilege_mgr.detect()
        await self._log(
            "tool_check",
            f"Privilege level: {priv_status.level.value.upper()} | "
            f"User: {priv_status.username} | "
            f"Root/Admin: {priv_status.is_admin} | "
            f"Sudo: {priv_status.has_sudo} (passwordless={priv_status.sudo_passwordless}) | "
            f"Raw sockets: {priv_status.can_raw_socket}"
        )
        for warning in priv_status.warnings:
            await self._log("tool_check", f"⚠ PRIVILEGE WARNING: {warning}")

        # Log which tools need root and if we can run them
        tool_privs = self.privilege_mgr.get_tool_privilege_map()
        root_tools_installed = [
            name for name, info in tool_privs.items()
            if info["installed"]
        ]
        if root_tools_installed:
            can_elevate = all(
                tool_privs[t]["can_run_elevated"] for t in root_tools_installed
            )
            status_msg = "ALL can be elevated" if can_elevate else "SOME cannot be elevated without root"
            await self._log(
                "tool_check",
                f"Root-required tools installed: {', '.join(root_tools_installed)} — {status_msg}"
            )

        # ── External API Status ────────────────────────────────
        await self._log("tool_check", "Checking external API health and free-tier status...")
        api_health = await loop.run_in_executor(None, self.api_mgr.check_all_health)
        free_apis = self.api_mgr.get_free_apis()
        paid_apis = self.api_mgr.get_paid_apis()
        healthy_count = sum(1 for h in api_health.values() if h == "healthy")
        await self._log(
            "tool_check",
            f"External APIs: {len(api_health)} configured | "
            f"{healthy_count} healthy | "
            f"{len(free_apis)} free | "
            f"{len(paid_apis)} freemium/paid"
        )
        for name, health in api_health.items():
            if health in ("down", "no_key"):
                api = self.api_mgr.apis.get(name)
                fallback_msg = ""
                if api and api.fallback_to:
                    fallback_msg = f" → falling back to {api.fallback_to}"
                await self._log(
                    "tool_check",
                    f"API [{name}]: {health.upper()}{fallback_msg}"
                )

        # Extensible Tool Registry discovery
        detected_catalog = self.registry.get_detected()
        tool_names = [t.name for t in detected_catalog]
        await self._log(
            "tool_check",
            f"Extensible Tool Registry: {len(detected_catalog)} tools detected on host ({', '.join(tool_names[:8])}{'...' if len(tool_names) > 8 else ''})."
        )

        await self._update_stage(PipelineStage.TOOL_CHECK, StageStatus.COMPLETED)

    # ─── Stage 2: AI-Driven Autonomous Decision Loop ──────────────────

    async def _run_ai_orchestration_loop(self):
        """
        Core AI Decision Loop: iteratively consults the LLM (Groq/Ollama)
        to select, execute, and analyze tools dynamically based on live accumulated results.
        """
        await self._update_stage(PipelineStage.AI_ORCHESTRATION, StageStatus.RUNNING)
        await self._log("ai_orchestrator", "Initiating AI-Driven Decision Loop...")

        job = await self._get_job()
        max_iterations = job.max_iterations or self.settings.ai_max_iterations or 20
        max_time_seconds = self.settings.scan_max_time_seconds or 2400
        start_time = time.time()

        for iteration in range(1, max_iterations + 1):
            elapsed = time.time() - start_time
            if elapsed > max_time_seconds:
                await self._log(
                    "ai_orchestrator",
                    f"Overall scan timeout reached ({int(elapsed)}s / {max_time_seconds}s limit). Ending decision loop.",
                )
                break

            # Refresh job and update current_iteration
            job = await self._get_job()
            job.current_iteration = iteration
            await self.session.commit()

            # Gather live context
            knowledge = await self._gather_accumulated_knowledge(job.target)
            history = await self._gather_execution_history()
            available_tools = self._get_available_tools(job)

            await self._log(
                "ai_orchestrator",
                f"[Iteration {iteration}/{max_iterations}] Consulting AI Decision Engine (accumulated findings: {len(knowledge.get('findings', []))}, available tools: {len(available_tools)})...",
            )

            decision = await self.decision_engine.decide_next_step(
                target=job.target,
                scope_type=job.scope_type.value,
                authorized_exploitation=job.authorized_exploitation,
                available_tools=available_tools,
                execution_history=history,
                accumulated_knowledge=knowledge,
                iteration=iteration,
                max_iterations=max_iterations,
            )

            # Update job orchestration mode
            job.ai_orchestration_mode = (
                "heuristic_fallback"
                if decision.raw_response == "HEURISTIC_FALLBACK"
                else "ai_driven"
            )
            await self.session.commit()

            # Broadcast AI decision to logs
            await self._log(
                "ai_decision",
                f"[Iteration {iteration}/{max_iterations}] Action: {decision.action.upper()} | "
                f"Tool: {decision.tool_name or 'None'} | "
                f"Confidence: {int(decision.confidence * 100)}% | "
                f"Reasoning: {decision.reasoning}",
            )

            if decision.action == "finish":
                finish_log = AIDecisionLog(
                    job_id=self.job_id,
                    iteration=iteration,
                    chosen_tool=None,
                    action="finish",
                    reasoning=decision.reasoning,
                    expected_outcome=decision.expected_outcome,
                    confidence=decision.confidence,
                    tool_args={},
                    tool_execution_result={"summary": "Scan concluded by AI decision engine"},
                    prompt_tokens=decision.prompt_tokens,
                    completion_tokens=decision.completion_tokens,
                    latency=decision.latency,
                )
                self.session.add(finish_log)
                await self.session.commit()
                await self._log(
                    "ai_orchestrator",
                    "AI decided that sufficient evidence and coverage have been achieved. Proceeding to post-processing.",
                )
                break

            elif decision.action == "need_authorization":
                auth_log = AIDecisionLog(
                    job_id=self.job_id,
                    iteration=iteration,
                    chosen_tool=decision.tool_name,
                    action="need_authorization",
                    reasoning=decision.reasoning,
                    expected_outcome=decision.expected_outcome,
                    confidence=decision.confidence,
                    tool_args=decision.tool_args,
                    tool_execution_result={"summary": "Skipped: requires explicit user exploitation authorization"},
                    prompt_tokens=decision.prompt_tokens,
                    completion_tokens=decision.completion_tokens,
                    latency=decision.latency,
                )
                self.session.add(auth_log)
                await self.session.commit()
                await self._log(
                    "ai_decision",
                    f"⚠ Tool [{decision.tool_name}] requires exploitation authorization. Skipping and prompting AI for non-destructive alternative.",
                )
                continue

            elif decision.action in ("run_tool", "fallback"):
                tool_name = decision.tool_name
                await self._log(
                    "ai_orchestrator",
                    f"Executing [{tool_name}] — Expected: {decision.expected_outcome}",
                )

                tool_result = await self._execute_tool_by_name(tool_name, decision.tool_args, job)
                await self._save_tool_output(tool_name, PipelineStage.AI_ORCHESTRATION, tool_result)

                # Save findings if any
                findings_to_save = tool_result.findings or []
                if not findings_to_save:
                    findings_to_save = self._extract_findings_from_catalog_output(tool_name, tool_result, job.target)
                if findings_to_save:
                    await self._save_findings(findings_to_save)

                # Record decision log
                summary = (
                    f"{'Success' if tool_result.success else 'Failed'} with "
                    f"{len(findings_to_save)} findings in {tool_result.duration_seconds:.1f}s"
                )
                run_log = AIDecisionLog(
                    job_id=self.job_id,
                    iteration=iteration,
                    chosen_tool=tool_name,
                    action=decision.action,
                    reasoning=decision.reasoning,
                    expected_outcome=decision.expected_outcome,
                    confidence=decision.confidence,
                    tool_args=decision.tool_args,
                    tool_execution_result={
                        "success": tool_result.success,
                        "duration_seconds": tool_result.duration_seconds,
                        "findings_count": len(findings_to_save),
                        "summary": summary,
                        "error": tool_result.error_message,
                    },
                    prompt_tokens=decision.prompt_tokens,
                    completion_tokens=decision.completion_tokens,
                    latency=decision.latency,
                )
                self.session.add(run_log)
                await self.session.commit()

                await self._log("ai_orchestrator", f"Tool [{tool_name}] completed: {summary}")

        await self._update_stage(PipelineStage.AI_ORCHESTRATION, StageStatus.COMPLETED)
        await self._log("ai_orchestrator", "AI-Driven Decision Loop completed.")

    async def _execute_tool_by_name(
        self, tool_name: str, tool_args: Dict[str, Any], job: Job
    ) -> ParsedResult:
        """
        Unified tool executor that routes tool requests to native tool classes
        or dynamic ToolRegistry catalog items.
        """
        loop = asyncio.get_event_loop()
        target = tool_args.get("target") or job.target
        domain = self._extract_domain(target)
        name_lower = (tool_name or "").lower().strip()

        # 1. Native Tool Classes
        if name_lower == "nmap":
            nmap_opts = {"scan_type": "quick", "service_version": True}
            if job.scope_type == ScopeType.NETWORK:
                nmap_opts["os_detect"] = True
                nmap_opts["scan_type"] = "full"
            return await loop.run_in_executor(None, lambda: self.nmap.run(target, nmap_opts))

        elif name_lower == "nuclei":
            return await loop.run_in_executor(None, lambda: self.nuclei.run(target))

        elif name_lower == "zap":
            if self.zap.is_zap_running():
                return await loop.run_in_executor(None, lambda: self.zap.run(target, {"scan_type": "full"}))
            return ParsedResult(tool_name="zap", success=False, error_message="OWASP ZAP daemon is not currently active.")

        elif name_lower == "sqlmap":
            return await loop.run_in_executor(
                None, lambda: self.sqlmap.run(target, {"forms": True, "level": 2, "risk": 1})
            )

        elif name_lower == "subfinder":
            return await loop.run_in_executor(None, lambda: self.subfinder.run(domain))

        elif name_lower == "httpx":
            knowledge = await self._gather_accumulated_knowledge(target)
            subs = knowledge.get("subdomains", [])
            opts = {"hosts": subs} if subs else {}
            return await loop.run_in_executor(None, lambda: self.httpx.run(domain if subs else target, opts))

        elif name_lower == "nikto":
            return await loop.run_in_executor(None, lambda: self.nikto.run(target))

        elif name_lower == "amass":
            return await loop.run_in_executor(None, lambda: self.amass.run(domain, {"mode": "passive"}))

        elif name_lower == "metasploit":
            resolved_ip = self._resolve_target(target)
            if not job.authorized_exploitation or not self.settings.is_target_allowlisted(resolved_ip):
                return ParsedResult(
                    tool_name="metasploit",
                    success=False,
                    error_message=f"Target {resolved_ip} is not in the authorized exploitation allowlist.",
                )
            services = await self._get_discovered_services()
            cves = await self._get_discovered_cves()
            return await loop.run_in_executor(
                None,
                lambda: self.metasploit.run(
                    target,
                    {
                        "authorized_exploitation": True,
                        "services": services,
                        "cves": cves,
                        "module_type": "auxiliary",
                        "max_modules": 5,
                    },
                ),
            )

        elif name_lower == "api_security":
            return await loop.run_in_executor(None, lambda: self.api_security.run(target))

        # 2. Extensible Tool Registry Catalog Tools
        elif name_lower in self.registry.tools:
            entry = self.registry.tools[name_lower]
            res = await self.registry.execute_tool(entry, target, extra_vars=tool_args)
            extracted = self._extract_findings_from_catalog_output(name_lower, res, target)
            if extracted and not res.findings:
                res.findings = extracted
            return res

        else:
            return ParsedResult(
                tool_name=name_lower,
                success=False,
                error_message=f"Tool '{name_lower}' is not registered in the catalog.",
            )

    async def _gather_accumulated_knowledge(self, target: str) -> Dict[str, Any]:
        """Aggregate all intelligence discovered so far for LLM tool selection."""
        services = await self._get_discovered_services()
        ports = [s["port"] for s in services if s.get("port")]
        technologies = await self._get_discovered_tech()
        findings_summary = await self._get_current_findings_summary()

        # Discovered subdomains
        subdomains = set()
        sub_res = await self.session.execute(
            select(ToolOutput).where(
                ToolOutput.job_id == self.job_id,
                ToolOutput.tool_name.in_(["subfinder", "amass", "httpx"]),
            )
        )
        for out in sub_res.scalars().all():
            if out.parsed_output and isinstance(out.parsed_output, dict):
                for s in out.parsed_output.get("subdomains", []):
                    if isinstance(s, str):
                        subdomains.add(s)
                for h in out.parsed_output.get("hosts", []):
                    if isinstance(h, str):
                        subdomains.add(h)
                    elif isinstance(h, dict) and "host" in h:
                        subdomains.add(h["host"])

        # WAF detection status
        waf_info = "None detected / Not yet tested"
        waf_res = await self.session.execute(
            select(ToolOutput).where(
                ToolOutput.job_id == self.job_id,
                ToolOutput.tool_name == "wafw00f",
            )
        )
        waf_out = waf_res.scalars().first()
        if waf_out and waf_out.parsed_output:
            if waf_out.parsed_output.get("waf_detected"):
                wafs = waf_out.parsed_output.get("firewalls", [])
                waf_info = ", ".join(wafs) if wafs else "Generic WAF detected"
            else:
                waf_info = "No WAF detected"

        # Discovered endpoints
        endpoints = set()
        ep_res = await self.session.execute(
            select(ToolOutput).where(
                ToolOutput.job_id == self.job_id,
                ToolOutput.tool_name.in_(["gobuster", "zap"]),
            )
        )
        for out in ep_res.scalars().all():
            if out.parsed_output and isinstance(out.parsed_output, dict):
                for p in out.parsed_output.get("discovered_paths", []):
                    if isinstance(p, dict) and "path" in p:
                        endpoints.add(p["path"])
                    elif isinstance(p, str):
                        endpoints.add(p)

        return {
            "subdomains": sorted(list(subdomains)),
            "open_ports": ports,
            "services": services,
            "technologies": technologies,
            "waf": waf_info,
            "endpoints": sorted(list(endpoints)),
            "findings": findings_summary,
        }

    async def _gather_execution_history(self) -> List[Dict[str, Any]]:
        """Retrieve timeline of past tool runs from AIDecisionLog."""
        result = await self.session.execute(
            select(AIDecisionLog)
            .where(AIDecisionLog.job_id == self.job_id)
            .order_by(AIDecisionLog.iteration)
        )
        decisions = result.scalars().all()
        history = []
        for d in decisions:
            if d.action in ("run_tool", "fallback") and d.chosen_tool:
                res_data = d.tool_execution_result or {}
                history.append({
                    "iteration": d.iteration,
                    "tool_name": d.chosen_tool,
                    "success": res_data.get("success", True),
                    "duration_seconds": res_data.get("duration_seconds", 0.0),
                    "findings_count": res_data.get("findings_count", 0),
                    "summary": res_data.get("summary", d.reasoning),
                })
        return history

    def _get_available_tools(self, job: Job) -> List[Dict[str, Any]]:
        """Return the comprehensive list of installed/registered tools available for this job."""
        tools = []
        native_specs = [
            ("whatweb", "recon", 1, "Next-generation web scanner for technology and CMS fingerprinting"),
            ("wafw00f", "recon", 1, "Web Application Firewall (WAF) fingerprinting and detection"),
            ("nmap", "network", 1, "Port scanning, service detection, and OS fingerprinting"),
            ("subfinder", "recon", 1, "Passive subdomain discovery using OSINT sources"),
            ("httpx", "recon", 1, "Fast multi-purpose HTTP probe and tech detector"),
            ("amass", "recon", 1, "In-depth attack surface mapping and DNS asset discovery"),
            ("nuclei", "vuln_scan", 2, "Fast and customizable vulnerability scanner using community templates"),
            ("nikto", "vuln_scan", 2, "Web server scanner for dangerous files, outdated server software, and misconfigurations"),
            ("sqlmap", "vuln_scan", 2, "Automatic SQL injection detection and exploitation engine"),
            ("zap", "vuln_scan", 2, "OWASP ZAP dynamic application security testing (DAST)"),
            ("api_security", "vuln_scan", 2, "Automated OWASP API Security Top 10 auditing"),
            ("metasploit", "exploitation", 3, "Penetration testing and exploit execution platform"),
        ]

        manual_disabled = set(job.disabled_tools or [])
        manual_enabled = set(job.enabled_tools or [])
        seen = set()

        for name, cat, tier, desc in native_specs:
            if name in manual_disabled:
                continue
            if tier == 3 and not job.authorized_exploitation:
                continue

            installed = False
            if name == "nmap":
                installed = self.nmap.is_available()
            elif name == "nuclei":
                installed = self.nuclei.is_available()
            elif name == "zap":
                installed = self.zap.is_zap_running() or self.zap.is_available()
            elif name == "sqlmap":
                installed = self.sqlmap.is_available()
            elif name == "subfinder":
                installed = self.subfinder.is_available()
            elif name == "httpx":
                installed = self.httpx.is_available()
            elif name == "nikto":
                installed = self.nikto.is_available()
            elif name == "amass":
                installed = self.amass.is_available()
            elif name == "metasploit":
                installed = self.metasploit.is_available()
            elif name == "api_security":
                installed = True
            elif name in self.registry.tools:
                installed = self.registry.tools[name].installed
            else:
                installed = True

            if installed or name in manual_enabled:
                seen.add(name)
                tools.append({
                    "name": name,
                    "category": cat,
                    "tier": tier,
                    "description": desc,
                })

        # Add any additional detected tools from YAML catalog
        for name, entry in self.registry.tools.items():
            if name in seen or name in manual_disabled:
                continue
            if entry.tier == 3 and not job.authorized_exploitation:
                continue
            if entry.installed or name in manual_enabled:
                tools.append({
                    "name": entry.name,
                    "category": entry.category,
                    "tier": entry.tier,
                    "description": entry.description,
                })

        return tools

    # ─── Stage 2: Recon ────────────────────────────────

    async def _run_recon(self):
        await self._update_stage(PipelineStage.RECON, StageStatus.RUNNING)
        await self._log("recon", "Starting reconnaissance phase...")

        job = await self._get_job()
        target = job.target
        scope = job.scope_type
        loop = asyncio.get_event_loop()

        # Nmap port scan (always)
        if self.nmap.is_available():
            await self._log("recon", "Running Nmap port scan...")
            nmap_opts = {"scan_type": "quick", "service_version": True}
            if scope == ScopeType.NETWORK:
                nmap_opts["os_detect"] = True
                nmap_opts["scan_type"] = "full"

            nmap_result = await loop.run_in_executor(
                None, lambda: self.nmap.run(target, nmap_opts)
            )
            await self._save_tool_output("nmap", PipelineStage.RECON, nmap_result)
            if nmap_result.findings:
                await self._save_findings(nmap_result.findings)
            await self._log("recon", f"Nmap: {len(nmap_result.findings)} findings, {'success' if nmap_result.success else 'failed'}")
        else:
            await self._log("recon", "Nmap not available, skipping port scan.")

        # Subdomain enumeration (for web/api scopes with domain targets)
        if scope in (ScopeType.WEB, ScopeType.API) and not self._is_ip(target):
            domain = self._extract_domain(target)

            if self.subfinder.is_available():
                await self._log("recon", f"Running Subfinder on {domain}...")
                sf_result = await loop.run_in_executor(
                    None, lambda: self.subfinder.run(domain)
                )
                await self._save_tool_output("subfinder", PipelineStage.RECON, sf_result)
                if sf_result.findings:
                    await self._save_findings(sf_result.findings)
                await self._log("recon", f"Subfinder: {len(sf_result.findings)} subdomains found")

                # Probe discovered subdomains with httpx
                if sf_result.parsed_data.get("subdomains") and self.httpx.is_available():
                    subs = sf_result.parsed_data["subdomains"]
                    await self._log("recon", f"Probing {len(subs)} subdomains with httpx...")
                    httpx_result = await loop.run_in_executor(
                        None, lambda: self.httpx.run(domain, {"hosts": subs})
                    )
                    await self._save_tool_output("httpx", PipelineStage.RECON, httpx_result)
                    if httpx_result.findings:
                        await self._save_findings(httpx_result.findings)

            if self.amass.is_available():
                await self._log("recon", f"Running Amass on {domain}...")
                amass_result = await loop.run_in_executor(
                    None, lambda: self.amass.run(domain, {"mode": "passive"})
                )
                await self._save_tool_output("amass", PipelineStage.RECON, amass_result)
                if amass_result.findings:
                    await self._save_findings(amass_result.findings)
        elif self.httpx.is_available():
            # Probe single target
            await self._log("recon", "Probing target with httpx...")
            httpx_result = await loop.run_in_executor(
                None, lambda: self.httpx.run(target)
            )
            await self._save_tool_output("httpx", PipelineStage.RECON, httpx_result)
            if httpx_result.findings:
                await self._save_findings(httpx_result.findings)

        # ── Dynamic Extensible Catalog Recon Tools (Tier 1/2) ───────────
        open_ports = await self._get_discovered_ports()
        discovered_tech = await self._get_discovered_tech()

        dynamic_recon_tools = self.registry.select_tools_for_pipeline(
            scope_type=scope.value,
            authorized_exploitation=job.authorized_exploitation,
            discovered_ports=open_ports,
            discovered_tech=discovered_tech,
            manual_enabled=job.enabled_tools or [],
            manual_disabled=job.disabled_tools or [],
        )

        already_run = {"nmap", "subfinder", "httpx", "amass"}
        for tool_entry in dynamic_recon_tools:
            if tool_entry.name not in already_run and tool_entry.category in ("recon", "network"):
                await self._log("recon", f"Executing dynamic tool [{tool_entry.name}] (Tier {tool_entry.tier})...")
                res = await self.registry.execute_tool(tool_entry, target)
                await self._save_tool_output(tool_entry.name, PipelineStage.RECON, res)
                extracted = self._extract_findings_from_catalog_output(tool_entry.name, res, target)
                if extracted:
                    await self._save_findings(extracted)
                await self._log("recon", f"Dynamic tool [{tool_entry.name}] finished ({res.duration_seconds}s)")

        await self._update_stage(PipelineStage.RECON, StageStatus.COMPLETED)
        await self._log("recon", "Reconnaissance phase completed.")

    # ─── Stage 3: Vulnerability Scanning ───────────────

    async def _run_vuln_scan(self):
        await self._update_stage(PipelineStage.VULN_SCAN, StageStatus.RUNNING)
        await self._log("vuln_scan", "Starting vulnerability scanning phase...")

        job = await self._get_job()
        target = job.target
        scope = job.scope_type
        loop = asyncio.get_event_loop()

        # Nuclei
        if self.nuclei.is_available() and scope in (ScopeType.WEB, ScopeType.API):
            await self._log("vuln_scan", "Running Nuclei template scan...")
            nuclei_result = await loop.run_in_executor(
                None, lambda: self.nuclei.run(target)
            )
            await self._save_tool_output("nuclei", PipelineStage.VULN_SCAN, nuclei_result)
            if nuclei_result.findings:
                await self._save_findings(nuclei_result.findings)
            await self._log("vuln_scan", f"Nuclei: {len(nuclei_result.findings)} findings")
        else:
            await self._log("vuln_scan", "Nuclei not available or not applicable, skipping.")

        # ZAP
        if scope in (ScopeType.WEB, ScopeType.API):
            try:
                if self.zap.is_zap_running():
                    await self._log("vuln_scan", "Running OWASP ZAP scan...")
                    zap_result = await loop.run_in_executor(
                        None, lambda: self.zap.run(target, {"scan_type": "full"})
                    )
                    await self._save_tool_output("zap", PipelineStage.VULN_SCAN, zap_result)
                    if zap_result.findings:
                        await self._save_findings(zap_result.findings)
                    await self._log("vuln_scan", f"ZAP: {len(zap_result.findings)} alerts")
                else:
                    await self._log("vuln_scan", "ZAP daemon not running, skipping ZAP scan.")
            except Exception as e:
                await self._log("vuln_scan", f"ZAP error: {e}")

        # Nikto
        if self.nikto.is_available() and scope in (ScopeType.WEB, ScopeType.API):
            await self._log("vuln_scan", "Running Nikto web server scan...")
            nikto_result = await loop.run_in_executor(
                None, lambda: self.nikto.run(target)
            )
            await self._save_tool_output("nikto", PipelineStage.VULN_SCAN, nikto_result)
            if nikto_result.findings:
                await self._save_findings(nikto_result.findings)
            await self._log("vuln_scan", f"Nikto: {len(nikto_result.findings)} findings")

        # SQLMap (for web/API targets)
        if self.sqlmap.is_available() and scope in (ScopeType.WEB, ScopeType.API):
            await self._log("vuln_scan", "Running SQLMap injection scan...")
            sqlmap_result = await loop.run_in_executor(
                None, lambda: self.sqlmap.run(target, {"forms": True, "level": 2, "risk": 1})
            )
            await self._save_tool_output("sqlmap", PipelineStage.VULN_SCAN, sqlmap_result)
            if sqlmap_result.findings:
                await self._save_findings(sqlmap_result.findings)
            await self._log("vuln_scan", f"SQLMap: {len(sqlmap_result.findings)} findings")

        # API-specific testing
        if scope == ScopeType.API:
            await self._log("vuln_scan", "Running OWASP API Top 10 checks...")
            api_result = await loop.run_in_executor(
                None, lambda: self.api_security.run(target)
            )
            await self._save_tool_output("api_security", PipelineStage.VULN_SCAN, api_result)
            if api_result.findings:
                await self._save_findings(api_result.findings)
            await self._log("vuln_scan", f"API Security: {len(api_result.findings)} findings")

        # ── Dynamic Extensible Catalog Vulnerability Scanning Tools ─────
        open_ports = await self._get_discovered_ports()
        discovered_tech = await self._get_discovered_tech()

        # AI-driven tool recommendation based on current findings
        ai_suggested = []
        try:
            from backend.ai.analysis import AIAnalyzer
            analyzer = AIAnalyzer()
            installed_names = [t.name for t in self.registry.get_detected() if t.tier <= 2]
            current_findings = await self._get_current_findings_summary()
            ai_suggested = await analyzer.suggest_next_tools(current_findings, installed_names, scope.value)
            if ai_suggested:
                await self._log("vuln_scan", f"AI Analyzer queued recommended tools: {', '.join(ai_suggested)}")
        except Exception as e:
            logger.debug("AI tool recommendation step skipped: %s", e)

        dynamic_vuln_tools = self.registry.select_tools_for_pipeline(
            scope_type=scope.value,
            authorized_exploitation=job.authorized_exploitation,
            discovered_ports=open_ports,
            discovered_tech=discovered_tech,
            manual_enabled=(job.enabled_tools or []) + ai_suggested,
            manual_disabled=job.disabled_tools or [],
        )

        already_run = {"nuclei", "zap", "nikto", "sqlmap", "api_security", "nmap", "subfinder", "httpx"}
        for tool_entry in dynamic_vuln_tools:
            if tool_entry.name not in already_run and tool_entry.category in ("web", "enumeration", "scanning"):
                await self._log("vuln_scan", f"Executing dynamic tool [{tool_entry.name}] (Tier {tool_entry.tier})...")
                res = await self.registry.execute_tool(tool_entry, target)
                await self._save_tool_output(tool_entry.name, PipelineStage.VULN_SCAN, res)
                extracted = self._extract_findings_from_catalog_output(tool_entry.name, res, target)
                if extracted:
                    await self._save_findings(extracted)
                await self._log("vuln_scan", f"Dynamic tool [{tool_entry.name}] finished ({res.duration_seconds}s)")

        await self._update_stage(PipelineStage.VULN_SCAN, StageStatus.COMPLETED)
        await self._log("vuln_scan", "Vulnerability scanning phase completed.")

    # ─── Stage 4: Exploitation (Gated) ─────────────────

    async def _run_exploitation(self):
        job = await self._get_job()

        if not job.authorized_exploitation:
            await self._update_stage(PipelineStage.EXPLOITATION, StageStatus.SKIPPED)
            await self._log("exploitation", "Exploitation SKIPPED: not authorized by user.")
            return

        target_ip = self._resolve_target(job.target)
        if not self.settings.is_target_allowlisted(target_ip):
            await self._update_stage(PipelineStage.EXPLOITATION, StageStatus.SKIPPED)
            await self._log("exploitation",
                            f"Exploitation BLOCKED: {job.target} ({target_ip}) not in allowlist.")
            return

        await self._update_stage(PipelineStage.EXPLOITATION, StageStatus.RUNNING)
        await self._log("exploitation", "Starting exploitation phase (LAB TARGETS ONLY)...")

        loop = asyncio.get_event_loop()

        # Gather services/CVEs from recon findings for module search
        services = await self._get_discovered_services()
        cves = await self._get_discovered_cves()

        if self.metasploit.is_available() or True:  # Metasploit might be via Docker
            msf_result = await loop.run_in_executor(
                None, lambda: self.metasploit.run(job.target, {
                    "authorized_exploitation": True,
                    "services": services,
                    "cves": cves,
                    "module_type": "auxiliary",
                    "max_modules": 5,
                })
            )
            await self._save_tool_output("metasploit", PipelineStage.EXPLOITATION, msf_result)
            if msf_result.findings:
                await self._save_findings(msf_result.findings)
            await self._log("exploitation", f"Metasploit: {len(msf_result.findings)} results")

        # Dynamic Tier 3 Tools (Strictly Gated by Authorization & Allowlist)
        tier3_tools = self.registry.select_tools_for_pipeline(
            scope_type=job.scope_type.value,
            authorized_exploitation=True,
            discovered_ports=await self._get_discovered_ports(),
            manual_enabled=job.enabled_tools or [],
            manual_disabled=job.disabled_tools or [],
        )
        already_run = {"sqlmap", "metasploit"}
        for tool_entry in tier3_tools:
            if tool_entry.tier == 3 and tool_entry.name not in already_run:
                await self._log("exploitation", f"Executing authorized Tier 3 tool [{tool_entry.name}]...")
                res = await self.registry.execute_tool(tool_entry, job.target)
                await self._save_tool_output(tool_entry.name, PipelineStage.EXPLOITATION, res)
                extracted = self._extract_findings_from_catalog_output(tool_entry.name, res, job.target)
                if extracted:
                    await self._save_findings(extracted)
                await self._log("exploitation", f"Dynamic Tier 3 tool [{tool_entry.name}] finished ({res.duration_seconds}s)")

        await self._update_stage(PipelineStage.EXPLOITATION, StageStatus.COMPLETED)
        await self._log("exploitation", "Exploitation phase completed.")

    # ─── Stage 5: AI Analysis ──────────────────────────

    async def _run_ai_analysis(self):
        await self._update_stage(PipelineStage.AI_ANALYSIS, StageStatus.RUNNING)
        await self._log("ai_analysis", "Starting AI analysis of findings...")

        try:
            from backend.ai.analysis import AIAnalyzer

            # Gather all findings
            result = await self.session.execute(
                select(Finding).where(Finding.job_id == self.job_id)
            )
            findings = result.scalars().all()

            if not findings:
                await self._log("ai_analysis", "No findings to analyze.")
                await self._update_stage(PipelineStage.AI_ANALYSIS, StageStatus.COMPLETED)
                return

            findings_data = []
            for f in findings:
                findings_data.append({
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value if f.severity else "info",
                    "affected_asset": f.affected_asset,
                    "affected_component": f.affected_component,
                    "source_tool": f.source_tool,
                    "evidence": f.evidence,
                    "cve_ids": f.cve_ids or [],
                    "cwe_ids": f.cwe_ids or [],
                    "cvss_score": f.cvss_score,
                })

            analyzer = AIAnalyzer()
            job = await self._get_job()
            analysis_result = await analyzer.analyze_findings(
                findings_data, job.target, job.scope_type.value
            )

            # Update findings with AI analysis
            if analysis_result:
                job.ai_analysis_result = analysis_result
                job.executive_summary = analysis_result.get("executive_summary", "")

                # Update individual findings
                analyzed = analysis_result.get("findings", [])
                for af in analyzed:
                    fid = af.get("id")
                    if fid:
                        for f in findings:
                            if str(f.id) == fid:
                                f.severity = Severity(af.get("severity", f.severity.value))
                                f.confidence = Confidence(af.get("confidence", "medium"))
                                f.is_false_positive = af.get("is_false_positive", False)
                                f.ai_reasoning = af.get("ai_reasoning", "")
                                f.attack_chain = af.get("attack_chain", "")
                                f.remediation = af.get("remediation", f.remediation or "")
                                f.mitre_tactic = af.get("mitre_tactic", "")
                                f.mitre_technique_id = af.get("mitre_technique_id", "")
                                f.mitre_technique_name = af.get("mitre_technique_name", "")
                                break

                await self.session.commit()
                await self._log("ai_analysis", f"AI analysis complete. {len(analyzed)} findings analyzed.")

        except Exception as e:
            await self._log("ai_analysis", f"AI analysis error: {e}")
            logger.error("AI analysis failed: %s\n%s", e, traceback.format_exc())

        await self._update_stage(PipelineStage.AI_ANALYSIS, StageStatus.COMPLETED)

    # ─── Stage 6: Report Generation ────────────────────

    async def _run_report_generation(self):
        await self._update_stage(PipelineStage.REPORT_GENERATION, StageStatus.RUNNING)
        await self._log("report_gen", "Generating reports...")

        try:
            from backend.reporting.report_builder import ReportBuilder

            job = await self._get_job()
            result = await self.session.execute(
                select(Finding).where(
                    Finding.job_id == self.job_id,
                    Finding.is_false_positive == False,
                )
            )
            findings = result.scalars().all()

            tool_outputs_result = await self.session.execute(
                select(ToolOutput).where(ToolOutput.job_id == self.job_id)
            )
            tool_outputs = tool_outputs_result.scalars().all()

            builder = ReportBuilder()
            report_paths = await builder.generate_all(job, findings, tool_outputs)

            job.report_pdf_path = report_paths.get("pdf", "")
            job.report_json_path = report_paths.get("json", "")
            job.report_md_path = report_paths.get("markdown", "")
            await self.session.commit()

            await self._log("report_gen", f"Reports generated: {', '.join(report_paths.keys())}")
        except Exception as e:
            await self._log("report_gen", f"Report generation error: {e}")
            logger.error("Report generation failed: %s", e, exc_info=True)

        await self._update_stage(PipelineStage.REPORT_GENERATION, StageStatus.COMPLETED)

    # ─── Stage 7: Defensive Rule Generation ────────────

    async def _run_defensive_rules(self):
        await self._update_stage(PipelineStage.DEFENSIVE_RULE_GENERATION, StageStatus.RUNNING)
        await self._log("defensive_rules", "Generating defensive rules...")

        try:
            from backend.defensive.rule_generator import DefensiveRuleGenerator

            result = await self.session.execute(
                select(Finding).where(
                    Finding.job_id == self.job_id,
                    Finding.is_false_positive == False,
                )
            )
            findings = result.scalars().all()

            if not findings:
                await self._log("defensive_rules", "No confirmed findings; skipping rule generation.")
                await self._update_stage(PipelineStage.DEFENSIVE_RULE_GENERATION, StageStatus.COMPLETED)
                return

            generator = DefensiveRuleGenerator()

            for finding in findings:
                if finding.severity.value in ("info",):
                    continue  # Skip info-level findings

                try:
                    rules = await generator.generate_rules(finding)
                    if rules:
                        rule_obj = DefensiveRule(
                            job_id=self.job_id,
                            finding_id=finding.id,
                            sigma_rule=rules.get("sigma", ""),
                            sigma_valid=rules.get("sigma_valid", False),
                            wazuh_rule=rules.get("wazuh", ""),
                            suricata_rule=rules.get("suricata", ""),
                            firewall_rule=rules.get("firewall", ""),
                            mitre_tactic=finding.mitre_tactic,
                            mitre_technique_id=finding.mitre_technique_id,
                            mitre_technique_name=finding.mitre_technique_name,
                        )
                        self.session.add(rule_obj)
                except Exception as e:
                    self.logger.warning("Rule generation failed for finding %s: %s", finding.id, e)

            await self.session.commit()
            await self._log("defensive_rules", "Defensive rules generated.")

        except Exception as e:
            await self._log("defensive_rules", f"Defensive rule generation error: {e}")
            logger.error("Defensive rule generation failed: %s", e, exc_info=True)

        await self._update_stage(PipelineStage.DEFENSIVE_RULE_GENERATION, StageStatus.COMPLETED)

    # ─── Helpers ───────────────────────────────────────

    def _is_ip(self, target: str) -> bool:
        import re
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        clean = target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
        return bool(ip_pattern.match(clean))

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split(":")[0].split("/")[0]

    def _resolve_target(self, target: str) -> str:
        import socket
        hostname = self._extract_domain(target)
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname

    async def _get_discovered_services(self) -> List[Dict]:
        """Get services discovered by Nmap for Metasploit module search."""
        result = await self.session.execute(
            select(ToolOutput).where(
                ToolOutput.job_id == self.job_id,
                ToolOutput.tool_name == "nmap",
            )
        )
        outputs = result.scalars().all()
        services = []
        for output in outputs:
            if output.parsed_output and "hosts" in output.parsed_output:
                for host in output.parsed_output["hosts"]:
                    for port in host.get("ports", []):
                        if port.get("state") == "open":
                            services.append({
                                "port": port.get("port"),
                                "protocol": port.get("protocol"),
                                "service_name": port.get("service_name"),
                                "service_version": port.get("service_version"),
                            })
        return services

    async def _get_discovered_cves(self) -> List[str]:
        """Get CVE IDs from all findings for Metasploit module search."""
        result = await self.session.execute(
            select(Finding).where(Finding.job_id == self.job_id)
        )
        findings = result.scalars().all()
        cves = set()
        for f in findings:
            if f.cve_ids:
                cves.update(f.cve_ids)
        return list(cves)

    async def _get_discovered_ports(self) -> List[int]:
        """Extract open port numbers from Nmap discovery outputs."""
        services = await self._get_discovered_services()
        ports = []
        for s in services:
            p = s.get("port")
            if p is not None:
                try:
                    ports.append(int(p))
                except (ValueError, TypeError):
                    pass
        return ports

    async def _get_discovered_tech(self) -> List[str]:
        """Extract detected technology keywords from existing findings."""
        result = await self.session.execute(
            select(Finding).where(Finding.job_id == self.job_id)
        )
        findings = result.scalars().all()
        tech = set()
        for f in findings:
            combined = f"{f.title} {f.description or ''}".lower()
            for kw in ["wordpress", "drupal", "joomla", "apache", "nginx", "tomcat", "samba", "smb", "iis", "php"]:
                if kw in combined:
                    tech.add(kw)
        return list(tech)

    async def _get_current_findings_summary(self) -> List[Dict]:
        """Get condensed summary of current findings for AI tool recommendation."""
        result = await self.session.execute(
            select(Finding).where(Finding.job_id == self.job_id)
        )
        findings = result.scalars().all()
        return [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "component": f.affected_component or "",
                "tool": f.source_tool or "",
            }
            for f in findings
        ]

    def _extract_findings_from_catalog_output(
        self, tool_name: str, res: ParsedResult, target: str
    ) -> List[Dict]:
        """Convert structured catalog tool outputs into normalized Finding entries."""
        findings = []
        data = res.parsed_data or {}

        if tool_name == "wpscan":
            for f in data.get("findings", []):
                findings.append({
                    "title": f.get("title", "WordPress Vulnerability"),
                    "description": f"Vulnerability detected by WPScan: {f.get('title')}",
                    "severity": f.get("severity", "medium"),
                    "confidence": "high",
                    "affected_asset": target,
                    "affected_component": "WordPress",
                    "evidence": str(f.get("references", "")),
                    "source_tool": "wpscan",
                    "remediation": "Update WordPress core and all installed plugins/themes to their latest patched versions.",
                })

        elif tool_name == "wafw00f":
            if data.get("waf_detected"):
                wafs = ", ".join(data.get("firewalls", ["Unknown WAF"]))
                findings.append({
                    "title": f"Web Application Firewall Detected ({wafs})",
                    "description": f"Target is behind a Web Application Firewall: {wafs}.",
                    "severity": "info",
                    "confidence": "high",
                    "affected_asset": target,
                    "affected_component": "WAF",
                    "source_tool": "wafw00f",
                    "remediation": "Informational finding. Verify WAF inspection rules are tuned against OWASP Top 10.",
                })

        elif tool_name == "whatweb":
            techs = data.get("technologies_found", [])
            if techs:
                findings.append({
                    "title": f"Web Technologies Fingerprinted ({len(techs)} detected)",
                    "description": f"Technologies detected: {', '.join(techs[:15])}",
                    "severity": "info",
                    "confidence": "medium",
                    "affected_asset": target,
                    "affected_component": "Web Server Stack",
                    "source_tool": "whatweb",
                    "remediation": "Remove unnecessary server response headers (Server, X-Powered-By) to prevent technology disclosure.",
                })

        elif tool_name == "gobuster":
            paths = data.get("discovered_paths", [])
            sensitive = [
                p for p in paths 
                if any(s in p.get("path", "").lower() for s in ["admin", "config", "backup", ".git", ".env", "phpinfo", "debug"])
            ]
            if sensitive:
                findings.append({
                    "title": f"Potentially Sensitive Web Directories Exposed ({len(sensitive)} paths)",
                    "description": f"Gobuster discovered accessible endpoints:\n" + "\n".join([f"- {p.get('path')} (Status {p.get('status')})" for p in sensitive[:5]]),
                    "severity": "medium",
                    "confidence": "high",
                    "affected_asset": target,
                    "affected_component": "Web Directory",
                    "evidence": str(sensitive[:10]),
                    "source_tool": "gobuster",
                    "remediation": "Restrict access to administrative and sensitive directories using authentication or IP restriction.",
                })

        elif tool_name == "enum4linux":
            shares = data.get("shares", [])
            if shares:
                findings.append({
                    "title": f"SMB Shares Enumerated ({len(shares)} shares)",
                    "description": f"Enum4linux discovered SMB shares:\n" + "\n".join(shares[:6]),
                    "severity": "medium",
                    "confidence": "medium",
                    "affected_asset": target,
                    "affected_component": "SMB / CIFS",
                    "evidence": "\n".join(shares[:10]),
                    "source_tool": "enum4linux",
                    "remediation": "Restrict SMB share permissions. Disallow null/anonymous sessions.",
                })

        return findings

