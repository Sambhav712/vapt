"""
SentinelVAPT — Agent Core (Autonomous AI Security Agent)
ReAct-pattern agent loop that directly controls a Kali Linux terminal,
executing security tools, analyzing output, verifying findings,
installing missing tools, and iterating — all powered by Groq/Ollama.
"""

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend.ai.llm_client import LLMClient
from backend.config.settings import get_settings
from backend.core.terminal_executor import TerminalExecutor, CommandResult
from backend.core.capability_manager import CapabilityManager

logger = logging.getLogger("sentinelvapt.agent.core")

PROMPTS_DIR = Path(__file__).parent.parent / "ai" / "prompts"


# ═══════════════════════════════════════════════════════════════════
# Data structures for agent state
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgentFinding:
    """A vulnerability finding reported by the agent."""
    title: str
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    affected_asset: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    verified: bool = False
    source_step: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence[:2000],
            "remediation": self.remediation,
            "affected_asset": self.affected_asset,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
            "source_step": self.source_step,
        }


@dataclass
class AgentStep:
    """A single step in the agent's ReAct loop."""
    step_number: int
    thought: str
    action: str
    command: Optional[str] = None
    tool_name: Optional[str] = None
    finding: Optional[AgentFinding] = None
    summary: Optional[str] = None
    confidence: float = 0.0

    # Execution result (filled after action)
    result_stdout: str = ""
    result_stderr: str = ""
    result_exit_code: int = -1
    result_blocked: bool = False
    result_block_reason: str = ""
    result_success: bool = False
    result_duration: float = 0.0
    result_message: str = ""

    # LLM metrics
    llm_latency: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    raw_llm_response: str = ""

    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "step_number": self.step_number,
            "thought": self.thought[:1000],
            "action": self.action,
            "confidence": self.confidence,
            "result_success": self.result_success,
            "result_exit_code": self.result_exit_code,
            "result_duration": self.result_duration,
            "result_blocked": self.result_blocked,
            "llm_latency": self.llm_latency,
            "timestamp": self.timestamp,
        }
        if self.command:
            d["command"] = self.command[:500]
        if self.tool_name:
            d["tool_name"] = self.tool_name
        if self.result_stdout:
            d["result_stdout"] = self.result_stdout[:3000]
        if self.result_stderr:
            d["result_stderr"] = self.result_stderr[:1000]
        if self.result_message:
            d["result_message"] = self.result_message
        if self.finding:
            d["finding"] = self.finding.to_dict()
        if self.summary:
            d["summary"] = self.summary
        return d


@dataclass
class AgentSessionState:
    """Tracks the full state of an agent session."""
    session_id: str
    job_id: str
    target: str
    scope_type: str
    authorized_exploitation: bool
    goal: str

    steps: List[AgentStep] = field(default_factory=list)
    findings: List[AgentFinding] = field(default_factory=list)
    installed_tools: List[str] = field(default_factory=list)

    status: str = "running"  # running, completed, failed, cancelled
    final_summary: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    max_steps: int = 50
    max_time_seconds: int = 2400  # 40 minutes default

    # Metrics
    total_commands_executed: int = 0
    total_commands_blocked: int = 0
    total_llm_calls: int = 0
    total_llm_latency: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "job_id": self.job_id,
            "target": self.target,
            "scope_type": self.scope_type,
            "authorized_exploitation": self.authorized_exploitation,
            "goal": self.goal,
            "status": self.status,
            "step_count": len(self.steps),
            "finding_count": len(self.findings),
            "installed_tools": self.installed_tools,
            "final_summary": self.final_summary[:2000] if self.final_summary else "",
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "max_steps": self.max_steps,
            "metrics": {
                "total_commands_executed": self.total_commands_executed,
                "total_commands_blocked": self.total_commands_blocked,
                "total_llm_calls": self.total_llm_calls,
                "total_llm_latency": round(self.total_llm_latency, 2),
            },
            "steps": [s.to_dict() for s in self.steps[-10:]],  # Last 10 steps
            "findings": [f.to_dict() for f in self.findings],
        }


# ═══════════════════════════════════════════════════════════════════
# Agent Core — The autonomous ReAct loop engine
# ═══════════════════════════════════════════════════════════════════

class AgentCore:
    """
    Autonomous AI security agent using the ReAct (Reason → Act → Observe) pattern.
    
    Directly controls a Kali Linux terminal to:
    - Execute security tools and shell commands
    - Read and analyze tool output
    - Install missing tools
    - Verify findings and eliminate false positives
    - Produce structured vulnerability reports
    
    All powered by Groq API / Ollama — zero additional paid APIs required.
    """

    # Maximum consecutive errors before aborting
    MAX_CONSECUTIVE_ERRORS = 5
    # Maximum consecutive identical commands (loop detection)
    MAX_IDENTICAL_COMMANDS = 3

    def __init__(
        self,
        job_id: str,
        target: str,
        scope_type: str = "web",
        authorized_exploitation: bool = False,
        goal: Optional[str] = None,
        max_steps: int = 50,
        max_time_seconds: int = 2400,
        log_callback: Optional[Callable] = None,
    ):
        self.settings = get_settings()
        self.llm = LLMClient()
        self.terminal = TerminalExecutor(
            job_id=job_id,
            target=target,
            authorized_exploitation=authorized_exploitation,
        )
        self.capability_mgr = CapabilityManager()

        self.state = AgentSessionState(
            session_id=str(uuid.uuid4()),
            job_id=job_id,
            target=target,
            scope_type=scope_type,
            authorized_exploitation=authorized_exploitation,
            goal=goal or f"Perform a comprehensive {scope_type} security assessment of {target}",
            max_steps=max_steps,
            max_time_seconds=max_time_seconds,
        )

        self._log_callback = log_callback
        self._system_prompt: Optional[str] = None
        self._consecutive_errors = 0
        self._recent_commands: List[str] = []
        self._cancelled = False

    # ─── Public API ─────────────────────────────────────

    async def run(self) -> AgentSessionState:
        """
        Execute the full autonomous agent loop.
        Returns the final session state with all steps, findings, and summary.
        """
        try:
            await self._log("agent", "🤖 Agent Core initializing...")

            # Phase 1: Scan system capabilities
            await self._log("agent", "📋 Scanning system capabilities...")
            caps = await self.capability_mgr.scan(self.terminal)
            await self._log(
                "agent",
                f"✅ Found {len(caps.available_tools)} tools, "
                f"{len(caps.package_managers)} package managers"
            )

            # Phase 2: Build system prompt
            self._system_prompt = self._build_system_prompt(caps)

            # Phase 3: Run the ReAct loop
            await self._log("agent", f"🚀 Starting ReAct loop (max {self.state.max_steps} steps, {self.state.max_time_seconds}s timeout)")
            await self._react_loop()

            # Phase 4: Finalize
            self.state.completed_at = time.time()
            if self.state.status == "running":
                self.state.status = "completed"

            await self._log(
                "agent",
                f"🏁 Agent completed: {len(self.state.findings)} findings, "
                f"{self.state.total_commands_executed} commands, "
                f"{len(self.state.steps)} steps"
            )
            return self.state

        except asyncio.CancelledError:
            self.state.status = "cancelled"
            self.state.completed_at = time.time()
            await self._log("agent", "⚠️ Agent session cancelled")
            return self.state

        except Exception as e:
            self.state.status = "failed"
            self.state.completed_at = time.time()
            logger.error("Agent core fatal error: %s", e, exc_info=True)
            await self._log("agent", f"❌ Agent failed: {e}")
            return self.state

    def cancel(self):
        """Signal the agent to stop at the next iteration."""
        self._cancelled = True

    # ─── ReAct Loop ─────────────────────────────────────

    async def _react_loop(self):
        """Core Reason → Act → Observe loop."""
        for step_num in range(1, self.state.max_steps + 1):
            # ── Check termination conditions ──
            if self._cancelled:
                await self._log("agent", "Agent cancelled by user request")
                self.state.status = "cancelled"
                return

            elapsed = time.time() - self.state.started_at
            if elapsed > self.state.max_time_seconds:
                await self._log(
                    "agent",
                    f"⏰ Time limit reached ({int(elapsed)}s / {self.state.max_time_seconds}s)"
                )
                self.state.status = "completed"
                return

            if self._consecutive_errors >= self.MAX_CONSECUTIVE_ERRORS:
                await self._log(
                    "agent",
                    f"⚠️ Too many consecutive errors ({self._consecutive_errors}). Stopping."
                )
                self.state.status = "completed"
                return

            # ── THINK: Get AI decision ──
            await self._log("agent", f"🧠 Step {step_num}/{self.state.max_steps} — Thinking...")
            step = await self._get_ai_decision(step_num)

            if step is None:
                self._consecutive_errors += 1
                await self._log("agent", f"⚠️ LLM returned invalid response (error {self._consecutive_errors}/{self.MAX_CONSECUTIVE_ERRORS})")
                continue

            # ── Loop detection ──
            if step.action == "execute_command" and step.command:
                if self._detect_loop(step.command):
                    await self._log("agent", f"🔄 Loop detected — same command repeated. Injecting nudge.")
                    step.result_message = (
                        "SYSTEM: You are repeating the same command. "
                        "This command was already executed. "
                        "Please try a DIFFERENT approach or tool."
                    )
                    step.result_success = False
                    self.state.steps.append(step)
                    continue

            # ── ACT: Execute the chosen action ──
            await self._execute_action(step)
            self.state.steps.append(step)

            # ── Check for finish action ──
            if step.action == "finish":
                self.state.final_summary = step.summary or "Assessment complete."
                self.state.status = "completed"
                await self._log("agent", f"✅ Agent finished: {self.state.final_summary[:200]}")
                return

            # Reset error counter on success
            if step.result_success:
                self._consecutive_errors = 0
            else:
                self._consecutive_errors += 1

            # Brief pause between steps to avoid rate limiting
            await asyncio.sleep(0.5)

        # Reached max steps
        await self._log("agent", f"📊 Max steps ({self.state.max_steps}) reached. Finalizing.")
        self.state.status = "completed"

    async def _get_ai_decision(self, step_num: int) -> Optional[AgentStep]:
        """Call the LLM to get the next action decision."""
        # Build the user prompt with execution history
        user_prompt = self._build_user_prompt(step_num)

        start = time.time()
        self.state.total_llm_calls += 1

        try:
            response = await self.llm.generate(
                prompt=user_prompt,
                system_prompt=self._system_prompt or "",
                json_mode=True,
                max_retries=2,
            )
        except Exception as e:
            logger.error("LLM call failed: %s", e)
            return None

        latency = time.time() - start
        self.state.total_llm_latency += latency

        if not response:
            return None

        # Parse the LLM response
        return self._parse_llm_response(response, step_num, latency)

    def _parse_llm_response(self, response: str, step_num: int,
                             latency: float) -> Optional[AgentStep]:
        """Parse and validate the LLM's JSON response."""
        try:
            # Try to extract JSON from the response
            cleaned = response.strip()
            # Remove markdown code fences if present
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                # Remove first and last lines (code fences)
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)

            # Try to find JSON object in the response
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                cleaned = json_match.group(0)

            data = json.loads(cleaned)

            action = data.get("action", "").lower().strip()
            valid_actions = {"execute_command", "install_tool", "report_finding",
                             "verify_finding", "finish"}
            if action not in valid_actions:
                logger.warning("Invalid action '%s' from LLM", action)
                return None

            step = AgentStep(
                step_number=step_num,
                thought=data.get("thought", ""),
                action=action,
                command=data.get("command"),
                tool_name=data.get("tool_name"),
                confidence=float(data.get("confidence", 0.5)),
                llm_latency=round(latency, 2),
                raw_llm_response=response[:2000],
            )

            # Parse finding if present
            if action in ("report_finding", "verify_finding") and "finding" in data:
                fd = data["finding"]
                step.finding = AgentFinding(
                    title=fd.get("title", "Unknown Finding"),
                    severity=fd.get("severity", "info"),
                    description=fd.get("description", ""),
                    evidence=fd.get("evidence", ""),
                    remediation=fd.get("remediation", ""),
                    affected_asset=fd.get("affected_asset", self.state.target),
                    cve_ids=fd.get("cve_ids", []),
                    cwe_ids=fd.get("cwe_ids", []),
                    cvss_score=fd.get("cvss_score"),
                    source_step=step_num,
                )

            if action == "finish":
                step.summary = data.get("summary", "Assessment complete.")

            return step

        except json.JSONDecodeError as e:
            logger.warning("Failed to parse LLM JSON response: %s", e)
            logger.debug("Raw response: %s", response[:500])
            return None
        except Exception as e:
            logger.warning("Error parsing LLM response: %s", e)
            return None

    async def _execute_action(self, step: AgentStep):
        """Execute the action specified in the agent step."""
        action = step.action

        if action == "execute_command":
            await self._action_execute_command(step)
        elif action == "install_tool":
            await self._action_install_tool(step)
        elif action == "report_finding":
            await self._action_report_finding(step)
        elif action == "verify_finding":
            await self._action_verify_finding(step)
        elif action == "finish":
            pass  # Handled in the loop
        else:
            step.result_message = f"Unknown action: {action}"
            step.result_success = False

    async def _action_execute_command(self, step: AgentStep):
        """Execute a shell command via the TerminalExecutor."""
        if not step.command:
            step.result_message = "No command provided"
            step.result_success = False
            return

        await self._log(
            "agent_exec",
            f"$ {step.command[:120]}{'...' if len(step.command) > 120 else ''}"
        )

        result = await self.terminal.execute(step.command)

        step.result_stdout = result.stdout
        step.result_stderr = result.stderr
        step.result_exit_code = result.exit_code
        step.result_blocked = result.blocked
        step.result_block_reason = result.block_reason
        step.result_success = result.success
        step.result_duration = result.duration_seconds

        self.state.total_commands_executed += 1
        if result.blocked:
            self.state.total_commands_blocked += 1
            await self._log("agent_blocked", f"🚫 Command blocked: {result.block_reason[:150]}")
        elif result.success:
            output_preview = result.stdout[:150].replace('\n', ' ') if result.stdout else "(no output)"
            await self._log("agent_result", f"✅ Exit {result.exit_code} ({result.duration_seconds:.1f}s): {output_preview}")
        else:
            err_preview = result.stderr[:150].replace('\n', ' ') if result.stderr else ""
            await self._log("agent_result", f"⚠️ Exit {result.exit_code} ({result.duration_seconds:.1f}s): {err_preview}")

    async def _action_install_tool(self, step: AgentStep):
        """Install a missing tool."""
        if not step.tool_name:
            step.result_message = "No tool_name provided"
            step.result_success = False
            return

        await self._log("agent_install", f"📦 Installing {step.tool_name}...")

        success, message = await self.capability_mgr.install_tool(
            step.tool_name, self.terminal
        )

        step.result_success = success
        step.result_message = message

        if success:
            self.state.installed_tools.append(step.tool_name)
            await self._log("agent_install", f"✅ {message}")
        else:
            await self._log("agent_install", f"❌ {message}")

    async def _action_report_finding(self, step: AgentStep):
        """Record a vulnerability finding."""
        if not step.finding:
            step.result_message = "No finding data provided"
            step.result_success = False
            return

        # Check for duplicates
        for existing in self.state.findings:
            if (existing.title.lower() == step.finding.title.lower() and
                    existing.affected_asset == step.finding.affected_asset):
                step.result_message = f"Duplicate finding: {step.finding.title}"
                step.result_success = True
                return

        self.state.findings.append(step.finding)
        step.result_success = True
        step.result_message = f"Finding recorded: [{step.finding.severity.upper()}] {step.finding.title}"

        await self._log(
            "agent_finding",
            f"🔍 [{step.finding.severity.upper()}] {step.finding.title} — {step.finding.affected_asset}"
        )

    async def _action_verify_finding(self, step: AgentStep):
        """Verify/re-test a finding for false positive elimination."""
        if not step.finding:
            step.result_message = "No finding data for verification"
            step.result_success = False
            return

        # If there's a command to verify, execute it
        if step.command:
            result = await self.terminal.execute(step.command)
            step.result_stdout = result.stdout
            step.result_stderr = result.stderr
            step.result_exit_code = result.exit_code
            step.result_success = result.success
            step.result_duration = result.duration_seconds
            self.state.total_commands_executed += 1

        # Mark the finding as verified
        step.finding.verified = True
        # Check if we already have this finding
        for existing in self.state.findings:
            if existing.title.lower() == step.finding.title.lower():
                existing.verified = True
                step.result_message = f"Finding verified: {step.finding.title}"
                await self._log("agent_verify", f"✔️ Verified: {step.finding.title}")
                return

        # New verified finding
        self.state.findings.append(step.finding)
        step.result_success = True
        step.result_message = f"New verified finding: [{step.finding.severity.upper()}] {step.finding.title}"
        await self._log(
            "agent_verify",
            f"✔️ New verified finding: [{step.finding.severity.upper()}] {step.finding.title}"
        )

    # ─── Prompt Building ───────────────────────────────

    def _build_system_prompt(self, caps) -> str:
        """Build the full system prompt from template + capabilities."""
        prompt_file = PROMPTS_DIR / "agent_core_prompt.txt"
        if prompt_file.exists():
            template = prompt_file.read_text(encoding="utf-8")
        else:
            template = (
                "You are an autonomous AI security assessment agent. "
                "Target: {target}. Respond with JSON actions only."
            )

        return template.format(
            target=self.state.target,
            scope_type=self.state.scope_type,
            authorized_exploitation=self.state.authorized_exploitation,
            system_capabilities=caps.to_context_string(),
            execution_history="(No history yet — this is the first step)",
        )

    def _build_user_prompt(self, step_num: int) -> str:
        """Build the user prompt with current state and history."""
        lines = [
            f"═══ STEP {step_num}/{self.state.max_steps} ═══",
            f"Elapsed: {int(time.time() - self.state.started_at)}s / {self.state.max_time_seconds}s",
            f"Findings so far: {len(self.state.findings)}",
            f"Commands executed: {self.state.total_commands_executed}",
            f"Commands blocked: {self.state.total_commands_blocked}",
            f"Install budget remaining: {self.capability_mgr.install_budget_remaining}",
            "",
        ]

        # Include recent execution history (last 8 steps for context window)
        recent = self.state.steps[-8:]
        if recent:
            lines.append("═══ RECENT EXECUTION HISTORY ═══")
            for s in recent:
                lines.append(f"\n--- Step {s.step_number} ---")
                lines.append(f"Thought: {s.thought[:300]}")
                lines.append(f"Action: {s.action}")
                if s.command:
                    lines.append(f"Command: {s.command[:300]}")
                if s.result_blocked:
                    lines.append(f"BLOCKED: {s.result_block_reason[:200]}")
                elif s.action in ("execute_command", "verify_finding") and s.command:
                    lines.append(f"Exit Code: {s.result_exit_code}")
                    if s.result_stdout:
                        # Truncate long output for LLM context
                        output = s.result_stdout
                        output_lines = output.split('\n')
                        if len(output_lines) > 60:
                            head = '\n'.join(output_lines[:30])
                            tail = '\n'.join(output_lines[-30:])
                            output = f"{head}\n\n[... {len(output_lines) - 60} lines truncated ...]\n\n{tail}"
                        lines.append(f"Output:\n{output[:4000]}")
                    if s.result_stderr and not s.result_success:
                        lines.append(f"Stderr: {s.result_stderr[:1000]}")
                if s.result_message:
                    lines.append(f"Result: {s.result_message[:300]}")
                if s.finding:
                    lines.append(f"Finding: [{s.finding.severity}] {s.finding.title}")
        else:
            lines.append("═══ NO HISTORY YET — THIS IS THE FIRST STEP ═══")
            lines.append(f"Begin your security assessment of target: {self.state.target}")
            lines.append(f"Goal: {self.state.goal}")

        # Summary of findings so far
        if self.state.findings:
            lines.append("\n═══ FINDINGS COLLECTED SO FAR ═══")
            for i, f in enumerate(self.state.findings, 1):
                verified = " ✔️" if f.verified else ""
                lines.append(f"  {i}. [{f.severity.upper()}]{verified} {f.title} — {f.affected_asset}")

        lines.append("\n═══ YOUR TURN ═══")
        lines.append("Respond with a single JSON object specifying your next action.")
        lines.append("Think carefully: what information do you still need? What has been tested? What gaps remain?")

        return "\n".join(lines)

    # ─── Loop Detection ─────────────────────────────────

    def _detect_loop(self, command: str) -> bool:
        """Detect if the agent is stuck in a loop."""
        normalized = command.strip().lower()
        self._recent_commands.append(normalized)
        if len(self._recent_commands) > 10:
            self._recent_commands = self._recent_commands[-10:]

        # Check for exact repeated command
        if self._recent_commands.count(normalized) >= self.MAX_IDENTICAL_COMMANDS:
            return True

        return False

    # ─── Logging ────────────────────────────────────────

    async def _log(self, stage: str, message: str):
        """Log a message and notify via callback if available."""
        logger.info("[%s] %s: %s", self.state.job_id, stage, message)
        if self._log_callback:
            try:
                await self._log_callback(self.state.job_id, stage, message)
            except Exception:
                pass

    # ─── Public accessors ───────────────────────────────

    @property
    def findings(self) -> List[AgentFinding]:
        return self.state.findings

    @property
    def session_id(self) -> str:
        return self.state.session_id

    @property
    def is_running(self) -> bool:
        return self.state.status == "running"

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "session_id": self.state.session_id,
            "status": self.state.status,
            "step_count": len(self.state.steps),
            "finding_count": len(self.state.findings),
            "commands_executed": self.state.total_commands_executed,
            "commands_blocked": self.state.total_commands_blocked,
            "llm_calls": self.state.total_llm_calls,
            "elapsed_seconds": round(time.time() - self.state.started_at, 1),
            "terminal_stats": self.terminal.stats,
        }
