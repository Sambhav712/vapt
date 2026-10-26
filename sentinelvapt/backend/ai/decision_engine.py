"""
SentinelVAPT — AI Decision Engine & Tool Selector
Powers the dynamic orchestration loop: evaluates target context, execution history,
accumulated reconnaissance/vulnerabilities, and selects the optimal next tool.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.ai.llm_client import LLMClient
from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.ai.decision_engine")

PROMPTS_DIR = Path(__file__).parent / "prompts"


@dataclass
class AIDecision:
    """Structured decision output from the AI Decision Engine."""
    action: str  # "run_tool", "finish", "need_authorization", "fallback"
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    expected_outcome: str = ""
    confidence: float = 1.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency: float = 0.0
    raw_response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "reasoning": self.reasoning,
            "expected_outcome": self.expected_outcome,
            "confidence": self.confidence,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency": self.latency,
        }


class AIDecisionEngine:
    """
    Intelligent decision engine for dynamically choosing penetration testing tools.
    Acts as the brain of the VAPT pipeline.
    """

    def __init__(self):
        self.settings = get_settings()
        self.llm = LLMClient()
        self.consecutive_failures = 0
        self._prompt_template = self._load_template()

    def _load_template(self) -> str:
        prompt_file = PROMPTS_DIR / "tool_selector_prompt.txt"
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        return (
            "You are the AI Decision Engine for SentinelVAPT. Select the next security tool or finish the scan."
        )

    def _format_available_tools(self, tools: List[Dict[str, Any]]) -> str:
        """Format catalog tools into a concise Markdown summary for the LLM."""
        lines = []
        for t in tools:
            lines.append(
                f"- **{t['name']}** (Category: {t.get('category', 'general')}, "
                f"Tier: {t.get('tier', 1)}): {t.get('description', '')}"
            )
        return "\n".join(lines) if lines else "No tools available."

    def _format_execution_history(self, history: List[Dict[str, Any]]) -> str:
        """Format past tool executions for the LLM."""
        if not history:
            return "No tools executed yet. This is iteration 1."
        lines = []
        for idx, h in enumerate(history, 1):
            tool = h.get("tool_name", "unknown")
            success = "Success" if h.get("success", True) else "Failed"
            duration = round(h.get("duration_seconds", 0.0), 1)
            findings_count = h.get("findings_count", 0)
            summary = h.get("summary", "Finished execution")
            lines.append(
                f"{idx}. [{tool}] ({success}, {duration}s) -> {findings_count} findings. Note: {summary}"
            )
        return "\n".join(lines)

    def _format_accumulated_knowledge(self, knowledge: Dict[str, Any]) -> str:
        """Format discovered attack surface and findings into structured text."""
        subdomains = knowledge.get("subdomains", [])
        ports = knowledge.get("open_ports", [])
        services = knowledge.get("services", [])
        techs = knowledge.get("technologies", [])
        waf = knowledge.get("waf", "None detected / Not yet tested")
        endpoints = knowledge.get("endpoints", [])
        findings = knowledge.get("findings", [])

        sections = []
        if subdomains:
            sections.append(f"- Subdomains ({len(subdomains)}): {', '.join(subdomains[:15])}")
        else:
            sections.append("- Subdomains: None discovered yet")

        if ports or services:
            svc_strs = [f"{s.get('port')}/{s.get('protocol', 'tcp')} ({s.get('service_name', 'unknown')} {s.get('service_version', '')})".strip() for s in services]
            sections.append(f"- Open Ports & Services: {', '.join(svc_strs[:20]) if svc_strs else ', '.join(map(str, ports[:20]))}")
        else:
            sections.append("- Open Ports & Services: No port scan results yet")

        if techs:
            sections.append(f"- Detected Technologies: {', '.join(techs[:20])}")
        else:
            sections.append("- Detected Technologies: None identified yet")

        sections.append(f"- Web Application Firewall (WAF): {waf}")

        if endpoints:
            sections.append(f"- Discovered Endpoints/Paths ({len(endpoints)}): {', '.join(endpoints[:10])}")

        if findings:
            f_summaries = [f"[{f.get('severity', 'info').upper()}] {f.get('title')}" for f in findings[:15]]
            sections.append(f"- Key Findings ({len(findings)} total):\n  " + "\n  ".join(f_summaries))
        else:
            sections.append("- Current Vulnerabilities: 0 confirmed findings")

        return "\n".join(sections)

    def build_user_prompt(
        self,
        target: str,
        scope_type: str,
        authorized_exploitation: bool,
        available_tools: List[Dict[str, Any]],
        execution_history: List[Dict[str, Any]],
        accumulated_knowledge: Dict[str, Any],
        iteration: int,
        max_iterations: int,
    ) -> str:
        """Construct the prompt sent to the LLM on each orchestration cycle."""
        auth_level = (
            "EXPLOITATION ALLOWED (Tier 3 Active Exploitation & Proof-of-Concept Authorized)"
            if authorized_exploitation
            else "ACTIVE SCANNING ONLY (Passive Recon & Non-destructive Scans Allowed; Tier 3 Exploits Strictly Blocked)"
        )

        tools_str = self._format_available_tools(available_tools)
        history_str = self._format_execution_history(execution_history)
        knowledge_str = self._format_accumulated_knowledge(accumulated_knowledge)

        prompt = f"""
====================================================================
CURRENT SCAN STATE — ITERATION {iteration} OF {max_iterations}
====================================================================
TARGET: {target}
SCOPE TYPE: {scope_type.upper()}
AUTHORIZATION LEVEL: {auth_level}

GOAL:
Perform a comprehensive, methodical security assessment. Progress through discovery,
attack surface enumeration, targeted vulnerability scanning, and verification.
When you have collected adequate evidence across the surface, select action "finish".

AVAILABLE REGISTERED TOOLS:
{tools_str}

EXECUTION HISTORY SO FAR:
{history_str}

ACCUMULATED KNOWLEDGE BASE:
{knowledge_str}

DECISION INSTRUCTIONS:
1. Review what has already been run and what has been discovered.
2. Choose the single most effective next tool, or "finish" if assessment is complete.
3. If exploitation is NOT authorized and a Tier 3 exploit tool is needed, respond with "need_authorization".
4. Respond ONLY with the requested JSON object.
"""
        return prompt.strip()

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Safely extract JSON object from text even if markdown-wrapped."""
        if not text:
            return None
        text = text.strip()
        # Direct parse
        try:
            return json.loads(text)
        except Exception:
            pass

        # Check for ```json codeblocks
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass

        # Check for any { ... } block
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass

        return None

    def _generate_heuristic_fallback(
        self,
        target: str,
        scope_type: str,
        available_tool_names: Set[str],
        executed_tools: Set[str],
        accumulated_knowledge: Dict[str, Any],
        iteration: int,
    ) -> AIDecision:
        """
        Sensible fallback sequence if LLM fails or is unavailable.
        Sequence: whatweb/wafw00f -> nmap -> nuclei -> nikto/zap -> finish
        """
        logger.warning(
            "AI Decision Engine: triggering heuristic fallback decision for iteration %d",
            iteration,
        )

        # Standard web/api sequence
        candidate_sequence = []
        if scope_type in ("web", "api"):
            candidate_sequence = [
                ("whatweb", {"target": target}, "Fingerprint web application stack and technologies"),
                ("wafw00f", {"target": target}, "Detect presence of Web Application Firewall"),
                ("nmap", {"target": target}, "Scan target for open web and infrastructure ports"),
                ("nuclei", {"target": target}, "Execute vulnerability templates against target"),
                ("nikto", {"target": target}, "Scan web server for known vulnerabilities and misconfigurations"),
                ("sqlmap", {"target": target}, "Check web parameters for SQL injection vulnerabilities"),
            ]
        else:
            candidate_sequence = [
                ("nmap", {"target": target}, "Full network port and service version discovery"),
                ("nuclei", {"target": target}, "Scan discovered services for known vulnerabilities"),
            ]

        for tool_name, args, rationale in candidate_sequence:
            if tool_name in available_tool_names and tool_name not in executed_tools:
                return AIDecision(
                    action="run_tool",
                    tool_name=tool_name,
                    tool_args=args,
                    reasoning=f"[Heuristic Fallback] AI unavailable. Executing standard security sequence: {rationale}.",
                    expected_outcome=f"Collect baseline {tool_name} telemetry for target.",
                    confidence=0.80,
                    raw_response="HEURISTIC_FALLBACK",
                )

        # If all candidates executed or unavailable, finish
        return AIDecision(
            action="finish",
            tool_name=None,
            tool_args={},
            reasoning="[Heuristic Fallback] Baseline security tool sequence completed.",
            expected_outcome="Proceed to post-processing and report generation.",
            confidence=0.90,
            raw_response="HEURISTIC_FALLBACK",
        )

    async def decide_next_step(
        self,
        target: str,
        scope_type: str,
        authorized_exploitation: bool,
        available_tools: List[Dict[str, Any]],
        execution_history: List[Dict[str, Any]],
        accumulated_knowledge: Dict[str, Any],
        iteration: int,
        max_iterations: int,
    ) -> AIDecision:
        """
        Main entrypoint: Calls LLM with comprehensive context, validates
        output, applies safety guardrails, and returns structured AIDecision.
        """
        available_tool_map = {t["name"].lower(): t for t in available_tools}
        available_names = set(available_tool_map.keys())
        executed_names = {h.get("tool_name", "").lower() for h in execution_history}

        # If consecutive failures exceed threshold, jump straight to heuristic fallback
        if self.consecutive_failures >= 3:
            logger.warning(
                "AI Decision Engine: %d consecutive failures, using heuristic fallback.",
                self.consecutive_failures,
            )
            return self._generate_heuristic_fallback(
                target, scope_type, available_names, executed_names, accumulated_knowledge, iteration
            )

        user_prompt = self.build_user_prompt(
            target=target,
            scope_type=scope_type,
            authorized_exploitation=authorized_exploitation,
            available_tools=available_tools,
            execution_history=execution_history,
            accumulated_knowledge=accumulated_knowledge,
            iteration=iteration,
            max_iterations=max_iterations,
        )

        start_time = time.time()
        raw_output = None
        try:
            raw_output = await self.llm.generate(
                prompt=user_prompt,
                system_prompt=self._prompt_template,
                json_mode=True,
                max_retries=2,
            )
        except Exception as e:
            logger.error("LLM generate call failed: %s", e)

        latency = time.time() - start_time

        # Extract tokens and metrics
        last_log = self.llm.get_call_log()
        prompt_tokens = 0
        completion_tokens = 0
        if last_log:
            latest = last_log[-1]
            prompt_tokens = latest.get("estimated_tokens", 0) // 2
            completion_tokens = latest.get("estimated_tokens", 0) // 2

        if not raw_output:
            self.consecutive_failures += 1
            logger.warning(
                "LLM returned no response (failures=%d).", self.consecutive_failures
            )
            fallback = self._generate_heuristic_fallback(
                target, scope_type, available_names, executed_names, accumulated_knowledge, iteration
            )
            fallback.latency = latency
            return fallback

        data = self._extract_json(raw_output)
        if not data or not isinstance(data, dict):
            self.consecutive_failures += 1
            logger.warning("LLM response could not be parsed as JSON: %s", raw_output[:200])
            fallback = self._generate_heuristic_fallback(
                target, scope_type, available_names, executed_names, accumulated_knowledge, iteration
            )
            fallback.latency = latency
            fallback.raw_response = raw_output
            return fallback

        action = str(data.get("action", "run_tool")).strip().lower()
        tool_name = data.get("tool_name")
        tool_name_clean = str(tool_name).strip().lower() if tool_name else None
        tool_args = data.get("tool_args", {})
        if not isinstance(tool_args, dict):
            tool_args = {"target": target}
        if "target" not in tool_args:
            tool_args["target"] = target

        reasoning = str(data.get("reasoning", "")).strip()
        expected_outcome = str(data.get("expected_outcome", "")).strip()
        confidence = float(data.get("confidence", 0.9))

        # Reset consecutive failure counter upon successful parse
        self.consecutive_failures = 0

        # Action: finish
        if action == "finish" or tool_name_clean in ("finish", "done", "none", "null"):
            return AIDecision(
                action="finish",
                tool_name=None,
                tool_args={},
                reasoning=reasoning or "AI assessed that comprehensive data collection is complete.",
                expected_outcome=expected_outcome or "Proceed to vulnerability analysis and reporting.",
                confidence=confidence,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency=latency,
                raw_response=raw_output,
            )

        # Hallucination Protection: Tool must exist in available_tools
        if tool_name_clean not in available_names:
            logger.warning(
                "Hallucination protection: AI chose unregistered tool '%s'. Available: %s",
                tool_name_clean,
                list(available_names),
            )
            # Pick valid fallback
            fallback = self._generate_heuristic_fallback(
                target, scope_type, available_names, executed_names, accumulated_knowledge, iteration
            )
            fallback.reasoning = (
                f"AI suggested unregistered tool '{tool_name}'. Substituted with '{fallback.tool_name}'."
            )
            fallback.latency = latency
            fallback.raw_response = raw_output
            return fallback

        # Exploitation Gate & Authorization Guardrail
        chosen_entry = available_tool_map[tool_name_clean]
        is_tier_3 = chosen_entry.get("tier", 1) == 3

        if is_tier_3 and not authorized_exploitation:
            logger.warning(
                "Exploitation gate: AI requested Tier 3 tool '%s' without exploitation authorization.",
                tool_name_clean,
            )
            return AIDecision(
                action="need_authorization",
                tool_name=tool_name_clean,
                tool_args=tool_args,
                reasoning=(
                    f"AI requested Tier 3 tool '{tool_name_clean}' ({reasoning}). "
                    "Exploitation authorization is disabled for this job."
                ),
                expected_outcome=expected_outcome or "Exploitation verification requires explicit user authorization.",
                confidence=confidence,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency=latency,
                raw_response=raw_output,
            )

        # Loop Prevention: Don't repeat the exact same tool if already executed,
        # unless AI gives clear justification or different args
        if tool_name_clean in executed_names:
            # Check if this tool has already been run multiple times or if args are identical
            past_runs_for_tool = [h for h in execution_history if h.get("tool_name", "").lower() == tool_name_clean]
            if len(past_runs_for_tool) >= 2:
                logger.warning("Loop prevention: Tool '%s' has already run twice.", tool_name_clean)
                fallback = self._generate_heuristic_fallback(
                    target, scope_type, available_names, executed_names, accumulated_knowledge, iteration
                )
                if fallback.tool_name != tool_name_clean:
                    fallback.reasoning = (
                        f"Prevented loop on repeated tool '{tool_name_clean}'. " + fallback.reasoning
                    )
                    return fallback

        return AIDecision(
            action="run_tool",
            tool_name=tool_name_clean,
            tool_args=tool_args,
            reasoning=reasoning or f"Executing {tool_name_clean} to gather security intelligence.",
            expected_outcome=expected_outcome or f"Discover attack surface or vulnerabilities via {tool_name_clean}.",
            confidence=confidence,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency=latency,
            raw_response=raw_output,
        )
