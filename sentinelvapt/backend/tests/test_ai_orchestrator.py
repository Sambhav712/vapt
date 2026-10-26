"""
Unit and integration tests for SentinelVAPT AI-Driven Orchestrator & Decision Engine.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch

from backend.ai.decision_engine import AIDecisionEngine, AIDecision
from backend.db.models import Job, AIDecisionLog, PipelineStage, ScopeType


@pytest.fixture
def decision_engine():
    engine = AIDecisionEngine()
    return engine


@pytest.fixture
def sample_catalog():
    return [
        {
            "name": "whatweb",
            "category": "recon",
            "tier": 1,
            "description": "Web scanner for technology and CMS fingerprinting",
        },
        {
            "name": "wafw00f",
            "category": "recon",
            "tier": 1,
            "description": "WAF fingerprinting and detection",
        },
        {
            "name": "nmap",
            "category": "network",
            "tier": 1,
            "description": "Port scanning and service detection",
        },
        {
            "name": "nuclei",
            "category": "vuln_scan",
            "tier": 2,
            "description": "Community template vulnerability scanner",
        },
        {
            "name": "metasploit",
            "category": "exploitation",
            "tier": 3,
            "description": "Exploit execution framework",
        },
    ]


def test_build_user_prompt(decision_engine, sample_catalog):
    """Verify prompt formatting includes target, authorization, tools, and knowledge."""
    prompt = decision_engine.build_user_prompt(
        target="http://example.local",
        scope_type="web",
        authorized_exploitation=False,
        available_tools=sample_catalog,
        execution_history=[{"tool_name": "whatweb", "success": True, "duration_seconds": 1.5, "findings_count": 2, "summary": "Nginx detected"}],
        accumulated_knowledge={
            "subdomains": ["app.example.local"],
            "open_ports": [80, 443],
            "services": [{"port": 80, "protocol": "tcp", "service_name": "http", "service_version": "nginx 1.18"}],
            "technologies": ["nginx", "php"],
            "waf": "Cloudflare",
            "endpoints": ["/login", "/api"],
            "findings": [{"severity": "high", "title": "SQL Injection"}],
        },
        iteration=2,
        max_iterations=20,
    )

    assert "TARGET: http://example.local" in prompt
    assert "SCOPE TYPE: WEB" in prompt
    assert "ACTIVE SCANNING ONLY" in prompt
    assert "whatweb" in prompt
    assert "nginx 1.18" in prompt
    assert "Cloudflare" in prompt
    assert "ITERATION 2 OF 20" in prompt


@pytest.mark.asyncio
async def test_llm_valid_decision(decision_engine, sample_catalog):
    """Verify valid LLM JSON is parsed into an AIDecision."""
    mock_response = json.dumps({
        "action": "run_tool",
        "tool_name": "nuclei",
        "tool_args": {"target": "http://example.local"},
        "reasoning": "Open ports 80/443 found, running targeted CVE templates.",
        "expected_outcome": "Discover unpatched CVEs in nginx web server.",
        "confidence": 0.95
    })

    with patch.object(decision_engine.llm, "generate", new=AsyncMock(return_value=mock_response)):
        decision = await decision_engine.decide_next_step(
            target="http://example.local",
            scope_type="web",
            authorized_exploitation=False,
            available_tools=sample_catalog,
            execution_history=[],
            accumulated_knowledge={},
            iteration=1,
            max_iterations=20,
        )

        assert decision.action == "run_tool"
        assert decision.tool_name == "nuclei"
        assert decision.confidence == 0.95
        assert "targeted CVE templates" in decision.reasoning


@pytest.mark.asyncio
async def test_hallucination_guardrail(decision_engine, sample_catalog):
    """Verify that if LLM hallucinates an unregistered tool, it is caught and replaced."""
    mock_response = json.dumps({
        "action": "run_tool",
        "tool_name": "fictional_super_scanner_9000",
        "tool_args": {"target": "http://example.local"},
        "reasoning": "Using a tool that does not exist.",
        "expected_outcome": "Magic results.",
        "confidence": 0.9
    })

    with patch.object(decision_engine.llm, "generate", new=AsyncMock(return_value=mock_response)):
        decision = await decision_engine.decide_next_step(
            target="http://example.local",
            scope_type="web",
            authorized_exploitation=False,
            available_tools=sample_catalog,
            execution_history=[],
            accumulated_knowledge={},
            iteration=1,
            max_iterations=20,
        )

        # Hallucinated tool should be intercepted and substituted with a registered tool
        assert decision.tool_name != "fictional_super_scanner_9000"
        assert decision.tool_name in [t["name"] for t in sample_catalog]
        assert "unregistered tool" in decision.reasoning


@pytest.mark.asyncio
async def test_exploitation_gate_guardrail(decision_engine, sample_catalog):
    """Verify Tier 3 exploit tools require explicit authorization."""
    mock_response = json.dumps({
        "action": "run_tool",
        "tool_name": "metasploit",
        "tool_args": {"target": "http://example.local"},
        "reasoning": "Attempting remote code execution exploit.",
        "expected_outcome": "Open reverse shell.",
        "confidence": 0.85
    })

    with patch.object(decision_engine.llm, "generate", new=AsyncMock(return_value=mock_response)):
        decision = await decision_engine.decide_next_step(
            target="http://example.local",
            scope_type="web",
            authorized_exploitation=False,  # NOT authorized
            available_tools=sample_catalog,
            execution_history=[],
            accumulated_knowledge={},
            iteration=1,
            max_iterations=20,
        )

        assert decision.action == "need_authorization"
        assert decision.tool_name == "metasploit"
        assert "authorization is disabled" in decision.reasoning


@pytest.mark.asyncio
async def test_finish_action(decision_engine, sample_catalog):
    """Verify finish action terminates the decision loop cleanly."""
    mock_response = json.dumps({
        "action": "finish",
        "tool_name": None,
        "tool_args": {},
        "reasoning": "Sufficient evidence collected across all attack vectors.",
        "expected_outcome": "Proceed to correlation and reporting.",
        "confidence": 0.98
    })

    with patch.object(decision_engine.llm, "generate", new=AsyncMock(return_value=mock_response)):
        decision = await decision_engine.decide_next_step(
            target="http://example.local",
            scope_type="web",
            authorized_exploitation=False,
            available_tools=sample_catalog,
            execution_history=[{"tool_name": "whatweb"}, {"tool_name": "nuclei"}],
            accumulated_knowledge={"findings": [{"title": "Vuln 1"}]},
            iteration=3,
            max_iterations=20,
        )

        assert decision.action == "finish"
        assert decision.tool_name is None


@pytest.mark.asyncio
async def test_heuristic_fallback_when_llm_down(decision_engine, sample_catalog):
    """Verify that if LLM fails, heuristic fallback returns a valid sequence."""
    with patch.object(decision_engine.llm, "generate", new=AsyncMock(return_value=None)):
        decision = await decision_engine.decide_next_step(
            target="http://example.local",
            scope_type="web",
            authorized_exploitation=False,
            available_tools=sample_catalog,
            execution_history=[],
            accumulated_knowledge={},
            iteration=1,
            max_iterations=20,
        )

        assert decision.action == "run_tool"
        assert decision.tool_name in ["whatweb", "nmap", "nuclei", "wafw00f"]
        assert "Heuristic Fallback" in decision.reasoning
