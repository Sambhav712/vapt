"""
SentinelVAPT — Tests for Agent Core Module
Tests the terminal executor safety guardrails, capability manager,
and agent core ReAct loop logic.
"""

import asyncio
import os
import platform
import pytest
import sys
import uuid

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ═══════════════════════════════════════════════════════════════════
# Terminal Executor Tests
# ═══════════════════════════════════════════════════════════════════

class TestTerminalExecutorDenylist:
    """Test that the hard denylist correctly blocks destructive commands."""

    def _make_executor(self):
        from backend.core.terminal_executor import TerminalExecutor
        return TerminalExecutor(
            job_id="test-job-001",
            target="192.168.1.100",
            authorized_exploitation=False,
        )

    def test_rm_rf_root_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("rm -rf /")
        assert result is not None
        assert "HARD DENIED" in result

    def test_rm_rf_slash_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("rm -rf /etc")
        assert result is not None

    def test_mkfs_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("mkfs.ext4 /dev/sda1")
        assert result is not None

    def test_dd_disk_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("dd if=/dev/zero of=/dev/sda bs=1M")
        assert result is not None

    def test_reboot_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("reboot")
        assert result is not None

    def test_shutdown_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("shutdown -h now")
        assert result is not None

    def test_useradd_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("useradd hacker")
        assert result is not None

    def test_systemctl_disable_firewall_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("systemctl disable ufw")
        assert result is not None

    def test_modprobe_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("modprobe some_module")
        assert result is not None

    def test_poweroff_blocked(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("poweroff")
        assert result is not None

    def test_safe_nmap_allowed(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("nmap -sV -sC 192.168.1.100")
        assert result is None

    def test_safe_curl_allowed(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("curl -I http://192.168.1.100")
        assert result is None

    def test_safe_ls_allowed(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("ls -la /tmp")
        assert result is None

    def test_safe_cat_allowed(self):
        executor = self._make_executor()
        result = executor._is_hard_denied("cat /etc/hostname")
        assert result is None


class TestTerminalExecutorTier3:
    """Test Tier 3 exploitation command gating."""

    def _make_executor(self, authorized=False):
        from backend.core.terminal_executor import TerminalExecutor
        return TerminalExecutor(
            job_id="test-job-002",
            target="192.168.1.100",
            authorized_exploitation=authorized,
        )

    def test_msfconsole_is_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("msfconsole -q") is True

    def test_hydra_is_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("hydra -l admin -P wordlist.txt 192.168.1.100 ssh") is True

    def test_john_is_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt") is True

    def test_hashcat_is_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("hashcat -m 0 hashes.txt wordlist.txt") is True

    def test_responder_is_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("responder -I eth0") is True

    def test_nmap_is_not_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("nmap -sV 192.168.1.100") is False

    def test_nikto_is_not_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("nikto -h http://192.168.1.100") is False

    def test_curl_is_not_tier3(self):
        executor = self._make_executor()
        assert executor._is_tier3_command("curl http://192.168.1.100") is False


class TestTerminalExecutorScopeEnforcement:
    """Test target scope enforcement."""

    def _make_executor(self, target="192.168.1.100"):
        from backend.core.terminal_executor import TerminalExecutor
        return TerminalExecutor(
            job_id="test-job-003",
            target=target,
            authorized_exploitation=False,
        )

    def test_in_scope_ip_allowed(self):
        executor = self._make_executor("192.168.1.100")
        result = executor._check_target_scope("nmap -sV 192.168.1.100")
        assert result is None  # No violation

    def test_local_commands_always_allowed(self):
        executor = self._make_executor("192.168.1.100")
        for cmd in ["ls -la", "cat /etc/hostname", "which nmap", "whoami", "id"]:
            result = executor._check_target_scope(cmd)
            assert result is None, f"Local command '{cmd}' should be allowed"

    def test_apt_install_allowed(self):
        executor = self._make_executor("192.168.1.100")
        result = executor._check_target_scope("apt-get install -y nmap")
        assert result is None

    def test_pip_install_allowed(self):
        executor = self._make_executor("192.168.1.100")
        result = executor._check_target_scope("pip3 install wafw00f")
        assert result is None


class TestTerminalExecutorWorkspace:
    """Test workspace isolation."""

    def test_workspace_created(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-workspace-001",
            target="192.168.1.100",
        )
        assert executor.workspace.exists()
        assert "test-workspace-001" in str(executor.workspace)


class TestTerminalExecutorExecution:
    """Test actual command execution (platform-dependent)."""

    @pytest.mark.asyncio
    async def test_execute_echo(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-exec-001",
            target="192.168.1.100",
        )
        result = await executor.execute("echo hello_sentinel", timeout=5)
        assert result.success
        assert "hello_sentinel" in result.stdout
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_blocked_command(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-exec-002",
            target="192.168.1.100",
        )
        result = await executor.execute("reboot", timeout=5)
        assert result.blocked
        assert result.exit_code == -1
        assert "HARD DENIED" in result.block_reason or "HARD DENIED" in result.stderr

    @pytest.mark.asyncio
    async def test_execute_tier3_blocked_without_auth(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-exec-003",
            target="192.168.1.100",
            authorized_exploitation=False,
        )
        result = await executor.execute("hydra -l admin -P pass.txt 192.168.1.100 ssh", timeout=5)
        assert result.blocked
        assert "TIER 3" in result.block_reason or "TIER 3" in result.stderr

    @pytest.mark.asyncio
    async def test_audit_log_populated(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-exec-004",
            target="192.168.1.100",
        )
        await executor.execute("echo test1", timeout=5)
        await executor.execute("echo test2", timeout=5)
        assert len(executor.audit_log) == 2
        assert executor.stats["total_commands"] == 2

    @pytest.mark.asyncio
    async def test_command_timeout(self):
        from backend.core.terminal_executor import TerminalExecutor
        executor = TerminalExecutor(
            job_id="test-exec-005",
            target="192.168.1.100",
        )
        if platform.system() != "Windows":
            result = await executor.execute("sleep 30", timeout=2)
            assert result.timed_out
        else:
            # Windows equivalent
            result = await executor.execute("ping -n 30 127.0.0.1", timeout=2)
            assert result.timed_out


# ═══════════════════════════════════════════════════════════════════
# Capability Manager Tests
# ═══════════════════════════════════════════════════════════════════

class TestCapabilityManager:
    """Test the capability manager."""

    @pytest.mark.asyncio
    async def test_scan_returns_capabilities(self):
        from backend.core.capability_manager import CapabilityManager
        mgr = CapabilityManager()
        caps = await mgr.scan()
        assert caps.os_type in ("Linux", "Windows", "Darwin")
        assert caps.python_version
        assert isinstance(caps.available_tools, list)
        assert isinstance(caps.package_managers, list)

    @pytest.mark.asyncio
    async def test_context_string_generation(self):
        from backend.core.capability_manager import CapabilityManager
        mgr = CapabilityManager()
        caps = await mgr.scan()
        context = caps.to_context_string()
        assert "System:" in context
        assert "Python:" in context

    def test_install_budget(self):
        from backend.core.capability_manager import CapabilityManager
        mgr = CapabilityManager()
        assert mgr.install_budget_remaining == 10

    def test_reset(self):
        from backend.core.capability_manager import CapabilityManager
        mgr = CapabilityManager()
        mgr.reset()
        assert mgr._capabilities is None


# ═══════════════════════════════════════════════════════════════════
# Agent Core Tests
# ═══════════════════════════════════════════════════════════════════

class TestAgentCore:
    """Test the agent core module."""

    def test_agent_initialization(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
            scope_type="web",
            max_steps=5,
        )
        assert agent.state.status == "running"
        assert agent.state.target == "192.168.1.100"
        assert agent.state.max_steps == 5

    def test_agent_cancel(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        agent.cancel()
        assert agent._cancelled is True

    def test_loop_detection(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        cmd = "nmap -sV 192.168.1.100"
        assert agent._detect_loop(cmd) is False
        assert agent._detect_loop(cmd) is False
        assert agent._detect_loop(cmd) is True  # Third time triggers loop

    def test_parse_valid_llm_response(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        response = json.dumps({
            "thought": "I should scan the target first",
            "action": "execute_command",
            "command": "nmap -sV 192.168.1.100",
            "confidence": 0.9,
        })
        step = agent._parse_llm_response(response, 1, 1.5)
        assert step is not None
        assert step.action == "execute_command"
        assert step.command == "nmap -sV 192.168.1.100"
        assert step.confidence == 0.9

    def test_parse_finding_response(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        response = json.dumps({
            "thought": "Found an open port with outdated service",
            "action": "report_finding",
            "finding": {
                "title": "Outdated Apache httpd",
                "severity": "medium",
                "description": "Apache 2.4.29 has known vulnerabilities",
                "evidence": "nmap output showing Apache/2.4.29",
                "remediation": "Upgrade Apache to latest version",
                "affected_asset": "192.168.1.100:80",
                "cve_ids": ["CVE-2021-44790"],
                "cvss_score": 6.5,
            },
            "confidence": 0.85,
        })
        step = agent._parse_llm_response(response, 5, 2.0)
        assert step is not None
        assert step.action == "report_finding"
        assert step.finding is not None
        assert step.finding.title == "Outdated Apache httpd"
        assert step.finding.severity == "medium"
        assert step.finding.cvss_score == 6.5

    def test_parse_finish_response(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        response = json.dumps({
            "thought": "All checks complete, no critical issues found",
            "action": "finish",
            "summary": "Comprehensive scan found 3 medium and 5 low findings",
            "confidence": 0.95,
        })
        step = agent._parse_llm_response(response, 20, 1.0)
        assert step is not None
        assert step.action == "finish"
        assert "3 medium" in step.summary

    def test_parse_invalid_json_returns_none(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        step = agent._parse_llm_response("not valid json at all", 1, 0.5)
        assert step is None

    def test_parse_invalid_action_returns_none(self):
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        response = json.dumps({
            "thought": "test",
            "action": "invalid_action_xyz",
            "confidence": 0.5,
        })
        step = agent._parse_llm_response(response, 1, 0.5)
        assert step is None

    def test_parse_markdown_wrapped_json(self):
        """LLM sometimes wraps JSON in markdown code fences."""
        from backend.core.agent_core import AgentCore
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        response = '```json\n{"thought": "test", "action": "execute_command", "command": "whoami", "confidence": 0.8}\n```'
        step = agent._parse_llm_response(response, 1, 0.5)
        assert step is not None
        assert step.action == "execute_command"
        assert step.command == "whoami"


class TestAgentFinding:
    """Test the AgentFinding dataclass."""

    def test_finding_to_dict(self):
        from backend.core.agent_core import AgentFinding
        finding = AgentFinding(
            title="SQL Injection",
            severity="high",
            description="SQL injection in login form",
            evidence="sqlmap output confirming injection",
            remediation="Use parameterized queries",
            affected_asset="http://192.168.1.100/login",
            cve_ids=["CVE-2021-12345"],
            cwe_ids=["CWE-89"],
            cvss_score=8.5,
            verified=True,
            source_step=10,
        )
        d = finding.to_dict()
        assert d["title"] == "SQL Injection"
        assert d["severity"] == "high"
        assert d["cvss_score"] == 8.5
        assert d["verified"] is True


class TestCommandResult:
    """Test the CommandResult dataclass."""

    def test_success_property(self):
        from backend.core.terminal_executor import CommandResult
        r = CommandResult(
            command="echo test",
            exit_code=0,
            stdout="test\n",
            stderr="",
            duration_seconds=0.1,
        )
        assert r.success is True

    def test_failure_property(self):
        from backend.core.terminal_executor import CommandResult
        r = CommandResult(
            command="false",
            exit_code=1,
            stdout="",
            stderr="error",
            duration_seconds=0.1,
        )
        assert r.success is False

    def test_blocked_not_success(self):
        from backend.core.terminal_executor import CommandResult
        r = CommandResult(
            command="reboot",
            exit_code=-1,
            stdout="",
            stderr="blocked",
            duration_seconds=0.0,
            blocked=True,
            block_reason="HARD DENIED",
        )
        assert r.success is False

    def test_output_summary_truncation(self):
        from backend.core.terminal_executor import CommandResult
        # Create a result with 200 lines
        long_output = "\n".join([f"line {i}" for i in range(200)])
        r = CommandResult(
            command="test",
            exit_code=0,
            stdout=long_output,
            stderr="",
            duration_seconds=0.5,
        )
        summary = r.output_summary
        assert "truncated" in summary


# ═══════════════════════════════════════════════════════════════════
# Integration-style Test: Agent action execution
# ═══════════════════════════════════════════════════════════════════

class TestAgentActions:
    """Test agent action execution methods."""

    @pytest.mark.asyncio
    async def test_report_finding_action(self):
        from backend.core.agent_core import AgentCore, AgentStep, AgentFinding
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        step = AgentStep(
            step_number=1,
            thought="Found an issue",
            action="report_finding",
            finding=AgentFinding(
                title="Open SSH Port",
                severity="info",
                description="Port 22 is open",
                affected_asset="192.168.1.100:22",
            ),
        )
        await agent._action_report_finding(step)
        assert step.result_success
        assert len(agent.state.findings) == 1

    @pytest.mark.asyncio
    async def test_duplicate_finding_not_added(self):
        from backend.core.agent_core import AgentCore, AgentStep, AgentFinding
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        finding = AgentFinding(
            title="Open SSH Port",
            severity="info",
            affected_asset="192.168.1.100:22",
        )
        step1 = AgentStep(step_number=1, thought="test", action="report_finding", finding=finding)
        step2 = AgentStep(step_number=2, thought="test", action="report_finding",
                          finding=AgentFinding(title="Open SSH Port", severity="info",
                                               affected_asset="192.168.1.100:22"))
        await agent._action_report_finding(step1)
        await agent._action_report_finding(step2)
        assert len(agent.state.findings) == 1  # Duplicate not added

    @pytest.mark.asyncio
    async def test_execute_command_action(self):
        from backend.core.agent_core import AgentCore, AgentStep
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        step = AgentStep(
            step_number=1,
            thought="Check system info",
            action="execute_command",
            command="echo sentinel_test_marker",
        )
        await agent._action_execute_command(step)
        assert step.result_success
        assert "sentinel_test_marker" in step.result_stdout

    @pytest.mark.asyncio
    async def test_execute_blocked_command_action(self):
        from backend.core.agent_core import AgentCore, AgentStep
        agent = AgentCore(
            job_id=str(uuid.uuid4()),
            target="192.168.1.100",
        )
        step = AgentStep(
            step_number=1,
            thought="Try something dangerous",
            action="execute_command",
            command="reboot",
        )
        await agent._action_execute_command(step)
        assert step.result_blocked
        assert agent.state.total_commands_blocked == 1


# Need json import for test data
import json


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-x"])
