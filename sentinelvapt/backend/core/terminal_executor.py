"""
SentinelVAPT — Terminal Executor (Safe Shell Execution Layer)
Provides isolated, audited command execution with hard denylists,
target-scope enforcement, timeout management, and workspace isolation.
The AI agent uses this as its ONLY interface to the operating system.
"""

import asyncio
import logging
import os
import re
import shlex
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.agent.terminal")


# ═══════════════════════════════════════════════════════════════════
# HARD DENYLIST — Commands the agent may NEVER run, regardless of
# reasoning, authorization level, or any LLM persuasion.
# ═══════════════════════════════════════════════════════════════════
HARD_DENYLIST_PATTERNS: List[re.Pattern] = [
    # Catastrophic filesystem destruction
    re.compile(r"\brm\s+(-[rfRvd\s]*)*\s*/\s*$", re.IGNORECASE),
    re.compile(r"\brm\s+(-[rfRvd\s]*)*\s*/\b", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+.*of=/dev/[sh]d", re.IGNORECASE),
    re.compile(r"\bfdisk\b", re.IGNORECASE),
    re.compile(r"\bparted\b", re.IGNORECASE),
    re.compile(r"\bshred\s+.*(/dev/|/boot|/etc|/usr|/var|/home)", re.IGNORECASE),
    # Boot / system config modification
    re.compile(r"\bgrub-install\b", re.IGNORECASE),
    re.compile(r"\bupdate-grub\b", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+(disable|mask)\s+(ufw|iptables|firewalld|apparmor|selinux)", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+stop\s+(ufw|iptables|firewalld|apparmor|selinux)", re.IGNORECASE),
    # User/account manipulation on HOST
    re.compile(r"\buseradd\b", re.IGNORECASE),
    re.compile(r"\badduser\b", re.IGNORECASE),
    re.compile(r"\busermod\s+.*-aG\s+(sudo|wheel|root)", re.IGNORECASE),
    re.compile(r"\bpasswd\s+root\b", re.IGNORECASE),
    re.compile(r"\bvisudo\b", re.IGNORECASE),
    # Kernel module loading
    re.compile(r"\binsmod\b", re.IGNORECASE),
    re.compile(r"\bmodprobe\b", re.IGNORECASE),
    re.compile(r"\brmmod\b", re.IGNORECASE),
    # Crypto mining / malware fetching
    re.compile(r"\bxmrig\b", re.IGNORECASE),
    re.compile(r"\bcryptominer\b", re.IGNORECASE),
    # Fork bomb
    re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;", re.IGNORECASE),
    re.compile(r"\bfork\s*bomb\b", re.IGNORECASE),
    # Network shutdown on host
    re.compile(r"\bifconfig\s+\w+\s+down\b", re.IGNORECASE),
    re.compile(r"\bip\s+link\s+set\s+\w+\s+down\b", re.IGNORECASE),
    # Reboot / shutdown
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\binit\s+[06]\b", re.IGNORECASE),
    re.compile(r"\bpoweroff\b", re.IGNORECASE),
    re.compile(r"\bhalt\b", re.IGNORECASE),
]

# Commands that require Tier 3 authorization (exploitation, credential attacks)
TIER3_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bmsfconsole\b", re.IGNORECASE),
    re.compile(r"\bmsfvenom\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
    re.compile(r"\bexploit\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bmedusa\b", re.IGNORECASE),
    re.compile(r"\bjohn\b", re.IGNORECASE),
    re.compile(r"\bhashcat\b", re.IGNORECASE),
    re.compile(r"\bsqlmap\b.*--os-shell", re.IGNORECASE),
    re.compile(r"\bsqlmap\b.*--os-cmd", re.IGNORECASE),
    re.compile(r"\bresponder\b", re.IGNORECASE),
    re.compile(r"\bbettercap\b", re.IGNORECASE),
    re.compile(r"\bettercap\b", re.IGNORECASE),
    re.compile(r"\barpspoof\b", re.IGNORECASE),
    re.compile(r"\bcrackmapexec\b", re.IGNORECASE),
    re.compile(r"\bnetexec\b", re.IGNORECASE),
    re.compile(r"\bimpacket\b", re.IGNORECASE),
]


@dataclass
class CommandResult:
    """Result of a terminal command execution."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    blocked: bool = False
    block_reason: str = ""
    workspace_dir: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout[:8000] if self.stdout else "",
            "stderr": self.stderr[:4000] if self.stderr else "",
            "duration_seconds": round(self.duration_seconds, 2),
            "timed_out": self.timed_out,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
        }

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.blocked and not self.timed_out

    @property
    def output_summary(self) -> str:
        """Concise summary for LLM context (truncated to save tokens)."""
        lines = (self.stdout or "").strip().split("\n")
        if len(lines) > 80:
            head = "\n".join(lines[:40])
            tail = "\n".join(lines[-40:])
            return f"{head}\n\n... [{len(lines) - 80} lines truncated] ...\n\n{tail}"
        return self.stdout.strip() if self.stdout else "(no output)"


class TerminalExecutor:
    """
    Safe, audited terminal execution layer.
    
    Features:
    - Hard denylist enforcement (NEVER bypassed)
    - Target-scope enforcement (commands can only target the job's allowed targets)
    - Workspace isolation (all output files go to /sentinelvapt/workspace/<job_id>/)
    - Configurable timeouts per command
    - Full stdout/stderr/exit_code capture
    - Audit log of every command executed
    - Privilege auto-elevation via PrivilegeManager
    """

    MAX_STDOUT_BYTES = 512_000   # 512KB capture limit
    MAX_STDERR_BYTES = 128_000   # 128KB capture limit
    DEFAULT_TIMEOUT = 300        # 5 minutes default
    MAX_TIMEOUT = 1800           # 30 minutes absolute cap

    def __init__(self, job_id: str, target: str,
                 authorized_exploitation: bool = False,
                 workspace_root: Optional[str] = None):
        self.job_id = job_id
        self.target = target
        self.authorized_exploitation = authorized_exploitation
        self.settings = get_settings()

        # Workspace isolation
        if workspace_root:
            self._workspace = Path(workspace_root) / job_id
        else:
            self._workspace = self.settings.project_root / "workspace" / job_id
        self._workspace.mkdir(parents=True, exist_ok=True)

        # Audit log
        self._audit_log: List[Dict[str, Any]] = []
        self._command_count = 0
        self._total_execution_time = 0.0

        # Extract allowed target IPs/hostnames for scope enforcement
        self._allowed_targets: Set[str] = self._parse_target_scope(target)

    def _parse_target_scope(self, target: str) -> Set[str]:
        """Parse target into set of allowed IPs/hostnames."""
        targets = set()
        # Strip protocol
        clean = target
        if "://" in clean:
            from urllib.parse import urlparse
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
            if parsed.port:
                targets.add(f"{clean}:{parsed.port}")

        # Remove port
        host = clean.split(":")[0].split("/")[0].strip()
        targets.add(host)
        targets.add(target.strip())

        # Resolve hostname to IP
        try:
            import socket
            resolved = socket.gethostbyname(host)
            targets.add(resolved)
        except Exception:
            pass

        # Add localhost variants if target is local
        if host in ("localhost", "127.0.0.1", "::1"):
            targets.update({"localhost", "127.0.0.1", "::1"})

        return targets

    def _is_hard_denied(self, command: str) -> Optional[str]:
        """Check if a command matches the hard denylist. Returns reason or None."""
        for pattern in HARD_DENYLIST_PATTERNS:
            if pattern.search(command):
                return f"HARD DENIED: Command matches destructive pattern '{pattern.pattern}'"
        return None

    def _is_tier3_command(self, command: str) -> bool:
        """Check if command is Tier 3 (exploitation/credential attacks)."""
        for pattern in TIER3_PATTERNS:
            if pattern.search(command):
                return True
        return False

    def _check_target_scope(self, command: str) -> Optional[str]:
        """
        Verify that a command only targets the job's allowed targets.
        Returns a violation reason or None if clean.
        
        Heuristic approach: check if IPs/hostnames in the command are in scope.
        Some commands (cd, ls, cat, grep, etc.) are inherently local and exempt.
        """
        # Exempt: local-only commands that don't target remote hosts
        LOCAL_COMMANDS = {
            "ls", "cat", "head", "tail", "grep", "awk", "sed", "sort", "uniq",
            "wc", "cut", "tr", "echo", "printf", "pwd", "whoami", "id", "uname",
            "date", "which", "type", "file", "stat", "find", "locate",
            "dpkg", "apt-cache", "apt-list", "pip", "pip3", "gem", "go",
            "git", "python", "python3", "ruby", "perl", "node", "npm",
            "mkdir", "touch", "cp", "mv", "chmod", "chown", "ln",
            "jq", "xmllint", "base64", "md5sum", "sha256sum",
            "apt-get", "apt", "snap", "brew",  # installation
            "export", "env", "set", "unset",
        }

        parts = command.strip().split()
        if not parts:
            return None

        base_cmd = parts[0].split("/")[-1].lower()
        if base_cmd == "sudo" and len(parts) > 1:
            base_cmd = parts[1].split("/")[-1].lower()

        if base_cmd in LOCAL_COMMANDS:
            return None

        # For network-targeting tools, try to find IP/hostname arguments
        # that are NOT in our allowed set
        import re as re_mod
        ip_pattern = re_mod.compile(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        )
        found_ips = ip_pattern.findall(command)

        for ip in found_ips:
            # Skip common non-target IPs
            if ip.startswith("0.") or ip == "0.0.0.0":
                continue
            if ip not in self._allowed_targets:
                # Check if it's in the exploitation allowlist
                if not self.settings.is_target_allowlisted(ip):
                    return (
                        f"OUT OF SCOPE: IP {ip} is not in the job's target scope "
                        f"(allowed: {', '.join(self._allowed_targets)})"
                    )
        return None

    async def execute(self, command: str, timeout: Optional[int] = None,
                      use_shell: bool = True) -> CommandResult:
        """
        Execute a command safely with all guardrails.
        
        Args:
            command: The shell command string to execute
            timeout: Max seconds to wait (default: DEFAULT_TIMEOUT)
            use_shell: Whether to use shell mode (default True for complex commands)
            
        Returns:
            CommandResult with full stdout/stderr/exit_code
        """
        self._command_count += 1
        effective_timeout = min(timeout or self.DEFAULT_TIMEOUT, self.MAX_TIMEOUT)

        # ── Guard 1: Hard denylist ──────────────────────────
        deny_reason = self._is_hard_denied(command)
        if deny_reason:
            logger.critical(
                "AGENT BLOCKED [job=%s]: %s | cmd: %s",
                self.job_id, deny_reason, command[:200]
            )
            result = CommandResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=deny_reason,
                duration_seconds=0.0,
                blocked=True,
                block_reason=deny_reason,
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "BLOCKED_DENYLIST")
            return result

        # ── Guard 2: Tier 3 authorization gate ──────────────
        if self._is_tier3_command(command) and not self.authorized_exploitation:
            reason = (
                "TIER 3 BLOCKED: This command requires authorized_exploitation=True. "
                "The scan was started without exploitation authorization."
            )
            logger.warning(
                "AGENT TIER3 BLOCKED [job=%s]: %s", self.job_id, command[:200]
            )
            result = CommandResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=reason,
                duration_seconds=0.0,
                blocked=True,
                block_reason=reason,
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "BLOCKED_TIER3")
            return result

        # ── Guard 3: Target scope enforcement ───────────────
        scope_violation = self._check_target_scope(command)
        if scope_violation:
            logger.warning(
                "AGENT SCOPE VIOLATION [job=%s]: %s | cmd: %s",
                self.job_id, scope_violation, command[:200]
            )
            result = CommandResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=scope_violation,
                duration_seconds=0.0,
                blocked=True,
                block_reason=scope_violation,
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "BLOCKED_SCOPE")
            return result

        # ── Execute the command ─────────────────────────────
        logger.info(
            "AGENT EXEC [job=%s, #%d]: %s (timeout=%ds)",
            self.job_id, self._command_count, command[:200], effective_timeout
        )

        start = time.time()
        try:
            env = os.environ.copy()
            # Add tools_bin to PATH
            env["PATH"] = str(self.settings.tools_bin_dir) + os.pathsep + env.get("PATH", "")
            # Set HOME for tools that need it
            env.setdefault("HOME", os.path.expanduser("~"))

            if use_shell:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self._workspace),
                    env=env,
                )
            else:
                args = shlex.split(command)
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self._workspace),
                    env=env,
                )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=effective_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                duration = time.time() - start
                result = CommandResult(
                    command=command,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Command timed out after {effective_timeout}s",
                    duration_seconds=round(duration, 2),
                    timed_out=True,
                    workspace_dir=str(self._workspace),
                )
                self._audit(result, "TIMEOUT")
                self._total_execution_time += duration
                return result

            duration = time.time() - start
            stdout_str = (stdout_bytes or b"").decode("utf-8", errors="replace")[:self.MAX_STDOUT_BYTES]
            stderr_str = (stderr_bytes or b"").decode("utf-8", errors="replace")[:self.MAX_STDERR_BYTES]

            result = CommandResult(
                command=command,
                exit_code=proc.returncode or 0,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=round(duration, 2),
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "OK" if result.success else "ERROR")
            self._total_execution_time += duration
            return result

        except FileNotFoundError as e:
            duration = time.time() - start
            result = CommandResult(
                command=command,
                exit_code=127,
                stdout="",
                stderr=f"Command not found: {e}",
                duration_seconds=round(duration, 2),
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "NOT_FOUND")
            return result

        except Exception as e:
            duration = time.time() - start
            logger.error("Terminal execution error [job=%s]: %s", self.job_id, e)
            result = CommandResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                duration_seconds=round(duration, 2),
                workspace_dir=str(self._workspace),
            )
            self._audit(result, "EXCEPTION")
            return result

    def _audit(self, result: CommandResult, status: str):
        """Record command execution in the audit log."""
        entry = {
            "seq": self._command_count,
            "timestamp": time.time(),
            "command": result.command[:500],
            "exit_code": result.exit_code,
            "duration": result.duration_seconds,
            "status": status,
            "blocked": result.blocked,
            "timed_out": result.timed_out,
            "stdout_len": len(result.stdout),
            "stderr_len": len(result.stderr),
        }
        self._audit_log.append(entry)
        logger.info(
            "AUDIT [job=%s, #%d, %s]: exit=%d dur=%.1fs cmd=%s",
            self.job_id, self._command_count, status,
            result.exit_code, result.duration_seconds, result.command[:120]
        )

    @property
    def workspace(self) -> Path:
        return self._workspace

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        return self._audit_log.copy()

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_commands": self._command_count,
            "total_execution_time": round(self._total_execution_time, 2),
            "blocked_count": sum(1 for e in self._audit_log if e["blocked"]),
            "timeout_count": sum(1 for e in self._audit_log if e["timed_out"]),
            "error_count": sum(1 for e in self._audit_log if e["status"] == "ERROR"),
            "success_count": sum(1 for e in self._audit_log if e["status"] == "OK"),
        }
