"""
SentinelVAPT — Base Tool Abstraction
Every tool integration inherits from ToolBase and returns ParsedResult.
"""

import abc
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinelvapt.tools")


@dataclass
class ParsedResult:
    """Normalized output from any tool invocation."""
    tool_name: str
    success: bool
    raw_stdout: str = ""
    raw_stderr: str = ""
    exit_code: int = -1
    duration_seconds: float = 0.0
    command: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


class ToolBase(abc.ABC):
    """Abstract base class for all tool integrations."""

    name: str = "base"
    binary_name: str = "base"

    def __init__(self):
        self.logger = logging.getLogger(f"sentinelvapt.tools.{self.name}")

    def is_available(self) -> bool:
        """Check if the tool's binary is on PATH or in the local tools_bin."""
        from backend.config.settings import get_settings
        settings = get_settings()
        # Check PATH
        if shutil.which(self.binary_name):
            return True
        # Check local tools_bin
        local = settings.tools_bin_dir / self.binary_name
        if local.exists() and local.is_file():
            return True
        # Windows: check with .exe
        local_exe = settings.tools_bin_dir / f"{self.binary_name}.exe"
        if local_exe.exists() and local_exe.is_file():
            return True
        return False

    def get_binary_path(self) -> str:
        """Return the full path to the tool binary."""
        from backend.config.settings import get_settings
        settings = get_settings()
        system_path = shutil.which(self.binary_name)
        if system_path:
            return system_path
        local = settings.tools_bin_dir / self.binary_name
        if local.exists():
            return str(local)
        local_exe = settings.tools_bin_dir / f"{self.binary_name}.exe"
        if local_exe.exists():
            return str(local_exe)
        return self.binary_name  # fallback, will fail at runtime

    def run_subprocess(
        self,
        args: List[str],
        timeout: int = 600,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> ParsedResult:
        """Execute a subprocess with proper error handling, timeout, output capture, and privilege auto-elevation."""
        import os

        # Auto-elevate with sudo if tool requires root and auto_elevate is enabled
        from backend.config.settings import get_settings
        settings = get_settings()
        if getattr(settings, "auto_elevate", True):
            try:
                from backend.core.privilege_manager import get_privilege_manager
                pm = get_privilege_manager()
                args = pm.wrap_command(args, tool_name=self.name, flags=args[1:] if len(args) > 1 else None)
            except Exception as e:
                self.logger.debug("Privilege check skipped: %s", e)

        cmd_str = " ".join(args)
        self.logger.info("Running: %s", cmd_str)

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        # Ensure tools_bin is on PATH
        merged_env["PATH"] = str(settings.tools_bin_dir) + os.pathsep + merged_env.get("PATH", "")

        start = time.time()
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                shell=False,
            )
            duration = time.time() - start
            result = ParsedResult(
                tool_name=self.name,
                success=(proc.returncode == 0),
                raw_stdout=proc.stdout or "",
                raw_stderr=proc.stderr or "",
                exit_code=proc.returncode,
                duration_seconds=round(duration, 2),
                command=cmd_str,
            )
            if proc.returncode != 0:
                result.error_message = f"Exit code {proc.returncode}: {proc.stderr[:500]}"
                self.logger.warning("Tool %s returned exit code %d", self.name, proc.returncode)
            return result
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            self.logger.error("Tool %s timed out after %ds", self.name, timeout)
            return ParsedResult(
                tool_name=self.name,
                success=False,
                duration_seconds=round(duration, 2),
                command=cmd_str,
                error_message=f"Timeout after {timeout}s",
            )
        except FileNotFoundError:
            self.logger.error("Tool binary not found: %s", args[0])
            return ParsedResult(
                tool_name=self.name,
                success=False,
                command=cmd_str,
                error_message=f"Binary not found: {args[0]}",
            )
        except Exception as exc:
            duration = time.time() - start
            self.logger.error("Tool %s failed: %s", self.name, exc)
            return ParsedResult(
                tool_name=self.name,
                success=False,
                duration_seconds=round(duration, 2),
                command=cmd_str,
                error_message=str(exc),
            )

    @abc.abstractmethod
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """Run the tool against a target. Must be implemented by each tool module."""
        ...
