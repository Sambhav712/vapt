"""
SentinelVAPT — Plugin-Based Extensible Security Tool Registry
Discovers, categorizes, executes, and parses any Kali Linux or custom security tool.
Driven dynamically by data in config/tools_catalog.yaml.
"""

import asyncio
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from backend.config.settings import get_settings
from backend.tools.base import ParsedResult
from backend.core.privilege_manager import get_privilege_manager

logger = logging.getLogger("sentinelvapt.tools.registry")


@dataclass
class ToolCatalogEntry:
    name: str
    binary: str
    category: str
    tier: int
    description: str
    args_template: List[str] = field(default_factory=list)
    output_format: str = "text"
    parser_type: str = "generic_text"
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    apt_package: str = ""
    version_flag: str = "--version"
    timeout_seconds: int = 300
    installed: bool = False
    path: Optional[str] = None
    version: Optional[str] = None
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ToolRegistry:
    """
    Central registry that scans the host environment for security tools,
    manages dynamic tool selection, and executes tools according to catalog specifications.
    """

    _instance: Optional["ToolRegistry"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ToolRegistry, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, catalog_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return
        self.settings = get_settings()
        self.catalog_path = (
            catalog_path
            or self.settings.project_root / "backend" / "config" / "tools_catalog.yaml"
        )
        self.tools: Dict[str, ToolCatalogEntry] = {}
        self.load_catalog()
        self.scan_system()
        self._initialized = True

    def load_catalog(self):
        """Load tool specifications from the YAML catalog."""
        if not self.catalog_path.exists():
            logger.warning("Tool catalog not found at %s", self.catalog_path)
            return

        try:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            raw_tools = data.get("tools", [])
            for item in raw_tools:
                entry = ToolCatalogEntry(
                    name=item["name"],
                    binary=item["binary"],
                    category=item.get("category", "scanning"),
                    tier=int(item.get("tier", 1)),
                    description=item.get("description", ""),
                    args_template=item.get("args_template", []),
                    output_format=item.get("output_format", "text"),
                    parser_type=item.get("parser_type", "generic_text"),
                    trigger_conditions=item.get("trigger_conditions", {}),
                    apt_package=item.get("apt_package", item["binary"]),
                    version_flag=item.get("version_flag", "--version"),
                    timeout_seconds=int(item.get("timeout_seconds", 300)),
                )
                self.tools[entry.name] = entry
            logger.info("Loaded %d tool definitions from catalog.", len(self.tools))
        except Exception as e:
            logger.error("Failed to load tool catalog: %s", e, exc_info=True)

    def scan_system(self):
        """
        Scan system paths and common Linux/Kali directories to locate installed binaries.
        """
        is_windows = platform.system() == "Windows"
        local_bin = self.settings.tools_bin_dir

        common_search_dirs = []
        if not is_windows:
            common_search_dirs = [
                Path("/usr/bin"),
                Path("/usr/sbin"),
                Path("/usr/local/bin"),
                Path("/usr/share"),
                Path("/opt"),
            ]

        for name, tool in self.tools.items():
            binary = tool.binary
            found_path = shutil.which(binary)

            # Check local tools_bin
            if not found_path:
                local_candidate = local_bin / binary
                if local_candidate.exists():
                    found_path = str(local_candidate)
                elif is_windows:
                    win_candidate = local_bin / f"{binary}.exe"
                    if win_candidate.exists():
                        found_path = str(win_candidate)

            # Check common Linux/Kali directories if still not found
            if not found_path and not is_windows:
                for s_dir in common_search_dirs:
                    candidate = s_dir / binary
                    if candidate.exists() and os.access(candidate, os.X_OK):
                        found_path = str(candidate)
                        break

            if found_path:
                tool.installed = True
                tool.path = str(found_path)
                tool.version = self._probe_version(found_path, tool.version_flag)
            else:
                tool.installed = False
                tool.path = None
                tool.version = None

        installed_count = sum(1 for t in self.tools.values() if t.installed)
        logger.info(
            "Tool scan complete: %d / %d tools detected on system.",
            installed_count,
            len(self.tools),
        )

    def _probe_version(self, path: str, version_flag: str) -> str:
        """Run a lightweight subprocess to read the tool's version."""
        try:
            res = subprocess.run(
                [path, version_flag],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            raw = (res.stdout or res.stderr or "").strip().split("\n")[0]
            # Keep only first 40 chars
            return raw[:40] if raw else "Installed"
        except Exception:
            return "Installed"

    # ─── Query Helpers ─────────────────────────────────────────────────────────

    def get_all(self) -> List[ToolCatalogEntry]:
        return list(self.tools.values())

    def get_detected(self) -> List[ToolCatalogEntry]:
        return [t for t in self.tools.values() if t.installed]

    def get_by_tier(self, tier: int) -> List[ToolCatalogEntry]:
        return [t for t in self.tools.values() if t.tier == tier]

    def get_by_category(self, category: str) -> List[ToolCatalogEntry]:
        return [t for t in self.tools.values() if t.category == category]

    def get_missing_apt_packages(self) -> List[str]:
        """Return list of debian/apt package names for all uninstalled tools."""
        packages = []
        for t in self.tools.values():
            if not t.installed and t.apt_package:
                packages.append(t.apt_package)
        return sorted(list(set(packages)))

    # ─── Dynamic Selection Logic ───────────────────────────────────────────────

    def select_tools_for_pipeline(
        self,
        scope_type: str,
        authorized_exploitation: bool = False,
        discovered_ports: Optional[List[int]] = None,
        discovered_tech: Optional[List[str]] = None,
        manual_enabled: Optional[List[str]] = None,
        manual_disabled: Optional[List[str]] = None,
    ) -> List[ToolCatalogEntry]:
        """
        Intelligently select tools based on scope, risk tier, and recon feedback.
        - Tier 1: Included if matching scope
        - Tier 2: Included if matching scope or triggered by recon discovery (e.g. WordPress, open ports)
        - Tier 3: STRICTLY OMITTED unless authorized_exploitation is True!
        """
        selected: List[ToolCatalogEntry] = []
        discovered_ports = discovered_ports or []
        discovered_tech = [t.lower() for t in (discovered_tech or [])]
        manual_enabled = set(manual_enabled or [])
        manual_disabled = set(manual_disabled or [])

        for name, tool in self.tools.items():
            # Check manual user override first
            if name in manual_disabled:
                continue

            # Must be installed on the system
            if not tool.installed:
                continue

            # Tier 3 Gate: NEVER run Tier 3 without explicit authorization flag
            if tool.tier == 3 and not authorized_exploitation:
                continue

            # If user manually enabled this specific tool, include it (if authorized)
            if name in manual_enabled:
                selected.append(tool)
                continue

            triggers = tool.trigger_conditions
            tool_scopes = triggers.get("scopes", ["web", "api", "network"])

            # Scope check
            if scope_type.lower() not in tool_scopes:
                continue

            # Dynamic triggers
            trigger_ports = triggers.get("ports", [])
            trigger_tech = [t.lower() for t in triggers.get("tech_keywords", [])]

            should_include = False

            # If tool has no specific trigger requirements, it runs for this scope
            if not trigger_ports and not trigger_tech:
                should_include = True

            # If tool triggers on specific open ports (e.g. 139, 445 for SMB)
            if trigger_ports and any(p in discovered_ports for p in trigger_ports):
                should_include = True

            # If tool triggers on specific detected tech (e.g. wordpress for wpscan)
            if trigger_tech:
                for kw in trigger_tech:
                    if any(kw in tech for tech in discovered_tech):
                        should_include = True
                        break

            if should_include:
                selected.append(tool)

        return selected

    # ─── Execution & Normalized Parsing ────────────────────────────────────────

    async def execute_tool(
        self,
        tool: ToolCatalogEntry,
        target: str,
        extra_vars: Optional[Dict[str, str]] = None,
    ) -> ParsedResult:
        """
        Safely execute a catalog tool subprocess, capture stdout/stderr,
        and normalize its output into a ParsedResult.
        """
        start_time = time.time()
        extra_vars = extra_vars or {}

        # Parse target for domain/IP
        domain = target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

        temp_out = None
        output_file_path = ""
        if any("{output_file}" in arg for arg in tool.args_template):
            suffix = f".{tool.output_format}" if tool.output_format != "text" else ".txt"
            temp_out = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            output_file_path = temp_out.name
            temp_out.close()

        # Format command arguments
        cmd_args = [tool.path or tool.binary]
        for arg in tool.args_template:
            formatted = arg.format(
                target=target,
                domain=domain,
                output_file=output_file_path,
                **extra_vars,
            )
            cmd_args.append(formatted)

        cmd_str = " ".join(cmd_args)
        logger.info("Executing catalog tool [%s]: %s", tool.name, cmd_str)

        # Auto-elevate with sudo if tool needs root and we have settings enabled
        priv_mgr = get_privilege_manager()
        settings = get_settings()
        if settings.auto_elevate and priv_mgr.needs_elevation(tool.binary, cmd_args[1:]):
            cmd_args = priv_mgr.wrap_command(cmd_args, tool_name=tool.binary)
            cmd_str = " ".join(cmd_args)
            logger.info("Elevated to: %s", cmd_str)

        raw_stdout = ""
        raw_stderr = ""
        exit_code = -1

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=tool.timeout_seconds
                )
                raw_stdout = stdout_bytes.decode("utf-8", errors="replace")
                raw_stderr = stderr_bytes.decode("utf-8", errors="replace")
                exit_code = proc.returncode or 0
            except asyncio.TimeoutError:
                proc.kill()
                raw_stderr = f"Execution timed out after {tool.timeout_seconds} seconds"
                exit_code = -9
        except Exception as e:
            raw_stderr = f"Subprocess launch failed: {e}"
            exit_code = 127

        # Read output file if tool writes to file
        file_content = ""
        if output_file_path and os.path.exists(output_file_path):
            try:
                with open(output_file_path, "r", encoding="utf-8", errors="replace") as f:
                    file_content = f.read()
            except Exception as e:
                logger.warning("Could not read temp output file: %s", e)
            finally:
                try:
                    os.unlink(output_file_path)
                except OSError:
                    pass

        duration = time.time() - start_time
        effective_output = file_content if file_content else raw_stdout

        # Parse normalized output
        parsed_data = self._parse_output(tool, effective_output, raw_stdout)

        return ParsedResult(
            tool_name=tool.name,
            success=(exit_code == 0),
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            parsed_data=parsed_data,
            command=cmd_str,
            exit_code=exit_code,
            duration_seconds=round(duration, 2),
        )

    def _parse_output(
        self, tool: ToolCatalogEntry, output_text: str, stdout_text: str
    ) -> Dict[str, Any]:
        """Parse raw output according to the tool's parser_type."""
        parser = getattr(self, f"_parse_{tool.parser_type}", self._parse_generic_text)
        try:
            return parser(output_text, stdout_text)
        except Exception as e:
            logger.warning("Parser '%s' failed for tool '%s': %s", tool.parser_type, tool.name, e)
            return {"raw_text": output_text[:10000], "parse_error": str(e)}

    # ─── Specialized Parsers ───────────────────────────────────────────────────

    def _parse_whatweb_json(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse WhatWeb JSON output."""
        try:
            data = json.loads(output)
            results = []
            for item in data if isinstance(data, list) else [data]:
                target = item.get("target")
                status = item.get("http_status")
                plugins = item.get("plugins", {})
                techs = list(plugins.keys())
                results.append({"target": target, "status": status, "technologies": techs, "plugins": plugins})
            return {"targets": results, "technologies_found": [t for r in results for t in r["technologies"]]}
        except Exception:
            return self._parse_generic_text(output, stdout)

    def _parse_wafw00f_json(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse Wafw00f JSON output."""
        try:
            data = json.loads(output)
            waf_detected = False
            wafs = []
            for item in data if isinstance(data, list) else [data]:
                if item.get("detected"):
                    waf_detected = True
                    wafs.append(item.get("firewall", "Unknown WAF"))
            return {"waf_detected": waf_detected, "firewalls": wafs}
        except Exception:
            # Fallback regex on stdout
            waf_detected = "is behind" in stdout or "detected" in stdout.lower()
            return {"waf_detected": waf_detected, "raw_summary": stdout[:1000]}

    def _parse_wpscan_json(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse WPScan JSON output."""
        try:
            data = json.loads(output)
            findings = []
            version_info = data.get("version", {})
            if version_info and version_info.get("vulnerabilities"):
                for v in version_info["vulnerabilities"]:
                    findings.append({
                        "title": f"WordPress Core: {v.get('title', 'Vulnerability')}",
                        "severity": "high",
                        "references": v.get("references", {}),
                    })

            plugins = data.get("plugins", {})
            for p_name, p_data in plugins.items():
                for v in p_data.get("vulnerabilities", []):
                    findings.append({
                        "title": f"WP Plugin ({p_name}): {v.get('title', 'Vulnerability')}",
                        "severity": "medium",
                        "references": v.get("references", {}),
                    })

            return {"is_wordpress": True, "version": version_info.get("number"), "findings": findings}
        except Exception:
            return self._parse_generic_text(output, stdout)

    def _parse_gobuster_text(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse Gobuster dir output lines (Path (Status: 200) [Size: ...])."""
        discovered_paths = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("===") or line.startswith("Finished"):
                continue
            # Regex match: /path (Status: 200)
            m = re.search(r"^(\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                discovered_paths.append({"path": m.group(1), "status": int(m.group(2))})
            elif line.startswith("/"):
                parts = line.split()
                discovered_paths.append({"path": parts[0], "status": 200})
        return {"paths_count": len(discovered_paths), "discovered_paths": discovered_paths}

    def _parse_enum4linux_text(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse Enum4linux text output for workgroups, users, and shares."""
        shares = []
        users = []
        workgroup = ""

        for line in output.splitlines():
            if "Workgroup:" in line or "Domain Name:" in line:
                workgroup = line.split(":")[-1].strip()
            elif "Mapping:" in line and "Disk" in line:
                shares.append(line.strip())
            elif "user:[" in line.lower():
                m = re.search(r"user:\[(.*?)\]", line, re.IGNORECASE)
                if m:
                    users.append(m.group(1))

        return {
            "workgroup": workgroup,
            "shares": shares,
            "users": users,
            "raw_output": output[:5000],
        }

    def _parse_json_lines(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse JSON Lines output (one JSON object per line)."""
        items = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    items.append(json.loads(line))
                except Exception:
                    pass
        return {"count": len(items), "items": items}

    def _parse_generic_json(self, output: str, stdout: str) -> Dict[str, Any]:
        """Parse standard JSON."""
        try:
            return json.loads(output)
        except Exception:
            return self._parse_generic_text(output, stdout)

    def _parse_generic_text(self, output: str, stdout: str) -> Dict[str, Any]:
        """Generic text parser returning line counts and preview snippet."""
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        return {"line_count": len(lines), "preview": lines[:50]}
