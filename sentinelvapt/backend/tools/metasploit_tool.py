"""
SentinelVAPT — Metasploit Integration (Lab-Only, Gated)
Drives Metasploit via MSFRPC for authorized exploitation testing.
Safety: ONLY runs against allowlisted targets with explicit user authorization.
"""

import json
import logging
import socket
import time
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult
from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.tools.metasploit")


class MetasploitTool(ToolBase):
    """
    Metasploit integration via msfrpc.
    SAFETY GATED: Only runs if target is in allowlist AND user has authorized exploitation.
    """
    name = "metasploit"
    binary_name = "msfconsole"

    def __init__(self):
        super().__init__()
        self.settings = get_settings()
        self._client = None

    def _is_target_authorized(self, target: str) -> bool:
        """Double-check target against allowlist."""
        # Resolve hostname to IP if needed
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = target
        return self.settings.is_target_allowlisted(ip)

    def _get_rpc_client(self):
        """Lazy-initialize the MSFRPC client."""
        if self._client is not None:
            return self._client

        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            self._client = MsfRpcClient(
                self.settings.msfrpc_password,
                server=self.settings.msfrpc_host,
                port=self.settings.msfrpc_port,
                username=self.settings.msfrpc_user,
                ssl=False,
            )
            return self._client
        except ImportError:
            self.logger.error(
                "pymetasploit3 not installed. Install with: pip install pymetasploit3"
            )
            return None
        except Exception as e:
            self.logger.error("Failed to connect to MSFRPC: %s", e)
            return None

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run Metasploit modules against the target.
        SAFETY: Requires target in allowlist AND authorized_exploitation=True in options.

        Options:
            authorized_exploitation: bool — MUST be True (default: False)
            services: list — list of dicts with port/service/version info from Nmap
            cves: list — list of CVE IDs to search modules for
            module_type: str — "auxiliary" | "exploit" (default: "auxiliary")
            timeout: int — seconds per module (default: 120)
            max_modules: int — maximum modules to try (default: 5)
        """
        options = options or {}
        authorized = options.get("authorized_exploitation", False)

        result = ParsedResult(tool_name=self.name, success=False)

        # ─── SAFETY GATE ──────────────────────────────────
        if not authorized:
            result.error_message = (
                "EXPLOITATION SKIPPED: User did not authorize exploitation. "
                "Set authorized_exploitation=True to enable."
            )
            self.logger.warning(result.error_message)
            return result

        if not self._is_target_authorized(target):
            result.error_message = (
                f"EXPLOITATION BLOCKED: Target '{target}' is NOT in the exploitation allowlist. "
                f"Only allowlisted lab targets can be exploited. "
                f"Allowlist: {self.settings.exploit_allowlist}"
            )
            self.logger.error(result.error_message)
            return result
        # ─── END SAFETY GATE ──────────────────────────────

        client = self._get_rpc_client()
        if client is None:
            result.error_message = "Cannot connect to Metasploit RPC. Is msfrpcd running?"
            return result

        services = options.get("services", [])
        cves = options.get("cves", [])
        module_type = options.get("module_type", "auxiliary")
        timeout_per_module = options.get("timeout", 120)
        max_modules = options.get("max_modules", 5)

        start_time = time.time()

        try:
            # Search for relevant modules
            modules_to_run = self._find_modules(client, services, cves, module_type, max_modules)

            if not modules_to_run:
                result.error_message = "No matching Metasploit modules found for the target's services/CVEs."
                result.success = True  # Not a failure, just no modules
                return result

            # Run each module
            for module_info in modules_to_run:
                try:
                    finding = self._run_module(client, target, module_info, timeout_per_module)
                    if finding:
                        result.findings.append(finding)
                except Exception as e:
                    self.logger.error("Module %s failed: %s", module_info.get("fullname", ""), e)

            result.success = True
            result.duration_seconds = round(time.time() - start_time, 2)
            result.parsed_data = {
                "modules_tried": len(modules_to_run),
                "findings_count": len(result.findings),
            }

        except Exception as e:
            self.logger.error("Metasploit scan failed: %s", e)
            result.error_message = str(e)
            result.duration_seconds = round(time.time() - start_time, 2)

        return result

    def _find_modules(self, client, services: List[Dict], cves: List[str],
                      module_type: str, max_modules: int) -> List[Dict]:
        """Search for relevant Metasploit modules based on services and CVEs."""
        modules = []

        try:
            # Search by CVE
            for cve in cves[:10]:  # Limit CVE searches
                try:
                    search_results = client.modules.search(cve)
                    for mod in search_results:
                        if mod.get("type") in (module_type, "auxiliary"):
                            modules.append(mod)
                            if len(modules) >= max_modules:
                                return modules
                except Exception as e:
                    self.logger.warning("Module search for %s failed: %s", cve, e)

            # Search by service name/version
            for svc in services[:10]:
                service_name = svc.get("service_name", "")
                if not service_name:
                    continue
                try:
                    search_results = client.modules.search(service_name)
                    for mod in search_results:
                        if mod.get("type") in (module_type, "auxiliary"):
                            modules.append(mod)
                            if len(modules) >= max_modules:
                                return modules
                except Exception as e:
                    self.logger.warning("Module search for service %s failed: %s", service_name, e)

        except Exception as e:
            self.logger.error("Module search failed: %s", e)

        return modules[:max_modules]

    def _run_module(self, client, target: str, module_info: Dict,
                    timeout: int) -> Optional[Dict]:
        """Run a single Metasploit module and return a finding if successful."""
        fullname = module_info.get("fullname", "")
        mod_type = module_info.get("type", "auxiliary")

        self.logger.info("Running Metasploit module: %s", fullname)

        try:
            if mod_type == "auxiliary":
                module = client.modules.use("auxiliary", fullname)
            elif mod_type == "exploit":
                module = client.modules.use("exploit", fullname)
            else:
                return None

            # Set target
            if "RHOSTS" in module.options:
                module["RHOSTS"] = target
            elif "RHOST" in module.options:
                module["RHOST"] = target

            # Execute
            job_id = module.execute()

            # Wait for completion
            start = time.time()
            while time.time() - start < timeout:
                jobs = client.jobs.list
                if str(job_id) not in jobs:
                    break
                time.sleep(2)

            # Check for sessions (exploitation success)
            sessions = client.sessions.list
            session_data = None
            for sid, sinfo in sessions.items():
                if target in str(sinfo.get("target_host", "")):
                    session_data = sinfo
                    break

            if session_data:
                return {
                    "title": f"Exploitation Successful: {fullname}",
                    "description": (
                        f"Metasploit module '{fullname}' successfully exploited the target. "
                        f"Session type: {session_data.get('type', 'unknown')}. "
                        f"This confirms the vulnerability is actively exploitable."
                    ),
                    "severity": "critical",
                    "affected_asset": target,
                    "source_tool": "metasploit",
                    "evidence": f"Module: {fullname}, Session: {json.dumps(session_data, default=str)}",
                    "raw_data": {
                        "module": fullname,
                        "module_type": mod_type,
                        "session": session_data,
                    },
                }
            else:
                return {
                    "title": f"Module Executed: {fullname}",
                    "description": f"Metasploit module '{fullname}' ran against {target} but did not achieve exploitation.",
                    "severity": "info",
                    "affected_asset": target,
                    "source_tool": "metasploit",
                    "raw_data": {"module": fullname, "module_type": mod_type},
                }

        except Exception as e:
            self.logger.error("Module execution failed for %s: %s", fullname, e)
            return None
