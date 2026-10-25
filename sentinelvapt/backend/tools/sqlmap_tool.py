"""
SentinelVAPT — SQLMap Integration
Automated SQL injection testing via subprocess in --batch mode.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class SqlmapTool(ToolBase):
    name = "sqlmap"
    binary_name = "sqlmap"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run SQLMap against a target URL.
        Options:
            url: str — target URL with injectable parameter (overrides target)
            data: str — POST data
            method: str — HTTP method (default: GET)
            level: int — test level 1-5 (default: 2)
            risk: int — risk level 1-3 (default: 1)
            timeout: int — seconds (default: 600)
            forms: bool — test forms (default: True)
            crawl_depth: int — crawl depth for form discovery (default: 2)
        """
        options = options or {}
        url = options.get("url", target)
        level = options.get("level", 2)
        risk = options.get("risk", 1)
        timeout = options.get("timeout", 600)
        forms = options.get("forms", True)
        data = options.get("data", "")
        crawl_depth = options.get("crawl_depth", 2)

        # Output directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)

            args = [
                self.get_binary_path(),
                "-u", url,
                "--batch",  # Non-interactive
                "--level", str(level),
                "--risk", str(risk),
                "--output-dir", str(output_dir),
                "--flush-session",
                "--disable-coloring",
            ]

            if data:
                args.extend(["--data", data])
                args.extend(["--method", options.get("method", "POST")])

            if forms:
                args.append("--forms")
                args.extend(["--crawl", str(crawl_depth)])

            result = self.run_subprocess(args, timeout=timeout)

            # Parse output
            result.findings = self._parse_output(result.raw_stdout, result.raw_stderr, url)

            # Try to parse log files from output dir
            try:
                parsed_log = self._parse_log_files(output_dir)
                result.parsed_data = parsed_log
            except Exception as e:
                self.logger.warning("Could not parse SQLMap log files: %s", e)

        return result

    def _parse_output(self, stdout: str, stderr: str, target_url: str) -> List[Dict]:
        """Parse SQLMap stdout for SQL injection findings."""
        findings = []
        combined = stdout + "\n" + stderr

        # Detect injectable parameters
        injectable_params = []
        current_param = None
        injection_types = []

        for line in combined.split("\n"):
            line = line.strip()

            # Parameter is injectable
            if "is injectable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
                # Extract parameter name
                param = self._extract_param_name(line)
                if param:
                    current_param = param

            # Injection type
            if "Type:" in line and current_param:
                injection_type = line.split("Type:", 1)[1].strip() if "Type:" in line else ""
                injection_types.append(injection_type)

            # Title (technique description)
            if "Title:" in line and current_param:
                title = line.split("Title:", 1)[1].strip() if "Title:" in line else ""
                injection_types.append(title)

            # Payload
            if "Payload:" in line and current_param:
                payload = line.split("Payload:", 1)[1].strip() if "Payload:" in line else ""

                finding = {
                    "title": f"SQL Injection — Parameter: {current_param}",
                    "description": (
                        f"SQL injection vulnerability found in parameter '{current_param}' "
                        f"at {target_url}. "
                        f"Injection types: {', '.join(injection_types) if injection_types else 'unknown'}. "
                        f"Payload: {payload}"
                    ),
                    "severity": "critical",
                    "affected_asset": target_url,
                    "affected_component": current_param,
                    "source_tool": "sqlmap",
                    "evidence": f"Payload: {payload}",
                    "cwe_ids": ["CWE-89"],
                    "cve_ids": [],
                    "remediation": (
                        "Use parameterized queries / prepared statements. "
                        "Validate and sanitize all user input. "
                        "Apply the principle of least privilege to database accounts. "
                        "Use an ORM or query builder that automatically handles escaping."
                    ),
                    "raw_data": {
                        "parameter": current_param,
                        "injection_types": injection_types.copy(),
                        "payload": payload,
                    },
                }
                findings.append(finding)
                injection_types = []

            # Database identified
            if "back-end DBMS:" in line.lower():
                dbms = line.split(":", 1)[1].strip() if ":" in line else ""
                findings.append({
                    "title": f"Database Identified: {dbms}",
                    "description": f"Backend DBMS identified as {dbms} on {target_url}",
                    "severity": "info",
                    "affected_asset": target_url,
                    "source_tool": "sqlmap",
                    "raw_data": {"dbms": dbms},
                })

        # If no specific findings but output suggests vulnerability
        if not findings and ("injectable" in combined.lower() or "vulnerable" in combined.lower()):
            findings.append({
                "title": f"Potential SQL Injection at {target_url}",
                "description": "SQLMap detected potential SQL injection. Review output for details.",
                "severity": "high",
                "affected_asset": target_url,
                "source_tool": "sqlmap",
                "cwe_ids": ["CWE-89"],
                "raw_data": {"stdout_excerpt": combined[:2000]},
            })

        return findings

    def _extract_param_name(self, line: str) -> Optional[str]:
        """Extract parameter name from SQLMap output line."""
        # Patterns like "GET parameter 'id' is injectable" or "Parameter: id (GET)"
        import re
        patterns = [
            r"parameter\s+'([^']+)'",
            r"parameter\s+\"([^\"]+)\"",
            r"Parameter:\s+(\S+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _parse_log_files(self, output_dir: Path) -> Dict:
        """Parse SQLMap session log files for additional data."""
        parsed = {"databases": [], "tables": [], "injections": []}

        # Walk the output directory for log and session files
        for filepath in output_dir.rglob("*"):
            if filepath.is_file() and filepath.suffix in (".log", ".txt", ""):
                try:
                    content = filepath.read_text(encoding="utf-8", errors="replace")
                    if "database:" in content.lower():
                        for line in content.split("\n"):
                            if "database:" in line.lower():
                                parsed["databases"].append(line.strip())
                except Exception:
                    pass

        return parsed
