"""
SentinelVAPT — Nikto Integration
Web server misconfiguration scanning via subprocess with CSV/stdout parsing.
"""

import csv
import io
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class NiktoTool(ToolBase):
    name = "nikto"
    binary_name = "nikto"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run Nikto against a target web server.
        Options:
            port: int — port to scan (default: auto-detect from target)
            ssl: bool — use SSL (default: auto-detect)
            timeout: int — seconds (default: 600)
            tuning: str — scan tuning options (default: "x")
        """
        options = options or {}
        timeout = options.get("timeout", 600)
        tuning = options.get("tuning", "")

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as tmp:
            csv_output = Path(tmp.name)

        args = [
            self.get_binary_path(),
            "-h", target,
            "-Format", "csv",
            "-output", str(csv_output),
            "-nointeractive",
            "-Display", "V",
        ]

        if options.get("port"):
            args.extend(["-p", str(options["port"])])

        if options.get("ssl"):
            args.append("-ssl")

        if tuning:
            args.extend(["-Tuning", tuning])

        result = self.run_subprocess(args, timeout=timeout)

        # Parse CSV output
        if csv_output.exists():
            try:
                result.findings = self._parse_csv(csv_output, target)
            except Exception as e:
                self.logger.error("Failed to parse Nikto CSV: %s", e)
            finally:
                csv_output.unlink(missing_ok=True)

        # Also parse stdout for additional findings
        stdout_findings = self._parse_stdout(result.raw_stdout, target)
        if stdout_findings:
            existing_titles = {f["title"] for f in result.findings}
            for f in stdout_findings:
                if f["title"] not in existing_titles:
                    result.findings.append(f)

        result.parsed_data = {"finding_count": len(result.findings)}
        return result

    def _parse_csv(self, csv_path: Path, target: str) -> List[Dict]:
        """Parse Nikto CSV output."""
        findings = []
        try:
            content = csv_path.read_text(encoding="utf-8", errors="replace")
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if len(row) < 7:
                    continue
                # Nikto CSV: hostname, IP, port, ref, method, URI, description
                if row[0].startswith('"'):
                    row = [c.strip('"') for c in row]

                hostname = row[0] if len(row) > 0 else ""
                ip = row[1] if len(row) > 1 else ""
                port = row[2] if len(row) > 2 else ""
                ref = row[3] if len(row) > 3 else ""
                method = row[4] if len(row) > 4 else ""
                uri = row[5] if len(row) > 5 else ""
                description = row[6] if len(row) > 6 else ""

                if not description or description.startswith("#"):
                    continue

                severity = self._assess_severity(description, ref)

                finding = {
                    "title": f"Nikto: {description[:100]}",
                    "description": description,
                    "severity": severity,
                    "affected_asset": target,
                    "affected_component": uri,
                    "source_tool": "nikto",
                    "evidence": f"{method} {uri}",
                    "raw_data": {
                        "hostname": hostname,
                        "ip": ip,
                        "port": port,
                        "ref": ref,
                        "method": method,
                        "uri": uri,
                    },
                }
                findings.append(finding)
        except Exception as e:
            self.logger.error("CSV parsing error: %s", e)

        return findings

    def _parse_stdout(self, stdout: str, target: str) -> List[Dict]:
        """Parse Nikto stdout for findings not in CSV."""
        findings = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or not line.startswith("+"):
                continue
            # Lines starting with + contain findings
            content = line.lstrip("+ ").strip()
            if any(skip in content.lower() for skip in ["target ip:", "target hostname:", "target port:", "start time:", "end time:", "host(s) tested"]):
                continue
            if len(content) < 10:
                continue

            severity = self._assess_severity(content, "")

            findings.append({
                "title": f"Nikto: {content[:100]}",
                "description": content,
                "severity": severity,
                "affected_asset": target,
                "source_tool": "nikto",
                "raw_data": {"stdout_line": content},
            })

        return findings

    def _assess_severity(self, description: str, ref: str) -> str:
        """Heuristic severity assessment based on description content."""
        desc_lower = description.lower()
        critical_keywords = ["remote code execution", "rce", "command injection", "shell", "backdoor"]
        high_keywords = ["sql injection", "xss", "cross-site", "directory traversal", "path traversal", "file inclusion", "lfi", "rfi"]
        medium_keywords = ["information disclosure", "default password", "misconfiguration", "outdated", "deprecated", "clickjacking"]
        low_keywords = ["missing header", "cookie", "robots.txt", "sitemap"]

        for kw in critical_keywords:
            if kw in desc_lower:
                return "critical"
        for kw in high_keywords:
            if kw in desc_lower:
                return "high"
        for kw in medium_keywords:
            if kw in desc_lower:
                return "medium"
        for kw in low_keywords:
            if kw in desc_lower:
                return "low"
        return "info"
