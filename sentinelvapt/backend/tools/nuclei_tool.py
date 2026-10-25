"""
SentinelVAPT — Nuclei Integration
Template-based vulnerability scanning with JSON output parsing.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiTool(ToolBase):
    name = "nuclei"
    binary_name = "nuclei"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run Nuclei against a target URL/host.
        Options:
            severity: str — comma-separated severities to scan for (default: all)
            templates: list — specific template paths/tags
            rate_limit: int — requests per second (default: 150)
            timeout: int — seconds (default: 900)
            tags: str — comma-separated template tags
            exclude_tags: str — tags to exclude
        """
        options = options or {}
        severity = options.get("severity", "critical,high,medium,low,info")
        rate_limit = options.get("rate_limit", 150)
        timeout = options.get("timeout", 900)
        tags = options.get("tags", "")
        exclude_tags = options.get("exclude_tags", "dos,fuzz")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = Path(tmp.name)

        args = [
            self.get_binary_path(),
            "-target", target,
            "-jsonl",
            "-output", str(json_output),
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-silent",
            "-no-color",
        ]

        if tags:
            args.extend(["-tags", tags])
        if exclude_tags:
            args.extend(["-exclude-tags", exclude_tags])

        # Custom templates
        template_paths = options.get("templates", [])
        for tp in template_paths:
            args.extend(["-t", tp])

        result = self.run_subprocess(args, timeout=timeout)

        # Parse JSONL output
        if json_output.exists():
            try:
                result.findings = self._parse_jsonl(json_output)
                result.parsed_data = {"finding_count": len(result.findings)}
            except Exception as e:
                self.logger.error("Failed to parse Nuclei output: %s", e)
                result.error_message += f" | Parse error: {e}"
            finally:
                json_output.unlink(missing_ok=True)

        return result

    def _parse_jsonl(self, path: Path) -> List[Dict]:
        """Parse Nuclei JSONL output into normalized findings."""
        findings = []
        with open(str(path), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = entry.get("info", {})
                severity_raw = info.get("severity", "info").lower()
                severity = SEVERITY_MAP.get(severity_raw, "info")

                finding = {
                    "title": info.get("name", entry.get("template-id", "Unknown")),
                    "description": info.get("description", ""),
                    "severity": severity,
                    "affected_asset": entry.get("host", entry.get("matched-at", "")),
                    "affected_component": entry.get("matched-at", ""),
                    "source_tool": "nuclei",
                    "evidence": entry.get("matcher-name", ""),
                    "cve_ids": self._extract_cves(info),
                    "cwe_ids": self._extract_cwes(info),
                    "cvss_score": self._extract_cvss(info),
                    "remediation": info.get("remediation", ""),
                    "raw_data": {
                        "template_id": entry.get("template-id", ""),
                        "template_url": entry.get("template-url", ""),
                        "type": entry.get("type", ""),
                        "matcher_name": entry.get("matcher-name", ""),
                        "extracted_results": entry.get("extracted-results", []),
                        "curl_command": entry.get("curl-command", ""),
                        "request": entry.get("request", ""),
                        "response": entry.get("response", "")[:2000] if entry.get("response") else "",
                    },
                }

                # Tags for MITRE mapping
                tags = info.get("tags", [])
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",")]
                finding["raw_data"]["tags"] = tags

                findings.append(finding)

        return findings

    def _extract_cves(self, info: Dict) -> List[str]:
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, str):
            return [cve_ids] if cve_ids else []
        return cve_ids or []

    def _extract_cwes(self, info: Dict) -> List[str]:
        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])
        if isinstance(cwe_ids, str):
            return [cwe_ids] if cwe_ids else []
        return cwe_ids or []

    def _extract_cvss(self, info: Dict) -> Optional[float]:
        classification = info.get("classification", {})
        score = classification.get("cvss-score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
        # Try cvss-metrics
        metrics = classification.get("cvss-metrics", "")
        if metrics:
            # Try to extract score from CVSS vector — rough approximation
            pass
        return None
