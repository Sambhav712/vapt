"""
SentinelVAPT — Amass Integration
Advanced subdomain enumeration and asset discovery.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class AmassTool(ToolBase):
    name = "amass"
    binary_name = "amass"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run Amass passive/active subdomain enumeration.
        Options:
            mode: str — "passive" | "active" (default: "passive")
            timeout: int — minutes (default: 15)
            max_timeout_seconds: int — subprocess timeout (default: 1200)
        """
        options = options or {}
        mode = options.get("mode", "passive")
        timeout_minutes = options.get("timeout", 15)
        max_timeout = options.get("max_timeout_seconds", 1200)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = Path(tmp.name)

        args = [
            self.get_binary_path(),
            "enum",
            "-d", target,
            "-json", str(json_output),
            "-timeout", str(timeout_minutes),
        ]

        if mode == "passive":
            args.append("-passive")

        result = self.run_subprocess(args, timeout=max_timeout)

        # Parse JSON output
        subdomains = set()
        records = []
        if json_output.exists():
            try:
                content = json_output.read_text(encoding="utf-8", errors="replace")
                for line in content.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        name = entry.get("name", "")
                        if name:
                            subdomains.add(name)
                        records.append(entry)
                    except json.JSONDecodeError:
                        # Plain text subdomain
                        if "." in line:
                            subdomains.add(line)
            except Exception as e:
                self.logger.error("Failed to parse Amass output: %s", e)
            finally:
                json_output.unlink(missing_ok=True)

        # Parse stdout fallback
        if not subdomains and result.raw_stdout:
            for line in result.raw_stdout.strip().split("\n"):
                line = line.strip()
                if line and "." in line and " " not in line:
                    subdomains.add(line)

        sorted_subs = sorted(subdomains)

        result.findings = [{
            "title": f"Subdomain Discovered: {sub}",
            "description": f"Subdomain {sub} found via Amass ({mode} enumeration) for {target}",
            "severity": "info",
            "affected_asset": sub,
            "source_tool": "amass",
            "raw_data": {"subdomain": sub, "parent_domain": target, "mode": mode},
        } for sub in sorted_subs]

        result.parsed_data = {
            "domain": target,
            "subdomains": sorted_subs,
            "count": len(sorted_subs),
            "mode": mode,
            "records": records[:100],  # Limit stored records
        }

        return result
