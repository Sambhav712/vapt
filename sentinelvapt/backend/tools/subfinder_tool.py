"""
SentinelVAPT — Subfinder Integration
Subdomain enumeration using ProjectDiscovery's Subfinder.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class SubfinderTool(ToolBase):
    name = "subfinder"
    binary_name = "subfinder"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run Subfinder for subdomain enumeration.
        Options:
            timeout: int — seconds (default: 300)
            threads: int — concurrent goroutines (default: 30)
            recursive: bool — enable recursive enumeration (default: False)
        """
        options = options or {}
        timeout = options.get("timeout", 300)
        threads = options.get("threads", 30)
        recursive = options.get("recursive", False)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = Path(tmp.name)

        args = [
            self.get_binary_path(),
            "-d", target,
            "-o", str(json_output),
            "-oJ",  # JSON Lines output
            "-silent",
            "-t", str(threads),
        ]

        if recursive:
            args.append("-recursive")

        result = self.run_subprocess(args, timeout=timeout)

        # Parse output
        subdomains = []
        if json_output.exists():
            try:
                content = json_output.read_text(encoding="utf-8", errors="replace")
                for line in content.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", line)
                        subdomains.append(host)
                    except json.JSONDecodeError:
                        # Plain text output (one subdomain per line)
                        subdomains.append(line)
            except Exception as e:
                self.logger.error("Failed to parse Subfinder output: %s", e)
            finally:
                json_output.unlink(missing_ok=True)

        # Also parse stdout for subdomains
        if not subdomains and result.raw_stdout:
            for line in result.raw_stdout.strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.append(line)

        subdomains = sorted(set(subdomains))

        result.findings = [{
            "title": f"Subdomain Discovered: {sub}",
            "description": f"Subdomain {sub} found for domain {target}",
            "severity": "info",
            "affected_asset": sub,
            "source_tool": "subfinder",
            "raw_data": {"subdomain": sub, "parent_domain": target},
        } for sub in subdomains]

        result.parsed_data = {
            "domain": target,
            "subdomains": subdomains,
            "count": len(subdomains),
        }

        return result
