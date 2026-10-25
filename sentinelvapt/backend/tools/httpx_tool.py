"""
SentinelVAPT — httpx Integration
HTTP probing and technology detection using ProjectDiscovery's httpx.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class HttpxTool(ToolBase):
    name = "httpx"
    binary_name = "httpx"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Probe live hosts with httpx.
        Target can be a single host or a file containing hosts.
        Options:
            hosts: list — list of hosts to probe (used instead of target if provided)
            timeout: int — seconds (default: 300)
            threads: int — concurrent threads (default: 50)
            tech_detect: bool — detect technologies (default: True)
            status_code: bool — show status codes (default: True)
            follow_redirects: bool — follow redirects (default: True)
        """
        options = options or {}
        timeout = options.get("timeout", 300)
        threads = options.get("threads", 50)
        tech_detect = options.get("tech_detect", True)
        hosts = options.get("hosts", [])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = Path(tmp.name)

        # Build args
        args = [
            self.get_binary_path(),
            "-o", str(json_output),
            "-json",
            "-silent",
            "-threads", str(threads),
            "-status-code",
            "-title",
            "-server",
            "-content-length",
            "-follow-redirects",
        ]

        if tech_detect:
            args.append("-tech-detect")

        # Handle input: list of hosts or single target
        input_file = None
        if hosts:
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as hf:
                hf.write("\n".join(hosts))
                input_file = Path(hf.name)
            args.extend(["-l", str(input_file)])
        else:
            args.extend(["-u", target])

        result = self.run_subprocess(args, timeout=timeout)

        # Parse JSONL output
        probed_hosts = []
        if json_output.exists():
            try:
                content = json_output.read_text(encoding="utf-8", errors="replace")
                for line in content.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        probed_hosts.append(entry)
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                self.logger.error("Failed to parse httpx output: %s", e)
            finally:
                json_output.unlink(missing_ok=True)

        if input_file and input_file.exists():
            input_file.unlink(missing_ok=True)

        # Build findings
        result.findings = []
        for host_info in probed_hosts:
            url = host_info.get("url", host_info.get("input", ""))
            status = host_info.get("status_code", host_info.get("status-code", 0))
            title = host_info.get("title", "")
            server = host_info.get("webserver", host_info.get("server", ""))
            techs = host_info.get("tech", host_info.get("technologies", []))
            content_length = host_info.get("content_length", host_info.get("content-length", 0))

            finding = {
                "title": f"Live Host: {url} [{status}]",
                "description": (
                    f"HTTP service detected at {url}. "
                    f"Status: {status}, Title: '{title}', "
                    f"Server: {server}, Technologies: {', '.join(techs) if techs else 'N/A'}"
                ),
                "severity": "info",
                "affected_asset": url,
                "source_tool": "httpx",
                "raw_data": {
                    "url": url,
                    "status_code": status,
                    "title": title,
                    "server": server,
                    "technologies": techs,
                    "content_length": content_length,
                    "host": host_info.get("host", ""),
                    "scheme": host_info.get("scheme", ""),
                    "port": host_info.get("port", ""),
                },
            }
            result.findings.append(finding)

        result.parsed_data = {
            "live_hosts": [h.get("url", "") for h in probed_hosts],
            "count": len(probed_hosts),
        }

        return result
