"""
SentinelVAPT — OWASP ZAP Integration
Drives ZAP via its official REST API: daemon management, spider, active scan, alert retrieval.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, quote

import requests

from backend.tools.base import ToolBase, ParsedResult
from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.tools.zap")

SEVERITY_MAP = {
    "0": "info",       # Informational
    "1": "low",        # Low
    "2": "medium",     # Medium
    "3": "high",       # High
}


class ZapTool(ToolBase):
    name = "zap"
    binary_name = "zap-cli"

    def __init__(self):
        super().__init__()
        settings = get_settings()
        self.base_url = settings.zap_base_url
        self.api_key = settings.zap_api_key

    def _api(self, path: str, params: Optional[Dict] = None) -> Dict:
        """Make a ZAP API call."""
        params = params or {}
        params["apikey"] = self.api_key
        url = urljoin(self.base_url, path)
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def is_zap_running(self) -> bool:
        """Check if ZAP daemon is accessible."""
        try:
            self._api("/JSON/core/view/version/")
            return True
        except Exception:
            return False

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run a full ZAP scan: spider -> active scan -> retrieve alerts.
        Options:
            scan_type: str — "spider_only" | "active" | "full" (default: "full")
            max_depth: int — spider depth (default: 5)
            timeout: int — total timeout in seconds (default: 1800)
            poll_interval: int — seconds between status checks (default: 10)
        """
        options = options or {}
        scan_type = options.get("scan_type", "full")
        max_depth = options.get("max_depth", 5)
        timeout = options.get("timeout", 1800)
        poll_interval = options.get("poll_interval", 10)

        result = ParsedResult(tool_name=self.name, success=False)
        start_time = time.time()

        # Check if ZAP is running
        if not self.is_zap_running():
            result.error_message = (
                "ZAP daemon is not running. Start it with: "
                "zap.sh -daemon -port 8080 -config api.key=<key> "
                "or: zaproxy -daemon -port 8080"
            )
            self.logger.error(result.error_message)
            return result

        try:
            # Step 1: Spider the target
            self.logger.info("Starting ZAP spider on %s", target)
            spider_id = self._start_spider(target, max_depth)

            if spider_id is not None:
                self._wait_for_spider(spider_id, timeout // 3, poll_interval)

            # Step 2: Active scan (if requested)
            if scan_type in ("active", "full"):
                self.logger.info("Starting ZAP active scan on %s", target)
                scan_id = self._start_active_scan(target)

                if scan_id is not None:
                    remaining_time = timeout - (time.time() - start_time)
                    self._wait_for_active_scan(scan_id, max(60, int(remaining_time)), poll_interval)

            # Step 3: Retrieve all alerts
            self.logger.info("Retrieving ZAP alerts for %s", target)
            alerts = self._get_alerts(target)
            result.findings = self._normalize_alerts(alerts)
            result.parsed_data = {
                "alert_count": len(alerts),
                "finding_count": len(result.findings),
                "target": target,
            }
            result.success = True
            result.duration_seconds = round(time.time() - start_time, 2)

        except Exception as e:
            self.logger.error("ZAP scan failed: %s", e)
            result.error_message = str(e)
            result.duration_seconds = round(time.time() - start_time, 2)

        return result

    def _start_spider(self, target: str, max_depth: int) -> Optional[str]:
        try:
            resp = self._api("/JSON/spider/action/scan/", {
                "url": target,
                "maxDepth": str(max_depth),
                "recurse": "true",
            })
            return resp.get("scan")
        except Exception as e:
            self.logger.error("Failed to start spider: %s", e)
            return None

    def _wait_for_spider(self, scan_id: str, timeout: int, poll_interval: int):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self._api("/JSON/spider/view/status/", {"scanId": scan_id})
                status = int(resp.get("status", 0))
                self.logger.info("Spider progress: %d%%", status)
                if status >= 100:
                    return
            except Exception as e:
                self.logger.warning("Spider status check failed: %s", e)
            time.sleep(poll_interval)
        self.logger.warning("Spider timed out after %ds", timeout)

    def _start_active_scan(self, target: str) -> Optional[str]:
        try:
            resp = self._api("/JSON/ascan/action/scan/", {
                "url": target,
                "recurse": "true",
                "scanPolicyName": "",
            })
            return resp.get("scan")
        except Exception as e:
            self.logger.error("Failed to start active scan: %s", e)
            return None

    def _wait_for_active_scan(self, scan_id: str, timeout: int, poll_interval: int):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self._api("/JSON/ascan/view/status/", {"scanId": scan_id})
                status = int(resp.get("status", 0))
                self.logger.info("Active scan progress: %d%%", status)
                if status >= 100:
                    return
            except Exception as e:
                self.logger.warning("Active scan status check failed: %s", e)
            time.sleep(poll_interval)
        self.logger.warning("Active scan timed out after %ds", timeout)

    def _get_alerts(self, target: str) -> List[Dict]:
        """Retrieve all ZAP alerts for the target."""
        try:
            resp = self._api("/JSON/alert/view/alerts/", {
                "baseurl": target,
                "start": "0",
                "count": "1000",
            })
            return resp.get("alerts", [])
        except Exception as e:
            self.logger.error("Failed to get alerts: %s", e)
            return []

    def _normalize_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Normalize ZAP alerts into standard finding format."""
        findings = []
        for alert in alerts:
            risk = alert.get("risk", "0")
            severity = SEVERITY_MAP.get(str(risk), "info")

            cwe_id = alert.get("cweid", "")
            cwe_ids = [f"CWE-{cwe_id}"] if cwe_id and cwe_id != "-1" else []

            finding = {
                "title": alert.get("name", alert.get("alert", "Unknown ZAP Alert")),
                "description": alert.get("description", ""),
                "severity": severity,
                "affected_asset": alert.get("url", ""),
                "affected_component": alert.get("param", ""),
                "source_tool": "zap",
                "evidence": alert.get("evidence", ""),
                "remediation": alert.get("solution", ""),
                "cwe_ids": cwe_ids,
                "cve_ids": [],
                "raw_data": {
                    "alert_ref": alert.get("alertRef", ""),
                    "risk": risk,
                    "confidence": alert.get("confidence", ""),
                    "method": alert.get("method", ""),
                    "url": alert.get("url", ""),
                    "param": alert.get("param", ""),
                    "attack": alert.get("attack", ""),
                    "other_info": alert.get("other", ""),
                    "reference": alert.get("reference", ""),
                    "tags": alert.get("tags", {}),
                },
            }
            findings.append(finding)

        return findings
