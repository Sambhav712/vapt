"""
SentinelVAPT — API Security Testing Module
Custom OWASP API Top 10 checks: BOLA, mass assignment, broken auth, rate limits, etc.
Parses OpenAPI/Swagger specs and runs targeted security tests.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from backend.tools.base import ToolBase, ParsedResult

logger = logging.getLogger("sentinelvapt.tools.api_tester")


class ApiSecurityTool(ToolBase):
    """Custom API security scanner implementing OWASP API Top 10 checks."""
    name = "api_security"
    binary_name = "python"  # Not a CLI tool — runs as Python code

    def is_available(self) -> bool:
        return True  # Always available, it's a Python module

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run OWASP API Top 10 security checks against an API target.
        Options:
            openapi_spec_url: str — URL to OpenAPI/Swagger spec (optional)
            openapi_spec: dict — parsed OpenAPI spec (optional)
            auth_token: str — Bearer token for authenticated endpoints
            timeout: int — per-request timeout (default: 10)
            rate_limit_check: bool — test rate limiting (default: True)
        """
        options = options or {}
        spec_url = options.get("openapi_spec_url", "")
        spec = options.get("openapi_spec")
        auth_token = options.get("auth_token", "")
        timeout = options.get("timeout", 10)
        check_rate_limit = options.get("rate_limit_check", True)

        result = ParsedResult(tool_name=self.name, success=True)
        start = time.time()

        # Try to fetch and parse OpenAPI spec
        endpoints = []
        if spec_url and not spec:
            spec = self._fetch_spec(spec_url, timeout)
        if spec:
            endpoints = self._parse_openapi_endpoints(spec, target)

        # Common API spec discovery URLs
        if not endpoints:
            endpoints = self._discover_endpoints(target, timeout)

        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # Run checks
        all_findings = []

        # 1. BOLA (Broken Object Level Authorization)
        all_findings.extend(self._check_bola(target, endpoints, headers, timeout))

        # 2. Broken Authentication
        all_findings.extend(self._check_broken_auth(target, endpoints, headers, timeout))

        # 3. Excessive Data Exposure
        all_findings.extend(self._check_excessive_data(target, endpoints, headers, timeout))

        # 4. Rate Limiting
        if check_rate_limit:
            all_findings.extend(self._check_rate_limiting(target, endpoints, headers, timeout))

        # 5. Mass Assignment
        all_findings.extend(self._check_mass_assignment(target, endpoints, headers, timeout))

        # 6. Security Misconfiguration
        all_findings.extend(self._check_security_misconfig(target, headers, timeout))

        # 7. Injection (basic)
        all_findings.extend(self._check_injection(target, endpoints, headers, timeout))

        result.findings = all_findings
        result.duration_seconds = round(time.time() - start, 2)
        result.parsed_data = {
            "endpoints_tested": len(endpoints),
            "findings_count": len(all_findings),
        }
        return result

    def _fetch_spec(self, url: str, timeout: int) -> Optional[Dict]:
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            self.logger.warning("Failed to fetch OpenAPI spec from %s: %s", url, e)
        return None

    def _discover_endpoints(self, base_url: str, timeout: int) -> List[Dict]:
        """Try to discover API endpoints from common spec URLs."""
        spec_paths = [
            "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs",
            "/v3/api-docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json",
        ]
        for path in spec_paths:
            url = urljoin(base_url, path)
            spec = self._fetch_spec(url, timeout)
            if spec:
                return self._parse_openapi_endpoints(spec, base_url)
        return []

    def _parse_openapi_endpoints(self, spec: Dict, base_url: str) -> List[Dict]:
        """Extract endpoints from an OpenAPI spec."""
        endpoints = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [{"url": base_url}])
        server_url = servers[0].get("url", base_url) if servers else base_url

        if not server_url.startswith("http"):
            server_url = base_url

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "url": urljoin(server_url, path),
                    "parameters": details.get("parameters", []),
                    "request_body": details.get("requestBody", {}),
                    "security": details.get("security", []),
                    "summary": details.get("summary", ""),
                }
                endpoints.append(endpoint)
        return endpoints

    def _check_bola(self, base_url: str, endpoints: List[Dict],
                    headers: Dict, timeout: int) -> List[Dict]:
        """Check for Broken Object Level Authorization (API1:2023)."""
        findings = []
        for ep in endpoints:
            if "{" in ep.get("path", "") and ep.get("method") == "GET":
                # Try accessing with different IDs
                test_path = ep["path"]
                for param in ["id", "user_id", "userId", "account_id"]:
                    if f"{{{param}}}" in test_path:
                        for test_id in ["1", "2", "999", "0", "-1"]:
                            test_url = urljoin(base_url, test_path.replace(f"{{{param}}}", test_id))
                            try:
                                resp = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                                if resp.status_code == 200:
                                    findings.append({
                                        "title": f"Potential BOLA: {ep['method']} {ep['path']}",
                                        "description": (
                                            f"Endpoint {ep['path']} returned 200 for ID={test_id}. "
                                            f"If this returns data for other users' resources without "
                                            f"proper authorization checks, it's a BOLA vulnerability. "
                                            f"(OWASP API1:2023)"
                                        ),
                                        "severity": "high",
                                        "affected_asset": base_url,
                                        "affected_component": ep["path"],
                                        "source_tool": "api_security",
                                        "cwe_ids": ["CWE-639"],
                                        "remediation": "Implement object-level authorization checks. Verify the authenticated user has access to the requested resource.",
                                        "raw_data": {"endpoint": ep, "test_id": test_id, "status": resp.status_code},
                                    })
                                    break  # One finding per endpoint is enough
                            except Exception:
                                pass
        return findings

    def _check_broken_auth(self, base_url: str, endpoints: List[Dict],
                           headers: Dict, timeout: int) -> List[Dict]:
        """Check for Broken Authentication (API2:2023)."""
        findings = []
        # Test endpoints without auth token
        for ep in endpoints[:20]:
            try:
                resp = requests.request(
                    ep["method"], urljoin(base_url, ep["path"]),
                    timeout=timeout, verify=False
                )
                if resp.status_code == 200 and ep.get("security"):
                    findings.append({
                        "title": f"Missing Authentication: {ep['method']} {ep['path']}",
                        "description": (
                            f"Endpoint {ep['path']} is accessible without authentication "
                            f"despite having security requirements in its OpenAPI spec. "
                            f"(OWASP API2:2023)"
                        ),
                        "severity": "high",
                        "affected_asset": base_url,
                        "affected_component": ep["path"],
                        "source_tool": "api_security",
                        "cwe_ids": ["CWE-306"],
                        "remediation": "Enforce authentication on all non-public endpoints.",
                        "raw_data": {"endpoint": ep, "status": resp.status_code},
                    })
            except Exception:
                pass
        return findings

    def _check_excessive_data(self, base_url: str, endpoints: List[Dict],
                              headers: Dict, timeout: int) -> List[Dict]:
        """Check for Excessive Data Exposure (API3:2023)."""
        findings = []
        sensitive_fields = [
            "password", "secret", "token", "ssn", "credit_card", "creditCard",
            "social_security", "private_key", "privateKey", "api_key", "apiKey",
        ]
        for ep in endpoints[:20]:
            if ep["method"] != "GET":
                continue
            try:
                url = urljoin(base_url, ep["path"].replace("{", "1").replace("}", ""))
                resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        exposed = self._find_sensitive_fields(data, sensitive_fields)
                        if exposed:
                            findings.append({
                                "title": f"Excessive Data Exposure: {ep['path']}",
                                "description": (
                                    f"Endpoint {ep['path']} exposes potentially sensitive fields: "
                                    f"{', '.join(exposed)}. (OWASP API3:2023)"
                                ),
                                "severity": "medium",
                                "affected_asset": base_url,
                                "affected_component": ep["path"],
                                "source_tool": "api_security",
                                "cwe_ids": ["CWE-213"],
                                "remediation": "Filter response data to only include fields the client needs. Never expose sensitive fields like passwords or tokens.",
                                "raw_data": {"endpoint": ep, "sensitive_fields": exposed},
                            })
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass
        return findings

    def _find_sensitive_fields(self, data: Any, sensitive: List[str], prefix: str = "") -> List[str]:
        """Recursively find sensitive field names in JSON data."""
        found = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if any(s in key.lower() for s in sensitive):
                    found.append(full_key)
                found.extend(self._find_sensitive_fields(value, sensitive, full_key))
        elif isinstance(data, list) and data:
            found.extend(self._find_sensitive_fields(data[0], sensitive, prefix))
        return found

    def _check_rate_limiting(self, base_url: str, endpoints: List[Dict],
                             headers: Dict, timeout: int) -> List[Dict]:
        """Check for missing rate limiting (API4:2023)."""
        findings = []
        # Pick a safe endpoint to test
        test_url = base_url
        for ep in endpoints:
            if ep["method"] == "GET":
                test_url = urljoin(base_url, ep["path"].replace("{", "1").replace("}", ""))
                break

        # Send rapid requests
        success_count = 0
        try:
            for _ in range(50):
                resp = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                if resp.status_code == 200:
                    success_count += 1
                elif resp.status_code == 429:
                    return findings  # Rate limiting works

            if success_count >= 45:
                findings.append({
                    "title": f"Missing Rate Limiting on {urlparse(test_url).path}",
                    "description": (
                        f"API endpoint accepted all 50 rapid requests without rate limiting. "
                        f"This can lead to brute-force attacks, DoS, or resource exhaustion. "
                        f"(OWASP API4:2023)"
                    ),
                    "severity": "medium",
                    "affected_asset": base_url,
                    "affected_component": urlparse(test_url).path,
                    "source_tool": "api_security",
                    "cwe_ids": ["CWE-770"],
                    "remediation": "Implement rate limiting (e.g., token bucket algorithm). Return 429 Too Many Requests for excessive access.",
                    "raw_data": {"test_url": test_url, "requests_sent": 50, "success_count": success_count},
                })
        except Exception:
            pass
        return findings

    def _check_mass_assignment(self, base_url: str, endpoints: List[Dict],
                               headers: Dict, timeout: int) -> List[Dict]:
        """Check for Mass Assignment (API6:2023)."""
        findings = []
        privileged_fields = ["role", "admin", "is_admin", "isAdmin", "permissions", "privilege", "is_staff"]

        for ep in endpoints[:20]:
            if ep["method"] in ("POST", "PUT", "PATCH") and ep.get("request_body"):
                test_url = urljoin(base_url, ep["path"].replace("{", "1").replace("}", ""))
                test_body = {field: True for field in privileged_fields}
                try:
                    resp = requests.request(
                        ep["method"], test_url, json=test_body,
                        headers=headers, timeout=timeout, verify=False
                    )
                    if resp.status_code in (200, 201):
                        findings.append({
                            "title": f"Potential Mass Assignment: {ep['method']} {ep['path']}",
                            "description": (
                                f"Endpoint accepted a request body with privileged fields "
                                f"({', '.join(privileged_fields)}). If these fields are processed "
                                f"without whitelisting, it could allow privilege escalation. "
                                f"(OWASP API6:2023)"
                            ),
                            "severity": "high",
                            "affected_asset": base_url,
                            "affected_component": ep["path"],
                            "source_tool": "api_security",
                            "cwe_ids": ["CWE-915"],
                            "remediation": "Use an allowlist of permitted fields. Never bind request body directly to database models without filtering.",
                            "raw_data": {"endpoint": ep, "status": resp.status_code},
                        })
                except Exception:
                    pass
        return findings

    def _check_security_misconfig(self, base_url: str, headers: Dict,
                                   timeout: int) -> List[Dict]:
        """Check for Security Misconfiguration (API8:2023)."""
        findings = []
        try:
            resp = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
            resp_headers = resp.headers

            # Check security headers
            security_headers = {
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "X-Frame-Options": "Prevents clickjacking",
                "Strict-Transport-Security": "Enforces HTTPS",
                "Content-Security-Policy": "Prevents XSS and injection attacks",
                "X-XSS-Protection": "XSS filter",
            }

            missing = []
            for header, purpose in security_headers.items():
                if header.lower() not in {k.lower() for k in resp_headers.keys()}:
                    missing.append(f"{header} ({purpose})")

            if missing:
                findings.append({
                    "title": "Missing Security Headers",
                    "description": (
                        f"The API at {base_url} is missing the following security headers: "
                        f"{'; '.join(missing)}. (OWASP API8:2023)"
                    ),
                    "severity": "low",
                    "affected_asset": base_url,
                    "source_tool": "api_security",
                    "cwe_ids": ["CWE-693"],
                    "remediation": "Add the missing security headers to all API responses.",
                    "raw_data": {"missing_headers": missing},
                })

            # Check CORS
            cors_header = resp_headers.get("Access-Control-Allow-Origin", "")
            if cors_header == "*":
                findings.append({
                    "title": "Permissive CORS Policy",
                    "description": (
                        f"The API at {base_url} has Access-Control-Allow-Origin set to '*', "
                        f"allowing any domain to make cross-origin requests. "
                        f"This may expose the API to cross-site attacks."
                    ),
                    "severity": "medium",
                    "affected_asset": base_url,
                    "source_tool": "api_security",
                    "cwe_ids": ["CWE-942"],
                    "remediation": "Restrict CORS to specific trusted domains instead of using wildcard '*'.",
                    "raw_data": {"cors_header": cors_header},
                })

            # Check for debug/error info
            if resp_headers.get("Server"):
                server_val = resp_headers["Server"]
                findings.append({
                    "title": f"Server Header Exposed: {server_val}",
                    "description": f"Server header reveals technology: '{server_val}'. This aids attacker reconnaissance.",
                    "severity": "low",
                    "affected_asset": base_url,
                    "source_tool": "api_security",
                    "remediation": "Remove or obfuscate the Server header.",
                    "raw_data": {"server_header": server_val},
                })

        except Exception as e:
            self.logger.warning("Security misconfig check failed: %s", e)

        return findings

    def _check_injection(self, base_url: str, endpoints: List[Dict],
                         headers: Dict, timeout: int) -> List[Dict]:
        """Basic injection checks (API8:2023)."""
        findings = []
        payloads = {
            "sqli": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22"],
        }

        for ep in endpoints[:10]:
            if ep["method"] == "GET" and ep.get("parameters"):
                for param in ep["parameters"][:3]:
                    param_name = param.get("name", "")
                    if not param_name:
                        continue
                    for attack_type, attack_payloads in payloads.items():
                        for payload in attack_payloads[:1]:
                            try:
                                test_url = urljoin(base_url, ep["path"].replace("{", "1").replace("}", ""))
                                resp = requests.get(
                                    test_url, params={param_name: payload},
                                    headers=headers, timeout=timeout, verify=False
                                )
                                # Check for signs of injection
                                body = resp.text.lower()
                                if attack_type == "sqli" and any(err in body for err in ["sql", "syntax error", "mysql", "postgresql", "sqlite"]):
                                    findings.append({
                                        "title": f"SQL Injection Indicator: {ep['path']} param={param_name}",
                                        "description": f"Database error message in response when injecting SQL payload into parameter '{param_name}'.",
                                        "severity": "critical",
                                        "affected_asset": base_url,
                                        "affected_component": f"{ep['path']}?{param_name}=",
                                        "source_tool": "api_security",
                                        "cwe_ids": ["CWE-89"],
                                        "remediation": "Use parameterized queries. Validate all input.",
                                        "raw_data": {"endpoint": ep["path"], "param": param_name, "payload": payload},
                                    })
                                elif attack_type == "xss" and payload in resp.text:
                                    findings.append({
                                        "title": f"Reflected XSS: {ep['path']} param={param_name}",
                                        "description": f"XSS payload reflected unescaped in response for parameter '{param_name}'.",
                                        "severity": "high",
                                        "affected_asset": base_url,
                                        "affected_component": f"{ep['path']}?{param_name}=",
                                        "source_tool": "api_security",
                                        "cwe_ids": ["CWE-79"],
                                        "remediation": "Encode all output. Use Content-Security-Policy header.",
                                        "raw_data": {"endpoint": ep["path"], "param": param_name, "payload": payload},
                                    })
                            except Exception:
                                pass
        return findings
