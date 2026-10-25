"""
SentinelVAPT — Nmap Integration
Port scanning, service/version detection, and OS fingerprinting via subprocess + XML parsing.
"""

import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.tools.base import ToolBase, ParsedResult


class NmapTool(ToolBase):
    name = "nmap"
    binary_name = "nmap"

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ParsedResult:
        """
        Run an Nmap scan against the target.
        Options:
            ports: str — port specification (e.g., "1-1000", "80,443,8080")
            scan_type: str — "quick" | "full" | "stealth" (default: "quick")
            os_detect: bool — enable OS detection (default: False)
            service_version: bool — enable service/version detection (default: True)
            timeout: int — seconds (default: 600)
        """
        options = options or {}
        ports = options.get("ports", "1-10000")
        scan_type = options.get("scan_type", "quick")
        os_detect = options.get("os_detect", False)
        service_version = options.get("service_version", True)
        timeout = options.get("timeout", 600)

        # Create temp file for XML output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_output = Path(tmp.name)

        # Check privilege status to adapt scan flags gracefully
        from backend.core.privilege_manager import get_privilege_manager, PrivilegeLevel
        from backend.config.settings import get_settings
        pm = get_privilege_manager()
        priv_status = pm.detect()
        auto_elevate = getattr(get_settings(), "auto_elevate", True)
        can_elevate = priv_status.level == PrivilegeLevel.ROOT or (priv_status.has_sudo and auto_elevate) or priv_status.can_raw_socket

        stealth_flag = "-sS" if can_elevate else "-sT"
        if not can_elevate:
            self.logger.info("Raw sockets / root not available: using TCP connect scan (-sT) instead of SYN scan")

        args = [self.get_binary_path()]

        # Scan type flags
        if scan_type == "stealth":
            args.append(stealth_flag)
        elif scan_type == "full":
            if can_elevate:
                args.extend(["-sS", "-sV", "-sC", "-A"])
            else:
                args.extend(["-sT", "-sV", "-sC"])
        else:  # quick
            args.append(stealth_flag)

        # Port specification
        args.extend(["-p", ports])

        # Service version detection
        if service_version:
            args.append("-sV")

        # OS detection (requires root/admin)
        if os_detect:
            if can_elevate:
                args.append("-O")
            else:
                self.logger.warning("OS detection (-O) requires root/Administrator privileges; skipping.")

        # Output format
        args.extend(["-oX", str(xml_output)])

        # Timing (T4 = aggressive but not insane)
        args.append("-T4")

        # Target
        args.append(target)

        result = self.run_subprocess(args, timeout=timeout)

        # Parse XML output
        if xml_output.exists():
            try:
                result.findings, result.parsed_data = self._parse_xml(xml_output)
            except Exception as e:
                self.logger.error("Failed to parse Nmap XML: %s", e)
                result.error_message += f" | XML parse error: {e}"
            finally:
                xml_output.unlink(missing_ok=True)
        else:
            self.logger.warning("Nmap XML output file not found")

        return result

    def _parse_xml(self, xml_path: Path):
        """Parse Nmap XML output into structured findings and data."""
        tree = ET.parse(str(xml_path))
        root = tree.getroot()

        findings = []
        parsed_data = {
            "hosts": [],
            "scan_info": {},
        }

        # Scan info
        scan_info = root.find("scaninfo")
        if scan_info is not None:
            parsed_data["scan_info"] = {
                "type": scan_info.get("type", ""),
                "protocol": scan_info.get("protocol", ""),
                "services": scan_info.get("services", ""),
            }

        # Parse each host
        for host_elem in root.findall("host"):
            host_data = self._parse_host(host_elem)
            parsed_data["hosts"].append(host_data)

            # Create findings for open ports with services
            for port_info in host_data.get("ports", []):
                if port_info["state"] == "open":
                    finding = {
                        "title": f"Open Port {port_info['port']}/{port_info['protocol']} — {port_info.get('service_name', 'unknown')}",
                        "description": (
                            f"Port {port_info['port']}/{port_info['protocol']} is open on "
                            f"{host_data.get('ip', 'unknown')}. "
                            f"Service: {port_info.get('service_name', 'unknown')} "
                            f"Version: {port_info.get('service_version', 'unknown')}"
                        ),
                        "severity": "info",
                        "affected_asset": host_data.get("ip", "unknown"),
                        "affected_component": f"{port_info['port']}/{port_info['protocol']}",
                        "source_tool": "nmap",
                        "raw_data": port_info,
                    }

                    # Flag potentially dangerous open ports as higher severity
                    dangerous_ports = {21, 23, 445, 3389, 1433, 3306, 5432, 6379, 27017, 9200}
                    if port_info["port"] in dangerous_ports:
                        finding["severity"] = "medium"
                        finding["title"] = f"⚠ Sensitive Port Open: {port_info['port']}/{port_info['protocol']} — {port_info.get('service_name', 'unknown')}"
                        finding["description"] += " This port is commonly targeted and may expose sensitive services."

                    findings.append(finding)

            # OS detection findings
            if host_data.get("os_matches"):
                os_info = host_data["os_matches"][0]
                findings.append({
                    "title": f"OS Detected: {os_info.get('name', 'unknown')}",
                    "description": f"Operating system detected on {host_data.get('ip', 'unknown')}: {os_info.get('name', 'unknown')} (accuracy: {os_info.get('accuracy', 'unknown')}%)",
                    "severity": "info",
                    "affected_asset": host_data.get("ip", "unknown"),
                    "source_tool": "nmap",
                    "raw_data": os_info,
                })

        return findings, parsed_data

    def _parse_host(self, host_elem) -> Dict:
        """Parse a single <host> element."""
        host_data = {
            "status": "",
            "ip": "",
            "hostname": "",
            "ports": [],
            "os_matches": [],
            "scripts": [],
        }

        # Status
        status = host_elem.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "")

        # Address
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host_data["ip"] = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host_data["mac"] = addr.get("addr", "")

        # Hostnames
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                host_data["hostname"] = hn.get("name", "")
                break

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", ""),
                    "state": "",
                    "service_name": "",
                    "service_version": "",
                    "service_product": "",
                    "scripts": [],
                }

                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state", "")

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port_info["service_name"] = service_elem.get("name", "")
                    port_info["service_version"] = service_elem.get("version", "")
                    port_info["service_product"] = service_elem.get("product", "")

                # NSE scripts
                for script in port_elem.findall("script"):
                    port_info["scripts"].append({
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    })

                host_data["ports"].append(port_info)

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host_data["os_matches"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })

        return host_data
