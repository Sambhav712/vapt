"""
SentinelVAPT — Capability Manager
Scans the host system for installed security tools, package managers,
and runtime capabilities. Manages autonomous tool installation with caps.
"""

import asyncio
import logging
import os
import platform
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinelvapt.agent.capabilities")


# ═══════════════════════════════════════════════════════════════════
# Known security tools the agent should look for
# ═══════════════════════════════════════════════════════════════════
KNOWN_TOOLS: Dict[str, Dict[str, Any]] = {
    # ── Reconnaissance ────────────────────────────────────
    "nmap": {"category": "recon", "tier": 1, "pkg": "nmap", "desc": "Network port scanner and service enumerator"},
    "masscan": {"category": "recon", "tier": 1, "pkg": "masscan", "desc": "Fast mass port scanner"},
    "subfinder": {"category": "recon", "tier": 1, "pkg": None, "desc": "Subdomain discovery tool"},
    "amass": {"category": "recon", "tier": 1, "pkg": "amass", "desc": "Advanced subdomain enumeration"},
    "httpx": {"category": "recon", "tier": 1, "pkg": None, "desc": "HTTP probing and technology fingerprinting"},
    "whatweb": {"category": "recon", "tier": 1, "pkg": "whatweb", "desc": "Web technology fingerprinting"},
    "wafw00f": {"category": "recon", "tier": 1, "pkg": None, "desc": "WAF detection and fingerprinting"},
    "dig": {"category": "recon", "tier": 1, "pkg": "dnsutils", "desc": "DNS lookup utility"},
    "whois": {"category": "recon", "tier": 1, "pkg": "whois", "desc": "WHOIS lookup"},
    "theHarvester": {"category": "recon", "tier": 1, "pkg": "theharvester", "desc": "Email, subdomain, and name harvester"},
    "dnsrecon": {"category": "recon", "tier": 1, "pkg": "dnsrecon", "desc": "DNS enumeration"},
    "dnsenum": {"category": "recon", "tier": 1, "pkg": "dnsenum", "desc": "DNS enumeration"},
    "fierce": {"category": "recon", "tier": 1, "pkg": "fierce", "desc": "DNS brute-force and zone transfer"},
    "traceroute": {"category": "recon", "tier": 1, "pkg": "traceroute", "desc": "Network path tracer"},
    "enum4linux": {"category": "recon", "tier": 1, "pkg": "enum4linux", "desc": "SMB/NetBIOS enumeration"},
    "smbclient": {"category": "recon", "tier": 1, "pkg": "smbclient", "desc": "SMB client utility"},
    "snmpwalk": {"category": "recon", "tier": 1, "pkg": "snmp", "desc": "SNMP enumeration"},
    "onesixtyone": {"category": "recon", "tier": 1, "pkg": "onesixtyone", "desc": "Fast SNMP scanner"},
    "nbtscan": {"category": "recon", "tier": 1, "pkg": "nbtscan", "desc": "NetBIOS scanner"},

    # ── Web Vulnerability Scanning ────────────────────────
    "nikto": {"category": "vuln_scan", "tier": 1, "pkg": "nikto", "desc": "Web server vulnerability scanner"},
    "nuclei": {"category": "vuln_scan", "tier": 1, "pkg": None, "desc": "Template-based vulnerability scanner"},
    "wpscan": {"category": "vuln_scan", "tier": 1, "pkg": "wpscan", "desc": "WordPress security scanner"},
    "sqlmap": {"category": "vuln_scan", "tier": 2, "pkg": "sqlmap", "desc": "SQL injection detection and exploitation"},
    "xsser": {"category": "vuln_scan", "tier": 2, "pkg": "xsser", "desc": "XSS vulnerability testing"},
    "commix": {"category": "vuln_scan", "tier": 2, "pkg": "commix", "desc": "Command injection exploitation"},
    "dirb": {"category": "vuln_scan", "tier": 1, "pkg": "dirb", "desc": "Web directory brute-forcer"},
    "gobuster": {"category": "vuln_scan", "tier": 1, "pkg": None, "desc": "Directory/DNS/vhost brute-forcing"},
    "ffuf": {"category": "vuln_scan", "tier": 1, "pkg": None, "desc": "Fast web fuzzer"},
    "feroxbuster": {"category": "vuln_scan", "tier": 1, "pkg": None, "desc": "Recursive content discovery"},
    "wfuzz": {"category": "vuln_scan", "tier": 1, "pkg": "wfuzz", "desc": "Web fuzzing tool"},
    "sslyze": {"category": "vuln_scan", "tier": 1, "pkg": None, "desc": "SSL/TLS configuration scanner"},
    "testssl.sh": {"category": "vuln_scan", "tier": 1, "pkg": "testssl.sh", "desc": "SSL/TLS testing"},
    "sslscan": {"category": "vuln_scan", "tier": 1, "pkg": "sslscan", "desc": "SSL/TLS scanner"},

    # ── Network Analysis ──────────────────────────────────
    "tcpdump": {"category": "network", "tier": 2, "pkg": "tcpdump", "desc": "Packet capture and analysis"},
    "tshark": {"category": "network", "tier": 2, "pkg": "tshark", "desc": "Command-line packet analyzer"},
    "netcat": {"category": "network", "tier": 2, "pkg": "netcat-openbsd", "desc": "TCP/UDP networking utility"},
    "ncat": {"category": "network", "tier": 2, "pkg": "ncat", "desc": "Enhanced netcat"},
    "socat": {"category": "network", "tier": 2, "pkg": "socat", "desc": "Multipurpose relay"},
    "hping3": {"category": "network", "tier": 2, "pkg": "hping3", "desc": "Packet crafting tool"},
    "arp-scan": {"category": "network", "tier": 2, "pkg": "arp-scan", "desc": "ARP scanner"},

    # ── Exploitation (Tier 3 — requires authorization) ────
    "msfconsole": {"category": "exploit", "tier": 3, "pkg": "metasploit-framework", "desc": "Metasploit Framework"},
    "msfvenom": {"category": "exploit", "tier": 3, "pkg": "metasploit-framework", "desc": "Payload generator"},
    "searchsploit": {"category": "exploit", "tier": 2, "pkg": "exploitdb", "desc": "Exploit-DB search tool"},
    "hydra": {"category": "exploit", "tier": 3, "pkg": "hydra", "desc": "Login brute-forcer"},
    "medusa": {"category": "exploit", "tier": 3, "pkg": "medusa", "desc": "Login brute-forcer"},
    "john": {"category": "exploit", "tier": 3, "pkg": "john", "desc": "Password cracker"},
    "hashcat": {"category": "exploit", "tier": 3, "pkg": "hashcat", "desc": "GPU password cracker"},
    "crackmapexec": {"category": "exploit", "tier": 3, "pkg": "crackmapexec", "desc": "Network credential testing"},
    "responder": {"category": "exploit", "tier": 3, "pkg": "responder", "desc": "LLMNR/NBT-NS poisoner"},

    # ── Utilities ─────────────────────────────────────────
    "curl": {"category": "util", "tier": 1, "pkg": "curl", "desc": "HTTP request tool"},
    "wget": {"category": "util", "tier": 1, "pkg": "wget", "desc": "File downloader"},
    "jq": {"category": "util", "tier": 1, "pkg": "jq", "desc": "JSON processor"},
    "xmllint": {"category": "util", "tier": 1, "pkg": "libxml2-utils", "desc": "XML parser"},
    "openssl": {"category": "util", "tier": 1, "pkg": "openssl", "desc": "SSL toolkit"},
}


@dataclass
class ToolCapability:
    """Represents a discovered tool on the system."""
    name: str
    path: str
    category: str
    tier: int
    description: str
    version: Optional[str] = None
    installed_by_agent: bool = False


@dataclass
class SystemCapabilities:
    """Complete snapshot of system capabilities."""
    os_type: str
    os_version: str
    architecture: str
    hostname: str
    available_tools: List[ToolCapability] = field(default_factory=list)
    package_managers: List[str] = field(default_factory=list)
    python_version: str = ""
    has_internet: bool = False
    scan_timestamp: float = 0.0

    def to_context_string(self) -> str:
        """Format capabilities as LLM context string."""
        lines = [
            f"System: {self.os_type} {self.os_version} ({self.architecture})",
            f"Hostname: {self.hostname}",
            f"Python: {self.python_version}",
            f"Package Managers: {', '.join(self.package_managers) or 'None detected'}",
            f"Internet Access: {'Yes' if self.has_internet else 'Unknown/No'}",
            f"\nAvailable Security Tools ({len(self.available_tools)}):",
        ]
        by_category: Dict[str, List[ToolCapability]] = {}
        for t in self.available_tools:
            by_category.setdefault(t.category, []).append(t)

        for cat in ["recon", "vuln_scan", "network", "exploit", "util"]:
            tools = by_category.get(cat, [])
            if tools:
                lines.append(f"  [{cat.upper()}]")
                for t in tools:
                    ver = f" (v{t.version})" if t.version else ""
                    tier = f" [Tier {t.tier}]"
                    lines.append(f"    - {t.name}{ver}{tier}: {t.description}")

        missing = [name for name in KNOWN_TOOLS if name not in {t.name for t in self.available_tools}]
        if missing:
            lines.append(f"\nNot Installed ({len(missing)}): {', '.join(sorted(missing)[:20])}")
            if len(missing) > 20:
                lines.append(f"  ... and {len(missing) - 20} more")

        return "\n".join(lines)


class CapabilityManager:
    """
    Scans the host for installed tools, package managers, and runtime
    capabilities. Manages autonomous tool installation with safety caps.
    """

    MAX_INSTALLS_PER_SESSION = 10

    def __init__(self):
        self._capabilities: Optional[SystemCapabilities] = None
        self._install_count = 0
        self._installed_tools: Set[str] = set()

    async def scan(self, terminal=None) -> SystemCapabilities:
        """
        Scan the system for capabilities. If a TerminalExecutor is provided,
        uses it for more detailed discovery.
        """
        if self._capabilities is not None:
            return self._capabilities

        caps = SystemCapabilities(
            os_type=platform.system(),
            os_version=platform.release(),
            architecture=platform.machine(),
            hostname=platform.node(),
            python_version=platform.python_version(),
            scan_timestamp=time.time(),
        )

        # Discover package managers
        for pm in ["apt-get", "apt", "yum", "dnf", "pacman", "brew", "snap",
                    "pip3", "pip", "gem", "go", "cargo", "npm"]:
            if shutil.which(pm):
                caps.package_managers.append(pm)

        # Scan for known security tools
        for name, meta in KNOWN_TOOLS.items():
            path = shutil.which(name)
            if path:
                version = await self._get_tool_version(name, terminal)
                caps.available_tools.append(ToolCapability(
                    name=name,
                    path=path,
                    category=meta["category"],
                    tier=meta["tier"],
                    description=meta["desc"],
                    version=version,
                ))

        # Quick internet connectivity check
        caps.has_internet = await self._check_internet(terminal)

        self._capabilities = caps
        logger.info(
            "Capability scan complete: %d tools found, %d package managers",
            len(caps.available_tools), len(caps.package_managers)
        )
        return caps

    async def _get_tool_version(self, tool_name: str, terminal=None) -> Optional[str]:
        """Try to get tool version string."""
        try:
            if terminal:
                result = await terminal.execute(
                    f"{tool_name} --version 2>/dev/null || {tool_name} -V 2>/dev/null",
                    timeout=10
                )
                if result.success and result.stdout:
                    # Extract first line, first version-like pattern
                    import re
                    match = re.search(r'(\d+\.\d+[\.\d]*)', result.stdout.split('\n')[0])
                    return match.group(1) if match else None
            else:
                proc = await asyncio.create_subprocess_exec(
                    tool_name, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    import re
                    match = re.search(r'(\d+\.\d+[\.\d]*)', stdout.decode(errors="replace"))
                    return match.group(1) if match else None
        except Exception:
            pass
        return None

    async def _check_internet(self, terminal=None) -> bool:
        """Quick check if we have internet access."""
        try:
            if terminal:
                result = await terminal.execute(
                    "curl -s --max-time 5 -o /dev/null -w '%{http_code}' https://api.github.com/",
                    timeout=10
                )
                return result.success and result.stdout.strip() in ("200", "301", "302", "403")
            else:
                import socket
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                return True
        except Exception:
            return False

    async def install_tool(self, tool_name: str, terminal) -> Tuple[bool, str]:
        """
        Attempt to install a missing tool.
        Returns (success: bool, message: str)
        """
        if self._install_count >= self.MAX_INSTALLS_PER_SESSION:
            return False, f"Installation cap reached ({self.MAX_INSTALLS_PER_SESSION} per session)"

        if tool_name in self._installed_tools:
            return True, f"{tool_name} was already installed this session"

        # Check if already available
        if shutil.which(tool_name):
            return True, f"{tool_name} is already available"

        meta = KNOWN_TOOLS.get(tool_name)
        pkg_name = meta["pkg"] if meta else tool_name

        if not self._capabilities:
            await self.scan(terminal)

        caps = self._capabilities
        success = False
        message = ""

        # Try package managers in order of preference
        if "apt-get" in caps.package_managers and pkg_name:
            result = await terminal.execute(
                f"sudo apt-get install -y {pkg_name}", timeout=120
            )
            if result.success:
                success = True
                message = f"Installed {tool_name} via apt-get"
            else:
                message = f"apt-get install failed: {result.stderr[:200]}"

        if not success and "pip3" in caps.package_managers:
            # Some Python-based tools
            pip_tools = {"wafw00f", "sslyze", "commix", "xsser", "wfuzz",
                         "theHarvester", "dnsrecon", "fierce"}
            if tool_name in pip_tools:
                pip_pkg = tool_name.lower().replace("-", "")
                result = await terminal.execute(
                    f"pip3 install {pip_pkg}", timeout=120
                )
                if result.success:
                    success = True
                    message = f"Installed {tool_name} via pip3"

        if not success and "gem" in caps.package_managers:
            gem_tools = {"wpscan"}
            if tool_name in gem_tools:
                result = await terminal.execute(
                    f"gem install {tool_name}", timeout=120
                )
                if result.success:
                    success = True
                    message = f"Installed {tool_name} via gem"

        if not success and "go" in caps.package_managers:
            go_tools = {
                "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "gobuster": "github.com/OJ/gobuster/v3@latest",
                "ffuf": "github.com/ffuf/ffuf/v2@latest",
                "feroxbuster": "github.com/epi052/feroxbuster@latest",
            }
            if tool_name in go_tools:
                result = await terminal.execute(
                    f"go install {go_tools[tool_name]}", timeout=180
                )
                if result.success:
                    success = True
                    message = f"Installed {tool_name} via go install"

        if not success:
            # Try git clone as last resort for select tools
            message = f"Could not install {tool_name}: no compatible package manager or install method found"

        if success:
            self._install_count += 1
            self._installed_tools.add(tool_name)
            # Update capabilities cache
            self._capabilities = None  # Force re-scan on next access
            logger.info("Successfully installed %s (%d/%d installs used)",
                        tool_name, self._install_count, self.MAX_INSTALLS_PER_SESSION)
        else:
            logger.warning("Failed to install %s: %s", tool_name, message)

        return success, message

    @property
    def available_tool_names(self) -> Set[str]:
        """Return set of available tool names."""
        if not self._capabilities:
            return set()
        return {t.name for t in self._capabilities.available_tools}

    @property
    def install_budget_remaining(self) -> int:
        return self.MAX_INSTALLS_PER_SESSION - self._install_count

    def reset(self):
        """Clear cached capabilities (force re-scan)."""
        self._capabilities = None
