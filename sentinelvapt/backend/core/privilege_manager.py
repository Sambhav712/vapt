"""
SentinelVAPT — Privilege Manager
Detects root/admin status, auto-prefixes sudo for tools that need it,
and manages privilege escalation across Linux/Windows/macOS.
"""

import ctypes
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelvapt.privilege")


class PrivilegeLevel(str, Enum):
    ROOT = "root"           # Linux/macOS root or Windows Administrator
    NORMAL = "normal"       # Regular user
    UNKNOWN = "unknown"


@dataclass
class PrivilegeStatus:
    """Snapshot of current privilege state."""
    level: PrivilegeLevel
    os_type: str               # Linux / Windows / Darwin
    username: str
    uid: Optional[int]         # Unix UID (None on Windows)
    has_sudo: bool             # Can escalate via sudo (Linux/macOS)
    sudo_passwordless: bool    # sudo works without password prompt
    is_admin: bool             # Windows admin check
    can_raw_socket: bool       # Can open raw sockets (needed by nmap SYN)
    warnings: List[str] = field(default_factory=list)


# ── Tools that REQUIRE elevated privileges ──────────────────────
# These tools need root/admin to function fully.
# key: tool binary name → description of why
TOOLS_REQUIRING_ROOT: Dict[str, str] = {
    "nmap":       "SYN/OS detection scans require raw socket access",
    "masscan":    "Raw packet transmission needs root",
    "tcpdump":    "Packet capture requires promiscuous mode",
    "tshark":     "Packet capture requires promiscuous mode",
    "hping3":     "Raw socket packet crafting needs root",
    "aircrack-ng": "Wireless monitor mode requires root",
    "airmon-ng":  "Wireless interface management requires root",
    "ettercap":   "ARP spoofing / MitM requires root",
    "responder":  "Network service poisoning requires root",
    "arp-scan":   "ARP scanning requires raw sockets",
    "bettercap":  "Network attack framework requires root",
    "john":       "Some wordlist paths and hash access need root",
    "hashcat":    "GPU access and /dev permissions may need root",
}

# Nmap flags that specifically need root
NMAP_ROOT_FLAGS = {"-sS", "-sA", "-sF", "-sN", "-sX", "-sM", "-O", "--osscan-guess",
                   "--traceroute", "-sU", "--packet-trace"}


class PrivilegeManager:
    """
    Cross-platform privilege detection and tool elevation manager.
    - On Linux/macOS: checks UID, sudo availability, passwordless sudo
    - On Windows: checks admin token via ctypes
    - Wraps tool commands with `sudo` when needed and possible
    """

    def __init__(self):
        self.os_type = platform.system()
        self._status: Optional[PrivilegeStatus] = None
        self._sudo_password: Optional[str] = None  # cached if user provides

    # ── Public API ──────────────────────────────────────────────

    def detect(self) -> PrivilegeStatus:
        """Detect current privilege level and capabilities."""
        if self._status is not None:
            return self._status

        username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        uid = None
        has_sudo = False
        sudo_passwordless = False
        is_admin = False
        can_raw_socket = False
        warnings: List[str] = []

        if self.os_type in ("Linux", "Darwin"):
            uid = os.getuid()
            is_root = uid == 0
            is_admin = is_root

            # Check sudo availability
            has_sudo = shutil.which("sudo") is not None

            if not is_root and has_sudo:
                # Test if sudo works passwordless
                sudo_passwordless = self._check_passwordless_sudo()

            # Raw socket test (nmap SYN needs this)
            can_raw_socket = is_root or self._test_raw_socket_capability()

            if not is_root and not has_sudo:
                warnings.append(
                    "Not running as root and sudo is not available. "
                    "Tools like nmap (SYN scan), masscan, tcpdump will have limited functionality."
                )
            elif not is_root and has_sudo and not sudo_passwordless:
                warnings.append(
                    "Running as non-root user. sudo is available but requires password. "
                    "Set NOPASSWD in sudoers or run SentinelVAPT as root for full tool access."
                )

            level = PrivilegeLevel.ROOT if is_root else PrivilegeLevel.NORMAL

        elif self.os_type == "Windows":
            is_admin = self._check_windows_admin()
            can_raw_socket = is_admin  # On Windows, admin ≈ raw socket access
            level = PrivilegeLevel.ROOT if is_admin else PrivilegeLevel.NORMAL

            if not is_admin:
                warnings.append(
                    "Not running as Administrator. Some tools (nmap raw scans, WinPcap) "
                    "need admin privileges. Right-click → 'Run as administrator'."
                )
        else:
            level = PrivilegeLevel.UNKNOWN
            warnings.append(f"Unsupported OS: {self.os_type}")

        self._status = PrivilegeStatus(
            level=level,
            os_type=self.os_type,
            username=username,
            uid=uid,
            has_sudo=has_sudo,
            sudo_passwordless=sudo_passwordless,
            is_admin=is_admin,
            can_raw_socket=can_raw_socket,
            warnings=warnings,
        )

        logger.info(
            "Privilege detection: level=%s user=%s uid=%s sudo=%s passwordless=%s raw_socket=%s",
            level.value, username, uid, has_sudo, sudo_passwordless, can_raw_socket
        )
        for w in warnings:
            logger.warning("Privilege warning: %s", w)

        return self._status

    def needs_elevation(self, tool_name: str, flags: Optional[List[str]] = None) -> bool:
        """Check if a given tool needs root/admin to run with the given flags."""
        status = self.detect()

        # Already root — never needs elevation
        if status.level == PrivilegeLevel.ROOT:
            return False

        binary = tool_name.lower().split("/")[-1].split("\\")[-1]
        # Remove .exe suffix on Windows
        if binary.endswith(".exe"):
            binary = binary[:-4]

        # General tool check
        if binary in TOOLS_REQUIRING_ROOT:
            return True

        # Nmap-specific: only certain flags need root
        if binary == "nmap" and flags:
            return bool(set(flags) & NMAP_ROOT_FLAGS)

        return False

    def wrap_command(self, cmd: List[str], tool_name: str = "",
                     flags: Optional[List[str]] = None) -> List[str]:
        """
        Wrap a command list with `sudo` if the tool needs elevation
        and we're not already root. On Windows, returns as-is (must
        start the process as admin externally).
        """
        if not cmd:
            return cmd

        status = self.detect()
        binary = tool_name or cmd[0]

        if not self.needs_elevation(binary, flags):
            return cmd

        if status.level == PrivilegeLevel.ROOT:
            return cmd

        if self.os_type in ("Linux", "Darwin") and status.has_sudo:
            # Don't double-wrap
            if cmd[0] == "sudo":
                return cmd
            logger.info("Elevating command with sudo: %s", " ".join(cmd[:3]))
            return ["sudo", "-n"] + cmd if status.sudo_passwordless else ["sudo"] + cmd

        # On Windows or no sudo — return as-is, log warning
        logger.warning(
            "Tool '%s' requires elevation but cannot auto-elevate on %s. "
            "Run SentinelVAPT as root/admin for full functionality.",
            binary, self.os_type
        )
        return cmd

    def get_tool_privilege_map(self) -> Dict[str, Dict]:
        """
        Return a map of all known tools → whether they need root
        and the current user's ability to run them.
        """
        status = self.detect()
        result = {}

        for tool, reason in TOOLS_REQUIRING_ROOT.items():
            path = shutil.which(tool)
            can_run_elevated = (
                status.level == PrivilegeLevel.ROOT or
                (status.has_sudo and self.os_type in ("Linux", "Darwin")) or
                (status.is_admin and self.os_type == "Windows")
            )
            result[tool] = {
                "requires_root": True,
                "reason": reason,
                "installed": path is not None,
                "path": path,
                "can_run_elevated": can_run_elevated,
                "current_level": status.level.value,
            }

        return result

    def to_dict(self) -> Dict:
        """Serialize current privilege status for API responses."""
        status = self.detect()
        return {
            "level": status.level.value,
            "os_type": status.os_type,
            "username": status.username,
            "uid": status.uid,
            "has_sudo": status.has_sudo,
            "sudo_passwordless": status.sudo_passwordless,
            "is_admin": status.is_admin,
            "can_raw_socket": status.can_raw_socket,
            "warnings": status.warnings,
            "tool_privileges": self.get_tool_privilege_map(),
        }

    # ── Internal Helpers ────────────────────────────────────────

    def _check_passwordless_sudo(self) -> bool:
        """Test if `sudo -n true` works (passwordless sudo)."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _test_raw_socket_capability(self) -> bool:
        """Test if the current user can open a raw socket."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
        except (PermissionError, OSError):
            return False

    def _check_windows_admin(self) -> bool:
        """Check if the current process has admin privileges on Windows."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            # Not Windows or ctypes not available
            return False

    def reset(self):
        """Clear cached status (useful after privilege change)."""
        self._status = None


# ── Module-level singleton ──────────────────────────────────────

_privilege_manager: Optional[PrivilegeManager] = None


def get_privilege_manager() -> PrivilegeManager:
    """Get the global PrivilegeManager singleton."""
    global _privilege_manager
    if _privilege_manager is None:
        _privilege_manager = PrivilegeManager()
    return _privilege_manager
