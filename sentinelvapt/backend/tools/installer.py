"""
SentinelVAPT — Cross-Platform Tool Installer
Checks, auto-installs, and verifies all required security tools.
Works on Linux (Debian/Kali/Ubuntu), Windows, and macOS.
"""

import io
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.installer")


@dataclass
class ToolStatus:
    name: str
    binary_name: str
    installed: bool
    path: Optional[str]
    version: Optional[str]
    install_method: Optional[str]
    error: Optional[str] = None


# ───────────────────────────────────────────────────
# Tool definitions: name -> (binary, version_flag)
# ───────────────────────────────────────────────────
TOOL_DEFINITIONS = {
    "nmap": ("nmap", "--version"),
    "nuclei": ("nuclei", "-version"),
    "zap": ("zap-cli", "--version"),  # or zaproxy
    "sqlmap": ("sqlmap", "--version"),
    "subfinder": ("subfinder", "-version"),
    "httpx": ("httpx", "-version"),
    "nikto": ("nikto", "-Version"),
    "amass": ("amass", "version"),
    "metasploit": ("msfconsole", "--version"),
}

# Binary names that may differ by platform
PLATFORM_BINARIES = {
    "Windows": {
        "httpx": "httpx.exe",
        "nuclei": "nuclei.exe",
        "subfinder": "subfinder.exe",
        "nmap": "nmap.exe",
        "amass": "amass.exe",
    }
}


def _detect_os() -> str:
    """Return 'Linux', 'Windows', or 'Darwin'."""
    return platform.system()


def _detect_distro() -> str:
    """Return Linux distro name (debian, ubuntu, kali, fedora, arch, unknown)."""
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "kali" in content:
            return "kali"
        if "ubuntu" in content:
            return "ubuntu"
        if "debian" in content:
            return "debian"
        if "fedora" in content:
            return "fedora"
        if "arch" in content:
            return "arch"
    except FileNotFoundError:
        pass
    return "unknown"


def _has_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _get_version(binary: str, flag: str) -> Optional[str]:
    """Try to get the version string of a tool."""
    try:
        result = subprocess.run(
            [binary, flag], capture_output=True, text=True, timeout=15, shell=False
        )
        output = (result.stdout + result.stderr).strip()
        # Return first non-empty line
        for line in output.split("\n"):
            line = line.strip()
            if line:
                return line[:200]
    except Exception:
        pass
    return None


def _download_file(url: str, dest: Path) -> bool:
    """Download a file from URL to dest path."""
    try:
        logger.info("Downloading %s -> %s", url, dest)
        req = Request(url, headers={"User-Agent": "SentinelVAPT/1.0"})
        with urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as e:
        logger.error("Download failed: %s — %s", url, e)
        return False


def _make_executable(path: Path):
    """chmod +x on Unix."""
    if _detect_os() != "Windows":
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _get_github_latest_release_url(owner: str, repo: str, asset_pattern: str) -> Optional[str]:
    """Get download URL for latest release asset matching pattern from GitHub API."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    try:
        req = Request(api_url, headers={
            "User-Agent": "SentinelVAPT/1.0",
            "Accept": "application/vnd.github+json"
        })
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        for asset in data.get("assets", []):
            name = asset["name"].lower()
            if asset_pattern.lower() in name:
                return asset["browser_download_url"]
    except Exception as e:
        logger.error("GitHub API error for %s/%s: %s", owner, repo, e)
    return None


def _extract_binary_from_zip(zip_path: Path, binary_name: str, dest_dir: Path) -> bool:
    """Extract a specific binary from a zip archive."""
    try:
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            for name in zf.namelist():
                if name.endswith(binary_name) or name.endswith(f"{binary_name}.exe"):
                    zf.extract(name, str(dest_dir))
                    src = dest_dir / name
                    final = dest_dir / src.name
                    if src != final:
                        shutil.move(str(src), str(final))
                    _make_executable(final)
                    return True
            # If exact match not found, extract all
            zf.extractall(str(dest_dir))
            return True
    except Exception as e:
        logger.error("Zip extraction failed: %s", e)
    return False


def _extract_binary_from_tar(tar_path: Path, binary_name: str, dest_dir: Path) -> bool:
    """Extract a specific binary from a tar/tar.gz archive."""
    try:
        with tarfile.open(str(tar_path), "r:*") as tf:
            for member in tf.getmembers():
                if member.name.endswith(binary_name):
                    tf.extract(member, str(dest_dir))
                    src = dest_dir / member.name
                    final = dest_dir / Path(member.name).name
                    if src != final:
                        shutil.move(str(src), str(final))
                    _make_executable(final)
                    return True
            tf.extractall(str(dest_dir))
            return True
    except Exception as e:
        logger.error("Tar extraction failed: %s", e)
    return False


class ToolInstaller:
    """Cross-platform tool checker and installer."""

    def __init__(self):
        self.settings = get_settings()
        self.os_type = _detect_os()
        self.distro = _detect_distro() if self.os_type == "Linux" else ""
        self.tools_dir = self.settings.tools_bin_dir

    def check_all(self) -> Dict[str, ToolStatus]:
        """Check installation status of all required tools."""
        results = {}
        for tool_name, (binary, ver_flag) in TOOL_DEFINITIONS.items():
            # Platform-specific binary name
            if self.os_type in PLATFORM_BINARIES and tool_name in PLATFORM_BINARIES[self.os_type]:
                binary = PLATFORM_BINARIES[self.os_type][tool_name]

            path = shutil.which(binary)
            if not path:
                # Check local tools_bin
                local = self.tools_dir / binary
                if local.exists():
                    path = str(local)
                elif self.os_type == "Windows":
                    local_exe = self.tools_dir / f"{binary}.exe" if not binary.endswith(".exe") else self.tools_dir / binary
                    if local_exe.exists():
                        path = str(local_exe)

            installed = path is not None
            version = None
            if installed and path:
                version = _get_version(path, ver_flag)

            results[tool_name] = ToolStatus(
                name=tool_name,
                binary_name=binary,
                installed=installed,
                path=path,
                version=version,
                install_method=None,
            )
        return results

    def install_all(self) -> Dict[str, ToolStatus]:
        """Check and install all missing tools. Returns final status dict."""
        # On Linux/Kali, perform batch installation of catalog packages first
        if self.os_type == "Linux":
            try:
                self.install_catalog_packages()
            except Exception as e:
                logger.warning("Batch catalog package installation encountered an issue: %s", e)

        statuses = self.check_all()
        for name, status in statuses.items():
            if not status.installed:
                logger.info("Tool '%s' not found, attempting install on %s...", name, self.os_type)
                statuses[name] = self._install_tool(name)
            else:
                logger.info("Tool '%s' already installed at %s", name, status.path)
        return statuses

    def install_catalog_packages(self) -> List[str]:
        """Dynamically batch-install all missing tools defined in tools_catalog.yaml on Linux."""
        from backend.tools.registry import ToolRegistry
        reg = ToolRegistry()
        missing = reg.get_missing_apt_packages()
        if not missing:
            return []
        if self.os_type == "Linux":
            logger.info("Batch installing missing Kali/Debian packages from catalog: %s", missing)
            self._run_apt_install(" ".join(missing))
            reg.scan_system()
        return missing

    def _install_tool(self, tool_name: str) -> ToolStatus:
        """Install a specific tool using the best method for the current OS."""
        binary, ver_flag = TOOL_DEFINITIONS[tool_name]
        try:
            if self.os_type == "Linux":
                return self._install_linux(tool_name, binary, ver_flag)
            elif self.os_type == "Darwin":
                return self._install_macos(tool_name, binary, ver_flag)
            elif self.os_type == "Windows":
                return self._install_windows(tool_name, binary, ver_flag)
            else:
                return self._make_skip_status(tool_name, binary, f"Unsupported OS: {self.os_type}")
        except Exception as e:
            logger.error("Install failed for %s: %s", tool_name, e)
            return self._make_skip_status(tool_name, binary, str(e))

    # ─── Linux Installation ────────────────────────────────

    def _install_linux(self, tool_name: str, binary: str, ver_flag: str) -> ToolStatus:
        APT_PACKAGES = {
            "nmap": "nmap",
            "nikto": "nikto",
            "sqlmap": "sqlmap",
            "metasploit": "metasploit-framework",
            "zap": "zaproxy",
        }
        GO_TOOLS = {
            "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "amass": "github.com/owasp-amass/amass/v4/...@master",
        }
        GITHUB_RELEASES = {
            "nuclei": ("projectdiscovery", "nuclei", "linux_amd64"),
            "subfinder": ("projectdiscovery", "subfinder", "linux_amd64"),
            "httpx": ("projectdiscovery", "httpx", "linux_amd64"),
            "amass": ("owasp-amass", "amass", "linux_amd64"),
        }

        # Try apt first for tools that have apt packages
        if tool_name in APT_PACKAGES and _has_command("apt-get"):
            success = self._run_apt_install(APT_PACKAGES[tool_name])
            if success:
                path = shutil.which(binary)
                if path:
                    return ToolStatus(
                        name=tool_name, binary_name=binary, installed=True,
                        path=path, version=_get_version(path, ver_flag),
                        install_method="apt-get",
                    )

        # Try go install for Go-based tools
        if tool_name in GO_TOOLS and _has_command("go"):
            success = self._run_go_install(GO_TOOLS[tool_name])
            if success:
                path = shutil.which(binary)
                if not path:
                    gopath = Path.home() / "go" / "bin" / binary
                    if gopath.exists():
                        path = str(gopath)
                if path:
                    return ToolStatus(
                        name=tool_name, binary_name=binary, installed=True,
                        path=path, version=_get_version(path, ver_flag),
                        install_method="go install",
                    )

        # Try GitHub release binary download
        if tool_name in GITHUB_RELEASES:
            owner, repo, pattern = GITHUB_RELEASES[tool_name]
            success = self._install_from_github(owner, repo, pattern, binary)
            if success:
                path = str(self.tools_dir / binary)
                return ToolStatus(
                    name=tool_name, binary_name=binary, installed=True,
                    path=path, version=_get_version(path, ver_flag),
                    install_method="github_release",
                )

        return self._make_skip_status(
            tool_name, binary,
            self._manual_instructions(tool_name, "Linux")
        )

    # ─── macOS Installation ────────────────────────────────

    def _install_macos(self, tool_name: str, binary: str, ver_flag: str) -> ToolStatus:
        BREW_PACKAGES = {
            "nmap": "nmap",
            "nuclei": "nuclei",
            "subfinder": "subfinder",
            "httpx": "httpx",
            "nikto": "nikto",
            "sqlmap": "sqlmap",
            "amass": "amass",
            "zap": "zaproxy",
        }

        if tool_name in BREW_PACKAGES and _has_command("brew"):
            success = self._run_brew_install(BREW_PACKAGES[tool_name])
            if success:
                path = shutil.which(binary)
                if path:
                    return ToolStatus(
                        name=tool_name, binary_name=binary, installed=True,
                        path=path, version=_get_version(path, ver_flag),
                        install_method="brew",
                    )

        # Metasploit on macOS — try Docker fallback
        if tool_name == "metasploit":
            return self._install_metasploit_docker(binary, ver_flag)

        return self._make_skip_status(
            tool_name, binary,
            self._manual_instructions(tool_name, "macOS")
        )

    # ─── Windows Installation ──────────────────────────────

    def _install_windows(self, tool_name: str, binary: str, ver_flag: str) -> ToolStatus:
        WINGET_PACKAGES = {
            "nmap": "Insecure.Nmap",
        }
        CHOCO_PACKAGES = {
            "nmap": "nmap",
        }
        GITHUB_RELEASES_WIN = {
            "nuclei": ("projectdiscovery", "nuclei", "windows_amd64"),
            "subfinder": ("projectdiscovery", "subfinder", "windows_amd64"),
            "httpx": ("projectdiscovery", "httpx", "windows_amd64"),
            "amass": ("owasp-amass", "amass", "windows_amd64"),
        }

        # Try winget
        if tool_name in WINGET_PACKAGES and _has_command("winget"):
            success = self._run_winget_install(WINGET_PACKAGES[tool_name])
            if success:
                path = shutil.which(binary)
                if path:
                    return ToolStatus(
                        name=tool_name, binary_name=binary, installed=True,
                        path=path, version=_get_version(path, ver_flag),
                        install_method="winget",
                    )

        # Try choco
        if tool_name in CHOCO_PACKAGES and _has_command("choco"):
            success = self._run_choco_install(CHOCO_PACKAGES[tool_name])
            if success:
                path = shutil.which(binary)
                if path:
                    return ToolStatus(
                        name=tool_name, binary_name=binary, installed=True,
                        path=path, version=_get_version(path, ver_flag),
                        install_method="choco",
                    )

        # Try GitHub releases download
        if tool_name in GITHUB_RELEASES_WIN:
            owner, repo, pattern = GITHUB_RELEASES_WIN[tool_name]
            win_binary = binary if binary.endswith(".exe") else f"{binary}.exe"
            success = self._install_from_github(owner, repo, pattern, win_binary)
            if success:
                path = str(self.tools_dir / win_binary)
                return ToolStatus(
                    name=tool_name, binary_name=win_binary, installed=True,
                    path=path, version=_get_version(path, ver_flag),
                    install_method="github_release",
                )

        # Metasploit on Windows — Docker fallback
        if tool_name == "metasploit":
            return self._install_metasploit_docker(binary, ver_flag)

        return self._make_skip_status(
            tool_name, binary,
            self._manual_instructions(tool_name, "Windows")
        )

    # ─── Package Manager Runners ───────────────────────────

    def _run_apt_install(self, package: str) -> bool:
        try:
            result = subprocess.run(
                ["sudo", "apt-get", "install", "-y", package],
                capture_output=True, text=True, timeout=300, shell=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.error("apt-get install %s failed: %s", package, e)
            return False

    def _run_brew_install(self, package: str) -> bool:
        try:
            result = subprocess.run(
                ["brew", "install", package],
                capture_output=True, text=True, timeout=300, shell=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.error("brew install %s failed: %s", package, e)
            return False

    def _run_go_install(self, package: str) -> bool:
        try:
            result = subprocess.run(
                ["go", "install", "-v", package],
                capture_output=True, text=True, timeout=300, shell=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.error("go install %s failed: %s", package, e)
            return False

    def _run_winget_install(self, package_id: str) -> bool:
        try:
            result = subprocess.run(
                ["winget", "install", "--id", package_id, "-e", "--accept-source-agreements", "--accept-package-agreements"],
                capture_output=True, text=True, timeout=300, shell=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.error("winget install %s failed: %s", package_id, e)
            return False

    def _run_choco_install(self, package: str) -> bool:
        try:
            result = subprocess.run(
                ["choco", "install", package, "-y"],
                capture_output=True, text=True, timeout=300, shell=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.error("choco install %s failed: %s", package, e)
            return False

    # ─── GitHub Release Download ───────────────────────────

    def _install_from_github(self, owner: str, repo: str, pattern: str, binary_name: str) -> bool:
        """Download latest release binary from GitHub."""
        url = _get_github_latest_release_url(owner, repo, pattern)
        if not url:
            logger.error("Could not find release asset for %s/%s pattern=%s", owner, repo, pattern)
            return False

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            filename = url.split("/")[-1]
            download_path = tmp / filename

            if not _download_file(url, download_path):
                return False

            # Extract based on file type
            if filename.endswith(".zip"):
                if not _extract_binary_from_zip(download_path, binary_name, self.tools_dir):
                    return False
            elif ".tar" in filename:
                if not _extract_binary_from_tar(download_path, binary_name, self.tools_dir):
                    return False
            else:
                # Assume it's a raw binary
                dest = self.tools_dir / binary_name
                shutil.move(str(download_path), str(dest))
                _make_executable(dest)

        # Verify
        final = self.tools_dir / binary_name
        return final.exists()

    # ─── Metasploit Docker Fallback ────────────────────────

    def _install_metasploit_docker(self, binary: str, ver_flag: str) -> ToolStatus:
        """For Windows/macOS, use Docker container for Metasploit."""
        if not _has_command("docker"):
            return self._make_skip_status(
                "metasploit", binary,
                "Metasploit not available and Docker not found. "
                "Install Docker Desktop or install Metasploit manually."
            )
        try:
            logger.info("Pulling Metasploit Docker image...")
            result = subprocess.run(
                ["docker", "pull", "metasploitframework/metasploit-framework:latest"],
                capture_output=True, text=True, timeout=600, shell=False
            )
            if result.returncode == 0:
                return ToolStatus(
                    name="metasploit",
                    binary_name="docker:metasploitframework/metasploit-framework",
                    installed=True,
                    path="docker:metasploitframework/metasploit-framework:latest",
                    version="Docker image",
                    install_method="docker",
                )
        except Exception as e:
            logger.error("Docker pull failed: %s", e)

        return self._make_skip_status(
            "metasploit", binary,
            "Failed to pull Metasploit Docker image."
        )

    # ─── Helpers ───────────────────────────────────────────

    def _make_skip_status(self, tool_name: str, binary: str, error_msg: str) -> ToolStatus:
        logger.warning("Tool '%s' could not be installed: %s", tool_name, error_msg)
        return ToolStatus(
            name=tool_name,
            binary_name=binary,
            installed=False,
            path=None,
            version=None,
            install_method=None,
            error=error_msg,
        )

    def _manual_instructions(self, tool_name: str, os_name: str) -> str:
        instructions = {
            "nmap": {
                "Linux": "sudo apt-get install nmap",
                "macOS": "brew install nmap",
                "Windows": "Download from https://nmap.org/download.html or: winget install Insecure.Nmap",
            },
            "nuclei": {
                "Linux": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "macOS": "brew install nuclei",
                "Windows": "Download from https://github.com/projectdiscovery/nuclei/releases",
            },
            "subfinder": {
                "Linux": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "macOS": "brew install subfinder",
                "Windows": "Download from https://github.com/projectdiscovery/subfinder/releases",
            },
            "httpx": {
                "Linux": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "macOS": "brew install httpx",
                "Windows": "Download from https://github.com/projectdiscovery/httpx/releases",
            },
            "nikto": {
                "Linux": "sudo apt-get install nikto",
                "macOS": "brew install nikto",
                "Windows": "Clone https://github.com/sullo/nikto and run with Perl",
            },
            "sqlmap": {
                "Linux": "sudo apt-get install sqlmap",
                "macOS": "brew install sqlmap",
                "Windows": "pip install sqlmap or download from https://sqlmap.org",
            },
            "amass": {
                "Linux": "go install github.com/owasp-amass/amass/v4/...@master",
                "macOS": "brew install amass",
                "Windows": "Download from https://github.com/owasp-amass/amass/releases",
            },
            "zap": {
                "Linux": "sudo apt-get install zaproxy",
                "macOS": "brew install --cask owasp-zap",
                "Windows": "Download from https://www.zaproxy.org/download/",
            },
            "metasploit": {
                "Linux": "sudo apt-get install metasploit-framework (Kali) or curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
                "macOS": "Install Docker and run: docker pull metasploitframework/metasploit-framework",
                "Windows": "Install Docker Desktop and run: docker pull metasploitframework/metasploit-framework",
            },
        }
        tool_inst = instructions.get(tool_name, {})
        msg = tool_inst.get(os_name, f"Please install {tool_name} manually for {os_name}.")
        return f"Auto-install failed. Manual install: {msg}"

    def get_summary(self) -> Dict:
        """Return a dict summary of all tool statuses for API/UI consumption."""
        statuses = self.check_all()
        return {
            "os": self.os_type,
            "distro": self.distro,
            "tools": {
                name: {
                    "installed": s.installed,
                    "path": s.path,
                    "version": s.version,
                    "error": s.error,
                }
                for name, s in statuses.items()
            }
        }
