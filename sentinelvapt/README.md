# 🛡️ SentinelVAPT — Autonomous AI Penetration Testing & Purple Team Framework

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20SQLAlchemy-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB?logo=react)](https://react.dev)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows%20%7C%20macOS-critical)](https://kali.org)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Authorized%20Lab%20Testing-brightgreen)]()

**SentinelVAPT** is an enterprise-grade, cross-platform autonomous Vulnerability Assessment and Penetration Testing (VAPT) framework. It connects automated offensive reconnaissance and vulnerability scanners (Nmap, Nuclei, OWASP ZAP, SQLMap, etc.) with dual-tier AI reasoning (Groq LLaMA 3.3 70B & local Ollama), automatic false-positive triage, allowlist-gated exploit verification, and instant **Purple-Team defensive detection engineering** (Sigma rules, Wazuh HIDS, Suricata NIDS, and host firewalls).

> ⚠️ **LEGAL & ETHICAL NOTICE:** This platform is engineered strictly for authorized security assessments on consented targets and lab environments (e.g., OWASP Juice Shop, DVWA, Metasploitable, crAPI, VAmPI, or private test subnets). Exploitation features are gated behind an IP/CIDR safety allowlist.

---

## 📑 Table of Contents

- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [Prerequisites](#-prerequisites)
- [Installation Guide](#-installation-guide)
  - [Windows Installation](#a-windows-10--11-setup)
  - [Kali Linux / Ubuntu / Debian Installation](#b-kali-linux--ubuntu--debian-setup)
- [Configuration (.env)](#-configuration-env)
- [Root & Administrator Privileges](#-root--administrator-privileges)
- [External APIs (100% Free Tiers)](#-external-apis-100-free-tiers)
- [How to Run SentinelVAPT](#-how-to-run-sentinelvapt)
  - [1. Diagnostic Pre-flight Checks](#step-1-pre-flight-diagnostics)
  - [2. Launch Web Dashboard](#step-2-launch-web-dashboard-recommended)
  - [3. Headless CLI Scans](#step-3-headless-cli-scans)
- [Supported Security Tools](#-supported-security-tools)
- [Reports & Defensive Outputs](#-reports--defensive-outputs)
- [Troubleshooting & FAQ](#-troubleshooting--faq)

---

## 🏛️ System Architecture

```
                       ┌───────────────────────────────┐
                       │  SentinelVAPT Core Controller │
                       └───────────────┬───────────────┘
                                       │
      ┌────────────────────────────────┼───────────────────────────────┐
      │                                │                               │
      ▼                                ▼                               ▼
┌──────────────┐             ┌───────────────────┐           ┌──────────────────┐
│ Tool Check & │             │ Reconnaissance &  │           │  Vulnerability   │
│  Privileges  │────────────►│ Attack Surface    │──────────►│     Auditing     │
└──────────────┘             └───────────────────┘           └──────────────────┘
 (Root / Sudo /               (Subfinder, Amass,              (Nuclei, ZAP, Nikto,
  Extensible Tools)            Nmap, httpx)                    API Security Fuzzer)
                                                                       │
                                                                       ▼
┌──────────────────┐         ┌───────────────────┐           ┌──────────────────┐
│  Purple Team &   │         │ Dual-Tier AI Core │           │ Allowlist-Gated  │
│  Audit Reports   │◄────────│ False-Positive    │◄──────────│  Exploitation    │
└──────────────────┘         │ Triage & Scoring  │           └──────────────────┘
 (Sigma, Wazuh,               (Groq LLaMA 3.3 /               (SQLMap, Metasploit)
  Suricata, PDF/MD)            Ollama Fallback)
```

---

## ✨ Key Features

1. **Cross-Platform Compatibility:**
   - Runs natively on **Windows 10/11**, **Kali Linux**, **Ubuntu/Debian**, and **macOS**.
   - Path-safe binary resolution via `pathlib` (scans PATH, local `tools_bin/`, and `/usr/bin`).
2. **Dual Execution Privilege Modes:**
   - **Root / Administrator Mode**: Enables raw packet sockets, Nmap SYN stealth scans (`-sS`), OS detection (`-O`), Masscan, and promiscuous network captures.
   - **Standard User Mode**: Gracefully adapts commands with `sudo` auto-elevation or falls back to TCP connect scans (`-sT`) without failing.
3. **Dual-Tier AI Intelligence (100% Free / Local):**
   - **Groq API**: High-speed cloud inference with LLaMA 3.3 70B (free community tier, 14,400 requests/day).
   - **Ollama**: 100% offline local inference (`llama3.1`) on your local hardware.
4. **Purple-Team Defensive Automation:**
   - Generates defensive detection rules for every confirmed vulnerability:
     - **Sigma rules** (YAML formatted)
     - **Wazuh HIDS XML rules**
     - **Suricata NIDS signatures**
     - **Host firewall block scripts** (iptables / PowerShell)
     - Exportable in a single ZIP bundle.
5. **Multi-Format Audit Reports:**
   - **Executive PDF** (visual scorecards, severity distributions, executive summary).
   - **Technical Markdown** (`.md`) for Git repositories.
   - **Machine-readable JSON** (`.json`) for CI/CD DevSecOps pipelines.
6. **Dark Glassmorphic Web Dashboard:**
   - Real-time Server-Sent Events (SSE) terminal logs, finding explorer, and one-click report generator.

---

## 📋 Prerequisites

Before installing, ensure you have:
- **Python 3.10, 3.11, or 3.12** installed ([python.org](https://python.org))
- **Git** installed ([git-scm.com](https://git-scm.com))
- *(Optional)* **Node.js 18+** (only needed if you wish to modify the React source code; pre-built production files are already included in `frontend/dist/`).

---

## 📦 Installation Guide

### A. Windows 10 / 11 Setup

1. **Open PowerShell as Administrator** (recommended for raw socket tool support) or standard terminal.
2. **Clone the repository:**
   ```powershell
   git clone https://github.com/your-username/sentinelvapt.git
   cd sentinelvapt
   ```
3. **Create and activate a Python virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   *(If PowerShell gives an execution policy error, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

4. **Install Python dependencies:**
   ```powershell
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. **Create your configuration file:**
   ```powershell
   copy .env.example .env
   ```

---

### B. Kali Linux / Ubuntu / Debian Setup

1. **Update system packages and install system essentials:**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip python3-venv git nmap
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/sentinelvapt.git
   cd sentinelvapt
   ```

3. **Create and activate a Python virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Python dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. **Create your configuration file:**
   ```bash
   cp .env.example .env
   ```

---

## ⚙️ Configuration (.env)

Open `.env` in any text editor (e.g., `nano .env` or `notepad .env`):

```ini
# ── Database (Default is local zero-config SQLite) ───────────────────────────
DATABASE_URL=sqlite+aiosqlite:///sentinelvapt.db
DATABASE_URL_SYNC=sqlite:///sentinelvapt.db

# ── AI Reasoning Core ────────────────────────────────────────────────────────
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_your_free_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# ── Ollama Local Fallback (Optional) ─────────────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1

# ── Safety Boundaries (Strict CIDR allowlist for active exploitation) ────────
EXPLOIT_ALLOWLIST=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# ── Privilege Auto-Elevation ──────────────────────────────────────────────────
AUTO_ELEVATE=true

# ── Web Server ───────────────────────────────────────────────────────────────
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
```

### 🔑 Getting a Free AI Key (Groq):
1. Go to [console.groq.com](https://console.groq.com).
2. Sign in with Google or GitHub (100% free, no credit card required).
3. Navigate to **API Keys** → **Create API Key**.
4. Paste the key in `.env` as `GROQ_API_KEY=gsk_...`.
5. *Note: If you don't provide a Groq key, SentinelVAPT automatically falls back to local Ollama or rule-based heuristics.*

---

## ⚡ Root & Administrator Privileges

SentinelVAPT executes security tools at two privilege tiers:

| Operating System | How to run with full privileges | Capabilities Unlocked |
|---|---|---|
| **Kali / Linux** | `sudo venv/bin/python run.py --server` | Raw packet sockets, SYN stealth scans (`-sS`), OS detection (`-O`), masscan, packet injection |
| **Windows** | Right-click PowerShell/CMD → **Run as administrator** | Raw socket binding, Nmap raw packet driver, WinPcap/Npcap access |

**What if you don't run as root?**
SentinelVAPT's [`PrivilegeManager`](file:///e:/vapt/sentinelvapt/backend/core/privilege_manager.py) automatically handles this:
- On Linux, if passwordless `sudo` is configured, tools are automatically prefixed with `sudo`.
- If neither root nor sudo is available, Nmap automatically shifts from raw SYN scan (`-sS`) to TCP Connect scan (`-sT`), preventing any execution failure.

---

## 🌐 External APIs (100% Free Tiers)

SentinelVAPT is built with zero mandatory subscription costs. All integrations are free or offer community quotas:

| Service | Tier | Cost / Quota | Purpose |
|---|---|---|---|
| **NVD (NIST)** | FREE | Unlimited (5 req/30s unauth) | Official CVE lookup & scoring |
| **CVE.circl.lu** | FREE | Unlimited community feed | Real-time vulnerability metadata |
| **Shodan InternetDB** | FREE | Unlimited, no key required | Open ports & known CVE mapping |
| **Exploit-DB** | LOCAL | 100% offline & free | Verified exploits & PoCs |
| **Groq AI** | FREE TIER | 14,400 requests/day | Vulnerability triage & analysis |
| **Ollama** | LOCAL | Unlimited local execution | Offline fallback LLM |
| **VirusTotal** | FREE TIER | 500 lookups/day | Threat intelligence & hash checks |
| **AbuseIPDB** | FREE TIER | 1,000 checks/day | IP reputation & geolocation |
| **Censys** | FREE TIER | 250 queries/month | Certificate & service scanning |
| **SecurityTrails** | FREE TIER | 50 queries/month | Subdomain history |
| **GreyNoise** | FREE TIER | Unlimited basic lookups | Internet scanner noise filter |
| **GitHub API** | FREE TIER | 60/hr (unauth), 5,000/hr (free token)| Exploit code verification |

Verify the live health of all APIs anytime with:
```bash
python run.py --check-apis
```

---

## 🚀 How to Run SentinelVAPT

### Step 1: Pre-flight Diagnostics

Before starting scans, verify your environment with the built-in diagnostic tools:

```bash
# 1. Check your privilege level (Root / Admin vs Normal user)
python run.py --check-privs

# 2. Check installed security tools
python run.py --check-tools

# 3. Check external API connectivity and free quotas
python run.py --check-apis

# 4. Automatically download missing security binaries
python run.py --install-tools
```

---

### Step 2: Launch Web Dashboard (Recommended)

Start the unified server (serves the backend REST API and React UI together):

```bash
python run.py --server
```

Then open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

**Web Dashboard Features:**
- **Dashboard**: Real-time KPI counters, recent scans, risk posture.
- **Active Scans**: Multi-stage progress tracking with live Server-Sent Events (SSE) terminal logs.
- **Findings Explorer**: Filterable vulnerability database (Severity, Tool, CVSS, MITRE ATT&CK ID).
- **Purple Team Rules**: View and download auto-generated Sigma, Wazuh, and Suricata rules.
- **Diagnostics**: Real-time view of Root permissions, host architecture, and API tiers.

*(Optional: For frontend developers running Vite with Hot Module Replacement, open a separate terminal in `frontend/`, run `npm run dev`, and browse to `http://localhost:5173`)*.

---

### Step 3: Headless CLI Scans

You can run automated scans completely headlessly from your terminal or CI/CD pipelines:

```bash
# 1. Web application assessment (Crawling, XSS, SQLi, Misconfigurations)
python run.py --scan http://192.168.1.150:3000 --scope web

# 2. API security assessment (OpenAPI / Swagger discovery & fuzzing)
python run.py --scan http://10.0.0.50/api/v1 --scope api

# 3. Network infrastructure assessment with allowlisted exploitation verification
python run.py --scan 192.168.1.200 --scope network --exploit
```

---

## 🛠️ Supported Security Tools

SentinelVAPT includes an **extensible tool registry** ([`backend/tools/registry.py`](file:///e:/vapt/sentinelvapt/backend/tools/registry.py)) that auto-detects tools installed on your operating system (especially on Kali Linux):

| Tool | Category | Automated Action in SentinelVAPT |
|---|---|---|
| **Nmap** | Port Scanning & OS | Deep service discovery, banner grabbing, OS fingerprinting |
| **Nuclei** | Vulnerability Matching | Fast template-based scanning (CVEs, misconfigs, exposures) |
| **OWASP ZAP** | Web App Testing | Spidering, active vulnerability scanning, header analysis |
| **SQLMap** | Database Auditing | Automated SQL injection verification against allowlisted targets |
| **Subfinder** | Reconnaissance | Passive subdomain enumeration |
| **httpx** | HTTP Probing | Live host verification, status codes, tech stack detection |
| **Nikto** | Web Server Auditing | Outdated server versions, sensitive files, misconfigurations |
| **Amass** | Attack Surface | In-depth network mapping and ASN discovery |
| **Metasploit** | Exploitation | Controlled RPC verification of critical vulnerabilities |
| **API Fuzzer**| REST API Testing | Native fuzzer for broken auth, IDOR, and schema violations |

---

## 📊 Reports & Defensive Outputs

When a scan finishes, SentinelVAPT automatically produces multiple artifacts inside the `reports/` folder:

1. **Executive PDF Audit Report** (`report_<job_id>.pdf`):
   - Executive risk scorecard, CVSS severity distribution chart, finding telemetry, and detailed remediation roadmap.
2. **Technical Markdown Report** (`report_<job_id>.md`):
   - GitHub-compatible documentation with reproducible curl PoCs and HTTP requests.
3. **Machine-Readable JSON Report** (`report_<job_id>.json`):
   - Structured JSON for ingestion into SIEMs, DefectDojo, or CI/CD quality gates.
4. **Purple Team Detection Bundle** (`defensive_rules_<job_id>.zip`):
   - Ready-to-deploy detection rules for your SOC team:
     - `sigma/*.yml` (SIEM agnostic log rules)
     - `wazuh/*.xml` (Endpoint detection rules)
     - `suricata/*.rules` (Network intrusion signatures)
     - `firewall/*.sh` / `firewall/*.ps1` (Emergency IP block scripts)

---

## ❓ Troubleshooting & FAQ

### Q1: Why does Nmap say "You requested a scan type which requires root privileges"?
- **Solution**: Run your terminal as Administrator (on Windows) or with `sudo` (on Linux).
- Alternatively, SentinelVAPT automatically detects this and gracefully switches to `-sT` (TCP Connect Scan) so your scan never crashes.

### Q2: Do I need to pay for any API or service?
- **No.** All features in SentinelVAPT work 100% out-of-the-box using completely free and open-source components. Groq offers a generous free tier (no credit card required), or you can use local Ollama with zero external calls.

### Q3: Why is my exploitation attempt rejected?
- **Solution**: Check your `EXPLOIT_ALLOWLIST` in `.env`. By design, SentinelVAPT strictly forbids automated exploitation against IP addresses not explicitly listed in your allowlist to prevent accidental testing against non-consented infrastructure.

### Q4: How do I install all tools in one go?
- Run: `python run.py --install-tools`
- On Kali Linux, standard tools (`nmap`, `sqlmap`, `nikto`) are already installed by default.

### Q5: Getting `ModuleNotFoundError: No module named 'greenlet'`?
- **Solution**: Run `pip install greenlet` or update via `pip install -r requirements.txt`. SQLAlchemy's async engine requires `greenlet` for asynchronous context switching.

---

## 📄 License & Disclaimer

This software is developed strictly for **authorized educational, laboratory, and consented professional penetration testing**. Users are solely responsible for ensuring compliance with applicable local, state, and international cybersecurity laws. Always obtain explicit, signed written authorization before scanning any target.
