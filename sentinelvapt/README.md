# 🛡️ SentinelVAPT — Autonomous AI Penetration Testing & Purple Team Framework

**SentinelVAPT** is an enterprise-ready, cross-platform vulnerability assessment and penetration testing (VAPT) automation framework. It merges multi-stage offensive discovery tools with AI-driven correlation, false-positive elimination, attack chain synthesis, and automated Purple-Team defensive detection engineering (Sigma, Wazuh, Suricata, and host firewalls).

> ⚠️ **LEGAL & ETHICAL NOTICE:** This platform is engineered strictly for authorized security assessments on consented targets and lab environments (e.g., OWASP Juice Shop, DVWA, Metasploitable, crAPI, VAmPI, or private test subnets). Exploitation features are gated behind an IP/CIDR safety allowlist.

---

## 🏛️ System Architecture

SentinelVAPT drives security audits via a sequential asynchronous state machine:

```
[Tool Diagnostics]
       │
       ▼
[Reconnaissance] ─────────► (Subfinder, Amass, Httpx, Nmap)
       │
       ▼
[Vulnerability Scan] ─────► (Nuclei, OWASP ZAP, Nikto, Native API Security Fuzzer)
       │
       ▼
[Safe Exploitation] ──────► (SQLMap, Metasploit RPC - strictly gated by allowlist)
       │
       ▼
[AI Analysis Layer] ──────► (Groq LLaMA 3.3 / Ollama fallback: False-Positive Triage)
       │
       ▼
[Reporting Engine] ───────► (Audit PDF via ReportLab, Technical Markdown, JSON)
       │
       ▼
[Purple Team Defense] ───► (Sigma YAML, Wazuh XML, Suricata Rules, Host Firewalls)
```

---

## ✨ Key Features

1. **Cross-Platform Compatibility:**
   - Runs natively on **Windows**, **Linux (including Kali/Debian/Ubuntu)**, and **macOS**.
   - Path-safe, cross-platform binary detection (`pathlib`, auto-discovery in system PATH and local `tools_bin/`).

2. **Automated Tool Installer & Ecosystem:**
   - Detects and manages 10 security assessment tools:
     - **Nmap** — Network port scanning and OS discovery
     - **Nuclei** — Template-based vulnerability matching
     - **OWASP ZAP** — Automated web application crawler & active scanner
     - **SQLMap** — SQL injection detection and database takeover
     - **Subfinder** — Passive DNS enumeration
     - **httpx** — Fast HTTP probing & tech stack discovery
     - **Nikto** — Web server misconfiguration scanner
     - **Amass** — In-depth attack surface mapping
     - **Metasploit** — RPC verification console
     - **Native API Security Fuzzer** — OpenAPI/Swagger fuzzer for REST APIs

3. **Dual-Tier AI Analysis:**
   - Primary: **Groq API** (`llama-3.3-70b-versatile` / `llama-3.1-70b-versatile`) with sub-second response times.
   - Fallback: Local **Ollama** instances (`llama3.1`).
   - Resistant to prompt injection from untrusted scan outputs.
   - Computes CVSS v3.1 scores, maps findings to MITRE ATT&CK tactics & techniques, and writes clear remediation instructions.

4. **Purple-Team Defensive Engineering:**
   - Automatically generates defensive detections for all confirmed findings:
     - **Sigma rules** (validated against schema)
     - **Wazuh HIDS XML rules**
     - **Suricata NIDS signatures**
     - **Host firewall (iptables/PowerShell) block scripts**
     - Packaged ZIP export for SIEM/SOC deployment.

5. **Multi-Format Audit Reporting:**
   - **Executive PDF Report** built with ReportLab (visual risk scorecards, tables, and telemetry).
   - **Technical Markdown Report** (`.md`) for Git-based tracking.
   - **Machine-Readable JSON Report** (`.json`) for CI/CD integration.

6. **Interactive Dark-Mode Web Dashboard:**
   - React + Vite dashboard with dark glassmorphism design, real-time Server-Sent Events (SSE) terminal streaming, vulnerability explorer, and one-click report downloads.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend development)

### 2. Installation
```bash
git clone https://github.com/your-org/sentinelvapt.git
cd sentinelvapt

# Install backend dependencies
pip install -r requirements.txt

# (Optional) Build frontend production bundle
cd frontend
npm install
npm run build
cd ..
```

### 3. Environment Configuration
Create a `.env` file in the project root (or copy from `.env.example`):
```ini
# Database (PostgreSQL or local SQLite fallback)
DATABASE_URL=sqlite+aiosqlite:///sentinelvapt.db
DATABASE_URL_SYNC=sqlite:///sentinelvapt.db

# LLM Provider (groq | ollama)
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# Safety Allowlist (Comma-separated IPs / CIDRs)
EXPLOIT_ALLOWLIST=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

---

## 💻 Usage Modes

### Mode A: Full Web Dashboard (Recommended)
Start the unified FastAPI server (which serves the React UI and API simultaneously):
```bash
python run.py --server
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

*(For active frontend development with Hot Module Replacement, run `npm run dev` in `frontend/` and browse to `http://localhost:5173`)*

### Mode B: Headless CLI Scans
Run autonomous scans directly from your terminal:
```bash
# Standard web assessment
python run.py --scan http://192.168.1.150:3000 --scope web

# API security assessment
python run.py --scan http://10.0.0.50/api/v1 --scope api

# Network infrastructure assessment with verified exploitation
python run.py --scan 192.168.1.200 --scope network --exploit
```

### Mode C: Tool Ecosystem Diagnostics
```bash
# Check installed tool status and paths
python run.py --check-tools

# Automatically install missing tools
python run.py --install-tools
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/system/health` | Health check & platform metrics |
| `GET` | `/api/tools` | Diagnostic status of all 10 security tools |
| `POST` | `/api/tools/install/{tool}` | Trigger installation of a specific tool |
| `POST` | `/api/scans` | Launch new scan (`target`, `scope_type`, `authorized_exploitation`) |
| `GET` | `/api/scans` | List all scans with severity counts |
| `GET` | `/api/scans/{id}` | Detailed scan record and stage status map |
| `GET` | `/api/scans/{id}/stream` | Server-Sent Events (SSE) real-time log stream |
| `POST` | `/api/scans/{id}/cancel` | Abort a running scan pipeline |
| `GET` | `/api/scans/{id}/findings` | Query scan findings (with `severity` and `tool` filters) |
| `PATCH` | `/api/findings/{id}` | Update finding triage / false-positive flag |
| `GET` | `/api/scans/{id}/defensive-rules` | List generated Sigma, Wazuh, Suricata rules |
| `GET` | `/api/scans/{id}/defensive-rules/export` | Download packaged ZIP of all detection rules |
| `GET` | `/api/scans/{id}/reports/download/{fmt}` | Download report (`pdf`, `json`, `markdown`) |

---

## 📁 Repository Structure

```
sentinelvapt/
├── backend/
│   ├── ai/               # LLM abstraction (Groq, Ollama) & analysis prompt templates
│   ├── api/              # FastAPI application, CORS, routers & SSE stream
│   ├── config/           # Pydantic BaseSettings & allowlist validator
│   ├── core/             # Pipeline orchestrator & state machine
│   ├── db/               # SQLAlchemy async models & session management
│   ├── defensive/        # Purple Team Sigma, Wazuh, Suricata rule generators
│   ├── reporting/        # ReportLab PDF, Markdown, and JSON report builders
│   └── tools/            # Tool wrappers (Nmap, Nuclei, ZAP, SQLMap, httpx, etc.) & installer
├── frontend/             # React + Vite cybersecurity dashboard
│   ├── src/
│   │   ├── components/   # Sidebar, NewScanModal, Stepper
│   │   ├── views/        # Dashboard, ScansList, ScanMonitor, Findings, Defensive, Tools
│   │   └── index.css     # Glassmorphic obsidian design system
│   └── vite.config.js    # Reverse proxy to backend
├── reports/              # Default destination for generated audit reports
├── requirements.txt      # Python dependencies
└── run.py                # Unified CLI & server runner
```

---

## 🛡️ License & Disclaimer
Built for professional penetration testers, purple teams, and application security engineers. Always obtain explicit written consent before assessing any target.
