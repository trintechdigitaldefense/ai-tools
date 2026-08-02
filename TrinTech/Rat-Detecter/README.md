# Rat-Detecter — SPECTER-THREAT v3.0

**TrinTech Digital Defense — RAT & Payload Detection Engine**

A professional-grade Remote Access Trojan (RAT) detection and threat analysis tool with real-time dashboard, AI-powered threat assessment, and multi-format reporting.

## Features

- **8-Module SPECTER Scan Engine** — System info, connections, ports, processes, files, persistence, shell history, hash verification
- **35+ RAT Signatures** — Detection of njRAT, NanoCore, DarkComet, Quasar, AsyncRAT, Remcos, Cobalt Strike, Metasploit, Sliver, and more
- **Live Web Dashboard** — Real-time scan progress, risk scores, findings, AI analysis (auto-refresh)
- **AI Threat Analysis** — Claude AI integration for plain-English threat summaries and remediation steps
- **Multi-format Reports** — PDF (professional), HTML, JSON export
- **CLI & API** — Full command-line interface and REST API
- **Safe PID Kill** — Terminate suspicious processes from dashboard or CLI
- **Whitelist Support** — Exclude trusted IPs/ports from alerts

## Installation

```bash
cd TrinTech/Rat-Detecter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### Web Dashboard (default)
```bash
python3 Rat-Detecter.py
# Open http://localhost:5050 in your browser
```

### CLI Quick Scan
```bash
python3 Rat-Detecter.py --quick
```

### CLI Full Scan
```bash
python3 Rat-Detecter.py --full --verbose
```

### Other Modes
```bash
python3 Rat-Detecter.py --ports     # Check suspicious ports only
python3 Rat-Detecter.py --procs     # Map PIDs to network activity
python3 Rat-Detecter.py --kill 1234 # Kill a flagged process
python3 Rat-Detecter.py --watch --interval 30  # Continuous monitoring
python3 Rat-Detecter.py --report json  # Export JSON report
python3 Rat-Detecter.py --report html  # Export HTML report
python3 Rat-Detecter.py --whitelist trusted.txt  # Whitelist trusted items
```

### With AI Analysis
```bash
python3 Rat-Detecter.py --full --api-key sk-ant-...
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/start` | POST | Start scan (body: `{"api_key": "", "mode": "full"}`) |
| `/api/state` | GET | Current scan state (progress, findings, risk) |
| `/api/report` | GET | Download PDF report |
| `/api/report/json` | GET | Download JSON report |
| `/api/kill` | POST | Kill process (body: `{"pid": 1234}`) |
| `/api/whitelist` | POST | Update whitelist (body: `{"items": ["8.8.8.8"]}`) |

## Project Structure

```
Rat-Detecter/
├── Rat-Detecter.py        # Main engine (Flask + CLI)
├── dashboard.html          # Live web dashboard UI
├── requirements.txt        # Python dependencies
├── tests/
│   └── test_api.py         # 24 integration tests (all passing)
├── trintech_reports/       # Generated reports (PDF, HTML, JSON)
│   ├── SPECTER_THREAT_Report_*.pdf
│   ├── SPECTER_JSON_*.json
│   ├── scanner.log         # Scan log file
│   └── ...
└── .venv/                  # Python virtual environment
```

## Threat Detection

### Process Signatures (35+)
njRAT, NanoCore, DarkComet, Quasar, AsyncRAT, Remcos, XtremeRAT, BlackShades, Cobalt Strike, Havoc, Sliver, Covenant, Empire, Meterpreter, Beacon, Pupy, Ducky, Venom, Platypus, Villain, HoaxShell, and more

### Suspicious Ports (25+)
Metasploit (4444), NetBus (12345, 20034), Back Orifice (31337, 54321), IRC C2 (6666, 6667), and 19 others

### Indicators of Compromise
- Reverse shell patterns (bash, python, PowerShell, PHP)
- Persistence mechanisms (cron, systemd, rc.local, startup scripts)
- Suspicious file keywords (keylogger, screen_capture, password_stealer)
- Known-bad file checksums (SHA-256, MD5)

## Upgrades from v2.0

- **Fixed**: Race conditions in thread-safe state management
- **Fixed**: JSON serialization crashes (sets → lists)
- **Fixed**: `threading` import missing
- **Fixed**: `requests.get().json()` crash on HTTP errors
- **Fixed**: SHA-256 hashes incorrectly labeled as MD5
- **Fixed**: Dangerous `chmod -R 777` on scanned files
- **Fixed**: `subprocess.Popen` without stdout capture
- **Added**: CLI arguments (`--quick`, `--full`, `--kill`, `--watch`, `--report`, `--whitelist`, `--procs`, `--ports`)
- **Added**: Safe PID kill endpoint with process validation
- **Added**: Whitelist/blacklist support
- **Added**: JSON report export API
- **Added**: File-based logging (scanner.log)
- **Added**: Mobile-first dashboard UI with real-time polling
- **Added**: 24 integration tests (all passing)
- **Improved**: Risk scoring with weighted severity + category multipliers
- **Improved**: Thread-safe finding counter (atomic read-modify-write)
- **Improved**: Error handling with proper try/except blocks
- **Improved**: Maximum findings limit (1000) to prevent unbounded growth

## Requirements

- Python 3.10+
- Flask, Flask-CORS, ReportLab, psutil, requests
- Anthropic SDK (optional, for AI analysis)
- No root required — runs in Termux/proot

## License

TrinTech Digital Defense — All rights reserved
