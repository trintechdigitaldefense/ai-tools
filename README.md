# TrinTech AI Tools

Custom-built AI security tools, autonomous scanners, and intelligence platforms by **TrinTech Digital Defense**.

## 🔍 Security Tools

### SPECTER-THREAT / Rat-Detecter
**Flask-based RAT detection engine** with 1,454+ threat signatures across 7 detection modules.

- **Real-time dashboard** — Browser UI with live scan progress, risk scoring, and alerting
- **8 scan modules** — System info, network connections, listening ports, process analysis, file integrity, persistence detection, shell history, and hash matching
- **Multi-format reports** — PDF, HTML, and JSON export
- **REST API** — Start/monitor scans, retrieve results via Flask backend
- **Signature database** — RAT process names, suspicious ports, file keywords, persistence triggers, shell history patterns, domain TLDs, known-bad hashes

[View Rat-Detecter](TrinTech/Rat-Detecter/) · [Dashboard](TrinTech/Rat-Detecter/dashboard.html)

### FootprintScanner
**Digital footprint scanner** generating professional PDF audit reports.

- Multi-scanner pipeline (DNS, domain, email, IP, certificate, social, search)
- Automated PDF report generation with remediation guidance
- Configurable targets and scanning profiles

[View FootprintScanner](footprintscanner/)

## 🧠 AI Agent Skills
Collection of reusable skill modules for AI agent workflows:

| Category | Skills |
|----------|--------|
| Cloud & DevOps | [aleph-cloud](skills/aleph-cloud/), [devops](skills/devops/) |
| Security | [security](skills/security/), [web-security](skills/web-security/), [prompt-injection-defense](skills/prompt-injection-defense/) |
| Development | [python-dev](skills/python-dev/), [node-dev](skills/node-dev/), [nextjs-dev](skills/nextjs-dev/) |
| Blockchain | [crypto-research](skills/crypto-research/), [token-analysis](skills/token-analysis/), [wallet-forensics](skills/wallet-forensics/) |
| Data & Analysis | [data-analysis](skills/data-analysis/), [summarization](skills/summarization/) |
| Productivity | [email-management](skills/email-management/), [calendar-management](skills/calendar-management/), [notes-management](skills/notes-management/) |
| Learning | [learning-tutor](skills/learning-tutor/), [code-review](skills/code-review/) |

## 🏗️ Architecture

```
ai-tools/
├── TrinTech/
│   └── Rat-Detecter/        # RAT detection scanner
│       ├── Rat-Detecter.py   # Flask backend (1,628 lines)
│       ├── dashboard.html    # Browser UI (643 lines)
│       ├── requirements.txt
│       └── tests/            # Integration tests
├── footprintscanner/         # Digital footprint PDF scanner
│   ├── footprintscanner/     # Scanner modules
│   ├── tests/                # 33 unit tests
│   └── requirements.txt
├── skills/                   # AI agent skill modules
├── TODO.json                 # Agent task tracker
└── .gitignore
```

## 📊 Current Tool Inventory

| Tool | Language | Lines | Status | Tests |
|------|----------|-------|--------|-------|
| Rat-Detecter | Python | ~2,300 | ✅ Operational | 24/24 integration |
| FootprintScanner | Python | ~800 | ✅ Operational | 33/33 unit |
| AI Skills | Python/Markdown | ~500 | ✅ Deployed | N/A |

## 📜 License

Proprietary — TrinTech Digital Defense. All rights reserved.

## 🔗 Links

- GitHub: https://github.com/trintechdigitaldefense
- Agent URL: https://random-oppose-horror-edge.2n6.me
