# FootprintScanner

**Digital Footprint Scanner** — Scans the clearnet for your digital footprint and generates actionable PDF security audit reports designed for non-technical stakeholders.

## Overview

FootprintScanner is a comprehensive digital footprint analysis tool that automatically scans public internet sources to discover and report on your organization's digital exposure. It produces professional PDF reports with:

- **Executive Summary** — Risk score, severity breakdown, and key findings at a glance
- **Detailed Findings** — All issues organized by severity with explanations
- **Remediation Plan** — Actionable steps to address each issue, prioritized by urgency
- **Professional Formatting** — Suitable for sharing with management, compliance teams, and auditors

## Features

### Scanners

| Module | What It Scans |
|--------|---------------|
| **Domain & WHOIS** | Domain age, registration details, privacy protection, MX records, internal IP exposure |
| **DNS Analysis** | DNSSEC, SPF, DKIM, DMARC, CAA, DANE, DNS record completeness |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CORS |
| **Email Footprint** | Breach data (HIBP), Gravatar profile, paste site leaks, email alias variations, professional profile links |
| **Social Media** | Username presence across 10+ platforms (Twitter, LinkedIn, GitHub, etc.) |
| **Search Engine** | Public web footprint for domain, email, and person name |
| **IP & Network** | IP reputation, geolocation, hosting type, reverse DNS, shared hosting analysis |
| **SSL/TLS** | Certificate validity, expiry, transparency logs, protocol support |

### Risk Assessment

- **5-tier severity** (Critical, High, Medium, Low, Info)
- **0-100 risk score** based on weighted findings across categories
- **Automated remediation** guidance for each finding
- **Priority categorization** for quick triage

### Reporting

- **Professional PDF** generated with ReportLab
- **Executive summary** with risk score bar and severity breakdown
- **Findings cards** with description, severity, and recommended actions
- **Remediation plan** with checkboxes and timelines
- **Confidentiality markings** for sensitive reports

## Installation

```bash
cd footprintscanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Quick scan of a domain

```bash
footprintscanner --domain example.com
```

### Scan with email address

```bash
footprintscanner --domain example.com --email admin@example.com
```

### Scan a person's footprint

```bash
footprintscanner --name "John Doe" --username johndoe
```

### Full scan with verbose output

```bash
footprintscanner -d example.com -e admin@example.com -n "John Doe" -v
```

### JSON output (for automation)

```bash
footprintscanner -d example.com --json > results.json
```

### Output to custom directory

```bash
footprintscanner -d example.com -o /path/to/reports/
```

## Configuration

Create `config.yaml` in the project root:

```yaml
request_delay: 1.0        # Seconds between HTTP requests
max_retries: 3            # Max retries per request
timeout: 15               # HTTP timeout (seconds)
hibp_api_key: null        # HaveIBeenPwned API key (optional)
max_concurrency: 6        # Concurrent scanner workers
output_dir: "footprint_reports"
```

Run `footprintscanner --help` to see all options.

## Project Structure

```
footprintscanner/
├── footprintscanner/
│   ├── main.py             # CLI entry point
│   ├── models.py           # Pydantic models (Finding, Target, ScanResult)
│   ├── config.py           # Configuration loader
│   ├── scanner.py          # Orchestrator (runs scanners concurrently)
│   ├── reputation.py       # Risk scoring engine
│   ├── remediation.py      # Remediation recommendations
│   ├── scanners/           # Individual scanner modules
│   │   ├── base.py         # Abstract base class
│   │   ├── domain.py       # WHOIS + domain registration
│   │   ├── dns.py          # DNSSEC, SPF, DKIM, DMARC
│   │   ├── email.py        # Breach checking, Gravatar, paste sites
│   │   ├── ip.py           # IP reputation, geolocation
│   │   ├── security_headers.py # HTTP header audit
│   │   ├── social.py       # Social media presence
│   │   ├── search.py       # Search engine footprint
│   │   └── certificate.py  # SSL/TLS certificate analysis
│   ├── reports/
│   │   └── pdf_generator.py  # ReportLab PDF generation
│   └── utils/
│       └── helpers.py      # Rate limiter, cache
├── tests/
│   ├── test_models.py
│   ├── test_reputation.py
│   ├── test_remediation.py
│   └── test_scanners.py
├── pyproject.toml
└── README.md
```

## License

MIT
