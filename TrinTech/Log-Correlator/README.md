# Log Correlator — TrinTech Digital Defense

## Overview

Unified Incident Timeline Engine. Ingests logs from multiple sources (system, auth, firewall, SPECTER-THREAT, Mirage, TI-Corr), correlates events by IP, user, hostname, process, and file — building actionable incident narratives across tools.

## Architecture

```
Log Correlator
├── engine.py          # Core: Ingestor, Correlator, Storage, Report, API
├── logcorrelator_server.py  # Flask server entry point
├── dashboard.html     # Web UI (incident timeline, events, correlations)
├── tests/             # 64 integration tests (all passing)
└── trintech_reports/log_correlator.db  # SQLite database
```

## Features

### Multi-Source Ingestion
- **Auth logs** — `/var/log/auth.log` or `/var/log/secure`
- **Syslog** — `/var/log/syslog` via journald
- **Firewall logs** — `/var/log/firewall.log` or `/var/log/kern.log`
- **SPECTER-THREAT** — Direct API import of scan findings
- **Mirage** — Direct API import of deception alerts
- **TI-Corr** — Direct API import of enrichment results
- **Custom** — Any JSON log file or raw text lines
- **JSON logs** — Structured JSON log ingestion

### Correlation Engine
- **IP correlation** — Same IP across sources = same attacker
- **User correlation** — Same user performing suspicious actions
- **Hostname correlation** — Targeted host with multiple alerts
- **Process correlation** — Same malicious process across log sources
- **File correlation** — Same file touched by multiple events
- **Time window** — Events within configurable window (default: 5 min)
- **Cross-source correlation** — Auth + Mirage + SPECTER = full attack narrative

### Incident Management
- Severity auto-computed (CRITICAL > HIGH > MEDIUM > LOW > INFO)
- Status tracking: NEW → INVESTIGATING → CONFIRMED → RESOLVED
- Human-readable narrative generation
- Manual IP assignment for incidents
- Notes and timeline per incident

### Reporting
- Text report with full incident details
- JSON stats (events, incidents, sources, severity breakdown)
- Top attacker IP ranking
- Source breakdown

## API Reference

### Health
```
GET /api/health
```

### Ingest
```
POST /api/ingest
Body: {"source": "auth", "lines": ["raw log line 1", ...]}

POST /api/ingest/specter
Body: {"findings": [{"module": "...", "description": "...", "severity": "HIGH", ...}]}

POST /api/ingest/mirage
Body: {"alerts": [{"alert_id": "m-1", "lure_type": "ssh_key", "actor_ip": "1.2.3.4", ...}]}

POST /api/ingest/ticorr
Body: {"enrichments": [{"finding_id": "f-1", "boosted_score": 80, ...}]}

POST /api/ingest/syslog
Body: {"path": "/var/log/syslog", "n_lines": 500}

POST /api/ingest/auth  (reads /var/log/auth.log)

POST /api/ingest/full-scan  (ingests all sources + correlates)
```

### Correlate
```
POST /api/correlate
Body: {"source": "auth"}  // Optional filter

POST /api/incident/<id>/narrative  // Regenerate narrative
```

### Query
```
GET /api/events?limit=500&source=auth
GET /api/event/<event_id>
GET /api/incidents?status=NEW&limit=100
GET /api/incident/<incident_id>
GET /api/incidents/unique-ips
GET /api/incidents/severity/CRITICAL
GET /api/stats
```

### Update
```
PUT /api/incident/<id>/status
Body: {"status": "CONFIRMED"}

PUT /api/incidents/<id>/assign-ip
Body: {"ip": "192.168.1.100"}
```

### Report
```
GET /api/report         (text/plain)
GET /api/report/json    (application/json)
```

## CLI

```bash
# Full scan (ingest all sources + correlate)
python3 logcorrelator_server.py --scan

# Correlate existing events
python3 logcorrelator_server.py --correlate

# Generate report
python3 logcorrelator_server.py --report

# Start API server (port 5053)
python3 logcorrelator_server.py --server

# Ingest from file
python3 logcorrelator_server.py --ingest-file /path/to/log --ingest-source custom
```

## Integration with Other TrinTech Tools

### With SPECTER-THREAT
```
SPECTER findings → Log Correlator → Cross-referenced with auth/syslog
→ Unified timeline: RAT detected at 10:00, auth failure at 09:55, firewall block at 09:50
```

### With Mirage
```
Mirage decoy hits → Log Correlator → Combined with SPECTER findings
→ "IP 5.6.7.8 touched SSH decoy at 09:50 → SPECTER detected C2 at 09:55"
```

### With TI-Corr
```
TI-Corr enrichment → Log Correlator → Adds threat intel context
→ "IP 5.6.7.8 confirmed APT group via CISA KEV + AbuseIPDB"
```

## Tests

```bash
python3 tests/test_logcorrelator.py
# 64 tests, all passing
```

## Database

SQLite database at `trintech_reports/log_correlator.db`:
- `events` — Normalized log events from all sources
- `incidents` — Correlated incident narratives
- `incident_events` — Junction table
- `correlation_links` — Event-to-event correlation edges
- `raw_logs` — Original log lines (for debugging)
