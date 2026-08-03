# Playbook Generator — TrinTech Digital Defense

## Overview

Automated incident response playbook generator. Takes incidents from Log Correlator and generates actionable response plans with MITRE ATT&CK mapping, containment/eradication/recovery steps, IOC extraction, and auto-generated firewall rules.

## Architecture

```
TrinTech Digital Defense
├── logcorrelator_playbook.py   # Core: Playbook, MITRE_MAP, SEVERITY_ESCALATION
├── playbook_server.py           # Flask API server (port 5054)
├── dashboard.html               # Web UI
├── test_playbook.py             # 46 tests (all passing)
└── trintech_reports/            # SQLite database
```

## Features

### MITRE ATT&CK Mapping
- Maps incident tags to specific ATT&CK techniques (T1059-T1595+)
- Maps severity to default techniques when tags are absent
- Includes tactic classification and mitigation steps per technique

### IOC Extraction
- Automatically extracts: IPs, files, processes, users from events
- Deduplicates across events
- Generates auto-firewall iptables rules for attacker IPs

### Three-Phase Response
- **Containment** — Immediate steps to stop the attack
- **Eradication** — Steps to remove the threat
- **Recovery** — Steps to restore normal operations

### Escalation Templates
- P1 (CRITICAL): CISO + Legal notification, 15 min response
- P2 (HIGH): SOC Lead notification, 1 hour response
- P3 (MEDIUM): On-call analyst, 4 hour response
- P4/P5 (LOW/INFO): Standard queue processing

### Integration
- Reads incidents directly from Log Correlator SQLite DB
- Works with Log Correlator's dict and object incident formats
- Auto-generates playbooks from full incident timelines

## API Reference

### Health
```
GET /api/health
```

### Playbook Generation
```
POST /api/playbook/generate
Body: {
  "incident_id": "inc-1",
  "severity": "CRITICAL",
  "tags": ["rat_detected", "privilege_escalation"],
  "events": [{"event_id":"e1","source":"specter","raw_message":"RAT",...}],
  "title": "Custom Title"
}

POST /api/playbook/from-logcorr
Body: {"db_path": "/path/to/log_correlator.db"}

POST /api/playbook/clear
```

### Query
```
GET /api/playbook/<playbook_id>      # Get specific playbook
GET /api/playbooks                    # List all playbooks
GET /api/playbook/<id>/text           # Playbook as plain text
```

### Report
```
GET /api/playbook/report              # All playbooks as text
GET /api/playbook/report/json         # All playbooks as JSON
```

### Dashboard
```
GET /dashboard                        # Web UI
```

## CLI

```bash
# Start API server (port 5054)
python3 playbook_server.py --server

# Generate playbooks from Log Correlator DB
python3 playbook_server.py --generate --db /path/to/log_correlator.db

# Print report
python3 playbook_server.py --report
```

## MITRE Techniques Mapped

| Tag | Technique | Tactic |
|-----|-----------|--------|
| authentication_failure | T1110 — Brute Force | Credential Access |
| privilege_escalation | T1068 — Exploitation for Privilege Escalation | Privilege Escalation |
| network_security | T1071 — Application Layer Protocol | C2 |
| rat_detected | T1547 — Boot or Logon Autostart | Persistence |
| persistence_mechanism | T1543 — Create/Modify System Process | Persistence |
| deception_triggered | T1595 — Active Scanning | Reconnaissance |
| threat_intel_match | Multiple | Various |

## Tests

```bash
python3 test_playbook.py
# 46 tests, all passing
```
